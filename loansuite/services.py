from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
import subprocess
import tempfile
import uuid
import datetime as dt
from typing import Any, Dict, List, Tuple

from .db import get_conn, sync_application_to_cloud, utcnow

REGIONS = ["North", "South", "East", "West", "Central"]
KYC_REQUIRED_DOCS = [
    "PAN Card",
    "Salary Slip 1",
    "Salary Slip 2",
    "Salary Slip 3",
    "Joining Letter",
    "Bank Statement (6 months)",
    "Selfie Image",
]
KYC_STEP_LABELS = {
    1: "Personal details",
    2: "Employment details",
    3: "Document upload",
    4: "OCR verification",
    5: "Risk review",
    6: "Final decision",
}
KYC_STATUS_SEQUENCE = ["pending", "verified", "manual_review", "rejected", "approved"]
QUALITY_LABELS = {"good", "blurred", "noisy", "low_contrast", "skewed", "insufficient_text"}
DOC_TYPE_ALIASES = {
    "pan_card": "PAN Card",
    "salary_slip_1": "Salary Slip 1",
    "salary_slip_2": "Salary Slip 2",
    "salary_slip_3": "Salary Slip 3",
    "joining_letter": "Joining Letter",
    "bank_statement": "Bank Statement (6 months)",
    "selfie_image": "Selfie Image",
}
DEMO_DOC_PACK = [
    ("PAN Card", "pan_card_n_v_jatin_pochiraju.pdf", "PAN Card"),
    ("Salary Slip 1", "salary_slip_1_n_v_jatin_pochiraju.pdf", "Salary Slip 1"),
    ("Salary Slip 2", "salary_slip_2_n_v_jatin_pochiraju.pdf", "Salary Slip 2"),
    ("Salary Slip 3", "salary_slip_3_n_v_jatin_pochiraju.pdf", "Salary Slip 3"),
    ("Joining Letter", "joining_letter_n_v_jatin_pochiraju.pdf", "Joining Letter"),
    ("Bank Statement (6 months)", "sbi_sample_bank_statement_n_v_jatin_pochiraju.pdf", "Bank Statement (6 months)"),
    ("Collateral Proof", "collateral_proof_n_v_jatin_pochiraju.pdf", "Collateral Proof"),
    ("Selfie Image", "selfie_placeholder_n_v_jatin_pochiraju.svg", "Selfie Image"),
]


def _json_loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-") or "item"


def _doc_storage_dir(db_path: str) -> str:
    root = os.path.dirname(os.path.abspath(db_path))
    path = os.path.join(root, "static", "generated_docs")
    os.makedirs(path, exist_ok=True)
    return path


def _demo_doc_dir(db_path: str) -> str:
    root = os.path.dirname(os.path.abspath(db_path))
    path = os.path.join(root, "generated_docs")
    os.makedirs(path, exist_ok=True)
    return path


def _write_demo_pdf(path: str, lines: List[str]):
    safe_lines = []
    for line in lines:
        safe = str(line).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        safe_lines.append(f"({safe}) Tj")
    content = "BT /F1 12 Tf 50 760 Td 0 -18 Td " + " T* ".join(safe_lines) + " ET"
    stream = content.encode("latin-1", errors="ignore")
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj\n"
        b"4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
        + f"5 0 obj<</Length {len(stream)}>>stream\n".encode("ascii")
        + stream
        + b"\nendstream\nendobj\nxref\n0 6\n0000000000 65535 f \n"
        b"0000000010 00000 n \n0000000063 00000 n \n0000000120 00000 n \n0000000246 00000 n \n0000000316 00000 n \n"
        b"trailer<</Size 6/Root 1 0 R>>\nstartxref\n"
        + str(316 + len(stream)).encode("ascii")
        + b"\n%%EOF\n"
    )
    with open(path, "wb") as f:
        f.write(pdf)


def _safe_ratio(numerator: float, denominator: float) -> float:
    return float(numerator) / max(1.0, float(denominator))


def _risk_label(score: float) -> str:
    if score >= 75:
        return "Low"
    if score >= 55:
        return "Medium"
    return "High"


def _approval_probability_from_review(review: Dict[str, Any]) -> float:
    status = str(review.get("approval_status", "manual_review"))
    base = {"approved": 0.84, "manual_review": 0.56, "rejected": 0.18}.get(status, 0.4)
    risk = str(review.get("risk_level", "Medium"))
    if risk == "High":
        base -= 0.14
    elif risk == "Low":
        base += 0.08
    return round(max(0.01, min(0.99, base)), 2)


def derive_application_credit_score(payload: Dict[str, Any]) -> Dict[str, Any]:
    annual_income = float(payload.get("current_salary") or 0.0)
    monthly_income = annual_income / 12.0 if annual_income else 0.0
    monthly_expenditure = float(payload.get("monthly_expenditure") or 0.0)
    existing_emi = float(payload.get("existing_emi") or 0.0)
    requested_amount = float(payload.get("requested_amount") or 0.0)
    employment_years = float(payload.get("employment_years") or 0.0)
    collateral_value = float(payload.get("collateral_value") or 0.0)

    dti = _safe_ratio(monthly_expenditure + existing_emi, monthly_income or 1.0)
    lti = _safe_ratio(requested_amount, annual_income or 1.0)
    collateral_cover = _safe_ratio(collateral_value, requested_amount or 1.0)

    score = 690.0
    score += min(85.0, max(0.0, (annual_income - 180000.0) / 1200000.0 * 85.0))
    score += min(45.0, max(0.0, employment_years / 10.0 * 45.0))
    score += min(40.0, max(0.0, min(collateral_cover, 1.0) * 40.0))
    score -= min(170.0, max(0.0, (dti - 0.22) * 240.0))
    score -= min(95.0, max(0.0, (lti - 0.35) * 38.0))

    rounded = max(300, min(900, int(round(score))))
    factors = {
        "annual_income": round(annual_income, 2),
        "monthly_income": round(monthly_income, 2),
        "dti": round(dti, 3),
        "lti": round(lti, 3),
        "collateral_cover": round(collateral_cover, 3),
        "employment_years": round(employment_years, 2),
        "source": "system_calculated",
    }
    return {"score": rounded, "factors": factors}


def _score_band_from_application(application: Dict[str, Any] | None) -> Tuple[str, str]:
    score = int((application or {}).get("credit_score") or 0)
    if score >= 750:
        return "excellent", f"Existing credit score output is {score}, which maps to an excellent repayment band."
    if score >= 700:
        return "good", f"Existing credit score output is {score}, which maps to a good repayment band."
    if score >= 650:
        return "fair", f"Existing credit score output is {score}, which maps to a fair band with tighter approval controls."
    if score > 0:
        return "low", f"Existing credit score output is {score}, which maps to a low band and raises review intensity."
    return "unavailable", "No linked application credit score is available yet."


def _latest_linked_application(db_path: str, user_id: int) -> Dict[str, Any] | None:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT *
            FROM loan_applications
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()


def _calculate_quality(file_bytes: bytes, text: str) -> Dict[str, Any]:
    size = len(file_bytes)
    unique = len(set(file_bytes[:1024])) if file_bytes else 0
    alpha = sum(1 for ch in text if ch.isalpha())
    spaces = text.count(" ")
    variance = unique / max(1, min(size, 1024))
    density = alpha / max(1, len(text))
    contrast_score = round(min(1.0, (variance * 2.2)), 3)
    blur_score = round(max(0.0, 1.0 - density * 2.4), 3)
    noise_score = round(max(0.0, min(1.0, _safe_ratio(sum(1 for ch in text if not ch.isalnum() and not ch.isspace()), max(1, len(text))), 0.18)), 3)
    skew_angle = round((sum(file_bytes[:64]) % 19) - 9 if file_bytes else 0, 2)
    quality = "good"
    if alpha < 25 or len(text.strip()) < 32:
        quality = "insufficient_text"
    elif contrast_score < 0.22:
        quality = "low_contrast"
    elif abs(skew_angle) > 7:
        quality = "skewed"
    elif noise_score > 0.72:
        quality = "noisy"
    elif blur_score > 0.72 or spaces < 3:
        quality = "blurred"
    return {
        "label": quality,
        "details": {
            "blur_score": blur_score,
            "noise_score": noise_score,
            "contrast_score": contrast_score,
            "skew_angle": skew_angle,
            "text_density": round(density, 3),
            "character_count": len(text),
        },
    }


def _parse_ocr_fields(doc_type: str, text: str, case_row: Dict[str, Any]) -> Dict[str, Any]:
    upper = text.upper()
    fields: Dict[str, Any] = {
        "employeeName": case_row.get("full_name", ""),
        "companyName": case_row.get("company_name", ""),
        "grossSalary": float(case_row.get("monthly_salary") or 0),
        "netSalary": round(float(case_row.get("monthly_salary") or 0) * 0.89, 2),
        "payPeriod": "",
        "joiningDate": "",
        "salaryCredits": [],
        "panNumber": case_row.get("pan_number", ""),
    }
    pan_match = re.search(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b", upper)
    if pan_match:
        fields["panNumber"] = pan_match.group(1)
    company_patterns = [
        r"(?:COMPANY|EMPLOYER|ORGANISATION|ORGANIZATION)\s*[:\-]\s*([A-Z0-9 &.,-]{3,80})",
        r"(?:M/S|M\.S\.)\s*([A-Z0-9 &.,-]{3,80})",
    ]
    for pattern in company_patterns:
        match = re.search(pattern, upper)
        if match:
            fields["companyName"] = match.group(1).strip(" .,-")
            break
    name_match = re.search(r"(?:EMPLOYEE|NAME)\s*[:\-]\s*([A-Z ]{4,80})", upper)
    if name_match:
        fields["employeeName"] = name_match.group(1).strip()
    join_match = re.search(r"(?:JOINING DATE|DOJ|DATE OF JOINING)\s*[:\-]\s*([0-9/\-]{6,16})", upper)
    if join_match:
        fields["joiningDate"] = join_match.group(1)
    period_match = re.search(r"(?:PAY PERIOD|SALARY MONTH|MONTH)\s*[:\-]\s*([A-Z0-9/\- ]{3,24})", upper)
    if period_match:
        fields["payPeriod"] = period_match.group(1).strip()
    gross_match = re.search(r"(?:GROSS SALARY|GROSS PAY|CTC)\s*[:\-]?\s*([0-9][0-9,]*(?:\.[0-9]+)?)", upper)
    if gross_match:
        fields["grossSalary"] = float(gross_match.group(1).replace(",", ""))
    net_match = re.search(r"(?:NET SALARY|NET PAY|TAKE HOME)\s*[:\-]?\s*([0-9][0-9,]*(?:\.[0-9]+)?)", upper)
    if net_match:
        fields["netSalary"] = float(net_match.group(1).replace(",", ""))
    credits = re.findall(r"(?:SALARY CREDIT|CREDIT|SALARY)\s*[:\-]?\s*([0-9][0-9,]*(?:\.[0-9]+)?)", upper)
    if credits:
        fields["salaryCredits"] = [float(item.replace(",", "")) for item in credits[:8]]
    if "bank statement" in doc_type.lower() and not fields["salaryCredits"]:
        number_matches = re.findall(r"\b([0-9]{4,7}(?:\.[0-9]{1,2})?)\b", upper)
        fields["salaryCredits"] = [float(item) for item in number_matches[:6]]
    return fields


def _extract_uploaded_text(filename: str, file_bytes: bytes) -> str:
    if filename.lower().endswith(".pdf") or file_bytes.startswith(b"%PDF"):
        try:
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as tmp:
                tmp.write(file_bytes)
                tmp.flush()
                result = subprocess.run(
                    ["pdftotext", "-layout", tmp.name, "-"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except (OSError, subprocess.SubprocessError):
            pass
    return file_bytes.decode("utf-8", errors="ignore")


def _verification_breakdown(case_row: Dict[str, Any], parsed_fields: Dict[str, Any]) -> Dict[str, Any]:
    monthly_salary = float(case_row.get("monthly_salary") or 0)
    stated_company = str(case_row.get("company_name", "")).strip().lower()
    stated_exp = float(case_row.get("years_of_experience") or 0)
    stated_name = str(case_row.get("full_name", "")).strip().lower()
    gross = float(parsed_fields.get("grossSalary") or parsed_fields.get("netSalary") or 0)
    company = str(parsed_fields.get("companyName", "")).strip().lower()
    joining_date = str(parsed_fields.get("joiningDate", "")).strip()
    credits = [float(x) for x in parsed_fields.get("salaryCredits", []) if float(x) > 0]
    salary_match = monthly_salary > 0 and abs(gross - monthly_salary) / max(1.0, monthly_salary) <= 0.15
    company_match = bool(stated_company and company and stated_company in company)
    experience_match = stated_exp <= 0
    if joining_date:
        year_match = re.search(r"(20[0-9]{2})", joining_date)
        if year_match:
            years = max(0.0, dt.datetime.utcnow().year - int(year_match.group(1)))
            experience_match = abs(years - stated_exp) <= 1.5 if stated_exp > 0 else True
    recurring_salary = bool(credits) and len([amt for amt in credits if monthly_salary <= 0 or abs(amt - monthly_salary) / max(1.0, monthly_salary) <= 0.2]) >= min(3, len(credits))
    employee_match = not stated_name or stated_name in str(parsed_fields.get("employeeName", "")).strip().lower()
    score = 0
    if salary_match:
        score += 30
    if company_match:
        score += 25
    if experience_match:
        score += 20
    if recurring_salary:
        score += 25
    mismatch_flags = []
    if not employee_match:
        mismatch_flags.append("employee_name_mismatch")
    if not salary_match:
        mismatch_flags.append("salary_mismatch")
    if not company_match:
        mismatch_flags.append("company_mismatch")
    if not experience_match:
        mismatch_flags.append("experience_mismatch")
    if not recurring_salary:
        mismatch_flags.append("salary_credit_inconsistency")
    return {
        "score": score,
        "salary_match": salary_match,
        "company_match": company_match,
        "experience_match": experience_match,
        "recurring_salary": recurring_salary,
        "mismatch_flags": mismatch_flags,
    }


def create_or_get_kyc_case(db_path: str, user_id: int, application_id: int | None = None) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        if application_id:
            row = conn.execute(
                "SELECT * FROM kyc_cases WHERE application_id = ? ORDER BY id DESC LIMIT 1",
                (application_id,),
            ).fetchone()
            if row:
                return row
        row = conn.execute(
            """
            SELECT *
            FROM kyc_cases
            WHERE user_id = ? AND approval_status = 'pending'
            ORDER BY id DESC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        if row:
            if application_id and not row.get("application_id"):
                conn.execute(
                    "UPDATE kyc_cases SET application_id = ?, updated_at = ? WHERE id = ?",
                    (application_id, utcnow(), row["id"]),
                )
                conn.commit()
                row = conn.execute("SELECT * FROM kyc_cases WHERE id = ?", (row["id"],)).fetchone()
            return row
        user = conn.execute(
            "SELECT id, full_name, email, phone FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        now = utcnow()
        conn.execute(
            """
            INSERT INTO kyc_cases (
                user_id, application_id, onboarding_step, full_name, email, phone, created_at, updated_at
            ) VALUES (?, ?, 1, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                application_id,
                (user or {}).get("full_name", ""),
                (user or {}).get("email", ""),
                (user or {}).get("phone", ""),
                now,
                now,
            ),
        )
        conn.commit()
        return conn.execute("SELECT * FROM kyc_cases ORDER BY id DESC LIMIT 1").fetchone()


def log_case_audit(
    db_path: str,
    case_id: int | None,
    application_id: int | None,
    action: str,
    actor: str,
    remarks: str,
    status_flow: str,
):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO decision_audit_ext (case_id, application_id, action, actor, remarks, status_flow, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (case_id, application_id, action, actor, remarks, status_flow, utcnow()),
        )
        conn.commit()


def update_kyc_case_profile(db_path: str, case_id: int, payload: Dict[str, Any], step: int) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        current = conn.execute("SELECT * FROM kyc_cases WHERE id = ?", (case_id,)).fetchone()
        if not current:
            raise ValueError("KYC case not found")
        merged = dict(current)
        merged.update(payload)
        conn.execute(
            """
            UPDATE kyc_cases
            SET onboarding_step = ?,
                full_name = ?,
                email = ?,
                phone = ?,
                pan_number = ?,
                aadhaar_last4 = ?,
                company_name = ?,
                designation = ?,
                years_of_experience = ?,
                monthly_salary = ?,
                requested_loan = ?,
                existing_emi = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                max(int(step), int(current.get("onboarding_step") or 1)),
                str(merged.get("full_name", ""))[:120],
                str(merged.get("email", ""))[:160],
                str(merged.get("phone", ""))[:30],
                str(merged.get("pan_number", ""))[:20],
                str(merged.get("aadhaar_last4", ""))[:4],
                str(merged.get("company_name", ""))[:120],
                str(merged.get("designation", ""))[:80],
                float(merged.get("years_of_experience") or 0),
                float(merged.get("monthly_salary") or 0),
                float(merged.get("requested_loan") or 0),
                float(merged.get("existing_emi") or 0),
                utcnow(),
                case_id,
            ),
        )
        conn.commit()
        return conn.execute("SELECT * FROM kyc_cases WHERE id = ?", (case_id,)).fetchone()


def upload_kyc_case_document(
    db_path: str,
    case_id: int,
    doc_type: str,
    filename: str,
    file_bytes: bytes,
) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        case_row = conn.execute("SELECT * FROM kyc_cases WHERE id = ?", (case_id,)).fetchone()
        if not case_row:
            raise ValueError("KYC case not found")
    text = _extract_uploaded_text(filename, file_bytes)
    quality = _calculate_quality(file_bytes, text)
    parsed_fields = _parse_ocr_fields(doc_type, text, case_row)
    verification = _verification_breakdown(case_row, parsed_fields)
    status = "manual_review" if quality["label"] != "good" or verification["score"] < 70 else "verified"
    storage_name = f"case-{case_id}-{_slug(doc_type)}-{_slug(filename)}"
    storage_path = os.path.join(_doc_storage_dir(db_path), storage_name)
    with open(storage_path, "wb") as f:
        f.write(file_bytes)
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO kyc_case_documents (
                case_id, application_id, doc_type, file_name, storage_path, mime_type, extracted_text,
                parsed_fields, verification_score, mismatch_flags, quality_label, quality_details, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                case_row.get("application_id"),
                doc_type,
                filename,
                storage_path,
                "",
                text[:4000],
                json.dumps(parsed_fields, separators=(",", ":")),
                float(verification["score"]),
                json.dumps(verification["mismatch_flags"], separators=(",", ":")),
                quality["label"],
                json.dumps(quality["details"], separators=(",", ":")),
                status,
                utcnow(),
            ),
        )
        if case_row.get("application_id"):
            conn.execute(
                """
                INSERT INTO document_intelligence (
                    application_id, ocr_payload, extracted_salary, extracted_region, mismatch_score, status,
                    created_at, extracted_text, parsed_fields_json, verification_score, mismatch_flags_json,
                    quality_label, quality_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_row["application_id"],
                    json.dumps({"doc_type": doc_type, "filename": filename}, separators=(",", ":")),
                    float(parsed_fields.get("grossSalary") or parsed_fields.get("netSalary") or 0),
                    case_row.get("company_name", ""),
                    round(len(verification["mismatch_flags"]) / 5.0, 3),
                    "Mismatch" if status == "manual_review" else "Clear",
                    utcnow(),
                    text[:4000],
                    json.dumps(parsed_fields, separators=(",", ":")),
                    float(verification["score"]),
                    json.dumps(verification["mismatch_flags"], separators=(",", ":")),
                    quality["label"],
                    json.dumps(quality["details"], separators=(",", ":")),
                ),
            )
        conn.execute(
            """
            UPDATE kyc_cases
            SET onboarding_step = CASE WHEN onboarding_step < 4 THEN 4 ELSE onboarding_step END,
                ocr_status = ?,
                verification_score = CASE WHEN verification_score < ? THEN ? ELSE verification_score END,
                quality_label = CASE WHEN ? != 'good' THEN ? ELSE quality_label END,
                kyc_status = CASE WHEN ? = 'manual_review' THEN 'manual_review' ELSE kyc_status END,
                status_flow = CASE WHEN ? = 'manual_review' THEN 'manual_review' ELSE status_flow END,
                updated_at = ?
            WHERE id = ?
            """,
            (
                status,
                float(verification["score"]),
                float(verification["score"]),
                quality["label"],
                quality["label"],
                status,
                status,
                utcnow(),
                case_id,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM kyc_case_documents ORDER BY id DESC LIMIT 1").fetchone()
    log_case_audit(
        db_path,
        case_id=case_id,
        application_id=case_row.get("application_id"),
        action="DOCUMENT_UPLOADED",
        actor="system",
        remarks=f"{doc_type} uploaded with quality={quality['label']} verification={verification['score']}",
        status_flow="manual_review" if status == "manual_review" else "ocr_verified",
    )
    return row


def get_kyc_case_documents(db_path: str, case_id: int) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT *
            FROM kyc_case_documents
            WHERE case_id = ?
            ORDER BY id ASC
            """,
            (case_id,),
        ).fetchall()


def list_demo_document_pack(db_path: str) -> List[Dict[str, Any]]:
    root = _demo_doc_dir(db_path)
    rows: List[Dict[str, Any]] = []
    for label, filename, doc_type in DEMO_DOC_PACK:
        path = os.path.join(root, filename)
        rows.append(
            {
                "label": label,
                "doc_type": doc_type,
                "file_name": filename,
                "path": path,
                "exists": os.path.exists(path),
            }
        )
    return rows


def import_demo_document_pack(db_path: str, case_id: int) -> Dict[str, Any]:
    detail = get_case_detail(db_path, case_id)
    if not detail:
        raise ValueError("KYC case not found")
    existing = {(row["doc_type"], row["file_name"]) for row in detail.get("documents", [])}
    imported = 0
    skipped = 0
    for item in list_demo_document_pack(db_path):
        if not item["exists"]:
            skipped += 1
            continue
        key = (item["doc_type"], item["file_name"])
        if key in existing:
            skipped += 1
            continue
        with open(item["path"], "rb") as f:
            upload_kyc_case_document(db_path, case_id, item["doc_type"], item["file_name"], f.read())
        imported += 1
    log_case_audit(
        db_path,
        case_id=case_id,
        application_id=detail.get("application_id"),
        action="DEMO_DOC_PACK_IMPORTED",
        actor="system",
        remarks=f"Imported {imported} demo docs; skipped {skipped}.",
        status_flow=detail.get("status_flow", "submitted"),
    )
    return {"imported": imported, "skipped": skipped}


def _latest_underwriting_review(db_path: str, case_id: int) -> Dict[str, Any] | None:
    with get_conn(db_path) as conn:
        return conn.execute(
            "SELECT * FROM underwriting_reviews WHERE case_id = ? ORDER BY id DESC LIMIT 1",
            (case_id,),
        ).fetchone()


def run_extended_underwriting(db_path: str, case_id: int) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        case_row = conn.execute("SELECT * FROM kyc_cases WHERE id = ?", (case_id,)).fetchone()
        if not case_row:
            raise ValueError("KYC case not found")
        docs = conn.execute(
            "SELECT * FROM kyc_case_documents WHERE case_id = ? ORDER BY id DESC",
            (case_id,),
        ).fetchall()
    salary = float(case_row.get("monthly_salary") or 0)
    emi = float(case_row.get("existing_emi") or 0)
    experience = float(case_row.get("years_of_experience") or 0)
    requested = float(case_row.get("requested_loan") or 0)
    ocr_score = float(case_row.get("verification_score") or 0)
    safe_loan = max(0.0, (0.4 * salary * 48) - (emi * 12))
    eligible = safe_loan
    approval_status = "approved"
    risk_level = "Low"
    remarks = []
    if salary <= 0:
        approval_status = "manual_review"
        risk_level = "High"
        remarks.append("Salary missing from KYC data.")
    if emi > salary * 0.4:
        approval_status = "manual_review"
        risk_level = "High"
        remarks.append("EMI exceeds 40% of salary.")
    if ocr_score < 70:
        approval_status = "manual_review"
        risk_level = "Medium" if risk_level == "Low" else risk_level
        remarks.append("OCR verification score below 70.")
    if experience < 1:
        eligible = min(eligible, safe_loan * 0.78)
        risk_level = "Medium" if risk_level == "Low" else risk_level
        remarks.append("Experience below 1 year; eligibility reduced.")
    mismatch_flags = []
    for doc in docs:
        mismatch_flags.extend(_json_loads(doc.get("mismatch_flags"), []))
        if doc.get("quality_label") != "good":
            approval_status = "manual_review"
            risk_level = "High"
            remarks.append(f"{doc.get('doc_type')} quality requires manual review.")
    if "salary_credit_inconsistency" in mismatch_flags:
        approval_status = "rejected"
        risk_level = "High"
        remarks.append("Inconsistent bank salary credits detected.")
    if case_row.get("kyc_status") in {"rejected", "manual_review"}:
        approval_status = "manual_review" if case_row.get("kyc_status") == "manual_review" else "rejected"
    suggested_safer_amount = max(0.0, min(eligible, safe_loan * 0.92))
    if requested > eligible and approval_status == "approved":
        risk_level = "Medium"
        remarks.append("Requested amount exceeds safer eligible amount.")
    confidence = max(0.15, min(0.98, (ocr_score / 100.0) * 0.45 + (0.35 if approval_status == "approved" else 0.18)))
    if risk_level == "High":
        confidence -= 0.12
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO underwriting_reviews (
                case_id, application_id, requested_amount, eligible_amount, suggested_safer_amount,
                safe_loan_amount, risk_level, approval_status, ocr_score, kyc_status,
                explanation, recommendation_confidence, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                case_row.get("application_id"),
                requested,
                round(max(0.0, eligible), 2),
                round(suggested_safer_amount, 2),
                round(safe_loan, 2),
                risk_level,
                approval_status,
                ocr_score,
                case_row.get("kyc_status", "pending"),
                " ".join(dict.fromkeys(remarks)) or "Case passed underwriting extension checks.",
                round(confidence, 2),
                utcnow(),
            ),
        )
        status_flow = "underwriting_review" if approval_status == "manual_review" else {
            "approved": "approved",
            "rejected": "rejected",
        }.get(approval_status, "underwriting_review")
        conn.execute(
            """
            UPDATE kyc_cases
            SET onboarding_step = CASE WHEN onboarding_step < 6 THEN 6 ELSE onboarding_step END,
                risk_level = ?,
                approval_status = ?,
                eligible_amount = ?,
                suggested_safer_amount = ?,
                status_flow = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (risk_level, approval_status, round(max(0.0, eligible), 2), round(suggested_safer_amount, 2), status_flow, utcnow(), case_id),
        )
        conn.commit()
        review = conn.execute("SELECT * FROM underwriting_reviews ORDER BY id DESC LIMIT 1").fetchone()
    log_case_audit(
        db_path,
        case_id=case_id,
        application_id=case_row.get("application_id"),
        action="UNDERWRITING_REVIEW",
        actor="system",
        remarks=review["explanation"],
        status_flow={"approved": "approved", "rejected": "rejected", "manual_review": "underwriting_review"}.get(review["approval_status"], "underwriting_review"),
    )
    return review


def sync_case_with_application(db_path: str, case_id: int, application: Dict[str, Any]) -> Dict[str, Any]:
    band, explanation = _score_band_from_application(application)
    with get_conn(db_path) as conn:
        current = conn.execute("SELECT * FROM kyc_cases WHERE id = ?", (case_id,)).fetchone()
        if not current:
            raise ValueError("KYC case not found")
        conn.execute(
            """
            UPDATE kyc_cases
            SET application_id = ?,
                monthly_salary = CASE WHEN monthly_salary <= 0 THEN ? ELSE monthly_salary END,
                requested_loan = CASE WHEN requested_loan <= 0 THEN ? ELSE requested_loan END,
                existing_emi = CASE WHEN existing_emi <= 0 THEN ? ELSE existing_emi END,
                years_of_experience = CASE WHEN years_of_experience <= 0 THEN ? ELSE years_of_experience END,
                cibil_band = ?,
                cibil_explanation = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                application["id"],
                float(application.get("current_salary") or 0),
                float(application.get("requested_amount") or 0),
                float(application.get("existing_emi") or 0),
                float(application.get("employment_years") or 0),
                band,
                explanation,
                utcnow(),
                case_id,
            ),
        )
        conn.commit()
        return conn.execute("SELECT * FROM kyc_cases WHERE id = ?", (case_id,)).fetchone()


def get_case_timeline(db_path: str, case_id: int) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT created_at AS timestamp, action, actor, remarks, status_flow
            FROM decision_audit_ext
            WHERE case_id = ?
            ORDER BY id DESC
            """,
            (case_id,),
        ).fetchall()


def get_case_detail(db_path: str, case_id: int) -> Dict[str, Any] | None:
    with get_conn(db_path) as conn:
        case_row = conn.execute(
            """
            SELECT kc.*, u.username
            FROM kyc_cases kc
            JOIN users u ON u.id = kc.user_id
            WHERE kc.id = ?
            """,
            (case_id,),
        ).fetchone()
    if not case_row:
        return None
    docs = get_kyc_case_documents(db_path, case_id)
    review = _latest_underwriting_review(db_path, case_id)
    timeline = get_case_timeline(db_path, case_id)
    artifacts = []
    with get_conn(db_path) as conn:
        artifacts = conn.execute(
            "SELECT * FROM mock_document_artifacts WHERE case_id = ? ORDER BY id DESC",
            (case_id,),
        ).fetchall()
    result = dict(case_row)
    result["documents"] = docs
    result["review"] = review
    result["timeline"] = timeline
    result["artifacts"] = artifacts
    return result


def list_kyc_cases_for_user(db_path: str, user_id: int, limit: int = 12) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT *
            FROM kyc_cases
            WHERE user_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()


def kyc_dashboard_overview(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT kc.*, u.username
            FROM kyc_cases kc
            JOIN users u ON u.id = kc.user_id
            ORDER BY kc.updated_at DESC, kc.id DESC
            LIMIT 300
            """
        ).fetchall()
    total = len(rows)
    approved = len([r for r in rows if r["approval_status"] == "approved"])
    rejected = len([r for r in rows if r["approval_status"] == "rejected"])
    manual = len([r for r in rows if r["approval_status"] == "manual_review" or r["kyc_status"] == "manual_review"])
    avg_ocr = round(sum(float(r.get("verification_score") or 0) for r in rows) / max(1, total), 2)
    risk_map = {"Low": 80, "Medium": 55, "High": 25}
    avg_risk = round(sum(risk_map.get(str(r.get("risk_level", "Medium")), 50) for r in rows) / max(1, total), 2)
    avg_cibil = round(
        sum({"excellent": 790, "good": 735, "fair": 675, "low": 610, "unavailable": 0}.get(str(r.get("cibil_band", "unavailable")), 0) for r in rows)
        / max(1, len([r for r in rows if str(r.get("cibil_band", "unavailable")) != "unavailable"])),
        2,
    ) if rows else 0.0
    fraud_queue = [r for r in rows if r["quality_label"] != "good" or r["risk_level"] == "High"][:20]
    for row in rows:
        row["fraud_probability_pct"] = max(
            4,
            min(
                96,
                int(
                    (35 if row["quality_label"] != "good" else 8)
                    + (28 if row["risk_level"] == "High" else 14 if row["risk_level"] == "Medium" else 6)
                    + max(0, int(70 - float(row.get("verification_score") or 0)) // 2)
                ),
            ),
        )
    return {
        "rows": rows,
        "cards": {
            "total_applications": total,
            "approved": approved,
            "rejected": rejected,
            "manual_review": manual,
            "average_ocr_score": avg_ocr,
            "average_risk_score": avg_risk,
            "average_cibil_score": avg_cibil,
        },
        "manual_queue": [r for r in rows if r["approval_status"] == "manual_review"][:20],
        "fraud_queue": fraud_queue,
        "mismatch_chart": [
            {"label": "Quality Failures", "value": len([r for r in rows if r["quality_label"] != "good"])},
            {"label": "OCR Manual Review", "value": len([r for r in rows if r["ocr_status"] == "manual_review"])},
            {"label": "KYC Pending", "value": len([r for r in rows if r["kyc_status"] == "pending"])},
            {"label": "Approved", "value": approved},
        ],
    }


def underwriting_dashboard_overview(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT ur.*, kc.full_name, kc.company_name, kc.status_flow, u.username
            FROM underwriting_reviews ur
            JOIN kyc_cases kc ON kc.id = ur.case_id
            JOIN users u ON u.id = kc.user_id
            ORDER BY ur.id DESC
            LIMIT 300
            """
        ).fetchall()
    total = len(rows)
    avg_ocr = round(sum(float(r.get("ocr_score") or 0) for r in rows) / max(1, total), 2)
    risk_score_map = {"Low": 82, "Medium": 58, "High": 26}
    avg_risk = round(sum(risk_score_map.get(str(r.get("risk_level", "Medium")), 50) for r in rows) / max(1, total), 2)
    avg_confidence = round(sum(float(r.get("recommendation_confidence") or 0) for r in rows) / max(1, total), 2)
    with get_conn(db_path) as conn:
        cibil_rows = conn.execute(
            """
            SELECT cibil_band, COUNT(*) AS total
            FROM kyc_cases
            GROUP BY cibil_band
            ORDER BY total DESC
            """
        ).fetchall()
    monthly = {}
    for row in rows:
        key = str(row.get("created_at", ""))[:7] or "unknown"
        entry = monthly.setdefault(key, {"label": key, "approved": 0, "rejected": 0, "manual_review": 0})
        entry[str(row["approval_status"])] = entry.get(str(row["approval_status"]), 0) + 1
    heatmap = []
    for row in rows[:24]:
        heatmap.append(
            {
                "label": f"Case #{row['case_id']}",
                "risk": row["risk_level"],
                "approval_probability": int(_approval_probability_from_review(row) * 100),
                "recommendation_confidence": int(float(row.get("recommendation_confidence") or 0) * 100),
                "fraud_probability": max(4, min(95, 100 - int(_approval_probability_from_review(row) * 100) + (18 if row["risk_level"] == "High" else 6))),
            }
        )
        row["approval_probability_pct"] = int(_approval_probability_from_review(row) * 100)
    return {
        "rows": rows,
        "cards": {
            "total_applications": total,
            "approved": len([r for r in rows if r["approval_status"] == "approved"]),
            "rejected": len([r for r in rows if r["approval_status"] == "rejected"]),
            "average_ocr_score": avg_ocr,
            "average_risk_score": avg_risk,
            "average_recommendation_confidence": round(avg_confidence * 100, 2),
        },
        "monthly_trend": list(monthly.values())[-6:],
        "heatmap": heatmap,
        "avg_cibil_graph": [{"label": row["cibil_band"], "value": row["total"]} for row in cibil_rows],
        "rejection_analytics": [
            {"label": "High Risk", "value": len([r for r in rows if r["risk_level"] == "High"])},
            {"label": "Manual Review", "value": len([r for r in rows if r["approval_status"] == "manual_review"])},
            {"label": "Rejected", "value": len([r for r in rows if r["approval_status"] == "rejected"])},
        ],
    }


def generate_plan_comparisons(case_row: Dict[str, Any], review: Dict[str, Any] | None) -> List[Dict[str, Any]]:
    salary = float(case_row.get("monthly_salary") or 0)
    emi_obligation = float(case_row.get("existing_emi") or 0)
    requested = float(case_row.get("requested_loan") or 0)
    eligible = float((review or {}).get("eligible_amount") or case_row.get("eligible_amount") or requested)
    base = max(0.0, min(eligible if eligible > 0 else requested, max(requested, eligible)))
    rate_options = [0.109, 0.121, 0.136]
    tenure_options = [36, 48, 60]
    cards = []
    for idx, tenure in enumerate(tenure_options):
        amount = round(max(50000.0, min(base * (0.9 + idx * 0.06), max(base, 50000.0))), 2)
        rate = rate_options[idx]
        emi = repayment_projection(amount, rate, tenure)["baseline_emi"]
        affordability = max(1, min(99, int((1.0 - _safe_ratio(emi_obligation + emi, max(1.0, salary))) * 100)))
        approval_prob = max(5, min(97, int((_approval_probability_from_review(review or {"approval_status": "manual_review", "risk_level": "Medium"}) * 100) + (affordability - 50) * 0.2)))
        cards.append(
            {
                "name": ["Shield Smart", "Shield Balance", "Shield Stretch"][idx],
                "loan_amount": amount,
                "tenure_months": tenure,
                "interest_rate": round(rate * 100, 2),
                "emi": round(emi, 2),
                "eligibility_pct": affordability,
                "approval_probability_pct": approval_prob,
                "best_match": idx == 1,
            }
        )
    return cards


def case_chat_context(db_path: str, user_id: int | None) -> Dict[str, Any]:
    if not user_id:
        return {}
    cases = list_kyc_cases_for_user(db_path, user_id, 1)
    if not cases:
        return {}
    case_row = cases[0]
    review = _latest_underwriting_review(db_path, case_row["id"])
    docs = get_kyc_case_documents(db_path, case_row["id"])
    missing_docs = []
    uploaded = {d["doc_type"] for d in docs}
    for key, label in DOC_TYPE_ALIASES.items():
        if label not in uploaded and key not in uploaded:
            missing_docs.append(label)
    return {"case": case_row, "review": review, "documents": docs, "missing_docs": missing_docs}


def generate_mock_documents_for_case(db_path: str, case_id: int) -> List[Dict[str, Any]]:
    detail = get_case_detail(db_path, case_id)
    if not detail:
        return []
    salary = float(detail.get("monthly_salary") or 0)
    company = detail.get("company_name") or "LoanShield Demo Corp"
    name = detail.get("full_name") or "Demo Applicant"
    net_salary = round(salary * 0.89, 2)
    join_year = max(2018, dt.datetime.utcnow().year - int(max(1, float(detail.get("years_of_experience") or 1))))
    lines_by_doc = {
        "salary_slip_pdf": [
            "LoanShield Salary Slip",
            f"Employee: {name}",
            f"Company: {company}",
            f"Gross Salary: {salary:.2f}",
            f"Net Salary: {net_salary:.2f}",
            f"Pay Period: {dt.datetime.utcnow().strftime('%b %Y')}",
            f"PAN: {detail.get('pan_number') or 'ABCDE1234F'}",
        ],
        "joining_letter_pdf": [
            "LoanShield Joining Letter",
            f"Employee: {name}",
            f"Company: {company}",
            f"Designation: {detail.get('designation') or 'Associate Analyst'}",
            f"Joining Date: 01-04-{join_year}",
            f"Annualized Salary: {salary * 12:.2f}",
        ],
        "bank_statement_pdf": [
            "LoanShield Bank Statement",
            f"Account Holder: {name}",
            "Recurring salary credits",
            f"Salary Credit: {net_salary:.2f}",
            f"Salary Credit: {net_salary:.2f}",
            f"Salary Credit: {net_salary:.2f}",
            f"Company: {company}",
        ],
    }
    created = []
    storage_dir = _doc_storage_dir(db_path)
    with get_conn(db_path) as conn:
        for doc_type, lines in lines_by_doc.items():
            path = os.path.join(storage_dir, f"case-{case_id}-{doc_type}.pdf")
            _write_demo_pdf(path, lines)
            checksum = hashlib.sha256(open(path, "rb").read()).hexdigest()
            conn.execute(
                """
                INSERT INTO mock_document_artifacts (case_id, doc_type, file_path, checksum, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (case_id, doc_type, path, checksum, utcnow()),
            )
            created.append({"doc_type": doc_type, "file_path": path, "checksum": checksum})
        conn.commit()
    log_case_audit(
        db_path,
        case_id=case_id,
        application_id=detail.get("application_id"),
        action="MOCK_DOCS_GENERATED",
        actor="system",
        remarks="Generated demo salary slip, joining letter, and bank statement PDFs.",
        status_flow=detail.get("status_flow", "submitted"),
    )
    return created


def bootstrap_mock_kyc_cases(db_path: str):
    with get_conn(db_path) as conn:
        existing = conn.execute("SELECT COUNT(*) AS cnt FROM kyc_cases").fetchone()
        if existing and int(existing["cnt"]) >= 20:
            return
        now = utcnow()
        status_plan = ["approved"] * 10 + ["manual_review"] * 5 + ["rejected"] * 5
        for idx in range(20):
            username = f"mockuser{idx + 1}"
            full_name = f"Mock User {idx + 1}"
            email = f"{username}@demo.local"
            phone = f"+9100000{idx + 10000}"
            conn.execute(
                """
                INSERT OR IGNORE INTO users (
                    username, full_name, password_hash, role, access_level, region, email, phone, created_at
                ) VALUES (?, ?, 'demo-hash', 'user', 'end_user', ?, ?, ?, ?)
                """,
                (username, full_name, REGIONS[idx % len(REGIONS)], email, phone, now),
            )
        conn.commit()
        users = conn.execute(
            """
            SELECT id, full_name, email, phone, username
            FROM users
            WHERE username LIKE 'mockuser%'
            ORDER BY username
            LIMIT 20
            """
        ).fetchall()
        for idx, user in enumerate(users):
            current = conn.execute("SELECT id FROM kyc_cases WHERE user_id = ?", (user["id"],)).fetchone()
            if current:
                continue
            status = status_plan[idx]
            salary = 55000 + idx * 3200
            requested = round(salary * 9.5, 2)
            ocr_score = 86 if status == "approved" else 68 if status == "manual_review" else 42
            risk = "Low" if status == "approved" else "Medium" if status == "manual_review" else "High"
            quality = "good" if status == "approved" else "blurred" if status == "manual_review" else "noisy"
            conn.execute(
                """
                INSERT INTO kyc_cases (
                    user_id, onboarding_step, full_name, email, phone, pan_number, aadhaar_last4,
                    company_name, designation, years_of_experience, monthly_salary, requested_loan,
                    existing_emi, kyc_status, ocr_status, verification_score, risk_level, approval_status,
                    eligible_amount, suggested_safer_amount, recommended_tenure_months, quality_label,
                    cibil_band, cibil_explanation, status_flow, metadata, created_at, updated_at
                ) VALUES (?, 6, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 48, ?, ?, ?, ?, '{}', ?, ?)
                """,
                (
                    user["id"],
                    user["full_name"],
                    user["email"] or f"{user['username']}@demo.local",
                    user["phone"] or f"+9100000{idx + 10000}",
                    f"ABCDE{idx:04d}F",
                    f"{1000 + idx}"[-4:],
                    f"Demo Employer {idx % 6 + 1}",
                    ["Analyst", "Manager", "Lead", "Associate"][idx % 4],
                    round(1.5 + idx * 0.3, 1),
                    salary,
                    requested,
                    round(salary * 0.12, 2),
                    "verified" if status == "approved" else status,
                    "verified" if status == "approved" else status,
                    ocr_score,
                    risk,
                    status,
                    round(requested * (0.95 if status == "approved" else 0.76 if status == "manual_review" else 0.52), 2),
                    round(requested * (0.88 if status == "approved" else 0.66 if status == "manual_review" else 0.4), 2),
                    quality,
                    "good" if status == "approved" else "fair" if status == "manual_review" else "low",
                    f"Derived explanation for demo case {idx + 1} using the existing score output band only.",
                    "approved" if status == "approved" else "manual_review" if status == "manual_review" else "rejected",
                    now,
                    now,
                ),
            )
        conn.commit()


def admin_case_decision(db_path: str, case_id: int, decision: str, actor: str, remarks: str) -> Dict[str, Any]:
    decision = decision.lower()
    if decision not in {"approved", "manual_review", "rejected", "verified"}:
        raise ValueError("Unsupported decision")
    status_flow = {
        "approved": "approved",
        "manual_review": "manual_review",
        "rejected": "rejected",
        "verified": "ocr_verified",
    }[decision]
    with get_conn(db_path) as conn:
        conn.execute(
            """
            UPDATE kyc_cases
            SET kyc_status = ?,
                approval_status = CASE WHEN ? IN ('approved','rejected','manual_review') THEN ? ELSE approval_status END,
                status_flow = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (decision, decision, decision, status_flow, utcnow(), case_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM kyc_cases WHERE id = ?", (case_id,)).fetchone()
    log_case_audit(
        db_path,
        case_id=case_id,
        application_id=row.get("application_id") if row else None,
        action="ADMIN_DECISION",
        actor=actor,
        remarks=remarks or f"Case marked {decision}",
        status_flow=status_flow,
    )
    return row


def append_chain(db_path: str, application_id: int | None, actor_id: int | None, event_type: str, payload: str) -> str:
    payload_digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    nonce = uuid.uuid4().hex
    ts = utcnow()

    with get_conn(db_path) as conn:
        row = conn.execute("SELECT current_hash FROM audit_chain ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["current_hash"] if row else "GENESIS"
        block = "|".join([prev, str(application_id or "0"), str(actor_id or "0"), event_type, payload_digest, ts, nonce])
        current = hashlib.sha256(block.encode("utf-8")).hexdigest()

        conn.execute(
            """
            INSERT INTO audit_chain (
                application_id, actor_id, event_type, event_payload, payload_digest,
                block_timestamp, nonce, previous_hash, current_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (application_id, actor_id, event_type, payload, payload_digest, ts, nonce, prev, current),
        )
        conn.commit()
    return current


def verify_chain(db_path: str) -> Tuple[bool, int]:
    with get_conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM audit_chain ORDER BY id ASC").fetchall()

    prev = "GENESIS"
    for row in rows:
        if row["previous_hash"] != prev:
            return False, len(rows)
        digest = hashlib.sha256(row["event_payload"].encode("utf-8")).hexdigest()
        block = "|".join(
            [
                row["previous_hash"],
                str(row["application_id"] or "0"),
                str(row["actor_id"] or "0"),
                row["event_type"],
                digest,
                row["block_timestamp"],
                row["nonce"],
            ]
        )
        expected = hashlib.sha256(block.encode("utf-8")).hexdigest()
        if expected != row["current_hash"]:
            return False, len(rows)
        prev = row["current_hash"]
    return True, len(rows)


def upsert_model_registry(db_path: str, version: str, sample_count: int, accuracy: float, roc_auc: float, features: List[str]):
    with get_conn(db_path) as conn:
        conn.execute("UPDATE model_registry SET is_active = 0")
        conn.execute(
            """
            INSERT INTO model_registry (version, trained_at, sample_count, accuracy, roc_auc, features_json, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            """,
            (version, utcnow(), sample_count, accuracy, roc_auc, json.dumps(features),),
        )
        conn.commit()


def active_model_info(db_path: str) -> Dict[str, Any] | None:
    with get_conn(db_path) as conn:
        return conn.execute(
            "SELECT version, trained_at, sample_count, accuracy, roc_auc, features_json FROM model_registry WHERE is_active = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()


def historical_training_rows(db_path: str) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT region, current_salary, monthly_expenditure, existing_emi,
                   requested_amount, loan_term_months, employment_years,
                   credit_score, collateral_value, status
            FROM loan_applications
            """
        ).fetchall()


def create_application(db_path: str, payload: Dict[str, Any], decision: Dict[str, Any], user_id: int) -> int:
    created_at = utcnow()
    policy_type = str(payload.get("policy_type", "STANDARD") or "STANDARD")
    with get_conn(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO loan_applications (
                user_id, region, product_code, policy_type, current_salary, monthly_expenditure, existing_emi,
                requested_amount, loan_term_months, employment_years, credit_score,
                collateral_value, risk_score, approval_probability, status, tier,
                interest_rate, monthly_payment_est, recommended_amount, model_version,
                decision_factors, application_request_datetime, application_request_createdtime, created_at, blockchain_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                payload["region"],
                payload.get("product_code", "STANDARD"),
                policy_type,
                payload["current_salary"],
                payload["monthly_expenditure"],
                payload["existing_emi"],
                payload["requested_amount"],
                payload["loan_term_months"],
                payload["employment_years"],
                payload["credit_score"],
                payload["collateral_value"],
                decision["risk_score"],
                decision["approval_probability"],
                decision["status"],
                decision["tier"],
                decision["interest_rate"],
                decision["monthly_payment_est"],
                decision["recommended_amount"],
                decision["model_version"],
                decision["decision_factors"],
                created_at,
                created_at,
                created_at,
                "PENDING",
            ),
        )
        app_id = cur.lastrowid
        conn.commit()
    sync_application_to_cloud(
        {
            "id": app_id,
            "user_id": user_id,
            "region": payload["region"],
            "product_code": payload.get("product_code", "STANDARD"),
            "policy_type": policy_type,
            "requested_amount": payload["requested_amount"],
            "status": decision["status"],
            "tier": decision["tier"],
            "risk_score": decision["risk_score"],
            "approval_probability": decision["approval_probability"],
            "model_version": decision["model_version"],
            "decision_factors": decision["decision_factors"],
            "created_at": created_at,
        }
    )
    return app_id


def set_application_hash(db_path: str, app_id: int, block_hash: str):
    with get_conn(db_path) as conn:
        conn.execute("UPDATE loan_applications SET blockchain_hash = ? WHERE id = ?", (block_hash, app_id))
        conn.commit()


def _with_borrower_segment(row: Dict[str, Any] | None) -> Dict[str, Any] | None:
    if not row:
        return row
    result = dict(row)
    segment = "-"
    loan_type = "PERSONAL"
    preferred_currencies: List[str] = ["USD"]
    try:
        factors = json.loads(result.get("decision_factors", "{}"))
        segment = factors.get("borrower_segment", "-")
        loan_type = str(factors.get("loan_type", "PERSONAL") or "PERSONAL").upper()
        raw_currencies = factors.get("preferred_currencies", ["USD"])
        if isinstance(raw_currencies, list):
            preferred_currencies = [str(x).upper() for x in raw_currencies if str(x).strip()]
        elif isinstance(raw_currencies, str) and raw_currencies.strip():
            preferred_currencies = [raw_currencies.strip().upper()]
    except Exception:
        segment = "-"
        loan_type = "PERSONAL"
        preferred_currencies = ["USD"]
    if not preferred_currencies:
        preferred_currencies = ["USD"]
    result["borrower_segment"] = segment
    result["loan_type"] = loan_type
    result["preferred_currencies"] = preferred_currencies
    result["preferred_currencies_label"] = ", ".join(preferred_currencies)
    return result


def _with_borrower_segment_list(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [_with_borrower_segment(r) for r in rows]


def get_application(db_path: str, app_id: int) -> Dict[str, Any] | None:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM loan_applications WHERE id = ?", (app_id,)).fetchone()
    return _with_borrower_segment(row)


def user_applications(db_path: str, user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM loan_applications WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return _with_borrower_segment_list(rows)


def all_applications(db_path: str, limit: int = 200) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT la.*, u.username, u.full_name
            FROM loan_applications la
            JOIN users u ON u.id = la.user_id
            ORDER BY la.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return _with_borrower_segment_list(rows)


def update_application_decision(db_path: str, app_id: int, status: str, tier: str):
    with get_conn(db_path) as conn:
        conn.execute(
            "UPDATE loan_applications SET status = ?, tier = ? WHERE id = ?",
            (status, tier, app_id),
        )
        conn.commit()


def user_insights(db_path: str, user_id: int) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        totals = conn.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status = 'Approved' THEN 1 ELSE 0 END) AS approved,
                   AVG(approval_probability) AS avg_prob,
                   AVG(risk_score) AS avg_risk,
                   AVG(requested_amount) AS avg_req
            FROM loan_applications
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        regions = conn.execute(
            """
            SELECT region,
                   COUNT(*) AS count,
                   AVG(approval_probability) AS avg_prob
            FROM loan_applications
            WHERE user_id = ?
            GROUP BY region
            ORDER BY count DESC
            """,
            (user_id,),
        ).fetchall()

    totals = totals or {"total": 0, "approved": 0, "avg_prob": 0, "avg_risk": 0, "avg_req": 0}
    return {"totals": totals, "regions": regions}


def admin_insights(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        overview = conn.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status = 'Approved' THEN 1 ELSE 0 END) AS approved,
                   SUM(CASE WHEN status = 'Manual Review' THEN 1 ELSE 0 END) AS manual,
                   SUM(CASE WHEN status = 'Rejected' THEN 1 ELSE 0 END) AS rejected,
                   AVG(current_salary) AS avg_salary,
                   AVG(monthly_expenditure) AS avg_exp,
                   AVG(approval_probability) AS avg_prob
            FROM loan_applications
            """
        ).fetchone()

        by_region = conn.execute(
            """
            SELECT region,
                   COUNT(*) AS total,
                   AVG(CASE WHEN status = 'Approved' THEN 1.0 ELSE 0.0 END) AS approval_rate,
                   AVG(current_salary) AS avg_salary,
                   AVG(monthly_expenditure) AS avg_exp
            FROM loan_applications
            GROUP BY region
            ORDER BY total DESC
            """
        ).fetchall()

        recent_events = conn.execute(
            """
            SELECT ac.block_timestamp, ac.event_type, ac.current_hash,
                   COALESCE(u.username, 'system') AS actor
            FROM audit_chain ac
            LEFT JOIN users u ON u.id = ac.actor_id
            ORDER BY ac.id DESC
            LIMIT 12
            """
        ).fetchall()

    return {
        "overview": overview or {},
        "by_region": by_region,
        "recent_events": recent_events,
    }


def _safe_symbol(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "", value or "")
    return cleaned[:64]


def _pascal_case(value: str) -> str:
    tokens = re.split(r"[^A-Za-z0-9]+", value or "")
    joined = "".join(t[:1].upper() + t[1:] for t in tokens if t)
    return joined or "GeneratedEntity"


def _java_type(field_type: str, typelist_name: str | None) -> str:
    if typelist_name:
        return "String"
    mapping = {
        "string": "String",
        "int": "Integer",
        "float": "Double",
        "decimal": "Double",
        "bool": "Boolean",
        "date": "String",
        "datetime": "String",
        "createdtime": "String",
        "entity_ref": "String",
        "array": "java.util.List<String>",
    }
    return mapping.get((field_type or "").lower(), "String")


def _gosu_type(field_type: str, typelist_name: str | None) -> str:
    if typelist_name:
        return "String"
    mapping = {
        "string": "String",
        "int": "int",
        "float": "double",
        "decimal": "double",
        "bool": "boolean",
        "date": "String",
        "datetime": "String",
        "createdtime": "String",
        "entity_ref": "String",
        "array": "List<String>",
    }
    return mapping.get((field_type or "").lower(), "String")


def _generate_entity_java(entity: Dict[str, Any], fields: List[Dict[str, Any]]) -> str:
    class_name = _pascal_case(entity["name"])
    supertype = _pascal_case(entity["supertype"]) if entity.get("supertype") else None
    extends_clause = f" extends {supertype}" if supertype else ""
    lines: List[str] = [
        "package generated.model;",
        "",
        f"public class {class_name}{extends_clause} {{",
    ]
    for f in fields:
        fname = _safe_symbol(f["field_name"])
        ftype = _java_type(f["field_type"], f.get("typelist_name"))
        lines.append(f"    private {ftype} {fname};")
    if not fields:
        lines.append("    // No extension fields yet.")
    lines.append("")
    for f in fields:
        fname = _safe_symbol(f["field_name"])
        cap = fname[:1].upper() + fname[1:]
        ftype = _java_type(f["field_type"], f.get("typelist_name"))
        lines.append(f"    public {ftype} get{cap}() {{ return this.{fname}; }}")
        lines.append(f"    public void set{cap}({ftype} value) {{ this.{fname} = value; }}")
        lines.append("")
    lines.append("}")
    return "\n".join(lines)


def _generate_entity_gosu(entity: Dict[str, Any], fields: List[Dict[str, Any]]) -> str:
    class_name = _pascal_case(entity["name"])
    supertype = _pascal_case(entity["supertype"]) if entity.get("supertype") else None
    extends_clause = f" extends {supertype}" if supertype else ""
    lines: List[str] = [
        "package generated.model",
        "",
        f"class {class_name}{extends_clause} {{",
    ]
    if not fields:
        lines.append("  // No extension fields yet.")
    for f in fields:
        fname = _safe_symbol(f["field_name"])
        ftype = _gosu_type(f["field_type"], f.get("typelist_name"))
        lines.append(f"  var {fname}: {ftype}")
    lines.append("}")
    return "\n".join(lines)


def _generate_typelist_java(typelist_name: str, entries: List[Dict[str, Any]]) -> str:
    enum_name = _pascal_case(typelist_name)
    lines: List[str] = [
        "package generated.typelist;",
        "",
        f"public enum {enum_name} {{",
    ]
    if entries:
        constants = [re.sub(r"[^A-Za-z0-9_]", "_", e["code"].upper()) for e in entries]
        lines.append("    " + ", ".join(constants) + ";")
    else:
        lines.append("    // No entries yet")
    lines.append("}")
    return "\n".join(lines)


def _generate_typelist_gosu(typelist_name: str, entries: List[Dict[str, Any]]) -> str:
    enum_name = _pascal_case(typelist_name)
    lines: List[str] = [
        "package generated.typelist",
        "",
        f"enum {enum_name} {{",
    ]
    if entries:
        for idx, e in enumerate(entries):
            token = re.sub(r"[^A-Za-z0-9_]", "_", e["code"].upper())
            suffix = "," if idx < len(entries) - 1 else ""
            lines.append(f"  {token}{suffix}")
    else:
        lines.append("  // No entries yet")
    lines.append("}")
    return "\n".join(lines)


def create_entity_definition(
    db_path: str,
    name: str,
    supertype: str | None,
    subtype: str | None,
    description: str,
    created_by: int,
):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO entity_definitions (name, supertype, subtype, description, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, supertype, subtype, description, created_by, utcnow()),
        )
        conn.commit()


def create_or_update_entity_field(
    db_path: str,
    entity_name: str,
    field_name: str,
    field_type: str,
    extension_type: str,
    relation_type: str,
    related_entity: str | None,
    foreign_key_field: str | None,
    is_array: bool,
    is_circular: bool,
    nullable: bool,
    typelist_name: str | None,
    description: str,
    created_by: int,
):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO entity_fields (
                entity_name, field_name, field_type, extension_type, relation_type,
                related_entity, foreign_key_field, is_array, is_circular, nullable,
                typelist_name, description, created_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_name, field_name) DO UPDATE SET
                field_type=excluded.field_type,
                extension_type=excluded.extension_type,
                relation_type=excluded.relation_type,
                related_entity=excluded.related_entity,
                foreign_key_field=excluded.foreign_key_field,
                is_array=excluded.is_array,
                is_circular=excluded.is_circular,
                nullable=excluded.nullable,
                typelist_name=excluded.typelist_name,
                description=excluded.description
            """,
            (
                entity_name,
                field_name,
                field_type,
                extension_type,
                relation_type,
                related_entity,
                foreign_key_field,
                1 if is_array else 0,
                1 if is_circular else 0,
                1 if nullable else 0,
                typelist_name,
                description,
                created_by,
                utcnow(),
            ),
        )
        conn.commit()


def create_typelist(db_path: str, name: str, description: str, created_by: int):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO typelists (name, description, created_by, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (name, description, created_by, utcnow()),
        )
        conn.commit()


def add_typelist_entry(
    db_path: str,
    typelist_name: str,
    code: str,
    display_name: str,
    sort_order: int,
    created_by: int,
):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO typelist_entries (typelist_name, code, display_name, sort_order, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(typelist_name, code) DO UPDATE SET
                display_name=excluded.display_name,
                sort_order=excluded.sort_order
            """,
            (typelist_name, code, display_name, sort_order, created_by, utcnow()),
        )
        conn.commit()


def get_data_model(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        entities = conn.execute(
            """
            SELECT ed.*, COUNT(ef.id) AS field_count
            FROM entity_definitions ed
            LEFT JOIN entity_fields ef ON ef.entity_name = ed.name
            GROUP BY ed.id
            ORDER BY ed.name
            """
        ).fetchall()
        fields = conn.execute(
            "SELECT * FROM entity_fields ORDER BY entity_name, field_name"
        ).fetchall()
        typelists = conn.execute(
            """
            SELECT t.*, COUNT(te.id) AS entry_count
            FROM typelists t
            LEFT JOIN typelist_entries te ON te.typelist_name = t.name
            GROUP BY t.id
            ORDER BY t.name
            """
        ).fetchall()
        entries = conn.execute(
            "SELECT * FROM typelist_entries ORDER BY typelist_name, sort_order, code"
        ).fetchall()

    fields_by_entity: Dict[str, List[Dict[str, Any]]] = {}
    for f in fields:
        fields_by_entity.setdefault(f["entity_name"], []).append(f)
    entries_by_typelist: Dict[str, List[Dict[str, Any]]] = {}
    for e in entries:
        entries_by_typelist.setdefault(e["typelist_name"], []).append(e)

    return {
        "entities": entities,
        "fields_by_entity": fields_by_entity,
        "typelists": typelists,
        "entries_by_typelist": entries_by_typelist,
    }


def regenerate_model_code(db_path: str, out_dir: str) -> Dict[str, Any]:
    data = get_data_model(db_path)
    java_model_dir = os.path.join(out_dir, "java", "generated", "model")
    gosu_model_dir = os.path.join(out_dir, "gosu", "generated", "model")
    java_type_dir = os.path.join(out_dir, "java", "generated", "typelist")
    gosu_type_dir = os.path.join(out_dir, "gosu", "generated", "typelist")
    os.makedirs(java_model_dir, exist_ok=True)
    os.makedirs(gosu_model_dir, exist_ok=True)
    os.makedirs(java_type_dir, exist_ok=True)
    os.makedirs(gosu_type_dir, exist_ok=True)

    generated_files: List[str] = []
    for entity in data["entities"]:
        name = _pascal_case(entity["name"])
        fields = data["fields_by_entity"].get(entity["name"], [])
        java_code = _generate_entity_java(entity, fields)
        gosu_code = _generate_entity_gosu(entity, fields)
        java_path = os.path.join(java_model_dir, f"{name}.java")
        gosu_path = os.path.join(gosu_model_dir, f"{name}.gs")
        with open(java_path, "w", encoding="utf-8") as f:
            f.write(java_code + "\n")
        with open(gosu_path, "w", encoding="utf-8") as f:
            f.write(gosu_code + "\n")
        generated_files.extend([java_path, gosu_path])

    for typelist in data["typelists"]:
        name = _pascal_case(typelist["name"])
        entries = data["entries_by_typelist"].get(typelist["name"], [])
        java_code = _generate_typelist_java(typelist["name"], entries)
        gosu_code = _generate_typelist_gosu(typelist["name"], entries)
        java_path = os.path.join(java_type_dir, f"{name}.java")
        gosu_path = os.path.join(gosu_type_dir, f"{name}.gs")
        with open(java_path, "w", encoding="utf-8") as f:
            f.write(java_code + "\n")
        with open(gosu_path, "w", encoding="utf-8") as f:
            f.write(gosu_code + "\n")
        generated_files.extend([java_path, gosu_path])

    return {"count": len(generated_files), "files": generated_files[-8:]}


def generated_artifacts_summary(out_dir: str, limit: int = 14) -> List[Dict[str, Any]]:
    if not os.path.isdir(out_dir):
        return []
    collected: List[Dict[str, Any]] = []
    for root, _, files in os.walk(out_dir):
        for name in files:
            if not (name.endswith(".java") or name.endswith(".gs")):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, out_dir)
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            collected.append({"path": rel, "size": size})
    collected.sort(key=lambda x: x["path"])
    return collected[:limit]


def bootstrap_loan_products(db_path: str):
    products = [
        ("MICRO", "Micro Loan", "BASIC", 1000, 50000, 0.082, "Low-value, minimal verification"),
        ("STANDARD", "Standard Loan", "STANDARD", 50001, 150000, 0.088, "General retail loan"),
        ("PLUS", "Plus Loan", "FAMILY", 150001, 300000, 0.095, "Enhanced verification and collateral"),
        ("PREMIUM", "Premium Loan", "PREMIUM", 300001, 3000000, 0.102, "Comprehensive checks with collateral"),
    ]
    rules = [
        ("MICRO", "Minimal", 0.0, 620, 0.68, ["Government ID", "Basic Income Proof"]),
        ("STANDARD", "Standard", 0.0, 650, 0.64, ["Government ID", "Income Proof", "Bank Statements (3 months)"]),
        ("PLUS", "Enhanced", 0.15, 680, 0.58, ["Government ID", "Income Proof", "Bank Statements (6 months)", "Employment Verification", "Tax Returns (1 year)"]),
        ("PREMIUM", "Comprehensive", 0.30, 700, 0.52, ["Government ID", "Income Proof", "Bank Statements (12 months)", "Employment Verification", "Tax Returns (2 years)", "Asset & Liability Statement"]),
    ]
    with get_conn(db_path) as conn:
        for p in products:
            conn.execute(
                """
                INSERT OR IGNORE INTO loan_products (code, name, policy_type, min_amount, max_amount, base_rate, description, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (*p, utcnow()),
            )
        for r in rules:
            conn.execute(
                """
                INSERT OR IGNORE INTO product_rules (
                    product_code, verification_level, required_collateral_ratio,
                    min_credit_score, max_dti, required_documents_json, is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (r[0], r[1], r[2], r[3], r[4], json.dumps(r[5]), utcnow()),
            )
        conn.commit()


def get_active_products(db_path: str) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            "SELECT code, name, policy_type, min_amount, max_amount, base_rate, description FROM loan_products WHERE is_active=1 ORDER BY min_amount ASC"
        ).fetchall()


def get_product_policy_for_amount(db_path: str, amount: float) -> Dict[str, Any] | None:
    with get_conn(db_path) as conn:
        product = conn.execute(
            """
            SELECT code, name, min_amount, max_amount, base_rate
            FROM loan_products
            WHERE is_active=1 AND ? BETWEEN min_amount AND max_amount
            ORDER BY min_amount ASC LIMIT 1
            """,
            (amount,),
        ).fetchone()
        if not product:
            product = conn.execute(
                "SELECT code, name, min_amount, max_amount, base_rate FROM loan_products WHERE is_active=1 ORDER BY max_amount DESC LIMIT 1"
            ).fetchone()
        if not product:
            return None
        rule = conn.execute(
            """
            SELECT verification_level, required_collateral_ratio, min_credit_score, max_dti, required_documents_json
            FROM product_rules
            WHERE is_active=1 AND product_code=?
            ORDER BY id DESC LIMIT 1
            """,
            (product["code"],),
        ).fetchone()
    if not rule:
        return None
    return {
        "product_code": product["code"],
        "product_name": product["name"],
        "base_rate": product["base_rate"],
        "verification_level": rule["verification_level"],
        "required_collateral_ratio": rule["required_collateral_ratio"],
        "min_credit_score": rule["min_credit_score"],
        "max_dti": rule["max_dti"],
        "required_documents": json.loads(rule["required_documents_json"]),
    }


def get_product_policy_by_code(db_path: str, product_code: str) -> Dict[str, Any] | None:
    with get_conn(db_path) as conn:
        product = conn.execute(
            """
            SELECT code, name, min_amount, max_amount, base_rate
            FROM loan_products
            WHERE is_active=1 AND code=?
            LIMIT 1
            """,
            (product_code,),
        ).fetchone()
        if not product:
            return None
        rule = conn.execute(
            """
            SELECT verification_level, required_collateral_ratio, min_credit_score, max_dti, required_documents_json
            FROM product_rules
            WHERE is_active=1 AND product_code=?
            ORDER BY id DESC LIMIT 1
            """,
            (product_code,),
        ).fetchone()
    if not rule:
        return None
    return {
        "product_code": product["code"],
        "product_name": product["name"],
        "base_rate": product["base_rate"],
        "verification_level": rule["verification_level"],
        "required_collateral_ratio": rule["required_collateral_ratio"],
        "min_credit_score": rule["min_credit_score"],
        "max_dti": rule["max_dti"],
        "required_documents": json.loads(rule["required_documents_json"]),
        "min_amount": product["min_amount"],
        "max_amount": product["max_amount"],
    }


def record_kyc_document_hash(db_path: str, application_id: int, doc_type: str, doc_source_value: str, metadata: str = "") -> str:
    payload = f"{doc_type}|{doc_source_value}"
    doc_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO kyc_documents (application_id, doc_type, doc_hash, metadata, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (application_id, doc_type, doc_hash, metadata, utcnow()),
        )
        conn.commit()
    return doc_hash


def _next_months_iso(months: int) -> str:
    due = dt.date.today() + dt.timedelta(days=int(30 * months))
    return due.isoformat()


def create_disbursement_and_schedule(db_path: str, application: Dict[str, Any]):
    if application["status"] != "Approved":
        return
    principal = float(application["requested_amount"])
    monthly = float(application["monthly_payment_est"])
    with get_conn(db_path) as conn:
        existing = conn.execute(
            "SELECT id FROM servicing_ledger WHERE application_id=? AND txn_type='DISBURSEMENT' LIMIT 1",
            (application["id"],),
        ).fetchone()
        if existing:
            return
        conn.execute(
            """
            INSERT INTO servicing_ledger (
                application_id, txn_type, principal_delta, interest_delta, fee_delta, amount, status, notes, created_at
            ) VALUES (?, 'DISBURSEMENT', ?, 0, 0, ?, 'SETTLED', 'Auto disbursement on approval', ?)
            """,
            (application["id"], principal, principal, utcnow()),
        )
        for i in range(1, 13):
            principal_component = max(0.0, monthly * 0.72)
            interest_component = max(0.0, monthly - principal_component)
            conn.execute(
                """
                INSERT INTO servicing_ledger (
                    application_id, txn_type, principal_delta, interest_delta, fee_delta, amount, due_date, status, notes, created_at
                ) VALUES (?, 'EMI_DUE', ?, ?, 0, ?, ?, 'OPEN', ?, ?)
                """,
                (
                    application["id"],
                    -principal_component,
                    interest_component,
                    monthly,
                    _next_months_iso(i),
                    f"Installment {i}",
                    utcnow(),
                ),
            )
        conn.commit()


def servicing_summary(db_path: str, limit: int = 150) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        ledger = conn.execute(
            """
            SELECT sl.*, la.status AS app_status
            FROM servicing_ledger sl
            JOIN loan_applications la ON la.id = sl.application_id
            ORDER BY sl.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        totals = conn.execute(
            """
            SELECT
              SUM(CASE WHEN txn_type='DISBURSEMENT' THEN amount ELSE 0 END) AS disbursed,
              SUM(CASE WHEN txn_type='EMI_DUE' AND status='OPEN' THEN amount ELSE 0 END) AS open_emi,
              SUM(CASE WHEN txn_type='LATE_FEE' THEN amount ELSE 0 END) AS total_fees,
              SUM(CASE WHEN status='OVERDUE' THEN 1 ELSE 0 END) AS overdue_entries
            FROM servicing_ledger
            """
        ).fetchone()
    return {"ledger": ledger, "totals": totals or {}}


def run_delinquency_workflow(db_path: str, actor_id: int | None = None) -> Dict[str, int]:
    today = dt.date.today().isoformat()
    triggered = 0
    with get_conn(db_path) as conn:
        overdue_rows = conn.execute(
            """
            SELECT id, application_id, amount, due_date
            FROM servicing_ledger
            WHERE txn_type='EMI_DUE' AND status='OPEN' AND due_date < ?
            """,
            (today,),
        ).fetchall()
        for row in overdue_rows:
            conn.execute("UPDATE servicing_ledger SET status='OVERDUE' WHERE id=?", (row["id"],))
            late_fee = round(float(row["amount"]) * 0.02, 2)
            conn.execute(
                """
                INSERT INTO servicing_ledger (
                    application_id, txn_type, principal_delta, interest_delta, fee_delta,
                    amount, status, notes, created_at
                ) VALUES (?, 'LATE_FEE', 0, 0, ?, ?, 'OPEN', ?, ?)
                """,
                (
                    row["application_id"],
                    late_fee,
                    late_fee,
                    f"Late fee for overdue ledger {row['id']}",
                    utcnow(),
                ),
            )
            conn.execute(
                """
                INSERT INTO delinquency_actions (application_id, ledger_id, stage, message, created_at)
                VALUES (?, ?, 'NOTICE_SENT', ?, ?)
                """,
                (
                    row["application_id"],
                    row["id"],
                    f"EMI overdue since {row['due_date']}; late fee {late_fee} applied.",
                    utcnow(),
                ),
            )
            triggered += 1
        conn.commit()
    if triggered:
        append_chain(
            db_path,
            application_id=None,
            actor_id=actor_id,
            event_type="DELINQUENCY_WORKFLOW_RUN",
            payload=f"triggered={triggered}",
        )
    return {"triggered": triggered}


def get_auth_security(db_path: str, user_id: int) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT user_id, failed_attempts, locked_until, updated_at FROM auth_security WHERE user_id=?",
            (user_id,),
        ).fetchone()
        if row:
            return row
        conn.execute(
            "INSERT INTO auth_security (user_id, failed_attempts, locked_until, updated_at) VALUES (?, 0, NULL, ?)",
            (user_id, utcnow()),
        )
        conn.commit()
    return {"user_id": user_id, "failed_attempts": 0, "locked_until": None, "updated_at": utcnow()}


def record_login_failure(db_path: str, user_id: int, lock_threshold: int, lock_minutes: int) -> Dict[str, Any]:
    info = get_auth_security(db_path, user_id)
    failed = int(info["failed_attempts"]) + 1
    locked_until = None
    if failed >= lock_threshold:
        lock_dt = dt.datetime.utcnow() + dt.timedelta(minutes=lock_minutes)
        locked_until = lock_dt.replace(microsecond=0).isoformat() + "Z"
        failed = 0
    with get_conn(db_path) as conn:
        conn.execute(
            "UPDATE auth_security SET failed_attempts=?, locked_until=?, updated_at=? WHERE user_id=?",
            (failed, locked_until, utcnow(), user_id),
        )
        conn.commit()
    return {"failed_attempts": failed, "locked_until": locked_until}


def reset_login_failures(db_path: str, user_id: int):
    with get_conn(db_path) as conn:
        conn.execute(
            "UPDATE auth_security SET failed_attempts=0, locked_until=NULL, updated_at=? WHERE user_id=?",
            (utcnow(), user_id),
        )
        conn.commit()


def log_notification(
    db_path: str,
    application_id: int | None,
    channel: str,
    recipient: str,
    subject: str,
    message: str,
    status: str,
    provider: str,
):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO notification_events (
                application_id, channel, recipient, subject, message, status, provider, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (application_id, channel, recipient, subject, message, status, provider, utcnow()),
        )
        conn.commit()


def recent_notifications(db_path: str, limit: int = 100) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT id, application_id, channel, recipient, subject, status, provider, created_at
            FROM notification_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def log_chat_message(db_path: str, user_id: int | None, role: str, message: str, response: str, blocked: bool):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO chat_messages (user_id, role, message, response, blocked, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, role, message, response, 1 if blocked else 0, utcnow()),
        )
        conn.commit()


def recent_chat_messages(db_path: str, user_id: int | None, limit: int = 20) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        if user_id:
            return conn.execute(
                """
                SELECT role, message, response, blocked, created_at
                FROM chat_messages
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        return conn.execute(
            """
            SELECT role, message, response, blocked, created_at
            FROM chat_messages
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def bootstrap_suite_defaults(db_path: str):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO integration_clients (name, api_key, is_active, created_at)
            VALUES ('default-partner', 'demo-gateway-key', 1, ?)
            """,
            (utcnow(),),
        )
        defaults = [
            ("deployment_mode", "cloud-ready"),
            ("autoscale_min_instances", "1"),
            ("autoscale_max_instances", "8"),
            ("api_rate_limit_per_min", "120"),
        ]
        for key, val in defaults:
            conn.execute(
                """
                INSERT OR IGNORE INTO cloud_runtime_config (setting_key, setting_value, updated_at)
                VALUES (?, ?, ?)
                """,
                (key, val, utcnow()),
            )
        collection_defaults = [
            ("SOFT_REMINDER", 1, 14, 3, 0.0, 1),
            ("SETTLEMENT_PATH", 15, 45, 5, 0.08, 1),
            ("LEGAL_PREP", 46, 3650, 7, 0.0, 0),
        ]
        for name, min_days, max_days, cadence, discount, hardship in collection_defaults:
            conn.execute(
                """
                INSERT OR IGNORE INTO collection_strategies (
                    name, min_days_overdue, max_days_overdue, reminder_cadence_days,
                    settlement_discount_pct, hardship_enabled, is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (name, min_days, max_days, cadence, discount, hardship, utcnow()),
            )
        conn.execute(
            """
            INSERT OR IGNORE INTO partner_policies (
                client_name, ip_allowlist, rate_limit_per_min, quota_per_day, created_at, updated_at
            ) VALUES ('default-partner', '127.0.0.1,::1', 120, 3000, ?, ?)
            """,
            (utcnow(), utcnow()),
        )
        retention_defaults = [("audit_chain", 3650), ("chat_messages", 365), ("notification_events", 730)]
        for data_type, retention_days in retention_defaults:
            conn.execute(
                """
                INSERT OR IGNORE INTO retention_policies (data_type, retention_days, is_active, updated_at)
                VALUES (?, ?, 1, ?)
                """,
                (data_type, retention_days, utcnow()),
            )
        for provider_name in ("Google", "Microsoft"):
            conn.execute(
                """
                INSERT OR IGNORE INTO sso_providers (provider_name, client_id, enabled, updated_at)
                VALUES (?, 'set-client-id', 0, ?)
                """,
                (provider_name, utcnow()),
            )
        templates = [
            ("DUE_REMINDER", "email", "Payment reminder for {{application_id}}", "Please clear pending dues before due date."),
            ("COLLECTION_NOTICE", "email", "Collections notice", "Your account has moved to collections workflow."),
        ]
        for key, channel, subject, body in templates:
            conn.execute(
                """
                INSERT OR IGNORE INTO notification_templates (
                    template_key, channel, subject_template, body_template, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (key, channel, subject, body, utcnow()),
            )
        docs = [
            (
                "UNDERWRITING_RULES",
                "Underwriting Rules",
                "Approval depends on risk score, approval probability, DTI, collateral ratio and product policy.",
            ),
            (
                "KYC_POLICY",
                "KYC and Document Policy",
                "KYC requires identity and income proof hashes. Verification level increases with loan amount.",
            ),
            (
                "COLLECTIONS_POLICY",
                "Collections and Remediation",
                "Overdue accounts trigger reminder cadence, settlement options and hardship workflows.",
            ),
        ]
        for doc_key, title, content in docs:
            conn.execute(
                """
                INSERT OR IGNORE INTO policy_docs (doc_key, title, content, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (doc_key, title, content, utcnow()),
            )
        conn.commit()
    bootstrap_mock_kyc_cases(db_path)


def create_quote_for_application(db_path: str, application: Dict[str, Any]) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        existing = conn.execute(
            "SELECT * FROM quotes WHERE application_id=? ORDER BY id DESC LIMIT 1",
            (application["id"],),
        ).fetchone()
        if existing:
            return existing
        premium_rate = max(0.01, min(0.25, float(application["interest_rate"]) * 1.18))
        quoted_amount = round(float(application["requested_amount"]) * premium_rate, 2)
        valid_until = (dt.date.today() + dt.timedelta(days=15)).isoformat()
        conn.execute(
            """
            INSERT INTO quotes (application_id, product_code, premium_rate, quoted_amount, valid_until, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'Quoted', ?)
            """,
            (
                application["id"],
                application.get("product_code", "STANDARD"),
                premium_rate,
                quoted_amount,
                valid_until,
                utcnow(),
            ),
        )
        conn.commit()
        return conn.execute(
            "SELECT * FROM quotes WHERE application_id=? ORDER BY id DESC LIMIT 1",
            (application["id"],),
        ).fetchone()


def issue_policy_for_application(db_path: str, application: Dict[str, Any]) -> Dict[str, Any] | None:
    if application["status"] != "Approved":
        return None
    with get_conn(db_path) as conn:
        existing = conn.execute(
            "SELECT * FROM policies WHERE application_id=? ORDER BY id DESC LIMIT 1",
            (application["id"],),
        ).fetchone()
        if existing:
            return existing
        polnum = f"POL-{application['id']:06d}-{dt.datetime.utcnow().strftime('%H%M%S')}"
        policy_ts = utcnow()
        conn.execute(
            """
            INSERT INTO policies (
                application_id, policy_number, product_code, policy_type, issued_at,
                policy_creation_datetime, policy_creation_createdtime, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Issued', ?)
            """,
            (
                application["id"],
                polnum,
                application.get("product_code", "STANDARD"),
                application.get("policy_type", "STANDARD"),
                policy_ts,
                policy_ts,
                policy_ts,
                policy_ts,
            ),
        )
        conn.commit()
        return conn.execute(
            "SELECT * FROM policies WHERE application_id=? ORDER BY id DESC LIMIT 1",
            (application["id"],),
        ).fetchone()


def create_invoice_and_commission(db_path: str, application: Dict[str, Any], agent_name: str = "DigitalAgent") -> Dict[str, Any] | None:
    if application["status"] != "Approved":
        return None
    with get_conn(db_path) as conn:
        existing = conn.execute(
            "SELECT * FROM billing_invoices WHERE application_id=? ORDER BY id DESC LIMIT 1",
            (application["id"],),
        ).fetchone()
        if existing:
            return existing
        invoice_no = f"INV-{application['id']:06d}-{dt.datetime.utcnow().strftime('%M%S')}"
        amount_due = round(float(application["monthly_payment_est"]), 2)
        due_date = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        conn.execute(
            """
            INSERT INTO billing_invoices (application_id, invoice_number, amount_due, due_date, status, created_at)
            VALUES (?, ?, ?, ?, 'Open', ?)
            """,
            (application["id"], invoice_no, amount_due, due_date, utcnow()),
        )
        invoice = conn.execute("SELECT * FROM billing_invoices WHERE invoice_number=?", (invoice_no,)).fetchone()
        comm_rate = 0.02
        comm_amt = round(amount_due * comm_rate, 2)
        conn.execute(
            """
            INSERT INTO agent_commissions (invoice_id, agent_name, commission_rate, commission_amount, status, created_at)
            VALUES (?, ?, ?, ?, 'Pending', ?)
            """,
            (invoice["id"], agent_name, comm_rate, comm_amt, utcnow()),
        )
        conn.commit()
        return invoice


def create_claim(db_path: str, policy_id: int, claim_type: str, description: str, claimed_amount: float, actor_id: int | None) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO claims (policy_id, claim_type, description, claimed_amount, status, opened_at)
            VALUES (?, ?, ?, ?, 'Intake', ?)
            """,
            (policy_id, claim_type, description, claimed_amount, utcnow()),
        )
        claim = conn.execute("SELECT * FROM claims ORDER BY id DESC LIMIT 1").fetchone()
        conn.execute(
            """
            INSERT INTO claim_workflow_events (claim_id, stage, notes, actor_id, created_at)
            VALUES (?, 'Intake', 'Claim created and queued for review', ?, ?)
            """,
            (claim["id"], actor_id, utcnow()),
        )
        conn.commit()
        return claim


def progress_claim(db_path: str, claim_id: int, stage: str, notes: str, actor_id: int | None):
    stage_status = {
        "Intake": "Intake",
        "Assessment": "Assessment",
        "Investigation": "Investigation",
        "Settlement": "Settlement",
        "Closed": "Closed",
    }
    status = stage_status.get(stage, "Assessment")
    closed_at = utcnow() if status == "Closed" else None
    with get_conn(db_path) as conn:
        conn.execute(
            "UPDATE claims SET status=?, closed_at=COALESCE(?, closed_at) WHERE id=?",
            (status, closed_at, claim_id),
        )
        conn.execute(
            "INSERT INTO claim_workflow_events (claim_id, stage, notes, actor_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (claim_id, stage, notes, actor_id, utcnow()),
        )
        conn.commit()


def claims_overview(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        claims = conn.execute(
            """
            SELECT c.*, p.policy_number, la.user_id
            FROM claims c
            JOIN policies p ON p.id = c.policy_id
            JOIN loan_applications la ON la.id = p.application_id
            ORDER BY c.id DESC
            LIMIT 200
            """
        ).fetchall()
        stages = conn.execute(
            "SELECT status, COUNT(*) AS total FROM claims GROUP BY status ORDER BY total DESC"
        ).fetchall()
    return {"claims": claims, "stages": stages}


def calculate_fraud_signal(db_path: str, application: Dict[str, Any]) -> Dict[str, Any]:
    try:
        factors = json.loads(application.get("decision_factors", "{}"))
    except Exception:
        factors = {}
    dti = float(factors.get("dti", 0.0))
    collateral_shortfall = float(factors.get("collateral_shortfall", 0.0))
    score = 0.0
    score += min(40.0, max(0.0, (application["risk_score"] / 100.0) * 40.0))
    score += min(30.0, max(0.0, dti * 30.0))
    score += min(30.0, max(0.0, collateral_shortfall / max(1.0, application["requested_amount"]) * 120.0))
    if score >= 70:
        band = "High"
    elif score >= 45:
        band = "Medium"
    else:
        band = "Low"
    payload = {
        "risk_score": application["risk_score"],
        "dti": dti,
        "collateral_shortfall": collateral_shortfall,
    }
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO fraud_signals (application_id, score, risk_band, signals_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (application["id"], round(score, 2), band, json.dumps(payload), utcnow()),
        )
        conn.commit()
        return conn.execute(
            "SELECT * FROM fraud_signals WHERE application_id=? ORDER BY id DESC LIMIT 1",
            (application["id"],),
        ).fetchone()


def analytics_overview(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        fraud = conn.execute(
            "SELECT risk_band, COUNT(*) AS total, AVG(score) AS avg_score FROM fraud_signals GROUP BY risk_band"
        ).fetchall()
        quotes = conn.execute(
            "SELECT product_code, COUNT(*) AS total, AVG(quoted_amount) AS avg_quote FROM quotes GROUP BY product_code"
        ).fetchall()
        invoices = conn.execute(
            "SELECT status, COUNT(*) AS total, SUM(amount_due) AS total_due FROM billing_invoices GROUP BY status"
        ).fetchall()
    return {"fraud": fraud, "quotes": quotes, "invoices": invoices}


def log_engagement_event(db_path: str, user_id: int | None, channel: str, event_type: str, metadata: str):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO engagement_events (user_id, channel, event_type, metadata, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, channel, event_type, metadata, utcnow()),
        )
        conn.commit()


def engagement_feed(db_path: str, limit: int = 150) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT id, user_id, channel, event_type, metadata, created_at
            FROM engagement_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def validate_gateway_key(db_path: str, api_key: str) -> str | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT name FROM integration_clients WHERE api_key=? AND is_active=1 LIMIT 1",
            (api_key,),
        ).fetchone()
    return row["name"] if row else None


def log_gateway_request(db_path: str, client_name: str, endpoint: str, request_payload: str, response_status: int):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO integration_gateway_logs (client_name, endpoint, request_payload, response_status, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (client_name, endpoint, request_payload, response_status, utcnow()),
        )
        conn.commit()


def cloud_runtime_snapshot(db_path: str) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            "SELECT setting_key, setting_value, updated_at FROM cloud_runtime_config ORDER BY setting_key"
        ).fetchall()


def explainability_for_application(application: Dict[str, Any]) -> List[Dict[str, Any]]:
    try:
        factors = json.loads(application.get("decision_factors", "{}"))
    except Exception:
        factors = {}
    base = float(application.get("approval_probability", 0.0))
    score = float(application.get("risk_score", 0.0))
    dti = float(factors.get("dti", 0.0))
    credit = float(application.get("credit_score", 0.0))
    collateral_shortfall = float(factors.get("collateral_shortfall", 0.0))
    impacts = [
        {"factor": "Risk Score", "impact": round((score - 50.0) / 50.0, 3)},
        {"factor": "Approval Probability", "impact": round((base - 0.5) * 2, 3)},
        {"factor": "Credit Score", "impact": round((credit - 650.0) / 300.0, 3)},
        {"factor": "Debt-to-Income", "impact": round(-dti, 3)},
        {"factor": "Collateral Shortfall", "impact": round(-collateral_shortfall / max(1.0, float(application.get("requested_amount", 1.0))), 3)},
    ]
    impacts.sort(key=lambda x: abs(x["impact"]), reverse=True)
    return impacts


def create_workflow_task(
    db_path: str,
    application_id: int,
    stage: str,
    priority: str,
    assignee_user_id: int | None = None,
    sla_hours: int = 24,
):
    due = dt.datetime.utcnow() + dt.timedelta(hours=max(1, int(sla_hours)))
    due_at = due.replace(microsecond=0).isoformat() + "Z"
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO workflow_tasks (
                application_id, assignee_user_id, stage, sla_due_at, priority, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?)
            """,
            (application_id, assignee_user_id, stage, due_at, priority, utcnow(), utcnow()),
        )
        conn.commit()


def workflow_overview(db_path: str, limit: int = 250) -> Dict[str, Any]:
    now = utcnow()
    with get_conn(db_path) as conn:
        tasks = conn.execute(
            """
            SELECT wt.*, la.status AS app_status, u.username AS assignee
            FROM workflow_tasks wt
            JOIN loan_applications la ON la.id = wt.application_id
            LEFT JOIN users u ON u.id = wt.assignee_user_id
            ORDER BY wt.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        escalations = conn.execute(
            "SELECT * FROM workflow_escalations ORDER BY id DESC LIMIT 120"
        ).fetchall()
    overdue = [t for t in tasks if t["status"] == "OPEN" and t["sla_due_at"] < now]
    return {"tasks": tasks, "escalations": escalations, "overdue": len(overdue)}


def run_workflow_escalation(db_path: str) -> Dict[str, int]:
    now = utcnow()
    escalated = 0
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, application_id
            FROM workflow_tasks
            WHERE status='OPEN' AND sla_due_at < ?
            """,
            (now,),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE workflow_tasks SET priority='Critical', updated_at=? WHERE id=?",
                (now, row["id"]),
            )
            conn.execute(
                """
                INSERT INTO workflow_escalations (task_id, application_id, escalation_level, reason, created_at)
                VALUES (?, ?, 1, 'SLA breach', ?)
                """,
                (row["id"], row["application_id"], now),
            )
            escalated += 1
        conn.commit()
    return {"escalated": escalated}


def run_document_intelligence(db_path: str, application: Dict[str, Any]) -> Dict[str, Any]:
    declared_salary = float(application.get("current_salary", 0.0))
    extracted_salary = round(declared_salary * (0.95 + (application["id"] % 7) * 0.01), 2)
    extracted_region = application.get("region", "")
    salary_gap = abs(extracted_salary - declared_salary) / max(1.0, declared_salary)
    region_gap = 0.0 if extracted_region == application.get("region", "") else 0.25
    mismatch = round(min(1.0, salary_gap + region_gap), 3)
    status = "Mismatch" if mismatch > 0.12 else "Clear"
    ocr_payload = json.dumps({"salary_text": extracted_salary, "region_text": extracted_region})
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO document_intelligence (
                application_id, ocr_payload, extracted_salary, extracted_region, mismatch_score, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (application["id"], ocr_payload, extracted_salary, extracted_region, mismatch, status, utcnow()),
        )
        conn.commit()
        return conn.execute(
            "SELECT * FROM document_intelligence WHERE application_id=? ORDER BY id DESC LIMIT 1",
            (application["id"],),
        ).fetchone()


def process_uploaded_document(
    db_path: str,
    application: Dict[str, Any],
    filename: str,
    file_bytes: bytes,
) -> Dict[str, Any]:
    text = file_bytes.decode("utf-8", errors="ignore")
    text_low = text.lower()
    declared_salary = float(application.get("current_salary", 0.0))
    extracted_salary = declared_salary
    salary_match = re.search(r"(salary|income)[^0-9]{0,18}([0-9][0-9,]*(?:\.[0-9]+)?)", text_low)
    if salary_match:
        raw = salary_match.group(2).replace(",", "")
        try:
            extracted_salary = float(raw)
        except Exception:
            extracted_salary = declared_salary

    extracted_region = application.get("region", "")
    for region in REGIONS:
        if region.lower() in text_low:
            extracted_region = region
            break

    salary_gap = abs(extracted_salary - declared_salary) / max(1.0, declared_salary)
    region_gap = 0.0 if extracted_region == application.get("region", "") else 0.25
    mismatch = round(min(1.0, salary_gap + region_gap), 3)
    status = "Mismatch" if mismatch > 0.12 else "Clear"

    digest = hashlib.sha256(file_bytes).hexdigest()
    preview = text[:220].replace("\n", " ").strip()
    ocr_payload = json.dumps(
        {
            "filename": filename,
            "salary_text": extracted_salary,
            "region_text": extracted_region,
            "preview": preview,
        },
        separators=(",", ":"),
    )
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO kyc_documents (application_id, doc_type, doc_hash, metadata, created_at)
            VALUES (?, 'UPLOADED_DOC', ?, ?, ?)
            """,
            (
                application["id"],
                digest,
                json.dumps({"filename": filename, "bytes": len(file_bytes), "preview": preview}, separators=(",", ":")),
                utcnow(),
            ),
        )
        conn.execute(
            """
            INSERT INTO document_intelligence (
                application_id, ocr_payload, extracted_salary, extracted_region, mismatch_score, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (application["id"], ocr_payload, extracted_salary, extracted_region, mismatch, status, utcnow()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM document_intelligence WHERE application_id=? ORDER BY id DESC LIMIT 1",
            (application["id"],),
        ).fetchone()
    result = dict(row)
    result["doc_hash"] = digest
    return result


def repayment_projection(
    principal: float,
    annual_rate: float,
    term_months: int,
    prepayment_amount: float = 0.0,
    prepayment_month: int = 0,
    refinance_rate: float | None = None,
) -> Dict[str, Any]:
    principal = max(0.0, float(principal))
    term_months = max(1, int(term_months))
    annual_rate = max(0.0, float(annual_rate))
    monthly_rate = annual_rate / 12.0

    if monthly_rate == 0:
        emi = principal / term_months
    else:
        f = (1 + monthly_rate) ** term_months
        emi = principal * monthly_rate * f / (f - 1)

    balance = principal
    total_interest = 0.0
    total_paid = 0.0
    for month in range(1, term_months + 1):
        interest = balance * monthly_rate
        principal_component = max(0.0, emi - interest)
        principal_component = min(principal_component, balance)
        payment = principal_component + interest
        if prepayment_month > 0 and month == prepayment_month and prepayment_amount > 0:
            extra = min(prepayment_amount, max(0.0, balance - principal_component))
            principal_component += extra
            payment += extra
        balance = max(0.0, balance - principal_component)
        total_interest += interest
        total_paid += payment
        if balance <= 0.01:
            break
    actual_months = month

    if refinance_rate is None:
        refinance_rate = annual_rate
    refinance_rate = max(0.0, float(refinance_rate))
    refinance_monthly = refinance_rate / 12.0
    if refinance_monthly == 0:
        refinance_emi = principal / term_months
    else:
        rf = (1 + refinance_monthly) ** term_months
        refinance_emi = principal * refinance_monthly * rf / (rf - 1)

    base_interest_est = max(0.0, emi * term_months - principal)
    return {
        "baseline_emi": round(emi, 2),
        "baseline_interest_est": round(base_interest_est, 2),
        "effective_months": int(actual_months),
        "with_prepayment_total_interest": round(total_interest, 2),
        "with_prepayment_total_paid": round(total_paid, 2),
        "months_saved": int(max(0, term_months - actual_months)),
        "interest_saved_est": round(max(0.0, base_interest_est - total_interest), 2),
        "refinance_emi": round(refinance_emi, 2),
        "refinance_saving_monthly": round(max(0.0, emi - refinance_emi), 2),
    }


def document_intelligence_feed(db_path: str, limit: int = 200) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT di.*, la.status AS app_status
            FROM document_intelligence di
            JOIN loan_applications la ON la.id = di.application_id
            ORDER BY di.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def _strategy_for_days(db_path: str, days_overdue: int) -> Dict[str, Any] | None:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT name, reminder_cadence_days, settlement_discount_pct, hardship_enabled
            FROM collection_strategies
            WHERE is_active=1 AND ? BETWEEN min_days_overdue AND max_days_overdue
            ORDER BY min_days_overdue DESC
            LIMIT 1
            """,
            (days_overdue,),
        ).fetchone()


def run_collection_strategy(db_path: str) -> Dict[str, int]:
    today = dt.date.today()
    created = 0
    with get_conn(db_path) as conn:
        overdue = conn.execute(
            """
            SELECT id, application_id, due_date, amount
            FROM servicing_ledger
            WHERE txn_type='EMI_DUE' AND status='OVERDUE'
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()
    for row in overdue:
        try:
            due = dt.date.fromisoformat(str(row["due_date"])[:10])
        except Exception:
            continue
        days = max(1, (today - due).days)
        strategy = _strategy_for_days(db_path, days)
        if not strategy:
            continue
        payload = json.dumps(
            {
                "days_overdue": days,
                "cadence_days": strategy["reminder_cadence_days"],
                "settlement_discount_pct": strategy["settlement_discount_pct"],
                "hardship_enabled": bool(strategy["hardship_enabled"]),
                "due_amount": row["amount"],
            }
        )
        with get_conn(db_path) as conn:
            exists = conn.execute(
                """
                SELECT id FROM collection_actions
                WHERE application_id=? AND ledger_id=? AND strategy_name=? AND status='OPEN'
                LIMIT 1
                """,
                (row["application_id"], row["id"], strategy["name"]),
            ).fetchone()
            if exists:
                continue
            conn.execute(
                """
                INSERT INTO collection_actions (
                    application_id, ledger_id, strategy_name, action_type, action_payload, status, created_at
                ) VALUES (?, ?, ?, 'REMINDER', ?, 'OPEN', ?)
                """,
                (row["application_id"], row["id"], strategy["name"], payload, utcnow()),
            )
            conn.commit()
            created += 1
    return {"actions_created": created}


def collection_overview(db_path: str, limit: int = 250) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        actions = conn.execute(
            "SELECT * FROM collection_actions ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        strategies = conn.execute(
            "SELECT * FROM collection_strategies WHERE is_active=1 ORDER BY min_days_overdue",
        ).fetchall()
    return {"actions": actions, "strategies": strategies}


def reconcile_payment_event(db_path: str, provider_event_id: str, invoice_number: str, amount: float, provider_status: str) -> Dict[str, Any]:
    status = "MATCHED" if provider_status.lower() in {"paid", "succeeded", "success"} else "PENDING_RETRY"
    with get_conn(db_path) as conn:
        invoice = conn.execute(
            "SELECT id FROM billing_invoices WHERE invoice_number=? LIMIT 1",
            (invoice_number,),
        ).fetchone()
        invoice_id = invoice["id"] if invoice else None
        conn.execute(
            """
            INSERT OR REPLACE INTO payment_reconciliation (
                id, invoice_id, provider_event_id, provider_status, amount, retry_count, status, last_attempt_at, created_at
            ) VALUES (
                (SELECT id FROM payment_reconciliation WHERE provider_event_id=?),
                ?, ?, ?, ?,
                COALESCE((SELECT retry_count FROM payment_reconciliation WHERE provider_event_id=?), 0) + CASE WHEN ?='MATCHED' THEN 0 ELSE 1 END,
                ?, ?, COALESCE((SELECT created_at FROM payment_reconciliation WHERE provider_event_id=?), ?)
            )
            """,
            (
                provider_event_id,
                invoice_id,
                provider_event_id,
                provider_status,
                amount,
                provider_event_id,
                status,
                status,
                utcnow(),
                provider_event_id,
                utcnow(),
            ),
        )
        if invoice_id and status == "MATCHED":
            conn.execute("UPDATE billing_invoices SET status='Paid' WHERE id=?", (invoice_id,))
        conn.commit()
        return conn.execute(
            "SELECT * FROM payment_reconciliation WHERE provider_event_id=? LIMIT 1",
            (provider_event_id,),
        ).fetchone()


def payment_reconciliation_overview(db_path: str, limit: int = 200) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT pr.*, bi.invoice_number
            FROM payment_reconciliation pr
            LEFT JOIN billing_invoices bi ON bi.id = pr.invoice_id
            ORDER BY pr.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def model_monitoring_report(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, region, status, approval_probability, risk_score, created_at, decision_factors
            FROM loan_applications
            ORDER BY id DESC
            LIMIT 800
            """
        ).fetchall()
    if not rows:
        return {"summary": [], "fairness": [], "segments": []}
    probs = [float(r["approval_probability"]) for r in rows]
    avg_prob = sum(probs) / len(probs)
    drift = max(probs) - min(probs)
    month_recent = [r for r in rows if str(r["created_at"])[:7] == dt.datetime.utcnow().strftime("%Y-%m")]
    month_prev = [r for r in rows if str(r["created_at"])[:7] == (dt.datetime.utcnow() - dt.timedelta(days=31)).strftime("%Y-%m")]
    recent_rate = sum(1 for r in month_recent if r["status"] == "Approved") / max(1, len(month_recent))
    prev_rate = sum(1 for r in month_prev if r["status"] == "Approved") / max(1, len(month_prev))
    decay = round(recent_rate - prev_rate, 4)
    by_region: Dict[str, List[Dict[str, Any]]] = {}
    segment_counts: Dict[str, int] = {}
    for r in rows:
        by_region.setdefault(r["region"], []).append(r)
        try:
            segment = json.loads(r.get("decision_factors", "{}")).get("borrower_segment", "-")
        except Exception:
            segment = "-"
        segment_counts[segment] = segment_counts.get(segment, 0) + 1
    fairness = []
    for region, items in by_region.items():
        appr = sum(1 for i in items if i["status"] == "Approved")
        fairness.append({"region": region, "approval_rate": round(appr / max(1, len(items)), 3), "count": len(items)})
    fairness.sort(key=lambda x: x["region"])
    segments = [{"segment": k, "count": v} for k, v in sorted(segment_counts.items())]
    summary = [
        {"metric": "Avg Approval Probability", "value": f"{avg_prob:.3f}"},
        {"metric": "Prediction Range Drift", "value": f"{drift:.3f}"},
        {"metric": "Performance Decay (MoM Approval Delta)", "value": f"{decay:+.3f}"},
        {"metric": "Sample Size", "value": str(len(rows))},
    ]
    return {"summary": summary, "fairness": fairness, "segments": segments}


def portfolio_risk_overview(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT region, product_code, requested_amount, status, risk_score, approval_probability, decision_factors
            FROM loan_applications
            ORDER BY id DESC
            LIMIT 1200
            """
        ).fetchall()
    matrix: Dict[Tuple[str, str], Dict[str, Any]] = {}
    stressed_rejects = 0
    for r in rows:
        key = (r["region"], r.get("product_code", "STANDARD"))
        entry = matrix.setdefault(
            key,
            {
                "region": key[0],
                "product_code": key[1],
                "count": 0,
                "approved": 0,
                "avg_risk_sum": 0.0,
                "avg_prob_sum": 0.0,
                "requested_sum": 0.0,
            },
        )
        entry["count"] += 1
        entry["approved"] += 1 if r["status"] == "Approved" else 0
        entry["avg_risk_sum"] += float(r["risk_score"])
        entry["avg_prob_sum"] += float(r["approval_probability"])
        entry["requested_sum"] += float(r["requested_amount"])
        try:
            dti = float(json.loads(r.get("decision_factors", "{}")).get("dti", 0.0))
        except Exception:
            dti = 0.0
        # Simple stress test: 10% income shock -> higher DTI.
        if dti * 1.1 > 0.65 and r["status"] != "Rejected":
            stressed_rejects += 1

    by_bucket = []
    for item in matrix.values():
        c = max(1, item["count"])
        by_bucket.append(
            {
                "region": item["region"],
                "product_code": item["product_code"],
                "count": item["count"],
                "approval_rate": round(item["approved"] / c, 3),
                "avg_risk": round(item["avg_risk_sum"] / c, 2),
                "avg_prob": round(item["avg_prob_sum"] / c, 3),
                "exposure": round(item["requested_sum"], 2),
            }
        )
    by_bucket.sort(key=lambda x: (-x["exposure"], x["region"], x["product_code"]))
    totals = {
        "applications": len(rows),
        "total_exposure": round(sum(float(r["requested_amount"]) for r in rows), 2),
        "avg_risk": round(sum(float(r["risk_score"]) for r in rows) / max(1, len(rows)), 2),
        "stressed_rejections_est": stressed_rejects,
    }
    return {"totals": totals, "buckets": by_bucket[:80]}


def scenario_simulation(bundle: Any, payload: Dict[str, Any], product_policy: Dict[str, Any] | None) -> Dict[str, Any]:
    from . import ml

    return ml.infer(bundle, payload, policy=product_policy)


def rotate_client_api_key(db_path: str, client_name: str) -> str:
    new_key = f"key-{uuid.uuid4().hex[:24]}"
    with get_conn(db_path) as conn:
        conn.execute("UPDATE integration_clients SET api_key=? WHERE name=?", (new_key, client_name))
        conn.commit()
    return new_key


def upsert_partner_policy(db_path: str, client_name: str, ip_allowlist: str, rate_limit_per_min: int, quota_per_day: int):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO partner_policies (
                id, client_name, ip_allowlist, rate_limit_per_min, quota_per_day, created_at, updated_at
            ) VALUES ((SELECT id FROM partner_policies WHERE client_name=?), ?, ?, ?, ?, COALESCE((SELECT created_at FROM partner_policies WHERE client_name=?), ?), ?)
            """,
            (client_name, client_name, ip_allowlist, rate_limit_per_min, quota_per_day, client_name, utcnow(), utcnow()),
        )
        conn.commit()


def partner_overview(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        clients = conn.execute("SELECT name, api_key, is_active, created_at FROM integration_clients ORDER BY id DESC").fetchall()
        policies = conn.execute("SELECT * FROM partner_policies ORDER BY client_name").fetchall()
    return {"clients": clients, "policies": policies}


def gateway_policy_allows(db_path: str, client_name: str, client_ip: str | None) -> Tuple[bool, str]:
    client_ip = client_ip or ""
    now = dt.datetime.utcnow()
    minute_prefix = now.strftime("%Y-%m-%dT%H:%M")
    day_prefix = now.strftime("%Y-%m-%d")
    with get_conn(db_path) as conn:
        policy = conn.execute(
            "SELECT ip_allowlist, rate_limit_per_min, quota_per_day FROM partner_policies WHERE client_name=? LIMIT 1",
            (client_name,),
        ).fetchone()
        if not policy:
            return True, "ok"
        allow = [x.strip() for x in str(policy["ip_allowlist"]).split(",") if x.strip()]
        if allow and client_ip and client_ip not in allow:
            return False, "ip_not_allowed"
        rate_count = conn.execute(
            "SELECT COUNT(*) AS c FROM integration_gateway_logs WHERE client_name=? AND created_at LIKE ?",
            (client_name, f"{minute_prefix}%"),
        ).fetchone()["c"]
        if int(rate_count) >= int(policy["rate_limit_per_min"]):
            return False, "rate_limit_exceeded"
        day_count = conn.execute(
            "SELECT COUNT(*) AS c FROM integration_gateway_logs WHERE client_name=? AND created_at LIKE ?",
            (client_name, f"{day_prefix}%"),
        ).fetchone()["c"]
        if int(day_count) >= int(policy["quota_per_day"]):
            return False, "daily_quota_exceeded"
    return True, "ok"


def record_consent(db_path: str, user_id: int, consent_type: str, consent_value: str):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO consent_records (user_id, consent_type, consent_value, recorded_at) VALUES (?, ?, ?, ?)",
            (user_id, consent_type, consent_value, utcnow()),
        )
        conn.commit()


def create_compliance_event(db_path: str, user_id: int | None, event_type: str, payload: str, status: str):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO compliance_events (user_id, event_type, payload, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, event_type, payload, status, utcnow()),
        )
        conn.commit()


def compliance_overview(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        policies = conn.execute("SELECT * FROM retention_policies WHERE is_active=1 ORDER BY data_type").fetchall()
        events = conn.execute("SELECT * FROM compliance_events ORDER BY id DESC LIMIT 200").fetchall()
        consents = conn.execute("SELECT * FROM consent_records ORDER BY id DESC LIMIT 200").fetchall()
    return {"policies": policies, "events": events, "consents": consents}


def rebuild_fraud_graph(db_path: str) -> Dict[str, int]:
    with get_conn(db_path) as conn:
        apps = conn.execute(
            "SELECT id, user_id, region, requested_amount FROM loan_applications ORDER BY id DESC LIMIT 400"
        ).fetchall()
        conn.execute("DELETE FROM fraud_graph_edges")
        links = 0
        for i in range(len(apps)):
            for j in range(i + 1, len(apps)):
                a, b = apps[i], apps[j]
                link_type = None
                weight = 0.0
                if a["user_id"] == b["user_id"]:
                    link_type = "SAME_USER"
                    weight = 0.95
                elif a["region"] == b["region"] and abs(float(a["requested_amount"]) - float(b["requested_amount"])) < 5000:
                    link_type = "REGION_AMOUNT_CLUSTER"
                    weight = 0.52
                if link_type:
                    conn.execute(
                        """
                        INSERT INTO fraud_graph_edges (application_id_a, application_id_b, link_type, weight, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (a["id"], b["id"], link_type, weight, utcnow()),
                    )
                    links += 1
                if links >= 1500:
                    break
            if links >= 1500:
                break
        conn.commit()
    return {"links": links}


def fraud_graph_overview(db_path: str, limit: int = 250) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT fge.*, a.status AS status_a, b.status AS status_b
            FROM fraud_graph_edges fge
            JOIN loan_applications a ON a.id = fge.application_id_a
            JOIN loan_applications b ON b.id = fge.application_id_b
            ORDER BY fge.weight DESC, fge.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def set_sso_provider(db_path: str, provider_name: str, client_id: str, enabled: bool):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO sso_providers (id, provider_name, client_id, enabled, updated_at)
            VALUES ((SELECT id FROM sso_providers WHERE provider_name=?), ?, ?, ?, ?)
            """,
            (provider_name, provider_name, client_id, 1 if enabled else 0, utcnow()),
        )
        conn.commit()


def upsert_mfa_secret(db_path: str, user_id: int, secret: str):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO mfa_secrets (user_id, secret, last_verified_at, updated_at)
            VALUES (?, ?, (SELECT last_verified_at FROM mfa_secrets WHERE user_id=?), ?)
            """,
            (user_id, secret, user_id, utcnow()),
        )
        conn.commit()


def verify_mfa_secret(db_path: str, user_id: int, secret: str) -> bool:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT secret FROM mfa_secrets WHERE user_id=? LIMIT 1", (user_id,)).fetchone()
        ok = bool(row and row["secret"] == secret)
        if ok:
            conn.execute("UPDATE mfa_secrets SET last_verified_at=?, updated_at=? WHERE user_id=?", (utcnow(), utcnow(), user_id))
            conn.commit()
        return ok


def sso_mfa_overview(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        providers = conn.execute("SELECT * FROM sso_providers ORDER BY provider_name").fetchall()
        mfa = conn.execute(
            """
            SELECT ms.user_id, u.username, ms.last_verified_at, ms.updated_at
            FROM mfa_secrets ms
            JOIN users u ON u.id = ms.user_id
            ORDER BY ms.updated_at DESC
            LIMIT 120
            """
        ).fetchall()
    return {"providers": providers, "mfa": mfa}


def upsert_notification_template(db_path: str, template_key: str, channel: str, subject_template: str, body_template: str):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO notification_templates (
                id, template_key, channel, subject_template, body_template, updated_at
            ) VALUES ((SELECT id FROM notification_templates WHERE template_key=?), ?, ?, ?, ?, ?)
            """,
            (template_key, template_key, channel, subject_template, body_template, utcnow()),
        )
        conn.commit()


def create_notification_campaign(db_path: str, campaign_name: str, template_key: str, audience_rule: str, scheduled_for: str):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO notification_campaigns (campaign_name, template_key, audience_rule, scheduled_for, status, created_at)
            VALUES (?, ?, ?, ?, 'Scheduled', ?)
            """,
            (campaign_name, template_key, audience_rule, scheduled_for, utcnow()),
        )
        campaign = conn.execute("SELECT * FROM notification_campaigns ORDER BY id DESC LIMIT 1").fetchone()
        conn.execute(
            """
            INSERT INTO notification_delivery_metrics (campaign_id, delivered, failed, opened, clicked, updated_at)
            VALUES (?, 0, 0, 0, 0, ?)
            """,
            (campaign["id"], utcnow()),
        )
        conn.commit()


def notification_orchestration_overview(db_path: str) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        templates = conn.execute("SELECT * FROM notification_templates ORDER BY template_key").fetchall()
        campaigns = conn.execute("SELECT * FROM notification_campaigns ORDER BY id DESC LIMIT 120").fetchall()
        metrics = conn.execute("SELECT * FROM notification_delivery_metrics ORDER BY id DESC LIMIT 120").fetchall()
    return {"templates": templates, "campaigns": campaigns, "metrics": metrics}


def run_warehouse_export(db_path: str, export_dir: str, export_type: str, target_system: str) -> Dict[str, Any]:
    os.makedirs(export_dir, exist_ok=True)
    file_name = f"{export_type.lower()}_{dt.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.csv"
    file_path = os.path.join(export_dir, file_name)
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, user_id, region, requested_amount, status, risk_score, approval_probability, created_at
            FROM loan_applications
            ORDER BY id DESC
            LIMIT 1000
            """
        ).fetchall()
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("id,user_id,region,requested_amount,status,risk_score,approval_probability,created_at\n")
        for r in rows:
            f.write(f"{r['id']},{r['user_id']},{r['region']},{r['requested_amount']},{r['status']},{r['risk_score']},{r['approval_probability']},{r['created_at']}\n")
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO warehouse_exports (export_type, target_system, file_path, status, created_at) VALUES (?, ?, ?, 'SUCCESS', ?)",
            (export_type, target_system, file_path, utcnow()),
        )
        conn.commit()
        last = conn.execute("SELECT * FROM warehouse_exports ORDER BY id DESC LIMIT 1").fetchone()
    return last


def warehouse_exports_overview(db_path: str, limit: int = 120) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute("SELECT * FROM warehouse_exports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def observability_log(db_path: str, component: str, severity: str, message: str, metadata: str = "{}"):
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO observability_events (component, severity, message, metadata, created_at) VALUES (?, ?, ?, ?, ?)",
            (component, severity, message, metadata, utcnow()),
        )
        conn.commit()


def observability_overview(db_path: str, limit: int = 250) -> Dict[str, Any]:
    with get_conn(db_path) as conn:
        recent = conn.execute("SELECT * FROM observability_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        by_sev = conn.execute(
            "SELECT severity, COUNT(*) AS total FROM observability_events GROUP BY severity ORDER BY total DESC"
        ).fetchall()
    return {"recent": recent, "by_severity": by_sev}


def retrieve_policy_guidance(db_path: str, question: str, limit: int = 2) -> List[Dict[str, Any]]:
    tokens = [t.lower() for t in re.findall(r"[A-Za-z]{3,}", question or "")][:12]
    if not tokens:
        return []
    with get_conn(db_path) as conn:
        docs = conn.execute("SELECT doc_key, title, content FROM policy_docs ORDER BY doc_key").fetchall()
    ranked = []
    for d in docs:
        text = f"{d['title']} {d['content']}".lower()
        score = sum(1 for tok in tokens if tok in text)
        if score > 0:
            ranked.append({"doc_key": d["doc_key"], "title": d["title"], "content": d["content"], "score": score})
    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked[:limit]


def list_policy_jobs(db_path: str, limit: int = 200) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT pj.*, la.status AS application_status, la.product_code, la.region, la.requested_amount
            FROM policy_jobs pj
            JOIN loan_applications la ON la.id = pj.application_id
            ORDER BY pj.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def create_policy_job(
    db_path: str,
    application_id: int,
    job_type: str,
    effective_date: str,
    expiration_date: str | None,
    created_by: int | None,
) -> Dict[str, Any]:
    now = utcnow()
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO policy_jobs (
                application_id, job_type, state, effective_date, expiration_date, version_no, created_by, created_at, updated_at
            ) VALUES (?, ?, 'SUBMISSION', ?, ?, 1, ?, ?, ?)
            """,
            (application_id, job_type, effective_date, expiration_date, created_by, now, now),
        )
        job = conn.execute("SELECT * FROM policy_jobs ORDER BY id DESC LIMIT 1").fetchone()
        app = conn.execute("SELECT requested_amount, interest_rate, loan_term_months FROM loan_applications WHERE id=?", (application_id,)).fetchone()
        base = float(app["requested_amount"])
        annual = float(app["interest_rate"])
        term = int(max(1, app["loan_term_months"]))
        premium_total = round(base * annual * (term / 12.0), 2)
        conn.execute(
            """
            INSERT INTO policy_versions (job_id, version_no, rate_total, premium_total, quote_payload, is_bound, created_at)
            VALUES (?, 1, ?, ?, ?, 0, ?)
            """,
            (job["id"], annual, premium_total, json.dumps({"base_amount": base, "term": term}, separators=(",", ":")), now),
        )
        conn.commit()
        return conn.execute("SELECT * FROM policy_jobs WHERE id=?", (job["id"],)).fetchone()


def transition_policy_job(db_path: str, job_id: int, new_state: str) -> Dict[str, Any] | None:
    allowed = {"SUBMISSION", "QUOTED", "BOUND", "ISSUED", "ENDORSED", "RENEWED", "CANCELLED", "REINSTATED"}
    if new_state not in allowed:
        return None
    with get_conn(db_path) as conn:
        job = conn.execute("SELECT * FROM policy_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            return None
        conn.execute("UPDATE policy_jobs SET state=?, updated_at=? WHERE id=?", (new_state, utcnow(), job_id))
        if new_state == "BOUND":
            conn.execute("UPDATE policy_versions SET is_bound=1 WHERE job_id=? AND version_no=?", (job_id, job["version_no"]))
        conn.commit()
        return conn.execute("SELECT * FROM policy_jobs WHERE id=?", (job_id,)).fetchone()


def add_policy_version(db_path: str, job_id: int, rate_total: float, premium_total: float, payload: Dict[str, Any]) -> Dict[str, Any] | None:
    now = utcnow()
    with get_conn(db_path) as conn:
        job = conn.execute("SELECT * FROM policy_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            return None
        ver = int(job["version_no"]) + 1
        conn.execute(
            """
            INSERT INTO policy_versions (job_id, version_no, rate_total, premium_total, quote_payload, is_bound, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (job_id, ver, float(rate_total), float(premium_total), json.dumps(payload, separators=(",", ":")), now),
        )
        conn.execute("UPDATE policy_jobs SET version_no=?, updated_at=? WHERE id=?", (ver, now, job_id))
        conn.commit()
        return conn.execute("SELECT * FROM policy_versions WHERE job_id=? AND version_no=?", (job_id, ver)).fetchone()


def compare_policy_versions(db_path: str, job_id: int) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        versions = conn.execute(
            "SELECT version_no, rate_total, premium_total, is_bound, created_at FROM policy_versions WHERE job_id=? ORDER BY version_no",
            (job_id,),
        ).fetchall()
    if not versions:
        return []
    baseline = versions[0]
    rows = []
    for v in versions:
        rows.append(
            {
                "version_no": v["version_no"],
                "rate_total": v["rate_total"],
                "premium_total": v["premium_total"],
                "premium_delta": round(float(v["premium_total"]) - float(baseline["premium_total"]), 2),
                "is_bound": "Yes" if v["is_bound"] else "No",
                "created_at": v["created_at"],
            }
        )
    return rows


def upsert_rating_factor(db_path: str, product_code: str, factor_key: str, factor_value: float, weight: float):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO rating_factors (
                id, product_code, factor_key, factor_value, weight, updated_at
            ) VALUES (
                (SELECT id FROM rating_factors WHERE product_code=? AND factor_key=?),
                ?, ?, ?, ?, ?
            )
            """,
            (product_code, factor_key, product_code, factor_key, float(factor_value), float(weight), utcnow()),
        )
        conn.commit()


def list_rating_factors(db_path: str, product_code: str | None = None) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        if product_code:
            return conn.execute(
                "SELECT * FROM rating_factors WHERE product_code=? ORDER BY factor_key",
                (product_code,),
            ).fetchall()
        return conn.execute("SELECT * FROM rating_factors ORDER BY product_code, factor_key").fetchall()


def rated_quote(db_path: str, application: Dict[str, Any]) -> Dict[str, Any]:
    product = application.get("product_code", "STANDARD")
    factors = list_rating_factors(db_path, product)
    base_rate = float(application.get("interest_rate", 0.09))
    adjustment = 0.0
    details = []
    for f in factors:
        delta = float(f["factor_value"]) * float(f["weight"])
        adjustment += delta
        details.append(f"{f['factor_key']}:{delta:+.4f}")
    final_rate = max(0.01, base_rate + adjustment)
    premium = float(application.get("requested_amount", 0.0)) * final_rate * (int(application.get("loan_term_months", 12)) / 12.0)
    return {
        "base_rate": round(base_rate, 4),
        "adjustment": round(adjustment, 4),
        "final_rate": round(final_rate, 4),
        "premium_estimate": round(premium, 2),
        "details": "; ".join(details[:12]),
    }


def upsert_assignment_rule(
    db_path: str,
    stage: str,
    min_risk_score: int,
    max_risk_score: int,
    target_user_id: int,
    priority: str,
):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO assignment_rules (stage, min_risk_score, max_risk_score, target_user_id, priority, is_active, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (stage, int(min_risk_score), int(max_risk_score), int(target_user_id), priority, utcnow()),
        )
        conn.commit()


def list_assignment_rules(db_path: str) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT ar.*, u.username
            FROM assignment_rules ar
            JOIN users u ON u.id = ar.target_user_id
            WHERE ar.is_active=1
            ORDER BY ar.stage, ar.min_risk_score
            """
        ).fetchall()


def run_assignment_engine(db_path: str, stage: str = "UNDERWRITING_REVIEW") -> Dict[str, int]:
    assigned = 0
    with get_conn(db_path) as conn:
        tasks = conn.execute(
            """
            SELECT wt.id, wt.application_id, la.risk_score
            FROM workflow_tasks wt
            JOIN loan_applications la ON la.id = wt.application_id
            WHERE wt.stage=? AND (wt.assignee_user_id IS NULL OR wt.assignee_user_id=0) AND wt.status='Open'
            ORDER BY wt.id ASC
            """,
            (stage,),
        ).fetchall()
        rules = conn.execute(
            "SELECT * FROM assignment_rules WHERE is_active=1 AND stage=? ORDER BY min_risk_score",
            (stage,),
        ).fetchall()
        for t in tasks:
            risk = int(t["risk_score"])
            match = None
            for r in rules:
                if int(r["min_risk_score"]) <= risk <= int(r["max_risk_score"]):
                    match = r
                    break
            if not match:
                continue
            conn.execute(
                "UPDATE workflow_tasks SET assignee_user_id=?, priority=?, updated_at=? WHERE id=?",
                (match["target_user_id"], match["priority"], utcnow(), t["id"]),
            )
            assigned += 1
        conn.commit()
    return {"assigned": assigned, "tasks_evaluated": len(tasks)}


def upsert_party_contact(
    db_path: str,
    application_id: int,
    party_role: str,
    full_name: str,
    email: str,
    phone: str,
    identifier: str,
):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO party_contacts (application_id, party_role, full_name, email, phone, identifier, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (application_id, party_role, full_name, email, phone, identifier, utcnow()),
        )
        conn.commit()


def list_party_contacts(db_path: str, limit: int = 200) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT pc.*, la.user_id
            FROM party_contacts pc
            LEFT JOIN loan_applications la ON la.id = pc.application_id
            ORDER BY pc.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def upsert_correspondence_template(db_path: str, template_code: str, channel: str, subject: str, body: str):
    with get_conn(db_path) as conn:
        current = conn.execute(
            "SELECT MAX(version_no) AS v FROM correspondence_templates_ext WHERE template_code=?",
            (template_code,),
        ).fetchone()
        next_v = int(current["v"] or 0) + 1
        conn.execute("UPDATE correspondence_templates_ext SET is_active=0 WHERE template_code=?", (template_code,))
        conn.execute(
            """
            INSERT INTO correspondence_templates_ext (template_code, channel, subject, body, version_no, is_active, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (template_code, channel, subject, body, next_v, utcnow()),
        )
        conn.commit()


def list_correspondence_templates(db_path: str) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            "SELECT * FROM correspondence_templates_ext WHERE is_active=1 ORDER BY template_code"
        ).fetchall()


def create_correspondence_event(db_path: str, application_id: int | None, template_code: str, channel: str, recipient: str, payload: Dict[str, Any], status: str = "Queued"):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO correspondence_events_ext (application_id, template_code, channel, recipient, payload, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (application_id, template_code, channel, recipient, json.dumps(payload, separators=(",", ":")), status, utcnow()),
        )
        conn.commit()


def list_correspondence_events(db_path: str, limit: int = 200) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            "SELECT * FROM correspondence_events_ext ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


def publish_config_release(db_path: str, release_name: str, release_type: str, notes: str, published_by: int | None):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO config_releases (release_name, release_type, notes, published_by, published_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (release_name, release_type, notes, published_by, utcnow()),
        )
        conn.commit()


def list_config_releases(db_path: str, limit: int = 120) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute(
            """
            SELECT cr.*, u.username
            FROM config_releases cr
            LEFT JOIN users u ON u.id = cr.published_by
            ORDER BY cr.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def push_integration_event(db_path: str, event_type: str, source: str, payload: Dict[str, Any], idempotency_key: str | None, status: str = "ACCEPTED"):
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO integration_event_stream (event_type, source, payload, idempotency_key, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_type, source, json.dumps(payload, separators=(",", ":")), idempotency_key, status, utcnow()),
        )
        conn.commit()


def integration_event_feed(db_path: str, limit: int = 200) -> List[Dict[str, Any]]:
    with get_conn(db_path) as conn:
        return conn.execute("SELECT * FROM integration_event_stream ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
