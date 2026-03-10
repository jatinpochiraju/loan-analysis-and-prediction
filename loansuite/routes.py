from __future__ import annotations

import hashlib
import json
from io import StringIO
import csv
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List, Tuple
import os
import random
import re
import uuid

from flask import current_app, flash, make_response, redirect, render_template, request, session, url_for

from . import ml
from .db import get_conn, utcnow
from .integrations import (
    address_validate,
    create_payment_intent,
    gemini_chat,
    integration_smoke_report,
    integration_status,
    send_email,
    send_sms,
    verify_kyc_external,
)
from .security import (
    client_id,
    csrf_token,
    login_required,
    password_policy_errors,
    password_hash,
    rate_limit_ok,
    role_required,
    sanitize_text,
    suspicious,
    verify_csrf,
    verify_password,
)
from .services import (
    REGIONS,
    active_model_info,
    add_typelist_entry,
    admin_insights,
    all_applications,
    append_chain,
    create_entity_definition,
    create_invoice_and_commission,
    create_application,
    create_claim,
    create_quote_for_application,
    create_or_update_entity_field,
    create_typelist,
    create_disbursement_and_schedule,
    issue_policy_for_application,
    progress_claim,
    claims_overview,
    analytics_overview,
    calculate_fraud_signal,
    engagement_feed,
    generated_artifacts_summary,
    get_active_products,
    get_application,
    get_auth_security,
    get_data_model,
    get_product_policy_by_code,
    get_product_policy_for_amount,
    historical_training_rows,
    record_kyc_document_hash,
    record_login_failure,
    log_chat_message,
    log_engagement_event,
    log_notification,
    recent_chat_messages,
    recent_notifications,
    regenerate_model_code,
    reset_login_failures,
    run_delinquency_workflow,
    set_application_hash,
    servicing_summary,
    validate_gateway_key,
    log_gateway_request,
    cloud_runtime_snapshot,
    collection_overview,
    compliance_overview,
    create_compliance_event,
    create_correspondence_event,
    create_notification_campaign,
    create_policy_job,
    create_workflow_task,
    document_intelligence_feed,
    explainability_for_application,
    fraud_graph_overview,
    model_monitoring_report,
    notification_orchestration_overview,
    observability_log,
    observability_overview,
    partner_overview,
    payment_reconciliation_overview,
    portfolio_risk_overview,
    process_uploaded_document,
    publish_config_release,
    gateway_policy_allows,
    integration_event_feed,
    list_assignment_rules,
    list_config_releases,
    list_correspondence_events,
    list_correspondence_templates,
    list_party_contacts,
    list_policy_jobs,
    list_rating_factors,
    repayment_projection,
    reconcile_payment_event,
    record_consent,
    retrieve_policy_guidance,
    rotate_client_api_key,
    run_collection_strategy,
    run_document_intelligence,
    run_warehouse_export,
    run_workflow_escalation,
    scenario_simulation,
    set_sso_provider,
    sso_mfa_overview,
    upsert_mfa_secret,
    upsert_assignment_rule,
    upsert_correspondence_template,
    upsert_notification_template,
    upsert_partner_policy,
    upsert_party_contact,
    upsert_rating_factor,
    verify_mfa_secret,
    warehouse_exports_overview,
    workflow_overview,
    rebuild_fraud_graph,
    update_application_decision,
    upsert_model_registry,
    user_applications,
    user_insights,
    verify_chain,
    push_integration_event,
    rated_quote,
    run_assignment_engine,
    add_policy_version,
    compare_policy_versions,
    transition_policy_job,
)

LOAN_TYPE_OPTIONS: List[Tuple[str, str]] = [
    ("CAR", "Car Loan"),
    ("HOME", "Home Loan"),
    ("FURNITURE", "Furniture Loan"),
    ("TRAVEL", "Travel Loan"),
    ("STUDENT", "Student Loan"),
    ("PERSONAL", "Personal Loan"),
]
SUPPORTED_LOAN_TYPES = {code for code, _ in LOAN_TYPE_OPTIONS}

CURRENCY_OPTIONS: List[Tuple[str, str]] = [
    ("USD", "US Dollar (USD)"),
    ("INR", "Indian Rupee (INR)"),
    ("AUD", "Australian Dollar (AUD)"),
    ("GBP", "Pound Sterling (GBP)"),
    ("ZAR", "South African Rand (ZAR)"),
    ("EUR", "Euro (EUR)"),
    ("CNY", "Chinese Yuan (CNY)"),
    ("THB", "Thai Baht (THB)"),
]
SUPPORTED_CURRENCIES = {code for code, _ in CURRENCY_OPTIONS}

POLICY_TYPE_OPTIONS: List[Tuple[str, str]] = [
    ("BASIC", "Basic Coverage"),
    ("STANDARD", "Standard Coverage"),
    ("FAMILY", "Family Coverage"),
    ("PREMIUM", "Premium Coverage"),
]
SUPPORTED_POLICY_TYPES = {code for code, _ in POLICY_TYPE_OPTIONS}

ACCESS_MATRIX_ROWS: List[Dict[str, str]] = [
    {"module": "AdminCenter", "route": "/admin/*", "access_level": "admin", "guard": "role_required('admin')", "description": "Full platform operations and governance"},
    {"module": "Admin User Management", "route": "/admin/user-management*", "access_level": "admin", "guard": "role_required('admin')", "description": "Set role/access tiers and promotions"},
    {"module": "Access Matrix", "route": "/admin/access-matrix", "access_level": "admin", "guard": "role_required('admin')", "description": "Audit need-to-know route/module access"},
    {"module": "Rules Engine", "route": "/admin/rules-engine", "access_level": "admin", "guard": "role_required('admin')", "description": "Underwriting and policy rule updates"},
    {"module": "PolicyCenter Models", "route": "/admin/policycenter*", "access_level": "admin", "guard": "role_required('admin')", "description": "Product model governance"},
    {"module": "ClaimCenter Workflows", "route": "/admin/claimcenter*", "access_level": "admin", "guard": "role_required('admin')", "description": "Claims processing control"},
    {"module": "Integration Gateway", "route": "/admin/integration-*", "access_level": "admin", "guard": "role_required('admin')", "description": "Partner and gateway operations"},
    {"module": "Security & SSO/MFA", "route": "/admin/security-center, /admin/sso-mfa", "access_level": "admin", "guard": "role_required('admin')", "description": "Security policy and identity controls"},
    {"module": "Company Workspace", "route": "/company/*", "access_level": "company, admin", "guard": "access_level_required('company','admin')", "description": "Small-scale lender operations and model customization"},
    {"module": "Company Entity Create", "route": "/company/datamodel/entity", "access_level": "company, admin", "guard": "access_level_required('company','admin')", "description": "Create company-scoped entities"},
    {"module": "Company Typelist Create", "route": "/company/datamodel/typelist", "access_level": "company, admin", "guard": "access_level_required('company','admin')", "description": "Create type lists and typecodes"},
    {"module": "Company Entity Extension", "route": "/company/datamodel/extension", "access_level": "company, admin", "guard": "access_level_required('company','admin')", "description": "Manage EIX/ETX and relations"},
    {"module": "Model Visualizer", "route": "/model-visualizer", "access_level": "end_user, company, admin", "guard": "login_required + scoped visibility", "description": "Visual diagrams scoped by creator unless admin"},
    {"module": "User Dashboard", "route": "/user/dashboard", "access_level": "end_user", "guard": "access_level_required('end_user')", "description": "Borrower portal and personal application history"},
    {"module": "User Apply", "route": "/user/apply", "access_level": "end_user", "guard": "access_level_required('end_user')", "description": "Submit new loan applications"},
    {"module": "User Claim Submit", "route": "/user/claim/create", "access_level": "end_user", "guard": "access_level_required('end_user')", "description": "Submit claims only for own policies"},
    {"module": "User Profile", "route": "/user/profile", "access_level": "end_user", "guard": "access_level_required('end_user')", "description": "Personal profile and verification status"},
    {"module": "User Digital Portal", "route": "/user/digital-portal", "access_level": "end_user", "guard": "access_level_required('end_user')", "description": "Customer self-service offers"},
    {"module": "User Simulator", "route": "/user/simulator", "access_level": "end_user", "guard": "access_level_required('end_user')", "description": "What-if projections for borrower decisions"},
    {"module": "Auth: Register", "route": "/register, /register/verify", "access_level": "public -> end_user", "guard": "csrf + otp verification", "description": "2FA onboarding via email + phone"},
    {"module": "Auth: User Login", "route": "/login", "access_level": "public", "guard": "rate_limit + password verify + lockout", "description": "Session access with tier-based redirect"},
]


def _validate_application(form: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    errors: List[str] = []

    region = sanitize_text(form.get("region", ""), 20)
    if region not in REGIONS:
        errors.append("Please select a valid region.")

    def parse_float(key: str, label: str, minv: float, maxv: float) -> float:
        raw = str(form.get(key, "")).strip()
        if suspicious(raw):
            errors.append(f"{label} failed security guardrails.")
            return 0.0
        try:
            value = float(raw)
        except ValueError:
            errors.append(f"{label} must be numeric.")
            return 0.0
        if value < minv or value > maxv:
            errors.append(f"{label} must be between {minv:,.0f} and {maxv:,.0f}.")
        return value

    def parse_int(key: str, label: str, minv: int, maxv: int) -> int:
        raw = str(form.get(key, "")).strip()
        if suspicious(raw):
            errors.append(f"{label} failed security guardrails.")
            return minv
        try:
            value = int(raw)
        except ValueError:
            errors.append(f"{label} must be an integer.")
            return minv
        if value < minv or value > maxv:
            errors.append(f"{label} must be between {minv} and {maxv}.")
        return value

    def parse_optional_float(key: str, label: str, minv: float, maxv: float) -> float | None:
        raw = str(form.get(key, "")).strip()
        if not raw:
            return None
        if suspicious(raw):
            errors.append(f"{label} failed security guardrails.")
            return None
        try:
            value = float(raw)
        except ValueError:
            errors.append(f"{label} must be numeric.")
            return None
        if value < minv or value > maxv:
            errors.append(f"{label} must be between {minv:,.0f} and {maxv:,.0f}.")
            return None
        return value

    def parse_optional_int(key: str, label: str, minv: int, maxv: int) -> int | None:
        raw = str(form.get(key, "")).strip()
        if not raw:
            return None
        if suspicious(raw):
            errors.append(f"{label} failed security guardrails.")
            return None
        try:
            value = int(raw)
        except ValueError:
            errors.append(f"{label} must be an integer.")
            return None
        if value < minv or value > maxv:
            errors.append(f"{label} must be between {minv} and {maxv}.")
            return None
        return value

    loan_type = sanitize_text(form.get("loan_type", "PERSONAL"), 20).upper()
    if loan_type not in SUPPORTED_LOAN_TYPES:
        errors.append("Please select a valid loan type.")
        loan_type = "PERSONAL"
    policy_type = sanitize_text(form.get("policy_type", "STANDARD"), 20).upper()
    if policy_type not in SUPPORTED_POLICY_TYPES:
        errors.append("Please select a valid policy type.")
        policy_type = "STANDARD"

    if hasattr(form, "getlist"):
        raw_currencies = form.getlist("preferred_currencies")
    else:
        raw_values = form.get("preferred_currencies", "USD")
        if isinstance(raw_values, list):
            raw_currencies = raw_values
        else:
            raw_currencies = str(raw_values).split(",")

    preferred_currencies: List[str] = []
    for raw in raw_currencies:
        code = sanitize_text(raw, 5).upper()
        if code and code in SUPPORTED_CURRENCIES and code not in preferred_currencies:
            preferred_currencies.append(code)
    if not preferred_currencies:
        preferred_currencies = ["USD"]

    loan_profile: Dict[str, Any] = {}
    if loan_type == "CAR":
        loan_profile = {
            "vehicle_make": sanitize_text(form.get("vehicle_make", ""), 40),
            "vehicle_model": sanitize_text(form.get("vehicle_model", ""), 40),
            "vehicle_year": parse_optional_int("vehicle_year", "Vehicle year", 1980, 2100),
        }
    elif loan_type == "HOME":
        loan_profile = {
            "property_city": sanitize_text(form.get("property_city", ""), 60),
            "property_value": parse_optional_float("property_value", "Property value", 0, 100000000),
            "property_type": sanitize_text(form.get("property_type", ""), 30),
        }
    elif loan_type == "FURNITURE":
        loan_profile = {
            "furniture_category": sanitize_text(form.get("furniture_category", ""), 40),
            "furniture_vendor": sanitize_text(form.get("furniture_vendor", ""), 60),
        }
    elif loan_type == "TRAVEL":
        loan_profile = {
            "travel_destination": sanitize_text(form.get("travel_destination", ""), 80),
            "travel_month": sanitize_text(form.get("travel_month", ""), 20),
            "travelers_count": parse_optional_int("travelers_count", "Travelers count", 1, 20),
        }
    elif loan_type == "STUDENT":
        loan_profile = {
            "institution_name": sanitize_text(form.get("institution_name", ""), 80),
            "course_name": sanitize_text(form.get("course_name", ""), 80),
            "course_duration_months": parse_optional_int("course_duration_months", "Course duration", 1, 120),
        }
    else:
        loan_profile = {
            "loan_use": sanitize_text(form.get("loan_use", ""), 80),
        }
    loan_profile = {k: v for k, v in loan_profile.items() if v not in (None, "")}

    payload = {
        "product_code": sanitize_text(form.get("product_code", ""), 20),
        "policy_type": policy_type,
        "region": region,
        "loan_type": loan_type,
        "preferred_currencies": preferred_currencies,
        "loan_profile": loan_profile,
        "kyc_id_number": sanitize_text(form.get("kyc_id_number", ""), 40),
        "income_doc_ref": sanitize_text(form.get("income_doc_ref", ""), 80),
        "current_salary": parse_float("current_salary", "Current salary", 12000, 1000000),
        "monthly_expenditure": parse_float("monthly_expenditure", "Monthly expenditure", 0, 100000),
        "existing_emi": parse_float("existing_emi", "Existing EMI", 0, 40000),
        "requested_amount": parse_float("requested_amount", "Requested amount", 1000, 3000000),
        "loan_term_months": parse_int("loan_term_months", "Loan term", 6, 420),
        "employment_years": parse_float("employment_years", "Employment years", 0, 45),
        "credit_score": parse_int("credit_score", "Credit score", 300, 900),
        "collateral_value": parse_float("collateral_value", "Collateral value", 0, 5000000),
    }
    if not payload["product_code"]:
        errors.append("Loan product is required.")
    if not payload["kyc_id_number"] or suspicious(payload["kyc_id_number"]):
        errors.append("KYC ID is required and must be valid.")
    if not payload["income_doc_ref"] or suspicious(payload["income_doc_ref"]):
        errors.append("Income document reference is required.")
    return payload, errors


def _model_or_retrain():
    model_dir = current_app.config["MODEL_DIR"]
    bundle = ml.load_model(model_dir)
    if bundle:
        return bundle

    rows = historical_training_rows(current_app.config["DB_PATH"])
    version = f"v{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    bundle = ml.train_model(rows, model_dir, version)
    upsert_model_registry(
        current_app.config["DB_PATH"],
        version=bundle.version,
        sample_count=bundle.sample_count,
        accuracy=bundle.accuracy,
        roc_auc=bundle.roc_auc,
        features=ml.FEATURES,
    )
    append_chain(
        current_app.config["DB_PATH"],
        application_id=None,
        actor_id=None,
        event_type="MODEL_TRAIN",
        payload=f"version={bundle.version};samples={bundle.sample_count}",
    )
    return bundle


def _safe_model_name(value: str, max_len: int = 40) -> str:
    value = sanitize_text(value, max_len)
    value = "".join(ch for ch in value if ch.isalnum() or ch == "_")
    return value


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9]{8,15}$")


def _is_valid_email(value: str) -> bool:
    return bool(value and EMAIL_RE.match(value))


def _is_valid_phone(value: str) -> bool:
    return bool(value and PHONE_RE.match(value))


def _otp_hash(secret: str, username: str, channel: str, code: str) -> str:
    raw = f"{secret}|{username}|{channel}|{code}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _masked_email(email: str) -> str:
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        local_masked = "*" * len(local)
    else:
        local_masked = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
    return f"{local_masked}@{domain}"


def _masked_phone(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    if len(digits) <= 4:
        return "*" * len(digits)
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


def _scoped_data_model_view(full_data: Dict[str, Any], user_id: int | None, is_admin: bool) -> Dict[str, Any]:
    if is_admin:
        return full_data
    uid = int(user_id or 0)
    entities = [e for e in full_data.get("entities", []) if int(e.get("created_by") or 0) == uid]
    typelists = [t for t in full_data.get("typelists", []) if int(t.get("created_by") or 0) == uid]
    entity_names = {e["name"] for e in entities}
    typelist_names = {t["name"] for t in typelists}

    fields_by_entity: Dict[str, List[Dict[str, Any]]] = {}
    for name, fields in full_data.get("fields_by_entity", {}).items():
        rows = [f for f in fields if int(f.get("created_by") or 0) == uid or name in entity_names]
        if rows:
            fields_by_entity[name] = rows

    entries_by_typelist: Dict[str, List[Dict[str, Any]]] = {}
    for tname, entries in full_data.get("entries_by_typelist", {}).items():
        rows = [e for e in entries if int(e.get("created_by") or 0) == uid or tname in typelist_names]
        if rows:
            entries_by_typelist[tname] = rows

    return {
        "entities": entities,
        "fields_by_entity": fields_by_entity,
        "typelists": typelists,
        "entries_by_typelist": entries_by_typelist,
    }


def _model_visual_payload(model_data: Dict[str, Any]) -> Dict[str, Any]:
    entities = model_data.get("entities", [])
    fields_by_entity = model_data.get("fields_by_entity", {})
    typelists = model_data.get("typelists", [])
    entries_by_typelist = model_data.get("entries_by_typelist", {})
    relation_rows = []
    ext_counts = {"EIX": 0, "ETX": 0, "UNKNOWN": 0}
    rel_counts: Dict[str, int] = {}
    hierarchy_edges = []
    for entity in entities:
        if entity.get("supertype"):
            hierarchy_edges.append({"from": entity["supertype"], "to": entity["name"]})
    for ename, rows in fields_by_entity.items():
        for row in rows:
            ext = str(row.get("extension_type") or "UNKNOWN").upper()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
            rel = str(row.get("relation_type") or "none")
            rel_counts[rel] = rel_counts.get(rel, 0) + 1
            if rel != "none" or row.get("related_entity"):
                relation_rows.append(
                    {
                        "entity": ename,
                        "field": row.get("field_name"),
                        "extension_type": ext,
                        "relation_type": rel,
                        "related_entity": row.get("related_entity") or "-",
                        "foreign_key_field": row.get("foreign_key_field") or "-",
                        "is_array": bool(row.get("is_array")),
                        "is_circular": bool(row.get("is_circular")),
                    }
                )
    typelist_cards = []
    for t in typelists:
        entries = entries_by_typelist.get(t["name"], [])
        typelist_cards.append(
            {
                "name": t["name"],
                "count": len(entries),
                "codes": [e.get("code", "") for e in entries[:14]],
            }
        )
    return {
        "entity_count": len(entities),
        "typelist_count": len(typelists),
        "field_count": sum(len(v) for v in fields_by_entity.values()),
        "hierarchy_edges": hierarchy_edges,
        "relation_rows": relation_rows,
        "ext_counts": ext_counts,
        "rel_counts": rel_counts,
        "typelist_cards": typelist_cards,
    }


def _chatbot_reply(db_path: str, user_id: int | None, text: str) -> str:
    lower = (text or "").lower()
    if user_id and any(tok in lower for tok in ["help me improve", "improve", "increase approval", "why rejected", "how to get approved"]):
        rows = user_applications(db_path, user_id, 3)
        if not rows:
            return "Submit your first application and I will generate a personalized approval-improvement plan."
        latest = rows[0]
        try:
            factors = json.loads(latest.get("decision_factors", "{}"))
        except Exception:
            factors = {}
        tips = []
        if float(factors.get("dti", 0.0)) > 0.45:
            tips.append("Reduce debt-to-income ratio by lowering current obligations.")
        if int(latest.get("credit_score", 0)) < 680:
            tips.append("Increase credit score above 680 for better approval odds.")
        if float(factors.get("collateral_shortfall", 0.0)) > 0:
            tips.append("Add collateral to cover shortfall for this loan amount.")
        if float(latest.get("employment_years", 0.0)) < 2:
            tips.append("More stable employment history improves risk profile.")
        if not tips:
            tips.append("Profile is already strong. Consider reducing requested amount for faster auto-approval.")
        return (
            f"Latest application #{latest['id']} is {latest['status']} (segment {latest.get('borrower_segment', '-')}). "
            f"Recommended actions: {' '.join(tips[:4])}"
        )
    docs = retrieve_policy_guidance(db_path, text, 2)
    if docs:
        ref = " | ".join([f"{d['title']}: {d['content'][:120]}" for d in docs])
        return f"Policy guidance: {ref}"
    if "status" in lower and user_id:
        rows = user_applications(db_path, user_id, 3)
        if not rows:
            return "No applications found yet. Submit one from PolicyCenter."
        latest = rows[0]
        return (
            f"Latest application #{latest['id']} is {latest['status']} in tier {latest['tier']}. "
            f"Risk score is {latest['risk_score']}, approval probability {latest['approval_probability']:.2f}, "
            f"borrower segment {latest.get('borrower_segment', '-')}, requested amount {latest['requested_amount']:.0f}."
        )
    if "document" in lower or "kyc" in lower:
        if user_id:
            rows = user_applications(db_path, user_id, 1)
            if rows:
                latest = rows[0]
                policy = get_product_policy_by_code(db_path, latest.get("product_code", "")) or get_product_policy_for_amount(db_path, float(latest.get("requested_amount", 0)))
                if policy:
                    docs_list = ", ".join(policy.get("required_documents", [])[:8])
                    return (
                        f"For your latest product {policy['product_code']}, verification level is {policy['verification_level']}. "
                        f"Required documents: {docs_list}. Collateral ratio requirement: {policy['required_collateral_ratio']:.2f}."
                    )
        return "Required documents depend on product and amount. The dashboard shows verification level and required docs after assessment."
    if "emi" in lower or "payment" in lower:
        if user_id:
            with get_conn(db_path) as conn:
                row = conn.execute(
                    """
                    SELECT sl.application_id, sl.amount, sl.due_date, sl.status
                    FROM servicing_ledger sl
                    JOIN loan_applications la ON la.id = sl.application_id
                    WHERE la.user_id = ? AND sl.txn_type='EMI_DUE'
                    ORDER BY sl.due_date ASC, sl.id ASC
                    LIMIT 1
                    """,
                    (user_id,),
                ).fetchone()
            if row:
                return (
                    f"Next EMI: application #{row['application_id']}, amount {float(row['amount']):.2f}, "
                    f"due {row['due_date']}, status {row['status']}."
                )
        return "Use Disbursement & Payments / Servicing Ledger pages to review EMI schedules and overdue entries."
    if "product" in lower:
        products = get_active_products(db_path)
        labels = ", ".join([f"{p['code']} ({int(p['min_amount'])}-{int(p['max_amount'])}, base {p['base_rate']:.3f})" for p in products[:6]])
        return f"Available products: {labels}."
    return (
        "I can help with application status, product ranges, required documents, EMI guidance, and admin modules. "
        "Try: 'what is my latest status?'"
    )


def _chatbot_system_context(db_path: str, user_id: int | None) -> str:
    docs = retrieve_policy_guidance(db_path, "underwriting policy kyc collections", 3)
    doc_text = "\n".join([f"- {d['title']}: {d['content'][:180]}" for d in docs])
    user_text = ""
    history_text = ""
    if user_id:
        rows = user_applications(db_path, user_id, 1)
        if rows:
            latest = rows[0]
            user_text = (
                f"Latest application: id={latest['id']}, status={latest['status']}, "
                f"risk={latest['risk_score']}, tier={latest['tier']}."
            )
        hist = recent_chat_messages(db_path, user_id, 4)
        if hist:
            lines = []
            for item in reversed(hist):
                lines.append(f"User: {item.get('message', '')[:140]}")
                lines.append(f"Assistant: {item.get('response', '')[:200]}")
            history_text = "\nRecent chat context:\n" + "\n".join(lines)
    return (
        "You are the LoanShield assistant. Keep responses concise and policy-safe. "
        "Never provide secrets, SQL, or admin bypass advice.\n"
        f"Policy snippets:\n{doc_text}\n"
        f"{user_text}\n{history_text}"
    )


def _application_status_markdown(app_row: Dict[str, Any]) -> str:
    factors: Dict[str, Any] = {}
    try:
        factors = json.loads(app_row.get("decision_factors", "{}"))
    except Exception:
        factors = {}
    loan_type = str(factors.get("loan_type", app_row.get("loan_type", "PERSONAL")) or "PERSONAL")
    preferred_currencies = factors.get("preferred_currencies", app_row.get("preferred_currencies", ["USD"]))
    if isinstance(preferred_currencies, str):
        preferred_currencies = [preferred_currencies]
    if not isinstance(preferred_currencies, list):
        preferred_currencies = ["USD"]
    preferred_currencies = [str(x).upper() for x in preferred_currencies if str(x).strip()] or ["USD"]
    docs = factors.get("required_documents", [])
    if not isinstance(docs, list):
        docs = []
    lines = [
        "# Loan Application Filing & Approval Status",
        "",
        f"- **Application ID:** {app_row.get('id')}",
        f"- **Filed On:** {app_row.get('created_at')}",
        f"- **Current Status:** {app_row.get('status')}",
        f"- **Decision Tier:** {app_row.get('tier')}",
        f"- **Approval Probability:** {float(app_row.get('approval_probability', 0.0)) * 100:.1f}%",
        f"- **Risk Score:** {app_row.get('risk_score')}",
        f"- **Region:** {app_row.get('region')}",
        f"- **Loan Product:** {app_row.get('product_code')}",
        f"- **Loan Type:** {loan_type}",
        f"- **Policy Type:** {app_row.get('policy_type', factors.get('policy_type', 'STANDARD'))}",
        f"- **Preferred Currencies:** {', '.join(preferred_currencies)}",
        "",
        "## Filing Details",
        "",
        f"- Requested Amount: {float(app_row.get('requested_amount', 0.0)):.2f}",
        f"- Current Salary: {float(app_row.get('current_salary', 0.0)):.2f}",
        f"- Monthly Expenditure: {float(app_row.get('monthly_expenditure', 0.0)):.2f}",
        f"- Existing EMI: {float(app_row.get('existing_emi', 0.0)):.2f}",
        f"- Loan Term (months): {app_row.get('loan_term_months')}",
        f"- Credit Score: {app_row.get('credit_score')}",
        f"- Employment Years: {app_row.get('employment_years')}",
        f"- Collateral Value: {float(app_row.get('collateral_value', 0.0)):.2f}",
        "",
        "## Approval Summary",
        "",
        f"- Monthly Payment Estimate: {float(app_row.get('monthly_payment_est', 0.0)):.2f}",
        f"- Recommended Amount: {float(app_row.get('recommended_amount', 0.0)):.2f}",
        f"- Interest Rate: {float(app_row.get('interest_rate', 0.0)) * 100:.2f}%",
        f"- Verification Level: {factors.get('verification_level', 'Standard')}",
        f"- Collateral Required: {'Yes' if factors.get('collateral_required', False) else 'No'}",
        f"- Collateral Shortfall: {float(factors.get('collateral_shortfall', 0.0)):.2f}",
        "",
    ]
    if docs:
        lines.append("## Required Documents")
        lines.append("")
        lines.extend([f"- {str(item)}" for item in docs[:12]])
        lines.append("")
    lines.append(f"_Generated at: {utcnow()}_")
    unsigned = "\n".join(lines)
    sig = hashlib.sha256((current_app.config.get("DATA_KEY", "") + "|" + unsigned).encode("utf-8")).hexdigest()
    lines.append(f"_Export Signature: `{sig}`_")
    return "\n".join(lines)


def register_routes(app):
    def current_access_level() -> str:
        level = sanitize_text(str(session.get("access_level", "")), 20).lower()
        if level in {"admin", "company", "end_user"}:
            return level
        if session.get("role") == "admin":
            return "admin"
        return "end_user"

    def access_level_required(*levels: str):
        allowed = {str(x).lower() for x in levels}

        def deco(view):
            @wraps(view)
            @login_required
            def wrapped(*args, **kwargs):
                lvl = current_access_level()
                if lvl not in allowed and session.get("role") != "admin":
                    flash("Unauthorized access.")
                    if lvl == "company":
                        return redirect(url_for("company_dashboard"))
                    return redirect(url_for("user_dashboard"))
                return view(*args, **kwargs)
            return wrapped

        return deco

    @app.context_processor
    def inject_common():
        return {
            "csrf_token": csrf_token(),
            "user_role": session.get("role"),
            "access_level": current_access_level(),
            "username": session.get("username"),
            "regions": REGIONS,
            "products": get_active_products(app.config["DB_PATH"]),
            "loan_types": LOAN_TYPE_OPTIONS,
            "policy_types": POLICY_TYPE_OPTIONS,
            "currency_options": CURRENCY_OPTIONS,
            "integration_flags": integration_status(),
        }

    @app.route("/")
    @app.route("/welcome")
    def home():
        chain_ok, chain_size = verify_chain(app.config["DB_PATH"])
        model_info = active_model_info(app.config["DB_PATH"])
        return render_template("home.html", chain_ok=chain_ok, chain_size=chain_size, model_info=model_info)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("register"))

            username = sanitize_text(request.form.get("username", ""), 30).lower()
            full_name = sanitize_text(request.form.get("full_name", ""), 80)
            region = sanitize_text(request.form.get("region", ""), 20)
            email = sanitize_text(request.form.get("email", ""), 120).lower()
            phone = "".join(ch for ch in sanitize_text(request.form.get("phone", ""), 20) if ch.isdigit() or ch == "+")
            password = request.form.get("password", "")

            errors = []
            if not username or suspicious(username):
                errors.append("Invalid username.")
            if not full_name:
                errors.append("Full name is required.")
            if not _is_valid_email(email):
                errors.append("Valid email is required.")
            if not _is_valid_phone(phone):
                errors.append("Valid phone number is required (8-15 digits, optional +).")
            if len(password) < 8:
                errors.append("Password must be at least 8 characters.")
            errors.extend(password_policy_errors(password))
            if region not in REGIONS:
                errors.append("Select a valid region.")
            if errors:
                for e in errors:
                    flash(e)
                return redirect(url_for("register"))

            with get_conn(app.config["DB_PATH"]) as conn:
                exists = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                if exists:
                    flash("Username already exists.")
                    return redirect(url_for("register"))
                email_exists = conn.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
                if email_exists:
                    flash("Email already exists.")
                    return redirect(url_for("register"))
                phone_exists = conn.execute("SELECT id FROM users WHERE phone = ?", (phone,)).fetchone()
                if phone_exists:
                    flash("Phone number already exists.")
                    return redirect(url_for("register"))

                email_code = f"{random.randint(100000, 999999)}"
                phone_code = f"{random.randint(100000, 999999)}"
                expires_at = (datetime.utcnow() + timedelta(minutes=10)).replace(microsecond=0).isoformat() + "Z"
                secret = app.config.get("DATA_KEY", "loanshield")
                conn.execute(
                    """
                    INSERT INTO signup_2fa_challenges (
                        username, full_name, password_hash, region, email, phone,
                        email_otp_hash, phone_otp_hash, expires_at, attempts, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        full_name=excluded.full_name,
                        password_hash=excluded.password_hash,
                        region=excluded.region,
                        email=excluded.email,
                        phone=excluded.phone,
                        email_otp_hash=excluded.email_otp_hash,
                        phone_otp_hash=excluded.phone_otp_hash,
                        expires_at=excluded.expires_at,
                        attempts=0,
                        created_at=excluded.created_at
                    """,
                    (
                        username,
                        full_name,
                        password_hash(password),
                        region,
                        email,
                        phone,
                        _otp_hash(secret, username, "email", email_code),
                        _otp_hash(secret, username, "phone", phone_code),
                        expires_at,
                        utcnow(),
                    ),
                )
                conn.commit()

            email_message = f"Your LoanShield email verification code is {email_code}. It expires in 10 minutes."
            sms_message = f"LoanShield phone verification code: {phone_code}. Expires in 10 minutes."
            email_res = send_email(email, "LoanShield signup verification code", email_message)
            sms_res = send_sms(phone, sms_message)
            if not email_res.get("ok") or not sms_res.get("ok"):
                with get_conn(app.config["DB_PATH"]) as conn:
                    conn.execute("DELETE FROM signup_2fa_challenges WHERE username = ?", (username,))
                    conn.commit()
                flash("Unable to send verification codes right now. Please try again.")
                return redirect(url_for("register"))

            session["signup_2fa_username"] = username
            flash("Verification codes sent to your email and phone.")
            return redirect(url_for("register_verify"))

        return render_template("auth/register.html")

    @app.route("/register/verify", methods=["GET", "POST"])
    def register_verify():
        username = sanitize_text(request.args.get("username", "") or session.get("signup_2fa_username", ""), 30).lower()
        if not username:
            flash("No pending verification found. Please register first.")
            return redirect(url_for("register"))
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("register_verify"))
            username = sanitize_text(request.form.get("username", ""), 30).lower()
            email_code = sanitize_text(request.form.get("email_code", ""), 8)
            phone_code = sanitize_text(request.form.get("phone_code", ""), 8)
            with get_conn(app.config["DB_PATH"]) as conn:
                challenge = conn.execute(
                    "SELECT * FROM signup_2fa_challenges WHERE username = ?",
                    (username,),
                ).fetchone()
                if not challenge:
                    flash("Verification session expired. Please register again.")
                    return redirect(url_for("register"))
                if challenge["expires_at"] < utcnow():
                    conn.execute("DELETE FROM signup_2fa_challenges WHERE username = ?", (username,))
                    conn.commit()
                    flash("Verification code expired. Please register again.")
                    return redirect(url_for("register"))
                secret = app.config.get("DATA_KEY", "loanshield")
                email_ok = _otp_hash(secret, username, "email", email_code) == challenge["email_otp_hash"]
                phone_ok = _otp_hash(secret, username, "phone", phone_code) == challenge["phone_otp_hash"]
                if not email_ok or not phone_ok:
                    attempts = int(challenge.get("attempts") or 0) + 1
                    if attempts >= 8:
                        conn.execute("DELETE FROM signup_2fa_challenges WHERE username = ?", (username,))
                    else:
                        conn.execute("UPDATE signup_2fa_challenges SET attempts = ? WHERE username = ?", (attempts, username))
                    conn.commit()
                    flash("Invalid verification codes.")
                    return redirect(url_for("register_verify"))
                exists = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                if exists:
                    conn.execute("DELETE FROM signup_2fa_challenges WHERE username = ?", (username,))
                    conn.commit()
                    flash("Username already exists.")
                    return redirect(url_for("user_login"))
                created_at = utcnow()
                conn.execute(
                    """
                    INSERT INTO users (
                        username, full_name, password_hash, role, access_level, region, email, phone,
                        email_verified_at, phone_verified_at, created_at
                    )
                    VALUES (?, ?, ?, 'user', 'end_user', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        challenge["username"],
                        challenge["full_name"],
                        challenge["password_hash"],
                        challenge["region"],
                        challenge["email"],
                        challenge["phone"],
                        created_at,
                        created_at,
                        created_at,
                    ),
                )
                conn.execute("DELETE FROM signup_2fa_challenges WHERE username = ?", (username,))
                conn.commit()
            session.pop("signup_2fa_username", None)
            flash("Registration complete with email and phone verification.")
            return redirect(url_for("user_login"))

        with get_conn(app.config["DB_PATH"]) as conn:
            challenge = conn.execute(
                "SELECT username, email, phone, expires_at FROM signup_2fa_challenges WHERE username = ?",
                (username,),
            ).fetchone()
        if not challenge:
            flash("No pending verification found. Please register again.")
            return redirect(url_for("register"))
        return render_template(
            "auth/register_verify.html",
            username=challenge["username"],
            email_masked=_masked_email(challenge["email"]),
            phone_masked=_masked_phone(challenge["phone"]),
            expires_at=challenge["expires_at"],
        )

    @app.route("/login", methods=["GET", "POST"])
    def user_login():
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("user_login"))

            if not rate_limit_ok(client_id(), app.config["RATE_LIMIT_WINDOW_SEC"], app.config["RATE_LIMIT_MAX"]):
                flash("Too many attempts. Try again later.")
                return redirect(url_for("user_login"))

            username = sanitize_text(request.form.get("username", ""), 30).lower()
            password = request.form.get("password", "")

            with get_conn(app.config["DB_PATH"]) as conn:
                user = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND role = 'user'",
                    (username,),
                ).fetchone()
                if not user:
                    flash("Invalid user credentials.")
                    return redirect(url_for("user_login"))
                sec = get_auth_security(app.config["DB_PATH"], user["id"])
                if sec.get("locked_until") and str(sec["locked_until"]) > utcnow():
                    flash("Account temporarily locked due to repeated failures. Try later.")
                    return redirect(url_for("user_login"))
                if not verify_password(user["password_hash"], password):
                    state = record_login_failure(
                        app.config["DB_PATH"],
                        user["id"],
                        app.config["LOGIN_LOCK_THRESHOLD"],
                        app.config["LOGIN_LOCK_MINUTES"],
                    )
                    if state.get("locked_until"):
                        flash("Account locked after repeated failures.")
                    else:
                        flash("Invalid user credentials.")
                    return redirect(url_for("user_login"))
                reset_login_failures(app.config["DB_PATH"], user["id"])

                conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (utcnow(), user["id"]))
                conn.commit()

            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["role"] = "user"
            session["access_level"] = str(user.get("access_level") or "end_user").lower()
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            flash("Welcome back.")
            if session["access_level"] == "company":
                return redirect(url_for("company_dashboard"))
            return redirect(url_for("user_dashboard"))

        return render_template("auth/user_login.html")

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("admin_login"))

            if not rate_limit_ok(client_id(), app.config["RATE_LIMIT_WINDOW_SEC"], app.config["RATE_LIMIT_MAX"]):
                flash("Too many attempts. Try again later.")
                return redirect(url_for("admin_login"))

            username = sanitize_text(request.form.get("username", ""), 30).lower()
            password = request.form.get("password", "")

            with get_conn(app.config["DB_PATH"]) as conn:
                admin = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND role = 'admin'",
                    (username,),
                ).fetchone()
                if not admin:
                    flash("Invalid admin credentials.")
                    return redirect(url_for("admin_login"))
                sec = get_auth_security(app.config["DB_PATH"], admin["id"])
                if sec.get("locked_until") and str(sec["locked_until"]) > utcnow():
                    flash("Admin account temporarily locked due to repeated failures.")
                    return redirect(url_for("admin_login"))
                if not verify_password(admin["password_hash"], password):
                    state = record_login_failure(
                        app.config["DB_PATH"],
                        admin["id"],
                        app.config["LOGIN_LOCK_THRESHOLD"],
                        app.config["LOGIN_LOCK_MINUTES"],
                    )
                    if state.get("locked_until"):
                        flash("Admin account locked after repeated failures.")
                    else:
                        flash("Invalid admin credentials.")
                    return redirect(url_for("admin_login"))
                reset_login_failures(app.config["DB_PATH"], admin["id"])

                conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (utcnow(), admin["id"]))
                conn.commit()

            session.clear()
            session.permanent = True
            session["user_id"] = admin["id"]
            session["role"] = "admin"
            session["access_level"] = "admin"
            session["username"] = admin["username"]
            session["full_name"] = admin["full_name"]
            flash("Admin session started.")
            return redirect(url_for("admin_dashboard"))

        return render_template("auth/admin_login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.")
        return redirect(url_for("home"))

    @app.route("/chatbot", methods=["GET", "POST"])
    def chatbot():
        if not session.get("user_id"):
            flash("Please log in to use assistant.")
            return redirect(url_for("user_login"))
        quick_prompts = [
            "What is my latest application status?",
            "How can I improve my approval chances?",
            "Which documents are required for my application?",
            "Show my next EMI details.",
            "List available loan products and ranges.",
        ]
        history = recent_chat_messages(app.config["DB_PATH"], session["user_id"], 25)
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("chatbot"))
            raw = request.form.get("message", "") or request.form.get("quick_prompt", "")
            text = sanitize_text(raw, app.config["CHATBOT_MAX_INPUT"])
            blocked = False
            if not text:
                flash("Message cannot be empty.")
                return redirect(url_for("chatbot"))
            blocked_tokens = [
                "ignore previous",
                "drop table",
                "reveal password",
                "bypass",
                "select * from",
                "delete from",
                "tool call",
                "exec(",
                "shell",
            ]
            if suspicious(text) or any(tok in text.lower() for tok in blocked_tokens):
                blocked = True
                response = "Message blocked by security guardrails."
            else:
                use_gemini = app.config.get("CHATBOT_ENABLE_GEMINI", False) and integration_status().get("gemini", False)
                if use_gemini:
                    g = gemini_chat(text, _chatbot_system_context(app.config["DB_PATH"], session.get("user_id")))
                    response = g.get("text", "").strip() if g.get("ok") else _chatbot_reply(app.config["DB_PATH"], session.get("user_id"), text)
                else:
                    response = _chatbot_reply(app.config["DB_PATH"], session.get("user_id"), text)
            log_chat_message(app.config["DB_PATH"], session.get("user_id"), session.get("role", "user"), text, response, blocked)
            return redirect(url_for("chatbot"))
        return render_template("chatbot.html", history=history, quick_prompts=quick_prompts)

    @app.route("/user/dashboard")
    @access_level_required("end_user")
    def user_dashboard():
        apps = user_applications(app.config["DB_PATH"], session["user_id"], 20)
        insights = user_insights(app.config["DB_PATH"], session["user_id"])
        with get_conn(app.config["DB_PATH"]) as conn:
            policies = conn.execute(
                """
                SELECT p.id, p.policy_number, p.policy_type, p.status, p.created_at
                FROM policies p
                JOIN loan_applications la ON la.id = p.application_id
                WHERE la.user_id = ?
                ORDER BY p.id DESC
                LIMIT 80
                """,
                (session["user_id"],),
            ).fetchall()
            claims = conn.execute(
                """
                SELECT c.id, c.policy_id, c.claim_type, c.claimed_amount, c.status, c.opened_at
                FROM claims c
                JOIN policies p ON p.id = c.policy_id
                JOIN loan_applications la ON la.id = p.application_id
                WHERE la.user_id = ?
                ORDER BY c.id DESC
                LIMIT 80
                """,
                (session["user_id"],),
            ).fetchall()
        chain_ok, chain_size = verify_chain(app.config["DB_PATH"])
        model_info = active_model_info(app.config["DB_PATH"])
        return render_template(
            "user/dashboard.html",
            apps=apps,
            policies=policies,
            claims=claims,
            insights=insights,
            chain_ok=chain_ok,
            chain_size=chain_size,
            model_info=model_info,
            result=None,
            result_meta=None,
            explainability=None,
        )

    @app.route("/user/apply", methods=["POST"])
    @access_level_required("end_user")
    def user_apply():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("user_dashboard"))

        payload, errors = _validate_application(request.form)
        if errors:
            for e in errors:
                flash(e)
            return redirect(url_for("user_dashboard"))

        bundle = _model_or_retrain()
        policy = get_product_policy_by_code(app.config["DB_PATH"], payload["product_code"])
        if not policy:
            policy = get_product_policy_for_amount(app.config["DB_PATH"], payload["requested_amount"])
        if policy and payload["product_code"] and payload["product_code"] != policy["product_code"]:
            flash(f"Selected product is out of range; product {policy['product_code']} was auto-applied.")
        if policy and not (policy.get("min_amount", 0) <= payload["requested_amount"] <= policy.get("max_amount", 10**12)):
            flash(f"Requested amount outside {policy['product_code']} range. Rule auto-adjusted by amount.")
            policy = get_product_policy_for_amount(app.config["DB_PATH"], payload["requested_amount"])
        decision = ml.infer(bundle, payload, policy=policy)

        app_id = create_application(app.config["DB_PATH"], payload, decision, session["user_id"])
        chain_payload = (
            f"app={app_id};status={decision['status']};risk={decision['risk_score']};"
            f"user={session['username']};loan_type={payload.get('loan_type', 'PERSONAL')};"
            f"currencies={','.join(payload.get('preferred_currencies', ['USD']))}"
        )
        block_hash = append_chain(
            app.config["DB_PATH"],
            application_id=app_id,
            actor_id=session["user_id"],
            event_type="APPLICATION_SUBMITTED",
            payload=chain_payload,
        )
        set_application_hash(app.config["DB_PATH"], app_id, block_hash)
        kyc_hash = record_kyc_document_hash(
            app.config["DB_PATH"],
            application_id=app_id,
            doc_type="KYC_ID",
            doc_source_value=payload["kyc_id_number"],
            metadata=f"user={session['username']}",
        )
        income_hash = record_kyc_document_hash(
            app.config["DB_PATH"],
            application_id=app_id,
            doc_type="INCOME_DOC",
            doc_source_value=payload["income_doc_ref"],
            metadata=f"user={session['username']}",
        )
        append_chain(
            app.config["DB_PATH"],
            application_id=app_id,
            actor_id=session["user_id"],
            event_type="KYC_HASHED",
            payload=f"kyc_hash={kyc_hash};income_hash={income_hash}",
        )
        ext_kyc = verify_kyc_external(payload["kyc_id_number"])
        append_chain(
            app.config["DB_PATH"],
            application_id=app_id,
            actor_id=session["user_id"],
            event_type="KYC_PROVIDER_CHECK",
            payload=f"provider={ext_kyc.get('provider')};ok={ext_kyc.get('ok')};verified={ext_kyc.get('verified', False)}",
        )
        addr_norm = address_validate(payload["region"])
        append_chain(
            app.config["DB_PATH"],
            application_id=app_id,
            actor_id=session["user_id"],
            event_type="ADDRESS_VALIDATION",
            payload=f"provider={addr_norm.get('provider', 'none')};ok={addr_norm.get('ok')}",
        )

        result = get_application(app.config["DB_PATH"], app_id)
        create_workflow_task(
            app.config["DB_PATH"],
            application_id=app_id,
            stage="UNDERWRITING_REVIEW",
            priority="High" if result["status"] == "Manual Review" else "Normal",
            assignee_user_id=None,
            sla_hours=24 if result["status"] == "Manual Review" else 48,
        )
        doc_intel = run_document_intelligence(app.config["DB_PATH"], result)
        if doc_intel["status"] == "Mismatch":
            create_workflow_task(
                app.config["DB_PATH"],
                application_id=app_id,
                stage="DOC_REVERIFICATION",
                priority="Critical",
                assignee_user_id=None,
                sla_hours=12,
            )
        record_consent(app.config["DB_PATH"], session["user_id"], "DATA_PROCESSING", "true")
        create_compliance_event(
            app.config["DB_PATH"],
            session["user_id"],
            "APPLICATION_DATA_PROCESSING",
            json.dumps({"application_id": app_id, "doc_intel_status": doc_intel["status"]}),
            "Recorded",
        )
        quote = create_quote_for_application(app.config["DB_PATH"], result)
        fraud = calculate_fraud_signal(app.config["DB_PATH"], result)
        append_chain(
            app.config["DB_PATH"],
            application_id=app_id,
            actor_id=session["user_id"],
            event_type="QUOTE_CREATED",
            payload=f"quote_id={quote['id']};quoted_amount={quote['quoted_amount']}",
        )
        append_chain(
            app.config["DB_PATH"],
            application_id=app_id,
            actor_id=session["user_id"],
            event_type="FRAUD_SIGNAL",
            payload=f"score={fraud['score']};band={fraud['risk_band']}",
        )
        create_disbursement_and_schedule(app.config["DB_PATH"], result)
        policy = issue_policy_for_application(app.config["DB_PATH"], result)
        if policy:
            create_invoice_and_commission(app.config["DB_PATH"], result)
            append_chain(
                app.config["DB_PATH"],
                application_id=app_id,
                actor_id=session["user_id"],
                event_type="POLICY_ISSUED",
                payload=f"policy={policy['policy_number']}",
            )
        log_engagement_event(
            app.config["DB_PATH"],
            session["user_id"],
            "web-portal",
            "APPLICATION_SUBMITTED",
            json.dumps({"application_id": app_id, "status": result["status"]}),
        )
        recipient = f"{session['username']}@example.local"
        subject = f"Loan Application #{app_id} - {result['status']}"
        message = f"Status: {result['status']} | Tier: {result['tier']} | Amount: {result['requested_amount']}"
        email_res = send_email(recipient, subject, message)
        log_notification(
            app.config["DB_PATH"],
            application_id=app_id,
            channel="email",
            recipient=recipient,
            subject=subject,
            message=message,
            status="sent" if email_res.get("ok") else "failed",
            provider=email_res.get("provider", "sendgrid"),
        )
        if result["status"] == "Approved":
            pay = create_payment_intent(float(result["monthly_payment_est"]))
            append_chain(
                app.config["DB_PATH"],
                application_id=app_id,
                actor_id=session["user_id"],
                event_type="PAYMENT_INTENT_CREATE",
                payload=f"provider={pay.get('provider')};ok={pay.get('ok')};id={pay.get('id', '')}",
            )
        observability_log(
            app.config["DB_PATH"],
            "origination",
            "INFO",
            "Application processed",
            json.dumps({"application_id": app_id, "status": result["status"], "segment": result.get("borrower_segment", "-")}),
        )
        result_meta = {}
        try:
            result_meta = json.loads(result["decision_factors"])
        except Exception:
            result_meta = {}
        insights = user_insights(app.config["DB_PATH"], session["user_id"])
        apps = user_applications(app.config["DB_PATH"], session["user_id"], 20)
        with get_conn(app.config["DB_PATH"]) as conn:
            policies = conn.execute(
                """
                SELECT p.id, p.policy_number, p.policy_type, p.status, p.created_at
                FROM policies p
                JOIN loan_applications la ON la.id = p.application_id
                WHERE la.user_id = ?
                ORDER BY p.id DESC
                LIMIT 80
                """,
                (session["user_id"],),
            ).fetchall()
            claims = conn.execute(
                """
                SELECT c.id, c.policy_id, c.claim_type, c.claimed_amount, c.status, c.opened_at
                FROM claims c
                JOIN policies p ON p.id = c.policy_id
                JOIN loan_applications la ON la.id = p.application_id
                WHERE la.user_id = ?
                ORDER BY c.id DESC
                LIMIT 80
                """,
                (session["user_id"],),
            ).fetchall()
        chain_ok, chain_size = verify_chain(app.config["DB_PATH"])
        model_info = active_model_info(app.config["DB_PATH"])
        return render_template(
            "user/dashboard.html",
            apps=apps,
            policies=policies,
            claims=claims,
            insights=insights,
            chain_ok=chain_ok,
            chain_size=chain_size,
            model_info=model_info,
            result=result,
            result_meta=result_meta,
            explainability=explainability_for_application(result)[:5] if result else [],
        )

    @app.route("/user/application/<int:app_id>/download.md")
    @access_level_required("end_user")
    def user_application_download(app_id: int):
        app_row = get_application(app.config["DB_PATH"], app_id)
        if not app_row or app_row.get("user_id") != session.get("user_id"):
            flash("Application not found.")
            return redirect(url_for("user_dashboard"))
        content = _application_status_markdown(app_row)
        response = make_response(content)
        response.headers["Content-Type"] = "text/markdown; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="application_{app_id}_status.md"'
        return response

    @app.route("/user/application/<int:app_id>/upload-document", methods=["POST"])
    @access_level_required("end_user")
    def user_application_upload_document(app_id: int):
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("user_dashboard"))
        app_row = get_application(app.config["DB_PATH"], app_id)
        if not app_row or app_row.get("user_id") != session.get("user_id"):
            flash("Application not found.")
            return redirect(url_for("user_dashboard"))
        uploaded = request.files.get("document_file")
        if not uploaded or not uploaded.filename:
            flash("Please select a file to upload.")
            return redirect(url_for("user_dashboard"))
        file_bytes = uploaded.read() or b""
        if not file_bytes:
            flash("Uploaded file is empty.")
            return redirect(url_for("user_dashboard"))
        if len(file_bytes) > 4 * 1024 * 1024:
            flash("File too large. Max size is 4 MB.")
            return redirect(url_for("user_dashboard"))
        doc = process_uploaded_document(app.config["DB_PATH"], app_row, uploaded.filename, file_bytes)
        append_chain(
            app.config["DB_PATH"],
            application_id=app_id,
            actor_id=session["user_id"],
            event_type="DOCUMENT_UPLOADED",
            payload=f"filename={sanitize_text(uploaded.filename, 80)};status={doc.get('status')};mismatch={doc.get('mismatch_score')}",
        )
        flash(f"Document processed. OCR status: {doc.get('status')} (mismatch {doc.get('mismatch_score')}).")
        return redirect(url_for("user_dashboard"))

    @app.route("/user/claim/create", methods=["POST"])
    @access_level_required("end_user")
    def user_claim_create():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("user_dashboard"))
        policy_id = int(request.form.get("policy_id", "0"))
        claim_type = sanitize_text(request.form.get("claim_type", ""), 40) or "General"
        description = sanitize_text(request.form.get("description", ""), 180) or "Submitted from user portal"
        claimed_amount = float(request.form.get("claimed_amount", 0) or 0)
        if policy_id <= 0 or claimed_amount <= 0:
            flash("Invalid claim payload.")
            return redirect(url_for("user_dashboard"))
        with get_conn(app.config["DB_PATH"]) as conn:
            policy = conn.execute(
                """
                SELECT p.id
                FROM policies p
                JOIN loan_applications la ON la.id = p.application_id
                WHERE p.id = ? AND la.user_id = ?
                """,
                (policy_id, session["user_id"]),
            ).fetchone()
        if not policy:
            flash("Policy not found for current user.")
            return redirect(url_for("user_dashboard"))
        claim = create_claim(app.config["DB_PATH"], policy_id, claim_type, description, claimed_amount, session["user_id"])
        append_chain(
            app.config["DB_PATH"],
            None,
            session["user_id"],
            "USER_CLAIM_CREATED",
            f"claim_id={claim['id']};policy_id={policy_id}",
        )
        flash(f"Claim #{claim['id']} submitted.")
        return redirect(url_for("user_dashboard"))

    @app.route("/model-visualizer")
    @login_required
    def model_visualizer():
        full = get_data_model(app.config["DB_PATH"])
        is_admin = session.get("role") == "admin"
        scoped = _scoped_data_model_view(full, session.get("user_id"), is_admin)
        visual = _model_visual_payload(scoped)
        return render_template(
            "shared/model_visualizer.html",
            data_model=scoped,
            visual=visual,
            is_admin=is_admin,
        )

    @app.route("/company/dashboard")
    @access_level_required("company", "admin")
    def company_dashboard():
        with get_conn(app.config["DB_PATH"]) as conn:
            app_totals = conn.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN status='Approved' THEN 1 ELSE 0 END) AS approved,
                       SUM(CASE WHEN status='Manual Review' THEN 1 ELSE 0 END) AS manual,
                       SUM(CASE WHEN status='Rejected' THEN 1 ELSE 0 END) AS rejected,
                       AVG(requested_amount) AS avg_requested
                FROM loan_applications
                """
            ).fetchone()
            by_product = conn.execute(
                """
                SELECT product_code, COUNT(*) AS total, AVG(approval_probability) AS avg_prob
                FROM loan_applications
                GROUP BY product_code
                ORDER BY total DESC
                LIMIT 20
                """
            ).fetchall()
        full = get_data_model(app.config["DB_PATH"])
        scoped = _scoped_data_model_view(full, session.get("user_id"), session.get("role") == "admin")
        visual = _model_visual_payload(scoped)
        return render_template(
            "company/dashboard.html",
            totals=app_totals or {},
            by_product=by_product,
            data_model=scoped,
            visual=visual,
        )

    @app.route("/company/datamodel/entity", methods=["POST"])
    @access_level_required("company", "admin")
    def company_create_entity():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("company_dashboard"))
        name = _safe_model_name(request.form.get("name", ""))
        supertype = _safe_model_name(request.form.get("supertype", "")) or None
        subtype = _safe_model_name(request.form.get("subtype", "")) or None
        description = sanitize_text(request.form.get("description", ""), 180)
        if not name:
            flash("Entity name is required.")
            return redirect(url_for("company_dashboard"))
        try:
            create_entity_definition(
                app.config["DB_PATH"],
                name=name,
                supertype=supertype,
                subtype=subtype,
                description=description,
                created_by=session["user_id"],
            )
            regenerate_model_code(app.config["DB_PATH"], app.config["MODEL_DIR"])
            flash(f"Entity {name} created.")
        except Exception:
            flash("Unable to create entity. Use a unique name.")
        return redirect(url_for("company_dashboard"))

    @app.route("/company/datamodel/typelist", methods=["POST"])
    @access_level_required("company", "admin")
    def company_create_typelist():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("company_dashboard"))
        name = _safe_model_name(request.form.get("name", ""))
        description = sanitize_text(request.form.get("description", ""), 180)
        code = _safe_model_name(request.form.get("code", ""), 30).upper()
        display_name = sanitize_text(request.form.get("display_name", ""), 40)
        if not name:
            flash("Typelist name is required.")
            return redirect(url_for("company_dashboard"))
        create_typelist(app.config["DB_PATH"], name, description, session["user_id"])
        if code:
            add_typelist_entry(app.config["DB_PATH"], name, code, display_name or code, 0, session["user_id"])
        regenerate_model_code(app.config["DB_PATH"], app.config["MODEL_DIR"])
        flash(f"Typelist {name} saved.")
        return redirect(url_for("company_dashboard"))

    @app.route("/company/datamodel/extension", methods=["POST"])
    @access_level_required("company", "admin")
    def company_extend_entity():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("company_dashboard"))
        entity_name = _safe_model_name(request.form.get("entity_name", ""))
        field_name = _safe_model_name(request.form.get("field_name", ""))
        field_type = sanitize_text(request.form.get("field_type", "string"), 20).lower()
        extension_type = sanitize_text(request.form.get("extension_type", "EIX"), 8).upper()
        relation_type = sanitize_text(request.form.get("relation_type", "none"), 20).lower()
        related_entity = _safe_model_name(request.form.get("related_entity", "")) or None
        foreign_key_field = _safe_model_name(request.form.get("foreign_key_field", "")) or None
        is_array = request.form.get("is_array") == "on"
        is_circular = request.form.get("is_circular") == "on"
        nullable = request.form.get("nullable") == "on"
        typelist_name = _safe_model_name(request.form.get("typelist_name", "")) or None
        description = sanitize_text(request.form.get("description", ""), 180)
        allowed_types = {"string", "int", "float", "decimal", "bool", "date", "datetime", "createdtime", "entity_ref", "array"}
        if not entity_name or not field_name or field_type not in allowed_types:
            flash("Invalid extension payload.")
            return redirect(url_for("company_dashboard"))
        create_or_update_entity_field(
            app.config["DB_PATH"],
            entity_name=entity_name,
            field_name=field_name,
            field_type=field_type,
            extension_type=extension_type if extension_type in {"EIX", "ETX"} else "EIX",
            relation_type=relation_type,
            related_entity=related_entity,
            foreign_key_field=foreign_key_field,
            is_array=is_array or relation_type == "array",
            is_circular=is_circular or relation_type == "circular",
            nullable=nullable,
            typelist_name=typelist_name,
            description=description,
            created_by=session["user_id"],
        )
        regenerate_model_code(app.config["DB_PATH"], app.config["MODEL_DIR"])
        flash("Entity extension saved.")
        return redirect(url_for("company_dashboard"))

    @app.route("/admin/dashboard")
    @role_required("admin")
    def admin_dashboard():
        applications = all_applications(app.config["DB_PATH"], 200)
        insights = admin_insights(app.config["DB_PATH"])
        data_model = get_data_model(app.config["DB_PATH"])
        chain_ok, chain_size = verify_chain(app.config["DB_PATH"])
        model_info = active_model_info(app.config["DB_PATH"])
        model_features = []
        if model_info and model_info.get("features_json"):
            try:
                model_features = json.loads(model_info["features_json"])
            except Exception:
                model_features = []
        manual_queue = [x for x in applications if x["status"] == "Manual Review"][:20]
        high_risk = [x for x in applications if x["risk_score"] <= 45][:20]
        generated_files = generated_artifacts_summary(app.config["MODEL_DIR"], 20)
        servicing = servicing_summary(app.config["DB_PATH"], 120)
        return render_template(
            "admin/dashboard.html",
            applications=applications,
            manual_queue=manual_queue,
            high_risk=high_risk,
            insights=insights,
            data_model=data_model,
            chain_ok=chain_ok,
            chain_size=chain_size,
            model_info=model_info,
            model_features=model_features,
            generated_files=generated_files,
            servicing=servicing,
        )

    @app.route("/admin/retrain", methods=["POST"])
    @role_required("admin")
    def admin_retrain():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_dashboard"))

        rows = historical_training_rows(app.config["DB_PATH"])
        version = f"v{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        bundle = ml.train_model(rows, app.config["MODEL_DIR"], version)
        upsert_model_registry(
            app.config["DB_PATH"],
            version=bundle.version,
            sample_count=bundle.sample_count,
            accuracy=bundle.accuracy,
            roc_auc=bundle.roc_auc,
            features=ml.FEATURES,
        )

        append_chain(
            app.config["DB_PATH"],
            application_id=None,
            actor_id=session["user_id"],
            event_type="MODEL_RETRAIN",
            payload=f"version={bundle.version};samples={bundle.sample_count};accuracy={bundle.accuracy:.3f}",
        )
        flash(f"Model retrained: {bundle.version} ({bundle.sample_count} samples)")
        return redirect(url_for("admin_dashboard"))

    @app.route("/admin/application/<int:app_id>/decision", methods=["POST"])
    @role_required("admin")
    def admin_decision(app_id: int):
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_dashboard"))

        status = sanitize_text(request.form.get("status", ""), 20)
        tier = sanitize_text(request.form.get("tier", ""), 20)
        allowed = {"Approved", "Manual Review", "Rejected"}
        if status not in allowed:
            flash("Invalid status transition.")
            return redirect(url_for("admin_dashboard"))

        update_application_decision(app.config["DB_PATH"], app_id, status, tier or "Standard")
        app_row = get_application(app.config["DB_PATH"], app_id)
        if app_row and status == "Approved":
            create_disbursement_and_schedule(app.config["DB_PATH"], app_row)
            policy = issue_policy_for_application(app.config["DB_PATH"], app_row)
            if policy:
                create_invoice_and_commission(app.config["DB_PATH"], app_row)
        append_chain(
            app.config["DB_PATH"],
            application_id=app_id,
            actor_id=session["user_id"],
            event_type="MANUAL_DECISION",
            payload=f"app={app_id};status={status};tier={tier or 'Standard'};admin={session['username']}",
        )
        flash(f"Application #{app_id} updated.")
        return redirect(url_for("admin_dashboard"))

    @app.route("/admin/datamodel/entity", methods=["POST"])
    @role_required("admin")
    def admin_create_entity():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_dashboard"))

        name = _safe_model_name(request.form.get("name", ""))
        supertype = _safe_model_name(request.form.get("supertype", "")) or None
        subtype = _safe_model_name(request.form.get("subtype", "")) or None
        description = sanitize_text(request.form.get("description", ""), 180)
        if not name:
            flash("Entity name is required.")
            return redirect(url_for("admin_dashboard"))
        try:
            create_entity_definition(
                app.config["DB_PATH"],
                name=name,
                supertype=supertype,
                subtype=subtype,
                description=description,
                created_by=session["user_id"],
            )
            gen = regenerate_model_code(app.config["DB_PATH"], app.config["MODEL_DIR"])
            append_chain(
                app.config["DB_PATH"],
                application_id=None,
                actor_id=session["user_id"],
                event_type="DATAMODEL_ENTITY_CREATE",
                payload=f"entity={name};supertype={supertype or ''};subtype={subtype or ''}",
            )
            flash(f"Entity {name} created. Generated {gen['count']} code files.")
        except Exception:
            flash("Entity creation failed. Use unique names and valid symbols.")
        return redirect(url_for("admin_dashboard"))

    @app.route("/admin/datamodel/typelist", methods=["POST"])
    @role_required("admin")
    def admin_create_typelist():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_dashboard"))
        name = _safe_model_name(request.form.get("name", ""))
        description = sanitize_text(request.form.get("description", ""), 180)
        code = _safe_model_name(request.form.get("code", ""), 30).upper()
        display_name = sanitize_text(request.form.get("display_name", ""), 40)
        if not name:
            flash("Typelist name is required.")
            return redirect(url_for("admin_dashboard"))
        create_typelist(app.config["DB_PATH"], name, description, session["user_id"])
        if code:
            add_typelist_entry(
                app.config["DB_PATH"],
                typelist_name=name,
                code=code,
                display_name=display_name or code,
                sort_order=0,
                created_by=session["user_id"],
            )
        gen = regenerate_model_code(app.config["DB_PATH"], app.config["MODEL_DIR"])
        append_chain(
            app.config["DB_PATH"],
            application_id=None,
            actor_id=session["user_id"],
            event_type="DATAMODEL_TYPELIST_UPSERT",
            payload=f"typelist={name};entry={code}",
        )
        flash(f"Typelist {name} saved. Generated {gen['count']} code files.")
        return redirect(url_for("admin_dashboard"))

    @app.route("/admin/datamodel/extension", methods=["POST"])
    @role_required("admin")
    def admin_extend_entity():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_dashboard"))
        entity_name = _safe_model_name(request.form.get("entity_name", ""))
        field_name = _safe_model_name(request.form.get("field_name", ""))
        field_type = sanitize_text(request.form.get("field_type", "string"), 20).lower()
        extension_type = sanitize_text(request.form.get("extension_type", "EIX"), 8).upper()
        relation_type = sanitize_text(request.form.get("relation_type", "none"), 20).lower()
        related_entity = _safe_model_name(request.form.get("related_entity", "")) or None
        foreign_key_field = _safe_model_name(request.form.get("foreign_key_field", "")) or None
        is_array = request.form.get("is_array") == "on"
        is_circular = request.form.get("is_circular") == "on"
        nullable = request.form.get("nullable") == "on"
        typelist_name = _safe_model_name(request.form.get("typelist_name", "")) or None
        description = sanitize_text(request.form.get("description", ""), 180)
        allowed_types = {"string", "int", "float", "decimal", "bool", "date", "datetime", "createdtime", "entity_ref", "array"}
        allowed_extensions = {"EIX", "ETX"}
        allowed_relations = {"none", "one_to_one", "one_to_many", "foreign_key", "array", "circular"}
        if not entity_name or not field_name or field_type not in allowed_types:
            flash("Invalid extension payload.")
            return redirect(url_for("admin_dashboard"))
        if extension_type not in allowed_extensions or relation_type not in allowed_relations:
            flash("Invalid extension payload.")
            return redirect(url_for("admin_dashboard"))
        if relation_type in {"one_to_one", "one_to_many", "foreign_key", "circular"} and not related_entity:
            flash("Related entity is required for this relation type.")
            return redirect(url_for("admin_dashboard"))
        if relation_type == "foreign_key" and not foreign_key_field:
            flash("Foreign key field is required for foreign_key relation.")
            return redirect(url_for("admin_dashboard"))
        if relation_type == "array":
            is_array = True
        if relation_type == "circular":
            is_circular = True

        create_or_update_entity_field(
            app.config["DB_PATH"],
            entity_name=entity_name,
            field_name=field_name,
            field_type=field_type,
            extension_type=extension_type,
            relation_type=relation_type,
            related_entity=related_entity,
            foreign_key_field=foreign_key_field,
            is_array=is_array,
            is_circular=is_circular,
            nullable=nullable,
            typelist_name=typelist_name,
            description=description,
            created_by=session["user_id"],
        )
        gen = regenerate_model_code(app.config["DB_PATH"], app.config["MODEL_DIR"])
        append_chain(
            app.config["DB_PATH"],
            application_id=None,
            actor_id=session["user_id"],
            event_type="DATAMODEL_ENTITY_EXTEND",
            payload=(
                f"entity={entity_name};field={field_name};type={field_type};"
                f"ext={extension_type};relation={relation_type};related={related_entity or ''};"
                f"fk={foreign_key_field or ''};array={int(is_array)};circular={int(is_circular)};"
                f"typelist={typelist_name or ''}"
            ),
        )
        flash(f"Entity extension applied and Java/Gosu updated ({gen['count']} files).")
        return redirect(url_for("admin_dashboard"))

    def _admin_base_payload():
        apps = all_applications(app.config["DB_PATH"], 400)
        insights = admin_insights(app.config["DB_PATH"])
        data_model = get_data_model(app.config["DB_PATH"])
        chain_ok, chain_size = verify_chain(app.config["DB_PATH"])
        model_info = active_model_info(app.config["DB_PATH"])
        gen_files = generated_artifacts_summary(app.config["MODEL_DIR"], 30)
        return {
            "apps": apps,
            "insights": insights,
            "data_model": data_model,
            "chain_ok": chain_ok,
            "chain_size": chain_size,
            "model_info": model_info,
            "generated_files": gen_files,
        }

    @app.route("/admin/modules")
    @role_required("admin")
    def admin_modules():
        modules = [
            ("PolicyCenter Models", "admin_policycenter"),
            ("ClaimCenter Workflows", "admin_claimcenter"),
            ("BillingCenter Ops", "admin_billingcenter"),
            ("Digital Engagement", "admin_digital_engagement"),
            ("Data & Analytics", "admin_data_analytics"),
            ("Integration Gateway API", "admin_integration_gateway"),
            ("Cloud Scalability", "admin_cloud_scalability"),
            ("Case Detail", "admin_case_detail_picker"),
            ("Submission Timeline", "admin_submission_timeline"),
            ("Document Center", "admin_document_center"),
            ("Underwriter Workbench", "admin_underwriter_workbench"),
            ("Rules Configuration", "admin_rules_config"),
            ("Rules Engine (Editable)", "admin_rules_engine"),
            ("Model Explainability", "admin_model_explainability"),
            ("Model Monitoring", "admin_model_monitoring"),
            ("Portfolio Risk", "admin_portfolio_risk"),
            ("Typelist Manager", "admin_typelist_manager"),
            ("Entity Explorer", "admin_entity_explorer"),
            ("Model Visualizer", "model_visualizer"),
            ("Codegen Console", "admin_codegen_console"),
            ("Audit Explorer", "admin_audit_explorer"),
            ("Security Center", "admin_security_center"),
            ("Admin User Management", "admin_user_management"),
            ("Access Control Matrix", "admin_access_matrix"),
            ("Notifications Center", "admin_notifications_center"),
            ("Reports & Exports", "admin_reports_exports"),
            ("Integration Hub", "admin_integration_hub"),
            ("Integration Test", "admin_integration_test"),
            ("Sandbox/Test Data", "admin_sandbox"),
            ("System Health", "admin_system_health"),
            ("Servicing Ledger", "admin_servicing_ledger"),
            ("HITL Workflow", "admin_hitl_workflow"),
            ("Document Intelligence", "admin_document_intelligence"),
            ("Collections Strategy", "admin_collections_strategy"),
            ("Payment Reconciliation", "admin_payment_reconciliation"),
            ("Decision Explainability+", "admin_explainability_plus"),
            ("Scenario Simulator+", "admin_scenario_simulator_plus"),
            ("Partner Onboarding", "admin_partner_onboarding"),
            ("Compliance Module", "admin_compliance_module"),
            ("Fraud Graph Analytics", "admin_fraud_graph"),
            ("SSO & MFA Center", "admin_sso_mfa"),
            ("Notification Orchestration", "admin_notification_orchestration"),
            ("Warehouse Export", "admin_warehouse_export"),
            ("Observability", "admin_observability"),
            ("Mobile PWA", "admin_mobile_pwa"),
        ]
        return render_template("admin/modules_index.html", modules=modules)

    @app.route("/admin/access-matrix")
    @role_required("admin")
    def admin_access_matrix():
        rows = sorted(ACCESS_MATRIX_ROWS, key=lambda x: (x["access_level"], x["module"]))
        return render_template(
            "admin/module_table.html",
            title="Access Control Matrix",
            subtitle="Need-to-know permissions across modules and route groups",
            rows=rows,
            columns=["module", "route", "access_level", "guard", "description"],
        )

    @app.route("/admin/rules-engine", methods=["GET", "POST"])
    @role_required("admin")
    def admin_rules_engine():
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("admin_rules_engine"))
            product_code = sanitize_text(request.form.get("product_code", ""), 20)
            verification_level = sanitize_text(request.form.get("verification_level", "Standard"), 20)
            try:
                required_collateral_ratio = float(request.form.get("required_collateral_ratio", 0))
                min_credit_score = int(request.form.get("min_credit_score", 650))
                max_dti = float(request.form.get("max_dti", 0.64))
            except ValueError:
                flash("Invalid numeric value in rules update.")
                return redirect(url_for("admin_rules_engine"))
            with get_conn(app.config["DB_PATH"]) as conn:
                conn.execute(
                    """
                    UPDATE product_rules
                    SET verification_level=?, required_collateral_ratio=?, min_credit_score=?, max_dti=?
                    WHERE product_code=? AND is_active=1
                    """,
                    (verification_level, required_collateral_ratio, min_credit_score, max_dti, product_code),
                )
                conn.commit()
            append_chain(
                app.config["DB_PATH"],
                application_id=None,
                actor_id=session["user_id"],
                event_type="RULE_ENGINE_UPDATE",
                payload=f"product={product_code};verification={verification_level};min_score={min_credit_score};max_dti={max_dti:.2f}",
            )
            flash(f"Rules updated for {product_code}.")
            return redirect(url_for("admin_rules_engine"))
        with get_conn(app.config["DB_PATH"]) as conn:
            rules = conn.execute(
                """
                SELECT product_code, verification_level, required_collateral_ratio, min_credit_score, max_dti
                FROM product_rules
                WHERE is_active=1
                ORDER BY product_code
                """
            ).fetchall()
        return render_template("admin/rules_engine.html", rules=rules)

    @app.route("/admin/policycenter")
    @role_required("admin")
    def admin_policycenter():
        with get_conn(app.config["DB_PATH"]) as conn:
            products = conn.execute(
                """
                SELECT lp.code, lp.name, lp.min_amount, lp.max_amount, lp.base_rate,
                       lp.policy_type, pr.verification_level, pr.required_collateral_ratio, pr.min_credit_score, pr.max_dti
                FROM loan_products lp
                LEFT JOIN product_rules pr ON pr.product_code = lp.code AND pr.is_active=1
                WHERE lp.is_active=1
                ORDER BY lp.min_amount
                """
            ).fetchall()
        return render_template("admin/policycenter.html", products=products, policy_types=POLICY_TYPE_OPTIONS)

    @app.route("/admin/policycenter/product", methods=["POST"])
    @role_required("admin")
    def admin_policycenter_product():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_policycenter"))
        code = _safe_model_name(request.form.get("code", ""), 20).upper()
        name = sanitize_text(request.form.get("name", ""), 60)
        policy_type = sanitize_text(request.form.get("policy_type", "STANDARD"), 20).upper()
        min_amount = float(request.form.get("min_amount", 0))
        max_amount = float(request.form.get("max_amount", 0))
        base_rate = float(request.form.get("base_rate", 0.09))
        verif = sanitize_text(request.form.get("verification_level", "Standard"), 30)
        coll = float(request.form.get("required_collateral_ratio", 0))
        min_score = int(request.form.get("min_credit_score", 300))
        max_dti = float(request.form.get("max_dti", 0.7))
        docs = [x.strip() for x in str(request.form.get("required_docs", "Government ID,Income Proof")).split(",") if x.strip()]
        if policy_type not in SUPPORTED_POLICY_TYPES:
            policy_type = "STANDARD"
        if not code or min_amount < 0 or max_amount <= min_amount:
            flash("Invalid product model values.")
            return redirect(url_for("admin_policycenter"))
        with get_conn(app.config["DB_PATH"]) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO loan_products (id, code, name, policy_type, min_amount, max_amount, base_rate, description, is_active, created_at)
                VALUES ((SELECT id FROM loan_products WHERE code=?), ?, ?, ?, ?, ?, ?, 'Configured from PolicyCenter', 1, ?)
                """,
                (code, code, name or code, policy_type, min_amount, max_amount, base_rate, utcnow()),
            )
            conn.execute(
                """
                INSERT INTO product_rules (
                    product_code, verification_level, required_collateral_ratio, min_credit_score,
                    max_dti, required_documents_json, is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (code, verif, coll, min_score, max_dti, json.dumps(docs), utcnow()),
            )
            conn.commit()
        append_chain(app.config["DB_PATH"], None, session["user_id"], "POLICYCENTER_PRODUCT_UPSERT", f"code={code};min={min_amount};max={max_amount}")
        flash(f"Product model {code} saved.")
        return redirect(url_for("admin_policycenter"))

    @app.route("/admin/claimcenter")
    @role_required("admin")
    def admin_claimcenter():
        overview = claims_overview(app.config["DB_PATH"])
        with get_conn(app.config["DB_PATH"]) as conn:
            policies = conn.execute(
                "SELECT id, policy_number, product_code, status FROM policies ORDER BY id DESC LIMIT 100"
            ).fetchall()
        return render_template("admin/claimcenter.html", claims=overview["claims"], stages=overview["stages"], policies=policies)

    @app.route("/admin/claimcenter/create", methods=["POST"])
    @role_required("admin")
    def admin_claimcenter_create():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_claimcenter"))
        policy_id = int(request.form.get("policy_id", "0"))
        claim_type = sanitize_text(request.form.get("claim_type", ""), 40)
        description = sanitize_text(request.form.get("description", ""), 180)
        claimed_amount = float(request.form.get("claimed_amount", 0))
        if policy_id <= 0 or claimed_amount <= 0:
            flash("Invalid claim payload.")
            return redirect(url_for("admin_claimcenter"))
        claim = create_claim(app.config["DB_PATH"], policy_id, claim_type or "General", description or "Submitted", claimed_amount, session["user_id"])
        append_chain(app.config["DB_PATH"], None, session["user_id"], "CLAIM_CREATED", f"claim_id={claim['id']};policy_id={policy_id}")
        flash(f"Claim #{claim['id']} created.")
        return redirect(url_for("admin_claimcenter"))

    @app.route("/admin/claimcenter/progress", methods=["POST"])
    @role_required("admin")
    def admin_claimcenter_progress():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_claimcenter"))
        claim_id = int(request.form.get("claim_id", "0"))
        stage = sanitize_text(request.form.get("stage", "Assessment"), 30)
        notes = sanitize_text(request.form.get("notes", ""), 180)
        progress_claim(app.config["DB_PATH"], claim_id, stage, notes or "Workflow progressed", session["user_id"])
        append_chain(app.config["DB_PATH"], None, session["user_id"], "CLAIM_PROGRESS", f"claim_id={claim_id};stage={stage}")
        flash(f"Claim #{claim_id} moved to {stage}.")
        return redirect(url_for("admin_claimcenter"))

    @app.route("/admin/billingcenter")
    @role_required("admin")
    def admin_billingcenter():
        with get_conn(app.config["DB_PATH"]) as conn:
            invoices = conn.execute(
                "SELECT * FROM billing_invoices ORDER BY id DESC LIMIT 200"
            ).fetchall()
            commissions = conn.execute(
                "SELECT * FROM agent_commissions ORDER BY id DESC LIMIT 200"
            ).fetchall()
        servicing = servicing_summary(app.config["DB_PATH"], 80)
        return render_template("admin/billingcenter.html", invoices=invoices, commissions=commissions, servicing=servicing)

    @app.route("/admin/digital-engagement")
    @role_required("admin")
    def admin_digital_engagement():
        feed = engagement_feed(app.config["DB_PATH"], 200)
        return render_template("admin/digital_engagement.html", feed=feed)

    @app.route("/admin/digital-engagement/event", methods=["POST"])
    @role_required("admin")
    def admin_digital_event():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_digital_engagement"))
        channel = sanitize_text(request.form.get("channel", "portal"), 20)
        event_type = sanitize_text(request.form.get("event_type", "campaign"), 40)
        metadata = sanitize_text(request.form.get("metadata", ""), 180)
        log_engagement_event(app.config["DB_PATH"], session["user_id"], channel, event_type, metadata or "{}")
        flash("Engagement event logged.")
        return redirect(url_for("admin_digital_engagement"))

    @app.route("/admin/data-analytics")
    @role_required("admin")
    def admin_data_analytics():
        data = analytics_overview(app.config["DB_PATH"])
        return render_template("admin/data_analytics.html", data=data)

    @app.route("/admin/integration-gateway")
    @role_required("admin")
    def admin_integration_gateway():
        with get_conn(app.config["DB_PATH"]) as conn:
            clients = conn.execute("SELECT name, api_key, is_active, created_at FROM integration_clients ORDER BY id DESC").fetchall()
            logs = conn.execute("SELECT client_name, endpoint, response_status, created_at FROM integration_gateway_logs ORDER BY id DESC LIMIT 100").fetchall()
        return render_template("admin/integration_gateway.html", clients=clients, logs=logs)

    @app.route("/admin/cloud-scalability")
    @role_required("admin")
    def admin_cloud_scalability():
        snap = cloud_runtime_snapshot(app.config["DB_PATH"])
        return render_template("admin/cloud_scalability.html", settings=snap)

    @app.route("/api/gateway/quote", methods=["POST"])
    def api_gateway_quote():
        api_key = request.headers.get("X-API-Key", "")
        client = validate_gateway_key(app.config["DB_PATH"], api_key)
        payload = request.get_json(silent=True) or {}
        if not client:
            log_gateway_request(app.config["DB_PATH"], "unknown", "/api/gateway/quote", json.dumps(payload), 401)
            return {"error": "unauthorized"}, 401
        allowed, reason = gateway_policy_allows(app.config["DB_PATH"], client, request.remote_addr)
        if not allowed:
            log_gateway_request(app.config["DB_PATH"], client, "/api/gateway/quote", json.dumps(payload), 429)
            return {"error": reason}, 429
        app_id = int(payload.get("application_id", 0))
        application = get_application(app.config["DB_PATH"], app_id)
        if not application:
            log_gateway_request(app.config["DB_PATH"], client, "/api/gateway/quote", json.dumps(payload), 404)
            return {"error": "application_not_found"}, 404
        quote = create_quote_for_application(app.config["DB_PATH"], application)
        log_gateway_request(app.config["DB_PATH"], client, "/api/gateway/quote", json.dumps(payload), 200)
        return {"quote": quote}

    @app.route("/api/gateway/claim", methods=["POST"])
    def api_gateway_claim():
        api_key = request.headers.get("X-API-Key", "")
        client = validate_gateway_key(app.config["DB_PATH"], api_key)
        payload = request.get_json(silent=True) or {}
        if not client:
            log_gateway_request(app.config["DB_PATH"], "unknown", "/api/gateway/claim", json.dumps(payload), 401)
            return {"error": "unauthorized"}, 401
        allowed, reason = gateway_policy_allows(app.config["DB_PATH"], client, request.remote_addr)
        if not allowed:
            log_gateway_request(app.config["DB_PATH"], client, "/api/gateway/claim", json.dumps(payload), 429)
            return {"error": reason}, 429
        policy_id = int(payload.get("policy_id", 0))
        amount = float(payload.get("claimed_amount", 0))
        if policy_id <= 0 or amount <= 0:
            log_gateway_request(app.config["DB_PATH"], client, "/api/gateway/claim", json.dumps(payload), 400)
            return {"error": "invalid_payload"}, 400
        claim = create_claim(
            app.config["DB_PATH"],
            policy_id=policy_id,
            claim_type=sanitize_text(payload.get("claim_type", "General"), 40),
            description=sanitize_text(payload.get("description", "Submitted through gateway"), 180),
            claimed_amount=amount,
            actor_id=None,
        )
        append_chain(app.config["DB_PATH"], None, None, "GATEWAY_CLAIM_CREATE", f"client={client};claim_id={claim['id']}")
        log_gateway_request(app.config["DB_PATH"], client, "/api/gateway/claim", json.dumps(payload), 201)
        return {"claim": claim}, 201

    @app.route("/admin/servicing-ledger")
    @role_required("admin")
    def admin_servicing_ledger():
        summary = servicing_summary(app.config["DB_PATH"], 220)
        return render_template(
            "admin/servicing_ledger.html",
            ledger=summary["ledger"],
            totals=summary["totals"],
        )

    @app.route("/admin/servicing/run-delinquency", methods=["POST"])
    @role_required("admin")
    def admin_run_delinquency():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_servicing_ledger"))
        res = run_delinquency_workflow(app.config["DB_PATH"], actor_id=session["user_id"])
        if res["triggered"] > 0:
            recipient = f"{session['username']}@example.local"
            subject = "Delinquency Workflow Alert"
            message = f"Delinquency workflow triggered {res['triggered']} actions."
            mail = send_email(recipient, subject, message)
            log_notification(
                app.config["DB_PATH"],
                application_id=None,
                channel="email",
                recipient=recipient,
                subject=subject,
                message=message,
                status="sent" if mail.get("ok") else "failed",
                provider=mail.get("provider", "sendgrid"),
            )
        flash(f"Delinquency workflow completed. Triggered actions: {res['triggered']}")
        return redirect(url_for("admin_servicing_ledger"))

    @app.route("/admin/case-detail")
    @role_required("admin")
    def admin_case_detail_picker():
        apps = all_applications(app.config["DB_PATH"], 100)
        return render_template("admin/case_picker.html", applications=apps)

    @app.route("/admin/case-detail/<int:app_id>")
    @role_required("admin")
    def admin_case_detail(app_id: int):
        app_row = get_application(app.config["DB_PATH"], app_id)
        with get_conn(app.config["DB_PATH"]) as conn:
            events = conn.execute(
                """
                SELECT block_timestamp, event_type, event_payload, current_hash
                FROM audit_chain
                WHERE application_id = ?
                ORDER BY id DESC
                """,
                (app_id,),
            ).fetchall()
        return render_template("admin/case_detail.html", app_row=app_row, events=events)

    @app.route("/admin/submission-timeline")
    @role_required("admin")
    def admin_submission_timeline():
        with get_conn(app.config["DB_PATH"]) as conn:
            events = conn.execute(
                """
                SELECT ac.block_timestamp, ac.event_type, COALESCE(u.username, 'system') AS actor, ac.event_payload
                FROM audit_chain ac
                LEFT JOIN users u ON u.id = ac.actor_id
                ORDER BY ac.id DESC
                LIMIT 150
                """
            ).fetchall()
        return render_template("admin/module_table.html", title="Submission Timeline", subtitle="Chronological decision and system events", rows=events, columns=["block_timestamp", "event_type", "actor", "event_payload"])

    @app.route("/admin/document-center")
    @role_required("admin")
    def admin_document_center():
        apps = all_applications(app.config["DB_PATH"], 120)
        rows = []
        for a in apps:
            try:
                factors = json.loads(a["decision_factors"])
            except Exception:
                factors = {}
            verification_level = factors.get("verification_level", "Standard")
            collateral_required = "Yes" if factors.get("collateral_required") else "No"
            shortfall = factors.get("collateral_shortfall", 0)
            state = "Verified" if a["status"] == "Approved" else ("Pending Review" if a["status"] == "Manual Review" else "Incomplete")
            rows.append(
                {
                    "id": a["id"],
                    "username": a["username"],
                    "region": a["region"],
                    "status": a["status"],
                    "verification_level": verification_level,
                    "collateral_required": collateral_required,
                    "collateral_shortfall": shortfall,
                    "document_state": state,
                }
            )
        return render_template(
            "admin/module_table.html",
            title="Document Center",
            subtitle="KYC and underwriting document verification status",
            rows=rows,
            columns=["id", "username", "region", "status", "verification_level", "collateral_required", "collateral_shortfall", "document_state"],
        )

    @app.route("/admin/underwriter-workbench")
    @role_required("admin")
    def admin_underwriter_workbench():
        apps = all_applications(app.config["DB_PATH"], 180)
        queue = [a for a in apps if a["status"] in {"Manual Review", "Rejected"} or a["risk_score"] < 55]
        return render_template("admin/module_table.html", title="Underwriter Workbench", subtitle="Prioritized queue by risk and review state", rows=queue[:120], columns=["id", "username", "region", "requested_amount", "risk_score", "approval_probability", "status", "tier"])

    @app.route("/admin/rules-config")
    @role_required("admin")
    def admin_rules_config():
        with get_conn(app.config["DB_PATH"]) as conn:
            rules_db = conn.execute(
                """
                SELECT pr.product_code, pr.verification_level, pr.required_collateral_ratio, pr.min_credit_score, pr.max_dti
                FROM product_rules pr
                WHERE pr.is_active=1
                ORDER BY pr.product_code
                """
            ).fetchall()
        rows = []
        for r in rules_db:
            rows.append({"rule_name": f"{r['product_code']} Verification", "value": r["verification_level"]})
            rows.append({"rule_name": f"{r['product_code']} Min Credit Score", "value": str(r["min_credit_score"])})
            rows.append({"rule_name": f"{r['product_code']} Max DTI", "value": f"{r['max_dti']:.2f}"})
            rows.append({"rule_name": f"{r['product_code']} Collateral Ratio", "value": f"{r['required_collateral_ratio']:.2f}"})
        rows.extend(
            [
                {"rule_name": "Auto Approval Threshold", "value": "risk_score >= 78 and prob >= 0.72"},
                {"rule_name": "Manual Review Threshold", "value": "risk_score >= 58 and prob >= 0.48"},
                {"rule_name": "High Risk Threshold", "value": "risk_score <= 45"},
            ]
        )
        return render_template("admin/module_cards.html", title="Rules Configuration", subtitle="Current underwriting and routing rules", items=rows)

    @app.route("/admin/model-explainability")
    @role_required("admin")
    def admin_model_explainability():
        apps = all_applications(app.config["DB_PATH"], 80)
        rows = []
        for a in apps:
            top = explainability_for_application(a)[:3]
            rows.append(
                {
                    "id": a["id"],
                    "status": a["status"],
                    "risk_score": a["risk_score"],
                    "factors": ", ".join([f"{x['factor']}({x['impact']:+.2f})" for x in top]),
                }
            )
        return render_template("admin/module_table.html", title="Model Explainability", subtitle="Decision factors by application", rows=rows, columns=["id", "status", "risk_score", "factors"])

    @app.route("/admin/model-monitoring")
    @role_required("admin")
    def admin_model_monitoring():
        report = model_monitoring_report(app.config["DB_PATH"])
        with get_conn(app.config["DB_PATH"]) as conn:
            versions = conn.execute(
                "SELECT version, trained_at, sample_count, is_active FROM model_registry ORDER BY id DESC LIMIT 20"
            ).fetchall()
        return render_template("admin/model_monitoring.html", summary=report["summary"], fairness=report["fairness"], segments=report["segments"], versions=versions)

    @app.route("/admin/model-lifecycle", methods=["POST"])
    @role_required("admin")
    def admin_model_lifecycle():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_model_monitoring"))
        action = sanitize_text(request.form.get("action", ""), 20).lower()
        if action == "retrain":
            rows = historical_training_rows(app.config["DB_PATH"])
            version = f"v{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            bundle = ml.train_model(rows, app.config["MODEL_DIR"], version)
            upsert_model_registry(
                app.config["DB_PATH"],
                version=bundle.version,
                sample_count=bundle.sample_count,
                accuracy=bundle.accuracy,
                roc_auc=bundle.roc_auc,
                features=ml.FEATURES,
            )
            append_chain(
                app.config["DB_PATH"],
                application_id=None,
                actor_id=session["user_id"],
                event_type="MODEL_RETRAIN",
                payload=f"version={bundle.version};samples={bundle.sample_count}",
            )
            flash(f"Model retrained and activated: {bundle.version}")
        elif action == "rollback":
            version = sanitize_text(request.form.get("version", ""), 40)
            if not version:
                flash("Version is required for rollback.")
                return redirect(url_for("admin_model_monitoring"))
            with get_conn(app.config["DB_PATH"]) as conn:
                found = conn.execute("SELECT id FROM model_registry WHERE version=? LIMIT 1", (version,)).fetchone()
                if not found:
                    flash("Version not found.")
                    return redirect(url_for("admin_model_monitoring"))
                conn.execute("UPDATE model_registry SET is_active=0")
                conn.execute("UPDATE model_registry SET is_active=1 WHERE version=?", (version,))
                conn.commit()
            append_chain(
                app.config["DB_PATH"],
                application_id=None,
                actor_id=session["user_id"],
                event_type="MODEL_ROLLBACK",
                payload=f"version={version}",
            )
            flash(f"Rolled back active model to {version}.")
        else:
            flash("Unsupported lifecycle action.")
        return redirect(url_for("admin_model_monitoring"))

    @app.route("/admin/portfolio-risk")
    @role_required("admin")
    def admin_portfolio_risk():
        data = portfolio_risk_overview(app.config["DB_PATH"])
        return render_template("admin/portfolio_risk.html", totals=data["totals"], buckets=data["buckets"])

    @app.route("/admin/typelist-manager")
    @role_required("admin")
    def admin_typelist_manager():
        data = get_data_model(app.config["DB_PATH"])
        rows = []
        for t in data["typelists"]:
            entries = data["entries_by_typelist"].get(t["name"], [])
            rows.append(
                {
                    "typelist": t["name"],
                    "entries": ", ".join([e["code"] for e in entries[:8]]),
                    "count": len(entries),
                }
            )
        return render_template("admin/module_table.html", title="Typelist Manager", subtitle="Typelist and code management", rows=rows, columns=["typelist", "count", "entries"])

    @app.route("/admin/typelist-entry", methods=["POST"])
    @role_required("admin")
    def admin_typelist_entry():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_typelist_manager"))
        name = _safe_model_name(request.form.get("name", ""))
        code = _safe_model_name(request.form.get("code", ""), 30).upper()
        display = sanitize_text(request.form.get("display_name", ""), 40) or code
        if not name or not code:
            flash("Typelist name and code are required.")
            return redirect(url_for("admin_typelist_manager"))
        create_typelist(app.config["DB_PATH"], name, "Managed from typelist manager", session["user_id"])
        add_typelist_entry(app.config["DB_PATH"], name, code, display, 50, session["user_id"])
        regenerate_model_code(app.config["DB_PATH"], app.config["MODEL_DIR"])
        flash(f"Typelist entry {name}.{code} saved.")
        return redirect(url_for("admin_typelist_manager"))

    @app.route("/admin/entity-explorer")
    @role_required("admin")
    def admin_entity_explorer():
        data = get_data_model(app.config["DB_PATH"])
        rows = []
        for entity in data["entities"]:
            rows.append(
                {
                    "entity": entity["name"],
                    "supertype": entity.get("supertype") or "-",
                    "subtype": entity.get("subtype") or "-",
                    "fields": len(data["fields_by_entity"].get(entity["name"], [])),
                }
            )
        return render_template("admin/module_table.html", title="Entity Explorer", subtitle="Entity hierarchy and extension map", rows=rows, columns=["entity", "supertype", "subtype", "fields"])

    @app.route("/admin/codegen-console")
    @role_required("admin")
    def admin_codegen_console():
        files = generated_artifacts_summary(app.config["MODEL_DIR"], 80)
        return render_template("admin/module_table.html", title="Code Generation Console", subtitle="Generated Java/Gosu artifacts", rows=files, columns=["path", "size"])

    @app.route("/admin/codegen-regenerate", methods=["POST"])
    @role_required("admin")
    def admin_codegen_regenerate():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_codegen_console"))
        res = regenerate_model_code(app.config["DB_PATH"], app.config["MODEL_DIR"])
        flash(f"Regenerated {res['count']} files.")
        return redirect(url_for("admin_codegen_console"))

    @app.route("/admin/audit-explorer")
    @role_required("admin")
    def admin_audit_explorer():
        event_type = sanitize_text(request.args.get("event_type", ""), 40)
        with get_conn(app.config["DB_PATH"]) as conn:
            if event_type:
                rows = conn.execute(
                    """
                    SELECT id, block_timestamp, event_type, event_payload, current_hash
                    FROM audit_chain WHERE event_type = ? ORDER BY id DESC LIMIT 250
                    """,
                    (event_type,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, block_timestamp, event_type, event_payload, current_hash
                    FROM audit_chain ORDER BY id DESC LIMIT 250
                    """
                ).fetchall()
        return render_template("admin/module_table.html", title="Audit Explorer", subtitle="Searchable chain-backed audit events", rows=rows, columns=["id", "block_timestamp", "event_type", "event_payload", "current_hash"])

    @app.route("/admin/security-center")
    @role_required("admin")
    def admin_security_center():
        with get_conn(app.config["DB_PATH"]) as conn:
            admin_actions = conn.execute(
                """
                SELECT event_type, COUNT(*) AS total
                FROM audit_chain
                WHERE actor_id IS NOT NULL
                GROUP BY event_type
                ORDER BY total DESC
                """
            ).fetchall()
        cards = [
            {"rule_name": "CSRF Protection", "value": "Enabled on all mutating forms"},
            {"rule_name": "Rate Limiting", "value": "Enabled on login and sensitive paths"},
            {"rule_name": "SQL Injection Guardrails", "value": "Parameterized SQL + suspicious pattern checks"},
            {"rule_name": "Data Leakage Guardrails", "value": "Role-based access and masked sensitive fields"},
        ]
        return render_template("admin/security_center.html", cards=cards, admin_actions=admin_actions)

    @app.route("/admin/user-management")
    @role_required("admin")
    def admin_user_management():
        with get_conn(app.config["DB_PATH"]) as conn:
            users = conn.execute(
                "SELECT id, username, full_name, role, access_level, region, created_at, last_login_at FROM users ORDER BY id DESC"
            ).fetchall()
        return render_template("admin/user_management.html", users=users)

    @app.route("/admin/user-management/promote", methods=["POST"])
    @role_required("admin")
    def admin_user_promote():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_user_management"))
        user_id = request.form.get("user_id", "")
        try:
            uid = int(user_id)
        except ValueError:
            flash("Invalid user id.")
            return redirect(url_for("admin_user_management"))
        with get_conn(app.config["DB_PATH"]) as conn:
            conn.execute("UPDATE users SET role = 'admin', access_level = 'admin' WHERE id = ?", (uid,))
            conn.commit()
        append_chain(app.config["DB_PATH"], None, session["user_id"], "USER_ROLE_PROMOTE", f"user_id={uid};role=admin")
        flash(f"User #{uid} promoted to admin.")
        return redirect(url_for("admin_user_management"))

    @app.route("/admin/user-management/access", methods=["POST"])
    @role_required("admin")
    def admin_user_set_access():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_user_management"))
        user_id = request.form.get("user_id", "")
        access_level = sanitize_text(request.form.get("access_level", "end_user"), 20).lower()
        if access_level not in {"end_user", "company", "admin"}:
            flash("Invalid access level.")
            return redirect(url_for("admin_user_management"))
        try:
            uid = int(user_id)
        except ValueError:
            flash("Invalid user id.")
            return redirect(url_for("admin_user_management"))
        with get_conn(app.config["DB_PATH"]) as conn:
            target = conn.execute("SELECT id, role FROM users WHERE id = ?", (uid,)).fetchone()
            if not target:
                flash("User not found.")
                return redirect(url_for("admin_user_management"))
            role = "admin" if access_level == "admin" else "user"
            conn.execute("UPDATE users SET access_level = ?, role = ? WHERE id = ?", (access_level, role, uid))
            conn.commit()
        append_chain(app.config["DB_PATH"], None, session["user_id"], "USER_ACCESS_LEVEL_SET", f"user_id={uid};access_level={access_level}")
        flash(f"User #{uid} access set to {access_level}.")
        return redirect(url_for("admin_user_management"))

    @app.route("/admin/notifications-center")
    @role_required("admin")
    def admin_notifications_center():
        apps = all_applications(app.config["DB_PATH"], 200)
        alerts = []
        for a in apps:
            if a["status"] == "Manual Review":
                alerts.append({"level": "Warning", "message": f"Application #{a['id']} pending manual review"})
            if a["risk_score"] <= 45:
                alerts.append({"level": "Critical", "message": f"Application #{a['id']} flagged high risk ({a['risk_score']})"})
        for n in recent_notifications(app.config["DB_PATH"], 80):
            alerts.append({"level": "Info", "message": f"Notification[{n['channel']}] {n['status']} via {n['provider']} to {n['recipient']}"})
        return render_template("admin/module_table.html", title="Notifications Center", subtitle="Operational alerts and escalation signals", rows=alerts[:250], columns=["level", "message"])

    @app.route("/admin/reports-exports")
    @role_required("admin")
    def admin_reports_exports():
        base = _admin_base_payload()
        rows = [
            {"report": "Portfolio Summary", "description": "Applications by status and region"},
            {"report": "Risk Distribution", "description": "Risk score and probability distribution"},
            {"report": "Audit Extract", "description": "Audit events with actor and timestamp"},
        ]
        return render_template("admin/reports_exports.html", rows=rows, total=base["insights"]["overview"].get("total", 0))

    @app.route("/admin/reports-exports/download")
    @role_required("admin")
    def admin_reports_download():
        apps = all_applications(app.config["DB_PATH"], 500)
        export_format = sanitize_text(request.args.get("format", "csv"), 10).lower()
        if export_format == "md":
            lines = ["# Loan Portfolio Export", "", f"- Generated At: {utcnow()}", f"- Record Count: {len(apps)}", "", "| ID | User | Region | Requested | Status | Risk | Prob |", "|---:|---|---|---:|---|---:|---:|"]
            for a in apps:
                lines.append(
                    f"| {a['id']} | {a['username']} | {a['region']} | {float(a['requested_amount']):.2f} | {a['status']} | {a['risk_score']} | {float(a['approval_probability']):.3f} |"
                )
            unsigned = "\n".join(lines)
            sig = hashlib.sha256((current_app.config.get("DATA_KEY", "") + "|" + unsigned).encode("utf-8")).hexdigest()
            content = unsigned + f"\n\n_Export Signature: `{sig}`_\n"
            response = make_response(content)
            response.headers["Content-Type"] = "text/markdown; charset=utf-8"
            response.headers["Content-Disposition"] = "attachment; filename=loan_reports.md"
            return response
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["id", "username", "region", "requested_amount", "status", "risk_score", "approval_probability", "created_at"])
        for a in apps:
            writer.writerow([a["id"], a["username"], a["region"], a["requested_amount"], a["status"], a["risk_score"], a["approval_probability"], a["created_at"]])
        csv_content = buffer.getvalue()
        sig = hashlib.sha256((current_app.config.get("DATA_KEY", "") + "|" + csv_content).encode("utf-8")).hexdigest()
        response = make_response(csv_content + f"# signature:{sig}\n")
        response.headers["Content-Type"] = "text/csv"
        response.headers["Content-Disposition"] = "attachment; filename=loan_reports.csv"
        return response

    @app.route("/admin/integration-hub")
    @role_required("admin")
    def admin_integration_hub():
        flags = integration_status()
        rows = [
            {"service": "SendGrid Email", "status": "Connected" if flags["sendgrid"] else "Not Configured", "last_sync": "N/A"},
            {"service": "Twilio SMS", "status": "Connected" if flags["twilio"] else "Not Configured", "last_sync": "N/A"},
            {"service": "Stripe Payments", "status": "Connected" if flags["stripe"] else "Not Configured", "last_sync": "N/A"},
            {"service": "KYC Provider", "status": "Connected" if flags["kyc"] else "Not Configured", "last_sync": "N/A"},
            {"service": "Mapbox Address Validation", "status": "Connected" if flags["mapbox"] else "Not Configured", "last_sync": "N/A"},
            {"service": "Sentry Monitoring", "status": "Connected" if flags["sentry"] else "Not Configured", "last_sync": "N/A"},
            {"service": "OpenAI Chat", "status": "Connected" if flags["openai"] else "Not Configured", "last_sync": "N/A"},
            {"service": "Gemini Chat", "status": "Connected" if flags["gemini"] else "Not Configured", "last_sync": "N/A"},
        ]
        return render_template("admin/module_table.html", title="Integration Hub", subtitle="External integration endpoints and connector status", rows=rows, columns=["service", "status", "last_sync"])

    @app.route("/admin/integration-test")
    @role_required("admin")
    def admin_integration_test():
        report = integration_smoke_report()
        rows = []
        for name, info in report.items():
            result = info.get("result", {})
            rows.append(
                {
                    "integration": name,
                    "configured": "Yes" if info.get("configured") else "No",
                    "mode": info.get("mode"),
                    "ok": "Yes" if result.get("ok") else "No",
                    "provider": result.get("provider", "-"),
                    "details": result.get("reason", f"status_code={result.get('status_code', '-')}; id={result.get('id', '-')}")
                }
            )
        return render_template("admin/integration_test.html", rows=rows)

    @app.route("/admin/integration-test/run", methods=["POST"])
    @role_required("admin")
    def admin_integration_test_run():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_integration_test"))
        recipient_email = sanitize_text(request.form.get("test_email", ""), 120)
        recipient_sms = sanitize_text(request.form.get("test_sms", ""), 30)

        if recipient_email:
            subject = "LoanShield Integration Test Email"
            message = "This is a controlled test email from LoanShield."
            res = send_email(recipient_email, subject, message)
            log_notification(
                app.config["DB_PATH"],
                application_id=None,
                channel="email",
                recipient=recipient_email,
                subject=subject,
                message=message,
                status="sent" if res.get("ok") else "failed",
                provider=res.get("provider", "sendgrid"),
            )
            append_chain(
                app.config["DB_PATH"],
                application_id=None,
                actor_id=session["user_id"],
                event_type="INTEGRATION_TEST_EMAIL",
                payload=f"recipient={recipient_email};ok={res.get('ok')}",
            )
        if recipient_sms:
            message = "LoanShield integration test SMS."
            res = send_sms(recipient_sms, message)
            log_notification(
                app.config["DB_PATH"],
                application_id=None,
                channel="sms",
                recipient=recipient_sms,
                subject="Integration Test SMS",
                message=message,
                status="sent" if res.get("ok") else "failed",
                provider=res.get("provider", "twilio"),
            )
            append_chain(
                app.config["DB_PATH"],
                application_id=None,
                actor_id=session["user_id"],
                event_type="INTEGRATION_TEST_SMS",
                payload=f"recipient={recipient_sms};ok={res.get('ok')}",
            )

        if not recipient_email and not recipient_sms:
            flash("Provide at least one test recipient (email or SMS).")
        else:
            flash("Integration test notification run completed.")
        return redirect(url_for("admin_integration_test"))

    @app.route("/webhooks/payment", methods=["POST"])
    def payment_webhook():
        payload = request.get_json(silent=True) or {}
        payload_raw = json.dumps(payload)
        append_chain(
            app.config["DB_PATH"],
            application_id=None,
            actor_id=None,
            event_type="PAYMENT_WEBHOOK",
            payload=f"len={len(payload_raw)}",
        )
        provider_event_id = sanitize_text(str(payload.get("event_id", "")), 80) or f"evt-{uuid.uuid4().hex[:12]}"
        invoice_number = sanitize_text(str(payload.get("invoice_number", "")), 64)
        amount = float(payload.get("amount", 0.0) or 0.0)
        provider_status = sanitize_text(str(payload.get("status", "pending")), 20)
        if invoice_number:
            rec = reconcile_payment_event(app.config["DB_PATH"], provider_event_id, invoice_number, amount, provider_status)
            observability_log(
                app.config["DB_PATH"],
                "payments",
                "INFO" if rec["status"] == "MATCHED" else "WARNING",
                "Payment webhook processed",
                json.dumps({"event_id": provider_event_id, "invoice_number": invoice_number, "status": rec["status"]}),
            )
        return {"received": True}

    @app.route("/admin/sandbox")
    @role_required("admin")
    def admin_sandbox():
        return render_template("admin/sandbox.html")

    @app.route("/admin/sandbox/seed", methods=["POST"])
    @role_required("admin")
    def admin_sandbox_seed():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_sandbox"))
        sample_payloads = [
            {"region": "North", "current_salary": 95000.0, "monthly_expenditure": 2300.0, "existing_emi": 250.0, "requested_amount": 45000.0, "loan_term_months": 84, "employment_years": 4.8, "credit_score": 730, "collateral_value": 18000.0},
            {"region": "West", "current_salary": 62000.0, "monthly_expenditure": 2600.0, "existing_emi": 500.0, "requested_amount": 98000.0, "loan_term_months": 120, "employment_years": 2.2, "credit_score": 645, "collateral_value": 7000.0},
            {"region": "South", "current_salary": 140000.0, "monthly_expenditure": 3200.0, "existing_emi": 450.0, "requested_amount": 110000.0, "loan_term_months": 96, "employment_years": 8.1, "credit_score": 785, "collateral_value": 60000.0},
        ]
        with get_conn(app.config["DB_PATH"]) as conn:
            user = conn.execute("SELECT id FROM users WHERE role='user' ORDER BY id ASC LIMIT 1").fetchone()
        if not user:
            flash("Create at least one user before seeding sandbox data.")
            return redirect(url_for("admin_sandbox"))
        bundle = _model_or_retrain()
        for p in sample_payloads:
            decision = ml.infer(bundle, p)
            app_id = create_application(app.config["DB_PATH"], p, decision, user["id"])
            block_hash = append_chain(app.config["DB_PATH"], app_id, session["user_id"], "SANDBOX_SEED_APPLICATION", f"app={app_id};status={decision['status']}")
            set_application_hash(app.config["DB_PATH"], app_id, block_hash)
        flash(f"Seeded {len(sample_payloads)} sandbox applications.")
        return redirect(url_for("admin_sandbox"))

    @app.route("/admin/system-health")
    @role_required("admin")
    def admin_system_health():
        chain_ok, chain_size = verify_chain(app.config["DB_PATH"])
        with get_conn(app.config["DB_PATH"]) as conn:
            db_ok = conn.execute("SELECT 1 AS ok").fetchone()["ok"] == 1
        model_info = active_model_info(app.config["DB_PATH"])
        rows = [
            {"component": "Database", "status": "Healthy" if db_ok else "Unhealthy"},
            {"component": "Audit Chain", "status": "Healthy" if chain_ok else "Compromised"},
            {"component": "Model Registry", "status": "Healthy" if model_info else "Missing"},
            {"component": "Codegen Artifacts", "status": "Healthy" if generated_artifacts_summary(app.config["MODEL_DIR"], 1) else "Missing"},
            {"component": "Audit Block Count", "status": str(chain_size)},
        ]
        return render_template("admin/module_table.html", title="System Health", subtitle="Runtime health checks", rows=rows, columns=["component", "status"])

    @app.route("/admin/hitl-workflow")
    @role_required("admin")
    def admin_hitl_workflow():
        overview = workflow_overview(app.config["DB_PATH"], 220)
        return render_template(
            "admin/hitl_workflow.html",
            tasks=overview["tasks"],
            escalations=overview["escalations"],
            overdue=overview["overdue"],
        )

    @app.route("/admin/hitl-workflow/escalate", methods=["POST"])
    @role_required("admin")
    def admin_hitl_escalate():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_hitl_workflow"))
        res = run_workflow_escalation(app.config["DB_PATH"])
        append_chain(app.config["DB_PATH"], None, session["user_id"], "WORKFLOW_ESCALATION_RUN", f"count={res['escalated']}")
        flash(f"Escalations executed: {res['escalated']}")
        return redirect(url_for("admin_hitl_workflow"))

    @app.route("/admin/document-intelligence")
    @role_required("admin")
    def admin_document_intelligence():
        rows = document_intelligence_feed(app.config["DB_PATH"], 240)
        return render_template("admin/module_table.html", title="Document Intelligence", subtitle="OCR extraction and mismatch detection", rows=rows, columns=["id", "application_id", "extracted_salary", "extracted_region", "mismatch_score", "status", "created_at"])

    @app.route("/admin/collections-strategy")
    @role_required("admin")
    def admin_collections_strategy():
        data = collection_overview(app.config["DB_PATH"], 220)
        return render_template("admin/collections_strategy.html", strategies=data["strategies"], actions=data["actions"])

    @app.route("/admin/collections-strategy/run", methods=["POST"])
    @role_required("admin")
    def admin_collections_run():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_collections_strategy"))
        res = run_collection_strategy(app.config["DB_PATH"])
        append_chain(app.config["DB_PATH"], None, session["user_id"], "COLLECTIONS_RUN", f"actions={res['actions_created']}")
        flash(f"Collection actions created: {res['actions_created']}")
        return redirect(url_for("admin_collections_strategy"))

    @app.route("/admin/payment-reconciliation")
    @role_required("admin")
    def admin_payment_reconciliation():
        rows = payment_reconciliation_overview(app.config["DB_PATH"], 240)
        return render_template("admin/module_table.html", title="Payment Reconciliation", subtitle="Webhook matching and retry status", rows=rows, columns=["id", "invoice_number", "provider_event_id", "provider_status", "amount", "retry_count", "status", "last_attempt_at"])

    @app.route("/admin/explainability-plus")
    @role_required("admin")
    def admin_explainability_plus():
        apps = all_applications(app.config["DB_PATH"], 120)
        rows = []
        for a in apps:
            top = explainability_for_application(a)[:4]
            rows.append(
                {
                    "application_id": a["id"],
                    "status": a["status"],
                    "segment": a.get("borrower_segment", "-"),
                    "top_factors": "; ".join([f"{x['factor']}:{x['impact']:+.2f}" for x in top]),
                }
            )
        return render_template("admin/module_table.html", title="Decision Explainability+", subtitle="SHAP-style ranked drivers", rows=rows, columns=["application_id", "status", "segment", "top_factors"])

    @app.route("/admin/scenario-simulator-plus", methods=["GET", "POST"])
    @role_required("admin")
    def admin_scenario_simulator_plus():
        result = None
        if request.method == "POST":
            payload, errors = _validate_application(request.form)
            if errors:
                for err in errors:
                    flash(err)
            else:
                bundle = _model_or_retrain()
                product_code = sanitize_text(request.form.get("whatif_product_code", payload.get("product_code", "STANDARD")), 20)
                policy = get_product_policy_by_code(app.config["DB_PATH"], product_code) or get_product_policy_for_amount(app.config["DB_PATH"], payload["requested_amount"])
                result = scenario_simulation(bundle, payload, policy)
        return render_template("admin/scenario_simulator_plus.html", result=result)

    @app.route("/admin/partner-onboarding", methods=["GET", "POST"])
    @role_required("admin")
    def admin_partner_onboarding():
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("admin_partner_onboarding"))
            action = sanitize_text(request.form.get("action", ""), 20)
            client = sanitize_text(request.form.get("client_name", "default-partner"), 40)
            if action == "rotate":
                key = rotate_client_api_key(app.config["DB_PATH"], client)
                flash(f"API key rotated for {client}: {key}")
            elif action == "policy":
                ip_allowlist = sanitize_text(request.form.get("ip_allowlist", "127.0.0.1"), 180)
                rate_limit = int(request.form.get("rate_limit_per_min", 120))
                quota = int(request.form.get("quota_per_day", 3000))
                upsert_partner_policy(app.config["DB_PATH"], client, ip_allowlist, rate_limit, quota)
                flash(f"Partner policy updated for {client}.")
        data = partner_overview(app.config["DB_PATH"])
        return render_template("admin/partner_onboarding.html", clients=data["clients"], policies=data["policies"])

    @app.route("/admin/compliance-module", methods=["GET", "POST"])
    @role_required("admin")
    def admin_compliance_module():
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("admin_compliance_module"))
            event_type = sanitize_text(request.form.get("event_type", "EXPORT_REQUEST"), 40)
            target_user = int(request.form.get("target_user_id", session["user_id"]))
            payload = sanitize_text(request.form.get("payload", "{}"), 220)
            create_compliance_event(app.config["DB_PATH"], target_user, event_type, payload, "OPEN")
            flash("Compliance event recorded.")
        data = compliance_overview(app.config["DB_PATH"])
        return render_template("admin/compliance_module.html", policies=data["policies"], events=data["events"], consents=data["consents"])

    @app.route("/admin/fraud-graph")
    @role_required("admin")
    def admin_fraud_graph():
        rows = fraud_graph_overview(app.config["DB_PATH"], 260)
        return render_template("admin/fraud_graph.html", rows=rows)

    @app.route("/admin/fraud-graph/rebuild", methods=["POST"])
    @role_required("admin")
    def admin_fraud_graph_rebuild():
        if not verify_csrf(request.form.get("csrf_token", "")):
            flash("Invalid security token.")
            return redirect(url_for("admin_fraud_graph"))
        res = rebuild_fraud_graph(app.config["DB_PATH"])
        append_chain(app.config["DB_PATH"], None, session["user_id"], "FRAUD_GRAPH_REBUILD", f"links={res['links']}")
        flash(f"Fraud graph rebuilt with {res['links']} links.")
        return redirect(url_for("admin_fraud_graph"))

    @app.route("/admin/sso-mfa", methods=["GET", "POST"])
    @role_required("admin")
    def admin_sso_mfa():
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("admin_sso_mfa"))
            action = sanitize_text(request.form.get("action", ""), 20)
            if action == "sso":
                provider = sanitize_text(request.form.get("provider_name", "Google"), 20)
                client_id = sanitize_text(request.form.get("client_id", "set-client-id"), 120)
                enabled = request.form.get("enabled") == "on"
                set_sso_provider(app.config["DB_PATH"], provider, client_id, enabled)
                flash(f"SSO provider {provider} updated.")
            elif action == "mfa":
                uid = int(request.form.get("user_id", session["user_id"]))
                secret = sanitize_text(request.form.get("secret", uuid.uuid4().hex[:8]), 20)
                upsert_mfa_secret(app.config["DB_PATH"], uid, secret)
                flash(f"MFA secret set for user #{uid}.")
            elif action == "verify":
                uid = int(request.form.get("user_id", session["user_id"]))
                secret = sanitize_text(request.form.get("secret", ""), 20)
                ok = verify_mfa_secret(app.config["DB_PATH"], uid, secret)
                flash("MFA verification succeeded." if ok else "MFA verification failed.")
        data = sso_mfa_overview(app.config["DB_PATH"])
        return render_template("admin/sso_mfa.html", providers=data["providers"], mfa=data["mfa"])

    @app.route("/admin/notification-orchestration", methods=["GET", "POST"])
    @role_required("admin")
    def admin_notification_orchestration():
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("admin_notification_orchestration"))
            action = sanitize_text(request.form.get("action", ""), 20)
            if action == "template":
                key = sanitize_text(request.form.get("template_key", ""), 40)
                channel = sanitize_text(request.form.get("channel", "email"), 12)
                subject = sanitize_text(request.form.get("subject_template", ""), 120)
                body = sanitize_text(request.form.get("body_template", ""), 220)
                if key:
                    upsert_notification_template(app.config["DB_PATH"], key, channel, subject or key, body or subject or key)
                    flash(f"Template {key} saved.")
            elif action == "campaign":
                campaign_name = sanitize_text(request.form.get("campaign_name", "Campaign"), 60)
                template_key = sanitize_text(request.form.get("template_key", "DUE_REMINDER"), 40)
                audience_rule = sanitize_text(request.form.get("audience_rule", "status=Manual Review"), 120)
                scheduled_for = sanitize_text(request.form.get("scheduled_for", utcnow()), 40)
                create_notification_campaign(app.config["DB_PATH"], campaign_name, template_key, audience_rule, scheduled_for)
                flash(f"Campaign {campaign_name} scheduled.")
        data = notification_orchestration_overview(app.config["DB_PATH"])
        return render_template("admin/notification_orchestration.html", templates=data["templates"], campaigns=data["campaigns"], metrics=data["metrics"])

    @app.route("/admin/warehouse-export", methods=["GET", "POST"])
    @role_required("admin")
    def admin_warehouse_export():
        if request.method == "POST":
            if not verify_csrf(request.form.get("csrf_token", "")):
                flash("Invalid security token.")
                return redirect(url_for("admin_warehouse_export"))
            target = sanitize_text(request.form.get("target_system", "BigQuery"), 20)
            export_type = sanitize_text(request.form.get("export_type", "loan_applications"), 30)
            export_dir = os.path.join(os.getcwd(), "exports")
            out = run_warehouse_export(app.config["DB_PATH"], export_dir, export_type, target)
            flash(f"Export generated: {out['file_path']}")
        rows = warehouse_exports_overview(app.config["DB_PATH"], 180)
        return render_template("admin/module_table.html", title="Data Warehouse Export", subtitle="Scheduled/snapshot exports for analytics platforms", rows=rows, columns=["id", "export_type", "target_system", "file_path", "status", "created_at"])

    @app.route("/admin/observability")
    @role_required("admin")
    def admin_observability():
        data = observability_overview(app.config["DB_PATH"], 240)
        return render_template("admin/observability.html", by_severity=data["by_severity"], recent=data["recent"])

    @app.route("/admin/mobile-pwa")
    @role_required("admin")
    def admin_mobile_pwa():
        cards = [
            {"rule_name": "Installability", "value": "Manifest + service worker enabled"},
            {"rule_name": "Borrower Features", "value": "Docs upload placeholder, repayment tracking, support chat entry"},
            {"rule_name": "Entry URL", "value": "/user/mobile"},
        ]
        return render_template("admin/module_cards.html", title="Mobile-first Borrower PWA", subtitle="Progressive web app rollout status", items=cards)

    @app.route("/user/mobile")
    @access_level_required("end_user")
    def user_mobile():
        apps = user_applications(app.config["DB_PATH"], session["user_id"], 10)
        return render_template("user/mobile.html", apps=apps)

    @app.route("/user/profile")
    @access_level_required("end_user")
    def user_profile():
        with get_conn(app.config["DB_PATH"]) as conn:
            user = conn.execute(
                """
                SELECT id, username, full_name, region, email, phone,
                       email_verified_at, phone_verified_at, created_at, last_login_at
                FROM users WHERE id = ?
                """,
                (session["user_id"],),
            ).fetchone()
        apps = user_applications(app.config["DB_PATH"], session["user_id"], 200)
        return render_template("user/profile.html", user=user, app_count=len(apps))

    @app.route("/user/simulator", methods=["GET", "POST"])
    @access_level_required("end_user")
    def user_simulator():
        result = None
        repayment = None
        if request.method == "POST":
            payload, errors = _validate_application(request.form)
            if errors:
                for e in errors:
                    flash(e)
            else:
                bundle = _model_or_retrain()
                result = ml.infer(bundle, payload)
                prepayment_amount = float(request.form.get("prepayment_amount", 0) or 0)
                prepayment_month = int(request.form.get("prepayment_month", 0) or 0)
                refinance_rate = request.form.get("refinance_rate", "").strip()
                refinance_rate_val = (float(refinance_rate) / 100.0) if refinance_rate else None
                repayment = repayment_projection(
                    principal=float(payload["requested_amount"]),
                    annual_rate=float(result["interest_rate"]),
                    term_months=int(payload["loan_term_months"]),
                    prepayment_amount=prepayment_amount,
                    prepayment_month=prepayment_month,
                    refinance_rate=refinance_rate_val,
                )
        return render_template("user/simulator.html", result=result, repayment=repayment)

    @app.route("/user/disbursement-payments")
    @access_level_required("end_user")
    def user_disbursement_payments():
        apps = user_applications(app.config["DB_PATH"], session["user_id"], 100)
        approved = [a for a in apps if a["status"] == "Approved"]
        return render_template("admin/module_table.html", title="Disbursement & Payments", subtitle="Approved applications and estimated payment schedules", rows=approved, columns=["id", "requested_amount", "loan_term_months", "interest_rate", "monthly_payment_est", "status"])

    @app.route("/user/digital-portal")
    @access_level_required("end_user")
    def user_digital_portal():
        offers = [
            {"offer": "Top-up Eligibility", "detail": "Eligible when 6 EMIs are paid on time"},
            {"offer": "Rate Repricing Review", "detail": "Available for AA/AAA profile upgrades"},
            {"offer": "Document Wallet", "detail": "Store reusable KYC and income proofs"},
        ]
        log_engagement_event(
            app.config["DB_PATH"],
            session["user_id"],
            "portal",
            "PORTAL_VISIT",
            json.dumps({"page": "digital-portal"}),
        )
        feed = engagement_feed(app.config["DB_PATH"], 40)
        personal = [e for e in feed if e.get("user_id") == session["user_id"]][:20]
        return render_template("user/digital_portal.html", offers=offers, feed=personal)
