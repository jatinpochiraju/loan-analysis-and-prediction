import os
import tempfile
import hashlib
import json
from importlib import reload

from flask import Flask

import loansuite.config as loansuite_config
from loansuite import ml
from loansuite.db import init_db
from loansuite.routes import _application_status_markdown, _validate_application
from loansuite.services import (
    create_or_get_kyc_case,
    create_application,
    create_or_update_entity_field,
    derive_application_credit_score,
    get_application,
    issue_policy_for_application,
    process_uploaded_document,
    repayment_projection,
    run_extended_underwriting,
    update_kyc_case_profile,
    upload_kyc_case_document,
)
from loansuite.db import get_conn, utcnow


def test_repayment_projection_saves_interest_with_prepayment():
    base = repayment_projection(100000, 0.1, 120, prepayment_amount=0, prepayment_month=0)
    prepay = repayment_projection(100000, 0.1, 120, prepayment_amount=10000, prepayment_month=12)
    assert prepay["interest_saved_est"] >= 0
    assert prepay["months_saved"] >= 0
    assert prepay["with_prepayment_total_interest"] <= base["with_prepayment_total_interest"]


def test_credit_score_is_system_calculated_from_application_profile():
    derived = derive_application_credit_score(
        {
            "current_salary": 540000.0,
            "monthly_expenditure": 18000.0,
            "existing_emi": 0.0,
            "requested_amount": 120000.0,
            "employment_years": 3.0,
            "collateral_value": 0.0,
        }
    )
    assert 300 <= derived["score"] <= 900
    assert derived["factors"]["source"] == "system_calculated"


def test_application_validation_uses_derived_credit_score_when_user_does_not_enter_one():
    payload, errors = _validate_application(
        {
            "product_code": "STANDARD",
            "policy_type": "STANDARD",
            "region": "South",
            "loan_type": "FURNITURE",
            "preferred_currencies": "INR",
            "kyc_id_number": "ABCDE1234F",
            "income_doc_ref": "SALARY_SLIPS_APR_JUN_2026",
            "current_salary": "540000",
            "monthly_expenditure": "18000",
            "existing_emi": "0",
            "requested_amount": "120000",
            "loan_term_months": "36",
            "employment_years": "3",
            "collateral_value": "0",
            "furniture_category": "Living Room",
            "furniture_vendor": "Urban Ladder",
        }
    )
    assert errors == []
    assert 300 <= payload["credit_score"] <= 900
    assert payload["credit_score_source"] == "system_calculated"


def test_process_uploaded_document_extracts_salary_and_region():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        init_db(db_path)
        app_row = {"id": 1, "current_salary": 120000, "region": "North"}
        content = b"Income statement says salary: 120000 and region North."
        row = process_uploaded_document(db_path, app_row, "income.txt", content)
        assert row["application_id"] == 1
        assert row["status"] in {"Clear", "Mismatch"}
        assert float(row["extracted_salary"]) > 0


def test_markdown_export_contains_signature():
    flask_app = Flask(__name__)
    flask_app.config["DATA_KEY"] = "unit-test-key"
    with flask_app.app_context():
        row = {
            "id": 44,
            "created_at": "2026-02-22T00:00:00Z",
            "status": "Approved",
            "tier": "Prime",
            "approval_probability": 0.81,
            "risk_score": 82,
            "region": "West",
            "product_code": "STANDARD",
            "requested_amount": 50000,
            "current_salary": 140000,
            "monthly_expenditure": 2500,
            "existing_emi": 300,
            "loan_term_months": 84,
            "credit_score": 760,
            "employment_years": 7,
            "collateral_value": 30000,
            "monthly_payment_est": 901.3,
            "recommended_amount": 64000,
            "interest_rate": 0.082,
            "decision_factors": "{\"verification_level\":\"Standard\",\"loan_type\":\"CAR\",\"preferred_currencies\":[\"USD\",\"INR\"]}",
        }
        md = _application_status_markdown(row)
        assert "Loan Application Filing & Approval Status" in md
        assert "Export Signature" in md


def test_policy_and_application_datetime_fields_are_populated():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        init_db(db_path)
        with get_conn(db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (username, full_name, password_hash, role, region, created_at)
                VALUES ('u1', 'User One', 'hash', 'user', 'North', ?)
                """,
                (utcnow(),),
            )
            conn.commit()
            user = conn.execute("SELECT id FROM users WHERE username='u1'").fetchone()

        payload = {
            "region": "North",
            "product_code": "STANDARD",
            "policy_type": "STANDARD",
            "current_salary": 100000.0,
            "monthly_expenditure": 2000.0,
            "existing_emi": 500.0,
            "requested_amount": 50000.0,
            "loan_term_months": 60,
            "employment_years": 5.0,
            "credit_score": 720,
            "collateral_value": 20000.0,
        }
        decision = {
            "risk_score": 80,
            "approval_probability": 0.82,
            "status": "Approved",
            "tier": "Prime",
            "interest_rate": 0.08,
            "monthly_payment_est": 1014.0,
            "recommended_amount": 52000.0,
            "model_version": "vtest",
            "decision_factors": "{}",
        }
        app_id = create_application(db_path, payload, decision, user["id"])
        app_row = get_application(db_path, app_id)
        assert app_row["application_request_datetime"]
        assert app_row["application_request_createdtime"]

        policy = issue_policy_for_application(db_path, app_row)
        assert policy is not None
        assert policy["policy_creation_datetime"]
        assert policy["policy_creation_createdtime"]


def test_high_value_application_requires_admin_review_even_if_score_is_prime():
    with tempfile.TemporaryDirectory() as td:
        bundle = ml.train_model([], td, "vtest")
        payload = {
            "region": "West",
            "product_code": "PLUS",
            "policy_type": "FAMILY",
            "current_salary": 1800000.0,
            "monthly_expenditure": 15000.0,
            "existing_emi": 0.0,
            "requested_amount": 250000.0,
            "loan_term_months": 36,
            "employment_years": 9.0,
            "credit_score": 825,
            "collateral_value": 100000.0,
        }
        decision = ml.infer(bundle, payload)
        factors = json.loads(decision["decision_factors"])

        assert decision["status"] == "Manual Review"
        assert factors["approval_route"] == "admin_review"
        assert factors["auto_approval_max_amount"] == 150000.0


def test_rejected_application_returns_lower_amount_suggestion():
    with tempfile.TemporaryDirectory() as td:
        bundle = ml.train_model([], td, "vtest")
        payload = {
            "region": "West",
            "product_code": "STANDARD",
            "policy_type": "STANDARD",
            "current_salary": 240000.0,
            "monthly_expenditure": 18000.0,
            "existing_emi": 6000.0,
            "requested_amount": 320000.0,
            "loan_term_months": 24,
            "employment_years": 1.0,
            "credit_score": 560,
            "collateral_value": 0.0,
        }
        decision = ml.infer(bundle, payload)
        factors = json.loads(decision["decision_factors"])

        assert decision["status"] == "Rejected"
        assert float(decision["recommended_amount"]) < float(payload["requested_amount"])
        assert float(factors["lower_apply_amount"]) == float(decision["recommended_amount"])
        assert "reapply" in factors["recommendation_note"].lower()


def test_entity_extension_supports_eix_etx_and_relationship_metadata():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        init_db(db_path)
        with get_conn(db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (username, full_name, password_hash, role, region, created_at)
                VALUES ('admin1', 'Admin One', 'hash', 'admin', 'Central', ?)
                """,
                (utcnow(),),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO entity_definitions (name, supertype, subtype, description, created_by, created_at)
                VALUES ('PolicySelectionRequest', 'PolicyPeriod', 'PolicySelectionRequestExt', 'seed', 1, ?)
                """,
                (utcnow(),),
            )
            conn.commit()

        create_or_update_entity_field(
            db_path=db_path,
            entity_name="PolicySelectionRequest",
            field_name="policyTypeRef",
            field_type="entity_ref",
            extension_type="ETX",
            relation_type="foreign_key",
            related_entity="PolicyTypeCatalog",
            foreign_key_field="policy_type_id",
            is_array=False,
            is_circular=False,
            nullable=False,
            typelist_name=None,
            description="FK relationship to policy type catalog",
            created_by=1,
        )
        with get_conn(db_path) as conn:
            row = conn.execute(
                """
                SELECT extension_type, relation_type, related_entity, foreign_key_field
                FROM entity_fields
                WHERE entity_name='PolicySelectionRequest' AND field_name='policyTypeRef'
                """
            ).fetchone()
        assert row["extension_type"] == "ETX"
        assert row["relation_type"] == "foreign_key"
        assert row["related_entity"] == "PolicyTypeCatalog"
        assert row["foreign_key_field"] == "policy_type_id"


def test_kyc_case_document_pipeline_and_underwriting_extension():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        init_db(db_path)
        with get_conn(db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (username, full_name, password_hash, role, access_level, region, email, phone, created_at)
                VALUES ('borrower1', 'Borrower One', 'hash', 'user', 'end_user', 'North', 'borrower1@example.com', '+911234567890', ?)
                """,
                (utcnow(),),
            )
            conn.commit()
            user = conn.execute("SELECT id FROM users WHERE username='borrower1'").fetchone()

        case_row = create_or_get_kyc_case(db_path, user["id"])
        case_row = update_kyc_case_profile(
            db_path,
            case_row["id"],
            {
                "full_name": "Borrower One",
                "email": "borrower1@example.com",
                "phone": "+911234567890",
                "pan_number": "ABCDE1234F",
                "aadhaar_last4": "4321",
                "company_name": "Acme Finance Ltd",
                "designation": "Analyst",
                "years_of_experience": 3.0,
                "monthly_salary": 60000,
                "requested_loan": 500000,
                "existing_emi": 5000,
            },
            3,
        )
        doc_content = (
            b"Employee: Borrower One\nCompany: Acme Finance Ltd\nGross Salary: 60000\n"
            b"Net Salary: 53400\nJoining Date: 01-04-2023\nSalary Credit: 60000\nSalary Credit: 60000\nSalary Credit: 60000\n"
        )
        doc = upload_kyc_case_document(db_path, case_row["id"], "Salary Slip 1", "slip1.txt", doc_content)
        review = run_extended_underwriting(db_path, case_row["id"])

        assert doc["status"] in {"verified", "manual_review"}
        assert float(doc["verification_score"]) >= 70
        assert review["case_id"] == case_row["id"]
        assert float(review["safe_loan_amount"]) > 0
        assert review["approval_status"] in {"approved", "manual_review", "rejected"}


def test_new_kyc_and_underwriting_dashboards_render_for_logged_in_users():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        model_dir = os.path.join(td, "model_store")
        old_db = os.environ.get("LOAN_DB_PATH")
        old_model_dir = os.environ.get("LOAN_MODEL_DIR")
        try:
            os.environ["LOAN_DB_PATH"] = db_path
            os.environ["LOAN_MODEL_DIR"] = model_dir
            reload(loansuite_config)
            import loansuite
            import loanshield

            reload(loansuite)
            reload(loanshield)
            app = loanshield.create_app()
            app.config["TESTING"] = True

            with get_conn(db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, full_name, password_hash, role, access_level, region, email, phone, created_at)
                    VALUES ('userx', 'User X', 'hash', 'user', 'end_user', 'North', 'userx@example.com', '+911111111111', ?)
                    """,
                    (utcnow(),),
                )
                conn.commit()
                user = conn.execute("SELECT id FROM users WHERE username='userx'").fetchone()
                admin = conn.execute("SELECT id FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1").fetchone()

            client = app.test_client()
            with client.session_transaction() as sess:
                sess["user_id"] = user["id"]
                sess["username"] = "userx"
                sess["role"] = "user"
                sess["access_level"] = "end_user"
            resp = client.get("/user/kyc-onboarding")
            assert resp.status_code == 200
            assert b"Mock KYC + Document Journey" in resp.data

            with client.session_transaction() as sess:
                sess["user_id"] = admin["id"]
                sess["username"] = "admin"
                sess["role"] = "admin"
                sess["access_level"] = "admin"
            resp = client.get("/admin/kyc-dashboard")
            assert resp.status_code == 200
            assert b"KYC Dashboard" in resp.data
            resp = client.get("/admin/underwriting-dashboard")
            assert resp.status_code == 200
            assert b"Underwriting Dashboard" in resp.data
        finally:
            if old_db is None:
                os.environ.pop("LOAN_DB_PATH", None)
            else:
                os.environ["LOAN_DB_PATH"] = old_db
            if old_model_dir is None:
                os.environ.pop("LOAN_MODEL_DIR", None)
            else:
                os.environ["LOAN_MODEL_DIR"] = old_model_dir


def test_register_verify_accepts_email_only_otp():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        model_dir = os.path.join(td, "model_store")
        old_db = os.environ.get("LOAN_DB_PATH")
        old_model_dir = os.environ.get("LOAN_MODEL_DIR")
        try:
            os.environ["LOAN_DB_PATH"] = db_path
            os.environ["LOAN_MODEL_DIR"] = model_dir
            reload(loansuite_config)
            import loansuite
            import loanshield

            reload(loansuite)
            reload(loanshield)
            app = loanshield.create_app()
            app.config["TESTING"] = True

            secret = app.config["DATA_KEY"]
            username = "otpuser"
            email_code = "123456"
            email_hash = hashlib.sha256(f"{secret}|{username}|email|{email_code}".encode("utf-8")).hexdigest()
            with get_conn(db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO signup_2fa_challenges (
                        username, full_name, password_hash, region, email, phone,
                        email_otp_hash, phone_otp_hash, expires_at, attempts, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                    """,
                    (
                        username,
                        "OTP User",
                        "hash",
                        "North",
                        "otp@example.com",
                        "+911234567890",
                        email_hash,
                        "",
                        "2099-01-01T00:00:00Z",
                        utcnow(),
                    ),
                )
                conn.commit()

            client = app.test_client()
            with client.session_transaction() as sess:
                sess["signup_2fa_username"] = username
                sess["csrf_token"] = "test-csrf"
            resp = client.post(
                "/register/verify",
                data={"csrf_token": "test-csrf", "username": username, "email_code": email_code},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            with get_conn(db_path) as conn:
                user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            assert user is not None
            assert user["email_verified_at"]
            assert not user["phone_verified_at"]
        finally:
            if old_db is None:
                os.environ.pop("LOAN_DB_PATH", None)
            else:
                os.environ["LOAN_DB_PATH"] = old_db
            if old_model_dir is None:
                os.environ.pop("LOAN_MODEL_DIR", None)
            else:
                os.environ["LOAN_MODEL_DIR"] = old_model_dir


def test_user_login_requires_email_otp(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        model_dir = os.path.join(td, "model_store")
        old_db = os.environ.get("LOAN_DB_PATH")
        old_model_dir = os.environ.get("LOAN_MODEL_DIR")
        try:
            os.environ["LOAN_DB_PATH"] = db_path
            os.environ["LOAN_MODEL_DIR"] = model_dir
            reload(loansuite_config)
            import loansuite
            import loanshield
            import loansuite.routes as route_mod

            reload(loansuite)
            reload(route_mod)
            reload(loanshield)
            app = loanshield.create_app()
            app.config["TESTING"] = True

            sent = {}

            def fake_send_email(recipient, subject, message):
                sent["recipient"] = recipient
                sent["subject"] = subject
                sent["message"] = message
                return {"ok": True, "provider": "smtp"}

            monkeypatch.setattr(route_mod, "send_email", fake_send_email)

            with get_conn(db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO users (
                        username, full_name, password_hash, role, access_level, region, email, phone,
                        email_verified_at, created_at
                    ) VALUES (?, ?, ?, 'user', 'end_user', ?, ?, ?, ?, ?)
                    """,
                    (
                        "loginuser",
                        "Login User",
                        route_mod.password_hash("Secret123!"),
                        "South",
                        "loginuser@example.com",
                        "+911234567890",
                        utcnow(),
                        utcnow(),
                    ),
                )
                conn.commit()

            client = app.test_client()
            with client.session_transaction() as sess:
                sess["csrf_token"] = "test-csrf"
            resp = client.post(
                "/login",
                data={"csrf_token": "test-csrf", "username": "loginuser", "password": "Secret123!"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert resp.headers["Location"].endswith("/login/verify")
            assert sent["recipient"] == "loginuser@example.com"

            secret = app.config["DATA_KEY"]
            otp_code = sent["message"].split(" is ")[1].split(".")[0]
            assert len(otp_code) == 6
            with client.session_transaction() as sess:
                sess["csrf_token"] = "verify-csrf"
            resp = client.post(
                "/login/verify",
                data={"csrf_token": "verify-csrf", "username": "loginuser", "email_code": otp_code},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert resp.headers["Location"].endswith("/user/dashboard")
            with client.session_transaction() as sess:
                assert sess["username"] == "loginuser"
                assert sess["user_id"] > 0
        finally:
            if old_db is None:
                os.environ.pop("LOAN_DB_PATH", None)
            else:
                os.environ["LOAN_DB_PATH"] = old_db
            if old_model_dir is None:
                os.environ.pop("LOAN_MODEL_DIR", None)
            else:
                os.environ["LOAN_MODEL_DIR"] = old_model_dir


def test_admin_can_record_underwriter_remark():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        model_dir = os.path.join(td, "model_store")
        old_db = os.environ.get("LOAN_DB_PATH")
        old_model_dir = os.environ.get("LOAN_MODEL_DIR")
        try:
            os.environ["LOAN_DB_PATH"] = db_path
            os.environ["LOAN_MODEL_DIR"] = model_dir
            reload(loansuite_config)
            import loansuite
            import loanshield

            reload(loansuite)
            reload(loanshield)
            app = loanshield.create_app()
            app.config["TESTING"] = True
            with get_conn(db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, full_name, password_hash, role, access_level, region, email, phone, created_at)
                    VALUES ('uwuser', 'UW User', 'hash', 'user', 'end_user', 'North', 'uw@example.com', '+911234500000', ?)
                    """,
                    (utcnow(),),
                )
                conn.commit()
                user = conn.execute("SELECT id FROM users WHERE username='uwuser'").fetchone()
                admin = conn.execute("SELECT id FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1").fetchone()
            case_row = create_or_get_kyc_case(db_path, user["id"])
            case_row = update_kyc_case_profile(
                db_path,
                case_row["id"],
                {
                    "full_name": "UW User",
                    "email": "uw@example.com",
                    "phone": "+911234500000",
                    "pan_number": "ABCDE4321F",
                    "aadhaar_last4": "1234",
                    "company_name": "Remark Corp",
                    "designation": "Lead",
                    "years_of_experience": 4,
                    "monthly_salary": 70000,
                    "requested_loan": 600000,
                    "existing_emi": 8000,
                },
                3,
            )
            run_extended_underwriting(db_path, case_row["id"])

            client = app.test_client()
            with client.session_transaction() as sess:
                sess["user_id"] = admin["id"]
                sess["username"] = "admin"
                sess["role"] = "admin"
                sess["access_level"] = "admin"
                sess["csrf_token"] = "test-csrf"
            resp = client.post(
                f"/admin/underwriting-case/{case_row['id']}/remark",
                data={"csrf_token": "test-csrf", "remark": "Need fraud review", "escalate": "yes"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            with get_conn(db_path) as conn:
                audit = conn.execute(
                    "SELECT * FROM decision_audit_ext WHERE case_id = ? ORDER BY id DESC LIMIT 1",
                    (case_row["id"],),
                ).fetchone()
            assert audit is not None
            assert audit["action"] == "UNDERWRITER_REMARK"
            assert "Need fraud review" in (audit["remarks"] or "")
        finally:
            if old_db is None:
                os.environ.pop("LOAN_DB_PATH", None)
            else:
                os.environ["LOAN_DB_PATH"] = old_db
            if old_model_dir is None:
                os.environ.pop("LOAN_MODEL_DIR", None)
            else:
                os.environ["LOAN_MODEL_DIR"] = old_model_dir


def test_user_can_prepare_reapply_with_lower_amount():
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        model_dir = os.path.join(td, "model_store")
        old_db = os.environ.get("LOAN_DB_PATH")
        old_model_dir = os.environ.get("LOAN_MODEL_DIR")
        try:
            os.environ["LOAN_DB_PATH"] = db_path
            os.environ["LOAN_MODEL_DIR"] = model_dir
            reload(loansuite_config)
            import loansuite
            import loanshield

            reload(loansuite)
            reload(loanshield)
            app = loanshield.create_app()
            app.config["TESTING"] = True
            with get_conn(db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, full_name, password_hash, role, access_level, region, email, phone, created_at)
                    VALUES ('reapply', 'Re Apply', 'hash', 'user', 'end_user', 'North', 'reapply@example.com', '+911111122222', ?)
                    """,
                    (utcnow(),),
                )
                conn.commit()
                user = conn.execute("SELECT id FROM users WHERE username='reapply'").fetchone()

            payload = {
                "region": "North",
                "product_code": "STANDARD",
                "policy_type": "STANDARD",
                "current_salary": 100000.0,
                "monthly_expenditure": 2000.0,
                "existing_emi": 500.0,
                "requested_amount": 50000.0,
                "loan_term_months": 60,
                "employment_years": 5.0,
                "credit_score": 720,
                "collateral_value": 20000.0,
            }
            decision = {
                "risk_score": 40,
                "approval_probability": 0.31,
                "status": "Rejected",
                "tier": "High Risk",
                "interest_rate": 0.08,
                "monthly_payment_est": 1014.0,
                "recommended_amount": 32000.0,
                "model_version": "vtest",
                "decision_factors": "{\"loan_type\":\"PERSONAL\"}",
            }
            app_id = create_application(db_path, payload, decision, user["id"])

            client = app.test_client()
            with client.session_transaction() as sess:
                sess["user_id"] = user["id"]
                sess["username"] = "reapply"
                sess["role"] = "user"
                sess["access_level"] = "end_user"
                sess["csrf_token"] = "test-csrf"
            resp = client.post(
                f"/user/application/{app_id}/reapply-lower",
                data={"csrf_token": "test-csrf"},
                follow_redirects=True,
            )
            assert resp.status_code == 200
            assert b"Reapply With Safer Amount" in resp.data or b"lower suggested loan amount has been prefilled" in resp.data
            assert b'value="32000.0"' in resp.data or b'value="32000"' in resp.data
        finally:
            if old_db is None:
                os.environ.pop("LOAN_DB_PATH", None)
            else:
                os.environ["LOAN_DB_PATH"] = old_db
            if old_model_dir is None:
                os.environ.pop("LOAN_MODEL_DIR", None)
            else:
                os.environ["LOAN_MODEL_DIR"] = old_model_dir
