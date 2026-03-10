import os
import tempfile

from flask import Flask

from loansuite.db import init_db
from loansuite.routes import _application_status_markdown
from loansuite.services import (
    create_application,
    create_or_update_entity_field,
    get_application,
    issue_policy_for_application,
    process_uploaded_document,
    repayment_projection,
)
from loansuite.db import get_conn, utcnow


def test_repayment_projection_saves_interest_with_prepayment():
    base = repayment_projection(100000, 0.1, 120, prepayment_amount=0, prepayment_month=0)
    prepay = repayment_projection(100000, 0.1, 120, prepayment_amount=10000, prepayment_month=12)
    assert prepay["interest_saved_est"] >= 0
    assert prepay["months_saved"] >= 0
    assert prepay["with_prepayment_total_interest"] <= base["with_prepayment_total_interest"]


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
