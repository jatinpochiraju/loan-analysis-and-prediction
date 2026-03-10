from __future__ import annotations

import datetime as dt
import logging
import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict


def dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


@contextmanager
def get_conn(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = dict_factory
    try:
        yield conn
    finally:
        conn.close()


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row["name"] for row in rows}


def ensure_table_shape(conn: sqlite3.Connection, table: str, required_cols: set[str]):
    existing = table_columns(conn, table)
    if existing and not required_cols.issubset(existing):
        legacy = f"{table}_legacy_{dt.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        conn.execute(f"ALTER TABLE {table} RENAME TO {legacy}")


def ensure_missing_columns(conn: sqlite3.Connection, table: str, column_defs: Dict[str, str]):
    existing = table_columns(conn, table)
    for name, ddl in column_defs.items():
        if name in existing:
            continue
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def init_db(db_path: str):
    with get_conn(db_path) as conn:
        ensure_table_shape(
            conn,
            "users",
            {"id", "username", "full_name", "password_hash", "role", "region", "created_at"},
        )
        ensure_table_shape(
            conn,
            "loan_applications",
            {
                "id",
                "user_id",
                "region",
                "product_code",
                "current_salary",
                "monthly_expenditure",
                "existing_emi",
                "requested_amount",
                "loan_term_months",
                "employment_years",
                "credit_score",
                "collateral_value",
                "risk_score",
                "approval_probability",
                "status",
                "tier",
                "interest_rate",
                "monthly_payment_est",
                "recommended_amount",
                "model_version",
                "decision_factors",
                "created_at",
                "blockchain_hash",
            },
        )
        ensure_table_shape(
            conn,
            "audit_chain",
            {
                "id",
                "application_id",
                "actor_id",
                "event_type",
                "event_payload",
                "payload_digest",
                "block_timestamp",
                "nonce",
                "previous_hash",
                "current_hash",
            },
        )
        ensure_table_shape(
            conn,
            "model_registry",
            {"id", "version", "trained_at", "sample_count", "accuracy", "roc_auc", "features_json", "is_active"},
        )
        ensure_table_shape(
            conn,
            "entity_definitions",
            {"id", "name", "supertype", "subtype", "description", "created_by", "created_at"},
        )
        ensure_table_shape(
            conn,
            "entity_fields",
            {
                "id",
                "entity_name",
                "field_name",
                "field_type",
                "nullable",
                "typelist_name",
                "description",
                "created_by",
                "created_at",
            },
        )
        ensure_table_shape(
            conn,
            "typelists",
            {"id", "name", "description", "created_by", "created_at"},
        )
        ensure_table_shape(
            conn,
            "typelist_entries",
            {"id", "typelist_name", "code", "display_name", "sort_order", "created_by", "created_at"},
        )
        ensure_table_shape(
            conn,
            "loan_products",
            {"id", "code", "name", "min_amount", "max_amount", "base_rate", "description", "is_active", "created_at"},
        )
        ensure_table_shape(
            conn,
            "product_rules",
            {
                "id",
                "product_code",
                "verification_level",
                "required_collateral_ratio",
                "min_credit_score",
                "max_dti",
                "required_documents_json",
                "is_active",
                "created_at",
            },
        )
        ensure_table_shape(
            conn,
            "kyc_documents",
            {"id", "application_id", "doc_type", "doc_hash", "metadata", "created_at"},
        )
        ensure_table_shape(
            conn,
            "servicing_ledger",
            {
                "id",
                "application_id",
                "txn_type",
                "principal_delta",
                "interest_delta",
                "fee_delta",
                "amount",
                "due_date",
                "paid_at",
                "status",
                "notes",
                "created_at",
            },
        )
        ensure_table_shape(
            conn,
            "delinquency_actions",
            {"id", "application_id", "ledger_id", "stage", "message", "created_at"},
        )
        ensure_table_shape(
            conn,
            "auth_security",
            {"user_id", "failed_attempts", "locked_until", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "notification_events",
            {"id", "application_id", "channel", "recipient", "subject", "message", "status", "provider", "created_at"},
        )
        ensure_table_shape(
            conn,
            "chat_messages",
            {"id", "user_id", "role", "message", "response", "blocked", "created_at"},
        )
        ensure_table_shape(
            conn,
            "quotes",
            {"id", "application_id", "product_code", "premium_rate", "quoted_amount", "valid_until", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "policies",
            {"id", "application_id", "policy_number", "product_code", "issued_at", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "claims",
            {"id", "policy_id", "claim_type", "description", "claimed_amount", "status", "opened_at", "closed_at"},
        )
        ensure_table_shape(
            conn,
            "claim_workflow_events",
            {"id", "claim_id", "stage", "notes", "actor_id", "created_at"},
        )
        ensure_table_shape(
            conn,
            "billing_invoices",
            {"id", "application_id", "invoice_number", "amount_due", "due_date", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "agent_commissions",
            {"id", "invoice_id", "agent_name", "commission_rate", "commission_amount", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "engagement_events",
            {"id", "user_id", "channel", "event_type", "metadata", "created_at"},
        )
        ensure_table_shape(
            conn,
            "fraud_signals",
            {"id", "application_id", "score", "risk_band", "signals_json", "created_at"},
        )
        ensure_table_shape(
            conn,
            "integration_clients",
            {"id", "name", "api_key", "is_active", "created_at"},
        )
        ensure_table_shape(
            conn,
            "integration_gateway_logs",
            {"id", "client_name", "endpoint", "request_payload", "response_status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "cloud_runtime_config",
            {"id", "setting_key", "setting_value", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "workflow_tasks",
            {"id", "application_id", "assignee_user_id", "stage", "sla_due_at", "priority", "status", "created_at", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "workflow_escalations",
            {"id", "task_id", "application_id", "escalation_level", "reason", "created_at"},
        )
        ensure_table_shape(
            conn,
            "document_intelligence",
            {"id", "application_id", "ocr_payload", "extracted_salary", "extracted_region", "mismatch_score", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "collection_strategies",
            {"id", "name", "min_days_overdue", "max_days_overdue", "reminder_cadence_days", "settlement_discount_pct", "hardship_enabled", "is_active", "created_at"},
        )
        ensure_table_shape(
            conn,
            "collection_actions",
            {"id", "application_id", "ledger_id", "strategy_name", "action_type", "action_payload", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "payment_reconciliation",
            {"id", "invoice_id", "provider_event_id", "provider_status", "amount", "retry_count", "status", "last_attempt_at", "created_at"},
        )
        ensure_table_shape(
            conn,
            "partner_policies",
            {"id", "client_name", "ip_allowlist", "rate_limit_per_min", "quota_per_day", "created_at", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "consent_records",
            {"id", "user_id", "consent_type", "consent_value", "recorded_at"},
        )
        ensure_table_shape(
            conn,
            "retention_policies",
            {"id", "data_type", "retention_days", "is_active", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "compliance_events",
            {"id", "user_id", "event_type", "payload", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "fraud_graph_edges",
            {"id", "application_id_a", "application_id_b", "link_type", "weight", "created_at"},
        )
        ensure_table_shape(
            conn,
            "sso_providers",
            {"id", "provider_name", "client_id", "enabled", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "mfa_secrets",
            {"user_id", "secret", "last_verified_at", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "notification_templates",
            {"id", "template_key", "channel", "subject_template", "body_template", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "notification_campaigns",
            {"id", "campaign_name", "template_key", "audience_rule", "scheduled_for", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "notification_delivery_metrics",
            {"id", "campaign_id", "delivered", "failed", "opened", "clicked", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "warehouse_exports",
            {"id", "export_type", "target_system", "file_path", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "observability_events",
            {"id", "component", "severity", "message", "metadata", "created_at"},
        )
        ensure_table_shape(
            conn,
            "policy_docs",
            {"id", "doc_key", "title", "content", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "policy_jobs",
            {"id", "application_id", "job_type", "state", "effective_date", "expiration_date", "version_no", "created_by", "created_at", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "policy_versions",
            {"id", "job_id", "version_no", "rate_total", "premium_total", "quote_payload", "is_bound", "created_at"},
        )
        ensure_table_shape(
            conn,
            "rating_factors",
            {"id", "product_code", "factor_key", "factor_value", "weight", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "assignment_rules",
            {"id", "stage", "min_risk_score", "max_risk_score", "target_user_id", "priority", "is_active", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "party_contacts",
            {"id", "application_id", "party_role", "full_name", "email", "phone", "identifier", "created_at"},
        )
        ensure_table_shape(
            conn,
            "correspondence_templates_ext",
            {"id", "template_code", "channel", "subject", "body", "version_no", "is_active", "updated_at"},
        )
        ensure_table_shape(
            conn,
            "correspondence_events_ext",
            {"id", "application_id", "template_code", "channel", "recipient", "payload", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "config_releases",
            {"id", "release_name", "release_type", "notes", "published_by", "published_at"},
        )
        ensure_table_shape(
            conn,
            "integration_event_stream",
            {"id", "event_type", "source", "payload", "idempotency_key", "status", "created_at"},
        )
        ensure_table_shape(
            conn,
            "signup_2fa_challenges",
            {
                "id",
                "username",
                "full_name",
                "password_hash",
                "region",
                "email",
                "phone",
                "email_otp_hash",
                "phone_otp_hash",
                "expires_at",
                "attempts",
                "created_at",
            },
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
                access_level TEXT NOT NULL DEFAULT 'end_user',
                region TEXT,
                email TEXT,
                phone TEXT,
                email_verified_at TEXT,
                phone_verified_at TEXT,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signup_2fa_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                region TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                email_otp_hash TEXT NOT NULL,
                phone_otp_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS loan_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                region TEXT NOT NULL,
                product_code TEXT NOT NULL,
                policy_type TEXT NOT NULL DEFAULT 'STANDARD',
                current_salary REAL NOT NULL,
                monthly_expenditure REAL NOT NULL,
                existing_emi REAL NOT NULL,
                requested_amount REAL NOT NULL,
                loan_term_months INTEGER NOT NULL,
                employment_years REAL NOT NULL,
                credit_score INTEGER NOT NULL,
                collateral_value REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                approval_probability REAL NOT NULL,
                status TEXT NOT NULL,
                tier TEXT NOT NULL,
                interest_rate REAL NOT NULL,
                monthly_payment_est REAL NOT NULL,
                recommended_amount REAL NOT NULL,
                model_version TEXT NOT NULL,
                decision_factors TEXT NOT NULL,
                application_request_datetime TEXT NOT NULL,
                application_request_createdtime TEXT NOT NULL,
                created_at TEXT NOT NULL,
                blockchain_hash TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER,
                actor_id INTEGER,
                event_type TEXT NOT NULL,
                event_payload TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                block_timestamp TEXT NOT NULL,
                nonce TEXT NOT NULL,
                previous_hash TEXT,
                current_hash TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id),
                FOREIGN KEY(actor_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS model_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL,
                trained_at TEXT NOT NULL,
                sample_count INTEGER NOT NULL,
                accuracy REAL NOT NULL,
                roc_auc REAL NOT NULL,
                features_json TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entity_definitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                supertype TEXT,
                subtype TEXT,
                description TEXT,
                created_by INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entity_fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_name TEXT NOT NULL,
                field_name TEXT NOT NULL,
                field_type TEXT NOT NULL,
                extension_type TEXT NOT NULL DEFAULT 'EIX',
                relation_type TEXT NOT NULL DEFAULT 'none',
                related_entity TEXT,
                foreign_key_field TEXT,
                is_array INTEGER NOT NULL DEFAULT 0,
                is_circular INTEGER NOT NULL DEFAULT 0,
                nullable INTEGER NOT NULL DEFAULT 1,
                typelist_name TEXT,
                description TEXT,
                created_by INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY(created_by) REFERENCES users(id),
                UNIQUE(entity_name, field_name)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS typelists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                created_by INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS typelist_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                typelist_name TEXT NOT NULL,
                code TEXT NOT NULL,
                display_name TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_by INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY(created_by) REFERENCES users(id),
                UNIQUE(typelist_name, code)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS loan_products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                policy_type TEXT NOT NULL DEFAULT 'STANDARD',
                min_amount REAL NOT NULL,
                max_amount REAL NOT NULL,
                base_rate REAL NOT NULL,
                description TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS product_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_code TEXT NOT NULL,
                verification_level TEXT NOT NULL,
                required_collateral_ratio REAL NOT NULL DEFAULT 0,
                min_credit_score INTEGER NOT NULL DEFAULT 300,
                max_dti REAL NOT NULL DEFAULT 0.75,
                required_documents_json TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                FOREIGN KEY(product_code) REFERENCES loan_products(code)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kyc_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                doc_type TEXT NOT NULL,
                doc_hash TEXT NOT NULL,
                metadata TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS servicing_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                txn_type TEXT NOT NULL,
                principal_delta REAL NOT NULL DEFAULT 0,
                interest_delta REAL NOT NULL DEFAULT 0,
                fee_delta REAL NOT NULL DEFAULT 0,
                amount REAL NOT NULL DEFAULT 0,
                due_date TEXT,
                paid_at TEXT,
                status TEXT NOT NULL,
                notes TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS delinquency_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                ledger_id INTEGER NOT NULL,
                stage TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id),
                FOREIGN KEY(ledger_id) REFERENCES servicing_ledger(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_security (
                user_id INTEGER PRIMARY KEY,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER,
                channel TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT,
                message TEXT NOT NULL,
                status TEXT NOT NULL,
                provider TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                role TEXT NOT NULL,
                message TEXT NOT NULL,
                response TEXT,
                blocked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS quotes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                product_code TEXT NOT NULL,
                premium_rate REAL NOT NULL,
                quoted_amount REAL NOT NULL,
                valid_until TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                policy_number TEXT UNIQUE NOT NULL,
                product_code TEXT NOT NULL,
                policy_type TEXT NOT NULL DEFAULT 'STANDARD',
                issued_at TEXT,
                policy_creation_datetime TEXT NOT NULL,
                policy_creation_createdtime TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_id INTEGER NOT NULL,
                claim_type TEXT NOT NULL,
                description TEXT NOT NULL,
                claimed_amount REAL NOT NULL,
                status TEXT NOT NULL,
                opened_at TEXT NOT NULL,
                closed_at TEXT,
                FOREIGN KEY(policy_id) REFERENCES policies(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS claim_workflow_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_id INTEGER NOT NULL,
                stage TEXT NOT NULL,
                notes TEXT NOT NULL,
                actor_id INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY(claim_id) REFERENCES claims(id),
                FOREIGN KEY(actor_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                invoice_number TEXT UNIQUE NOT NULL,
                amount_due REAL NOT NULL,
                due_date TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_commissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id INTEGER NOT NULL,
                agent_name TEXT NOT NULL,
                commission_rate REAL NOT NULL,
                commission_amount REAL NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(invoice_id) REFERENCES billing_invoices(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS engagement_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                channel TEXT NOT NULL,
                event_type TEXT NOT NULL,
                metadata TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fraud_signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                score REAL NOT NULL,
                risk_band TEXT NOT NULL,
                signals_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integration_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                api_key TEXT UNIQUE NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integration_gateway_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                request_payload TEXT NOT NULL,
                response_status INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cloud_runtime_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workflow_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                assignee_user_id INTEGER,
                stage TEXT NOT NULL,
                sla_due_at TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id),
                FOREIGN KEY(assignee_user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workflow_escalations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                application_id INTEGER NOT NULL,
                escalation_level INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES workflow_tasks(id),
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS document_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                ocr_payload TEXT NOT NULL,
                extracted_salary REAL,
                extracted_region TEXT,
                mismatch_score REAL NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS collection_strategies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                min_days_overdue INTEGER NOT NULL,
                max_days_overdue INTEGER NOT NULL,
                reminder_cadence_days INTEGER NOT NULL,
                settlement_discount_pct REAL NOT NULL,
                hardship_enabled INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS collection_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                ledger_id INTEGER,
                strategy_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_payload TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payment_reconciliation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id INTEGER,
                provider_event_id TEXT UNIQUE NOT NULL,
                provider_status TEXT NOT NULL,
                amount REAL NOT NULL,
                retry_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                last_attempt_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(invoice_id) REFERENCES billing_invoices(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS partner_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT UNIQUE NOT NULL,
                ip_allowlist TEXT NOT NULL,
                rate_limit_per_min INTEGER NOT NULL,
                quota_per_day INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(client_name) REFERENCES integration_clients(name)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS consent_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                consent_type TEXT NOT NULL,
                consent_value TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS retention_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_type TEXT UNIQUE NOT NULL,
                retention_days INTEGER NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS compliance_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fraud_graph_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id_a INTEGER NOT NULL,
                application_id_b INTEGER NOT NULL,
                link_type TEXT NOT NULL,
                weight REAL NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id_a) REFERENCES loan_applications(id),
                FOREIGN KEY(application_id_b) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sso_providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_name TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                last_verified_at TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                template_key TEXT UNIQUE NOT NULL,
                channel TEXT NOT NULL,
                subject_template TEXT NOT NULL,
                body_template TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_name TEXT NOT NULL,
                template_key TEXT NOT NULL,
                audience_rule TEXT NOT NULL,
                scheduled_for TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(template_key) REFERENCES notification_templates(template_key)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_delivery_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                opened INTEGER NOT NULL DEFAULT 0,
                clicked INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES notification_campaigns(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS warehouse_exports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                export_type TEXT NOT NULL,
                target_system TEXT NOT NULL,
                file_path TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS observability_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                metadata TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_docs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_key TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                job_type TEXT NOT NULL,
                state TEXT NOT NULL,
                effective_date TEXT NOT NULL,
                expiration_date TEXT,
                version_no INTEGER NOT NULL DEFAULT 1,
                created_by INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id),
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL,
                version_no INTEGER NOT NULL,
                rate_total REAL NOT NULL,
                premium_total REAL NOT NULL,
                quote_payload TEXT NOT NULL,
                is_bound INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(job_id) REFERENCES policy_jobs(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rating_factors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_code TEXT NOT NULL,
                factor_key TEXT NOT NULL,
                factor_value REAL NOT NULL,
                weight REAL NOT NULL DEFAULT 1.0,
                updated_at TEXT NOT NULL,
                UNIQUE(product_code, factor_key)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS assignment_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stage TEXT NOT NULL,
                min_risk_score INTEGER NOT NULL DEFAULT 0,
                max_risk_score INTEGER NOT NULL DEFAULT 99,
                target_user_id INTEGER NOT NULL,
                priority TEXT NOT NULL DEFAULT 'Normal',
                is_active INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(target_user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS party_contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                party_role TEXT NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                identifier TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS correspondence_templates_ext (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                template_code TEXT NOT NULL,
                channel TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                version_no INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS correspondence_events_ext (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER,
                template_code TEXT NOT NULL,
                channel TEXT NOT NULL,
                recipient TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(application_id) REFERENCES loan_applications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS config_releases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_name TEXT NOT NULL,
                release_type TEXT NOT NULL,
                notes TEXT NOT NULL,
                published_by INTEGER,
                published_at TEXT NOT NULL,
                FOREIGN KEY(published_by) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integration_event_stream (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                payload TEXT NOT NULL,
                idempotency_key TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_apps_user ON loan_applications(user_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_apps_status ON loan_applications(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chain_app ON audit_chain(application_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entity_fields ON entity_fields(entity_name, field_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_typelist_entries ON typelist_entries(typelist_name, sort_order)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_products_range ON loan_products(min_amount, max_amount, is_active)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_product ON product_rules(product_code, is_active)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_kyc_app ON kyc_documents(application_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_app ON servicing_ledger(application_id, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_due ON servicing_ledger(due_date, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notify_app ON notification_events(application_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_user ON chat_messages(user_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_quotes_app ON quotes(application_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_policies_app ON policies(application_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_policy ON claims(policy_id, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_invoices_app ON billing_invoices(application_id, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_commissions_invoice ON agent_commissions(invoice_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_engagement_user ON engagement_events(user_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fraud_app ON fraud_signals(application_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_gateway_logs_endpoint ON integration_gateway_logs(endpoint, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_workflow_app ON workflow_tasks(application_id, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_workflow_sla ON workflow_tasks(sla_due_at, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_docintel_app ON document_intelligence(application_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_collection_actions_app ON collection_actions(application_id, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_recon_status ON payment_reconciliation(status, last_attempt_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_consent_user ON consent_records(user_id, recorded_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_compliance_user ON compliance_events(user_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fraud_edges_a ON fraud_graph_edges(application_id_a)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_observe_component ON observability_events(component, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_jobs_app ON policy_jobs(application_id, state)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_versions_job ON policy_versions(job_id, version_no)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rating_factors_product ON rating_factors(product_code)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assignment_rules_stage ON assignment_rules(stage, is_active)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_party_contacts_app ON party_contacts(application_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_tpl_code ON correspondence_templates_ext(template_code, is_active)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_events_app ON correspondence_events_ext(application_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cfg_releases_type ON config_releases(release_type, published_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_stream_time ON integration_event_stream(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_signup_2fa_expires ON signup_2fa_challenges(expires_at)")

        ensure_missing_columns(
            conn,
            "users",
            {
                "access_level": "TEXT NOT NULL DEFAULT 'end_user'",
                "email": "TEXT",
                "phone": "TEXT",
                "email_verified_at": "TEXT",
                "phone_verified_at": "TEXT",
            },
        )
        ensure_missing_columns(
            conn,
            "loan_products",
            {
                "policy_type": "TEXT NOT NULL DEFAULT 'STANDARD'",
            },
        )
        ensure_missing_columns(
            conn,
            "loan_applications",
            {
                "policy_type": "TEXT NOT NULL DEFAULT 'STANDARD'",
                "application_request_datetime": "TEXT NOT NULL DEFAULT ''",
                "application_request_createdtime": "TEXT NOT NULL DEFAULT ''",
            },
        )
        ensure_missing_columns(
            conn,
            "policies",
            {
                "policy_type": "TEXT NOT NULL DEFAULT 'STANDARD'",
                "policy_creation_datetime": "TEXT NOT NULL DEFAULT ''",
                "policy_creation_createdtime": "TEXT NOT NULL DEFAULT ''",
            },
        )
        ensure_missing_columns(
            conn,
            "entity_fields",
            {
                "extension_type": "TEXT NOT NULL DEFAULT 'EIX'",
                "relation_type": "TEXT NOT NULL DEFAULT 'none'",
                "related_entity": "TEXT",
                "foreign_key_field": "TEXT",
                "is_array": "INTEGER NOT NULL DEFAULT 0",
                "is_circular": "INTEGER NOT NULL DEFAULT 0",
            },
        )
        conn.execute(
            """
            UPDATE loan_applications
            SET application_request_datetime = COALESCE(NULLIF(application_request_datetime, ''), created_at),
                application_request_createdtime = COALESCE(NULLIF(application_request_createdtime, ''), created_at),
                policy_type = COALESCE(NULLIF(policy_type, ''), 'STANDARD')
            """
        )
        conn.execute(
            """
            UPDATE policies
            SET policy_creation_datetime = COALESCE(NULLIF(policy_creation_datetime, ''), issued_at, created_at),
                policy_creation_createdtime = COALESCE(NULLIF(policy_creation_createdtime, ''), issued_at, created_at),
                policy_type = COALESCE(NULLIF(policy_type, ''), 'STANDARD')
            """
        )
        conn.execute(
            """
            UPDATE users
            SET access_level = CASE
                WHEN role = 'admin' THEN 'admin'
                ELSE COALESCE(NULLIF(access_level, ''), 'end_user')
            END
            """
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO entity_definitions (name, supertype, subtype, description, created_by, created_at)
            VALUES
                ('PolicyTypeCatalog', 'PolicyPeriod', 'PolicyTypeCatalogExt', 'Policy type catalog with relationships', NULL, ?),
                ('PolicySelectionRequest', 'PolicyTypeCatalog', 'PolicySelectionRequestExt', 'User policy selection request entity', NULL, ?)
            """,
            (utcnow(), utcnow()),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO entity_fields (
                entity_name, field_name, field_type, extension_type, relation_type,
                related_entity, foreign_key_field, is_array, is_circular, nullable,
                typelist_name, description, created_by, created_at
            ) VALUES
                ('PolicySelectionRequest', 'selectedPolicyType', 'string', 'EIX', 'one_to_one', 'PolicyTypeCatalog', 'policy_type_id', 0, 0, 0, NULL, 'One-to-one selected policy type', NULL, ?),
                ('PolicyTypeCatalog', 'requests', 'array', 'ETX', 'one_to_many', 'PolicySelectionRequest', 'policy_type_id', 1, 0, 1, NULL, 'One-to-many policy requests', NULL, ?),
                ('PolicySelectionRequest', 'policyTypeId', 'int', 'EIX', 'foreign_key', 'PolicyTypeCatalog', 'id', 0, 0, 0, NULL, 'Foreign key to policy type catalog', NULL, ?),
                ('PolicyTypeCatalog', 'linkedPolicyTypes', 'array', 'ETX', 'circular', 'PolicyTypeCatalog', 'parent_policy_type_id', 1, 1, 1, NULL, 'Circular relationship among policy types', NULL, ?)
            """,
            (utcnow(), utcnow(), utcnow(), utcnow()),
        )
        conn.commit()


def utcnow() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _cloud_db_url() -> str:
    return os.getenv("CLOUD_DB_URL", "").strip()


def cloud_db_enabled() -> bool:
    return bool(_cloud_db_url())


@contextmanager
def get_cloud_conn():
    dsn = _cloud_db_url()
    if not dsn:
        raise RuntimeError("CLOUD_DB_URL is not configured")
    try:
        import psycopg2  # type: ignore
        from psycopg2.extras import RealDictCursor  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency failure path
        raise RuntimeError("psycopg2-binary is required for cloud database support") from exc

    sslmode = os.getenv("CLOUD_DB_SSLMODE", "require").strip() or "require"
    conn = psycopg2.connect(dsn=dsn, sslmode=sslmode, connect_timeout=5, cursor_factory=RealDictCursor)
    try:
        yield conn
    finally:
        conn.close()


def init_cloud_db():
    if not cloud_db_enabled():
        return
    try:
        with get_cloud_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cloud_loan_applications (
                        local_app_id BIGINT PRIMARY KEY,
                        user_id BIGINT NOT NULL,
                        region TEXT NOT NULL,
                        product_code TEXT NOT NULL,
                        requested_amount DOUBLE PRECISION NOT NULL,
                        status TEXT NOT NULL,
                        tier TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        approval_probability DOUBLE PRECISION NOT NULL,
                        model_version TEXT NOT NULL,
                        decision_factors_json TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL,
                        synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
            conn.commit()
    except Exception as exc:
        logging.getLogger(__name__).warning("Cloud DB init skipped: %s", exc)


def sync_application_to_cloud(record: Dict[str, Any]):
    if not cloud_db_enabled():
        return
    try:
        with get_cloud_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cloud_loan_applications (
                        local_app_id, user_id, region, product_code, requested_amount,
                        status, tier, risk_score, approval_probability, model_version,
                        decision_factors_json, created_at, synced_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (local_app_id) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        region = EXCLUDED.region,
                        product_code = EXCLUDED.product_code,
                        requested_amount = EXCLUDED.requested_amount,
                        status = EXCLUDED.status,
                        tier = EXCLUDED.tier,
                        risk_score = EXCLUDED.risk_score,
                        approval_probability = EXCLUDED.approval_probability,
                        model_version = EXCLUDED.model_version,
                        decision_factors_json = EXCLUDED.decision_factors_json,
                        created_at = EXCLUDED.created_at,
                        synced_at = NOW()
                    """,
                    (
                        int(record["id"]),
                        int(record["user_id"]),
                        str(record["region"]),
                        str(record["product_code"]),
                        float(record["requested_amount"]),
                        str(record["status"]),
                        str(record["tier"]),
                        int(record["risk_score"]),
                        float(record["approval_probability"]),
                        str(record["model_version"]),
                        str(record["decision_factors"]),
                        str(record["created_at"]),
                    ),
                )
            conn.commit()
    except Exception as exc:
        logging.getLogger(__name__).warning("Cloud DB sync failed for application %s: %s", record.get("id"), exc)
