from __future__ import annotations

import os
from datetime import timedelta

from flask import Flask

from .config import Config
from .db import get_conn, init_cloud_db, init_db, utcnow
from .ml import FEATURES, synthetic_historical_data, train_model
from .routes import register_routes
from .security import password_hash
from .services import (
    add_typelist_entry,
    append_chain,
    bootstrap_loan_products,
    bootstrap_suite_defaults,
    create_entity_definition,
    create_or_update_entity_field,
    create_typelist,
    historical_training_rows,
    regenerate_model_code,
    upsert_model_registry,
)


def _load_local_env(project_root: str):
    env_path = os.path.join(project_root, ".env")
    if not os.path.isfile(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


def _seed_admin(app: Flask):
    with get_conn(app.config["DB_PATH"]) as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? AND role = 'admin' LIMIT 1",
            (app.config["ADMIN_USERNAME"],),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET password_hash = ?, full_name = ?, access_level = 'admin' WHERE id = ?",
                (
                    password_hash(app.config["ADMIN_PASSWORD"]),
                    "Platform Administrator",
                    existing["id"],
                ),
            )
            conn.commit()
            return

        conn.execute(
            """
            INSERT INTO users (username, full_name, password_hash, role, region, created_at)
            VALUES (?, ?, ?, 'admin', 'Central', ?)
            """,
            (
                app.config["ADMIN_USERNAME"],
                "Platform Administrator",
                password_hash(app.config["ADMIN_PASSWORD"]),
                utcnow(),
            ),
        )
        conn.execute("UPDATE users SET access_level = 'admin' WHERE username = ? AND role = 'admin'", (app.config["ADMIN_USERNAME"],))
        conn.commit()


def _bootstrap_model(app: Flask):
    os.makedirs(app.config["MODEL_DIR"], exist_ok=True)
    with get_conn(app.config["DB_PATH"]) as conn:
        reg = conn.execute("SELECT id FROM model_registry WHERE is_active = 1 LIMIT 1").fetchone()
        if reg:
            return

    rows = historical_training_rows(app.config["DB_PATH"])
    version = f"v{utcnow().replace(':', '').replace('-', '')}"
    bundle = train_model(rows, app.config["MODEL_DIR"], version)
    upsert_model_registry(
        app.config["DB_PATH"],
        version=bundle.version,
        sample_count=bundle.sample_count,
        accuracy=bundle.accuracy,
        roc_auc=bundle.roc_auc,
        features=FEATURES,
    )
    append_chain(
        app.config["DB_PATH"],
        application_id=None,
        actor_id=None,
        event_type="MODEL_BOOTSTRAP",
        payload=f"version={bundle.version};samples={bundle.sample_count}",
    )


def _bootstrap_datamodel(app: Flask):
    with get_conn(app.config["DB_PATH"]) as conn:
        admin = conn.execute("SELECT id FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1").fetchone()
        actor_id = admin["id"] if admin else None
        existing = conn.execute("SELECT COUNT(*) AS cnt FROM entity_definitions").fetchone()
        if existing and existing["cnt"] > 0:
            return

    actor = actor_id or 1
    create_typelist(app.config["DB_PATH"], "LoanStatusType", "Lifecycle status for loan policy decisions", actor)
    add_typelist_entry(app.config["DB_PATH"], "LoanStatusType", "SUBMITTED", "Submitted", 1, actor)
    add_typelist_entry(app.config["DB_PATH"], "LoanStatusType", "APPROVED", "Approved", 2, actor)
    add_typelist_entry(app.config["DB_PATH"], "LoanStatusType", "REJECTED", "Rejected", 3, actor)
    add_typelist_entry(app.config["DB_PATH"], "LoanStatusType", "MANUAL_REVIEW", "Manual Review", 4, actor)

    create_entity_definition(
        app.config["DB_PATH"],
        name="PolicyPeriod",
        supertype="EffDated",
        subtype="LoanPolicyPeriod",
        description="Guidewire-style policy container for loan lifecycle",
        created_by=actor,
    )
    create_entity_definition(
        app.config["DB_PATH"],
        name="LoanRiskAssessment",
        supertype="PolicyPeriod",
        subtype="LoanRiskAssessmentExt",
        description="Risk analysis entity linked with predictions and approvals",
        created_by=actor,
    )
    create_or_update_entity_field(
        app.config["DB_PATH"],
        entity_name="LoanRiskAssessment",
        field_name="statusType",
        field_type="string",
        extension_type="EIX",
        relation_type="none",
        related_entity=None,
        foreign_key_field=None,
        is_array=False,
        is_circular=False,
        nullable=False,
        typelist_name="LoanStatusType",
        description="Current loan status typelist code",
        created_by=actor,
    )
    create_or_update_entity_field(
        app.config["DB_PATH"],
        entity_name="LoanRiskAssessment",
        field_name="riskBand",
        field_type="string",
        extension_type="EIX",
        relation_type="none",
        related_entity=None,
        foreign_key_field=None,
        is_array=False,
        is_circular=False,
        nullable=True,
        typelist_name=None,
        description="Computed risk band",
        created_by=actor,
    )
    regenerate_model_code(app.config["DB_PATH"], app.config["MODEL_DIR"])
    append_chain(
        app.config["DB_PATH"],
        application_id=None,
        actor_id=actor_id,
        event_type="DATAMODEL_BOOTSTRAP",
        payload="seeded default entities and typelists",
    )


def create_app() -> Flask:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _load_local_env(project_root)
    app = Flask(
        __name__,
        template_folder=os.path.join(project_root, "templates"),
        static_folder=os.path.join(project_root, "static"),
    )
    app.config.from_object(Config)
    app.permanent_session_lifetime = timedelta(minutes=app.config["PERMANENT_SESSION_LIFETIME_MIN"])
    app.config["SESSION_COOKIE_SECURE"] = app.config["SESSION_COOKIE_SECURE"]

    sentry_dsn = os.getenv("SENTRY_DSN")
    if sentry_dsn:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.flask import FlaskIntegration

            sentry_sdk.init(dsn=sentry_dsn, integrations=[FlaskIntegration()], traces_sample_rate=0.1)
        except Exception:
            pass

    init_db(app.config["DB_PATH"])
    init_cloud_db()
    _seed_admin(app)
    bootstrap_loan_products(app.config["DB_PATH"])
    bootstrap_suite_defaults(app.config["DB_PATH"])
    _bootstrap_model(app)
    _bootstrap_datamodel(app)

    register_routes(app)

    return app
