# LoanShield Insurance Suite

A comprehensive, secure, Guidewire-inspired loan platform with:

- welcome home page with suite modules (`PolicyCenter`, `BillingCenter`, `ClaimCenter`, `DataHub`)
- separate user and admin login pages
- role-based access control for authorized personnel only
- user dashboard for loan application, prediction, approval insights, and history
- admin dashboard for portfolio analytics, model operations, and manual decisioning
- Guidewire-style Data Model Studio with popups for `Entity`, `Supertype`, `Subtype`, `Typelist`, and `Entity Extension`
- ML-driven loan approval prediction using historical + synthetic data
- blockchain-style tamper-evident audit chain for critical events
- SQL/data guardrails against injection and data leakage
- automatic Java and Gosu regeneration when entity extensions are created/updated
- product-driven underwriting rules in SQL (`loan_products`, `product_rules`)
- KYC document hash anchoring (`kyc_documents` + blockchain audit events)
- servicing ledger and delinquency workflow (`servicing_ledger`, `delinquency_actions`)
- login lockout controls via SQL-backed auth security state (`auth_security`)
- integration-ready outbound notifications (`notification_events`) for SendGrid/Twilio
- guarded chatbot (`/chatbot`) with SQL chat logs (`chat_messages`)

## Key Capabilities

## 1) Loan Assessment + Prediction + Approval

Users can submit applications with region and financial factors:

- region of residence
- current salary
- monthly expenditure
- existing EMI
- requested amount
- loan term
- employment years
- credit score
- collateral value

The platform returns:

- approval status (`Approved`, `Manual Review`, `Rejected`)
- risk score (0-99)
- approval probability
- estimated interest rate
- monthly payment estimate
- recommended safe loan amount

## 2) Historical Data Intelligence

- Past applications are stored and used for ongoing analysis.
- Admin insights include regional approval rates, average salary, expenditure, and funnel distribution.
- User insights include personal trend summaries and region-level outcomes.

## 3) ML Model Lifecycle

- Pipeline: preprocessing + one-hot region encoding + random forest classifier
- Bootstraps with synthetic baseline data and then incorporates historical real applications
- Admin can trigger model retraining from dashboard
- Active model metadata tracked in `model_registry` (version, metrics, sample size)

## 4) Secure Access + Guardrails

- Separate auth paths:
  - `/login` for users
  - `/admin/login` for admins
- Role-gated dashboards and actions
- CSRF token checks on form submissions
- Login/application rate limiting
- Strict input validation and suspicious-pattern blocking
- Parameterized SQL queries only
- Password hashing with Werkzeug

## 5) Blockchain-Style Audit Integrity

- Every application, model operation, and manual admin decision is appended to `audit_chain`
- Each block stores previous hash + payload digest + nonce + timestamp
- Chain integrity is validated and surfaced on dashboards

## 6) Guidewire-Style Data Model + Code Generation

- Admin dashboard includes popup workflows to create:
  - entities with supertype/subtype
  - typelists with entries
  - entity extensions (new fields)
- Each extension change automatically regenerates:
  - Java classes: `model_store/java/generated/model/*.java`
  - Gosu classes: `model_store/gosu/generated/model/*.gs`
- Typelist enums in Java/Gosu under `model_store/*/generated/typelist/`

## 7) Free/Freemium API Integrations

Optional integrations are enabled through environment variables:

- `SENDGRID_API_KEY` for email notifications
- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_PHONE` for SMS
- `STRIPE_API_KEY` for payment intent creation
- `KYC_API_KEY` for external KYC verification hook
- `MAPBOX_API_KEY` for address normalization hook
- `SENTRY_DSN` for monitoring

Current integration pages:

- `/admin/integration-hub`
- `/admin/integration-test`
- `/admin/notifications-center`
- `/admin/servicing-ledger`

Integration test env helpers:

- `TEST_EMAIL_RECIPIENT` for live SendGrid smoke test
- `TEST_SMS_TO` for live Twilio smoke test

## 8) Chatbot

- Route: `/chatbot`
- Capabilities:
  - status lookup guidance
  - product and document guidance
  - payment/EMI help
- Guardrails:
  - CSRF protected
  - suspicious prompt blocking
  - blocked message handling
  - persistent SQL chat audit log (`chat_messages`)

## 9) Component Architecture (Implemented)

### PolicyCenter Equivalent

- Product modeling and underwriting configuration:
  - `loan_products`, `product_rules`
  - Page: `/admin/policycenter`
- Quote and issuance automation:
  - `quotes`, `policies`
  - Quotes and policy issuance are triggered during approval flows.

### ClaimCenter Equivalent

- Claims lifecycle and workflow events:
  - `claims`, `claim_workflow_events`
  - Page: `/admin/claimcenter`
- Workflow stages:
  - Intake -> Assessment -> Investigation -> Settlement -> Closed

### BillingCenter Equivalent

- Invoicing, servicing, and commissions:
  - `billing_invoices`, `servicing_ledger`, `agent_commissions`
  - Page: `/admin/billingcenter`

### Digital Engagement

- Portal/mobile/agent interaction tracking:
  - `engagement_events`
  - Pages: `/admin/digital-engagement`, `/user/digital-portal`

### Data & Analytics

- Fraud and pricing/collection analytics:
  - `fraud_signals`
  - Page: `/admin/data-analytics`

### Integration Gateway

- API-key protected partner APIs:
  - `POST /api/gateway/quote`
  - `POST /api/gateway/claim`
- Client and gateway logs:
  - `integration_clients`, `integration_gateway_logs`
  - Page: `/admin/integration-gateway`

### Cloud Scalability (Cloud-Ready)

- Runtime cloud settings:
  - `cloud_runtime_config`
  - Page: `/admin/cloud-scalability`
- Deployment artifacts:
  - `Dockerfile`, `docker-compose.yml`

## 10) Enterprise Expansion Modules (Implemented)

- Decision Explainability+ (`/admin/explainability-plus`):
  - SHAP-style ranked factor impact per application.
- Human-in-the-loop Workflow (`/admin/hitl-workflow`):
  - SLA timers, assignment queue, automated escalation.
- Document Intelligence (`/admin/document-intelligence`):
  - OCR/extraction simulation with mismatch scoring.
- Collections Strategy Engine (`/admin/collections-strategy`):
  - Configurable reminder cadence, settlement, hardship paths.
- Payment Reconciliation (`/admin/payment-reconciliation` + `/webhooks/payment`):
  - Webhook ingestion, retry state, invoice matching updates.
- Advanced Model Monitoring (`/admin/model-monitoring`):
  - Drift proxy, fairness by region, segment distribution, performance decay.
- Scenario Simulator+ (`/admin/scenario-simulator-plus`):
  - What-if underwriting sandbox before production rollout.
- Partner Onboarding (`/admin/partner-onboarding`):
  - API key rotation, IP allowlist, per-client rate/quota policy.
- Compliance Module (`/admin/compliance-module`):
  - Retention rules, consent records, right-to-delete/export events.
- Fraud Graph Analytics (`/admin/fraud-graph`):
  - Linked-application graph scoring and relationship inspection.
- SSO + MFA Center (`/admin/sso-mfa`):
  - Google/Microsoft provider registry + MFA secret lifecycle.
- Notification Orchestration (`/admin/notification-orchestration`):
  - Template management, campaign scheduling, delivery metrics.
- Data Warehouse Export (`/admin/warehouse-export`):
  - Snapshot exports for BigQuery/Snowflake-style analytics flows.
- Observability (`/admin/observability`):
  - Structured logs, severity breakdown, recent event timeline.
- Mobile-first PWA:
  - User page `/user/mobile`, with `static/manifest.webmanifest` and `static/sw.js`.
- Chatbot hardening (`/chatbot`):
  - Retrieval over policy docs, stricter prompt guardrails, full SQL audit log.

## Project Structure

- `app.py`: entrypoint
- `loansuite/config.py`: app configuration
- `loansuite/db.py`: DB setup and schema management
- `loansuite/security.py`: auth/security/guardrail helpers
- `loansuite/ml.py`: model training + inference
- `loansuite/services.py`: data + chain + insights services
- `loansuite/routes.py`: all web routes and workflows
- `templates/`: home, auth pages, user and admin dashboards
- `static/style.css`: modern suite styling

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Default Admin Credentials

- Username: `jpcharlie2`
- Password: `guidewire@2026`

Change in production via environment variables:

```bash
export ADMIN_USERNAME="platformadmin"
export ADMIN_PASSWORD="strong-password"
export FLASK_SECRET_KEY="replace-this"
export DATA_KEY="replace-this-too"
```

## Notes

- Existing incompatible old tables are auto-migrated into timestamped `_legacy_...` tables.
- SQLite database file: `loan_suite.db`
- ML model artifact directory: `model_store/`
