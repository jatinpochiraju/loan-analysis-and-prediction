# LoanShield Full Project Guide

Date: 2026-04-07

## 1. Executive Summary

LoanShield is a Guidewire-inspired loan platform built primarily as a Flask web application with an SQLite operational database, machine learning based approval intelligence, KYC and underwriting workflows, role-based portals, and a broad AdminCenter module suite.

At runtime, users submit loan applications, the model computes approval probability and risk metrics, KYC artifacts are hash-anchored and reviewed, underwriting recommendations are generated, and business actions are tracked in a tamper-evident audit chain.

## 2. Project Structure and Runtime Composition

The repository contains multiple architectural layers and parallel implementation paths:

- Main active web app stack:
  - Flask app factory and route registry
  - SQLite-backed service layer
  - Jinja2 server-rendered dashboards
- Data science and decisioning:
  - Scikit-Learn RandomForest classification pipeline
  - Feature engineering and deterministic rule overlays
- Data model studio artifacts:
  - Entity/typelist metadata in SQL tables
  - Java and Gosu generated code in model_store
- Additional code paths:
  - A separate FastAPI-oriented backend folder is present for architectural/reference use, but the core integrated portal flow is currently Flask-first.

## 3. Tech Stack

### 3.1 Backend

- Python 3.x
- Flask (primary runtime web framework)
- FastAPI package also present in dependencies (secondary/parallel stack assets)
- SQLite (active DB in current app flow)
- SQLAlchemy listed in dependencies (the active Flask flow uses direct sqlite3 helpers)
- Scikit-Learn for ML model training and inference
- pandas and numpy for model data preparation
- requests for external integration calls
- sentry-sdk for observability integration

### 3.2 Frontend

- Jinja2 templates for core product dashboards and workflows
- React + Vite frontend package also present:
  - react 19.x
  - react-dom 19.x
  - vite 7.x
  - eslint toolchain

### 3.3 Security and Platform

- CSRF validation on state-changing forms
- Login rate limiting and lockout tracking
- Password hashing and verification
- Role/access-level route guards
- Blockchain-style audit chain integrity verification
- Optional cloud and integration modules (email, payment, KYC provider hooks, observability)

### 3.4 Deployment

- Dockerfile and docker-compose in repo
- PostgreSQL-oriented dependencies exist, while active local default is SQLite

## 4. Core Domain Model

Primary operational tables include:

- users
- loan_applications
- model_registry
- audit_chain
- kyc_cases
- kyc_case_documents
- underwriting_reviews
- workflow_tasks and workflow_escalations
- servicing_ledger and delinquency_actions
- loan_products and product_rules
- typelists and typelist_entries
- entity_definitions and entity_fields

## 5. Authentication and Access Model

### 5.1 User Authentication

- User login uses username/password, then email OTP verification.
- Failed attempts increment auth_security counters.
- Lockout applies after threshold breach.
- Session is established only after OTP verification.

### 5.2 Admin Authentication

- Separate admin login route.
- Rate limiting and lockout controls also enforced.
- Admin session receives role=admin and access_level=admin.

### 5.3 Access Levels

- end_user: user portal and personal journeys
- company: company workspace and scoped datamodel controls
- admin: full platform governance and operational controls

## 6. User Dashboard: How It Works

The User Dashboard is a combined origination + tracking + post-decision workbench.

### 6.1 Main Sections

- New Loan Application form
- Personal insights and historical performance
- KYC Journey summary
- Latest decision explanation
- Application history with document upload
- Claims initiation and claims history

### 6.2 User Loan Submission Flow

1. User submits application payload from dashboard.
2. Input validation and suspicious-pattern checks run.
3. Credit score is either user-supplied or system-calculated.
4. Model bundle is loaded or trained if missing.
5. Product policy is selected by product code or amount range.
6. ML + rule engine inference returns status, tier, risk score, probability, EMI, safer amount, and factors.
7. Application row is persisted.
8. Audit chain block is appended.
9. KYC hashes are recorded and provider checks triggered.
10. KYC case is created/synced.
11. Workflow tasks are created.
12. Document intelligence and fraud signal hooks run.
13. Quote/policy/servicing/invoice actions run based on decision.
14. Notifications and observability events are logged.
15. Underwriting extension review is executed.

### 6.3 User Dashboard Output Signals

- Decision status: Approved / Manual Review / Rejected
- Decision tier: Prime / Standard / High Risk
- Borrower segment: AAA..D
- Risk score (1-99)
- Approval probability
- Monthly EMI estimate
- Recommended safer amount
- Required documents based on product policy

## 7. Admin Dashboard: How It Works

The AdminCenter is an operations console that combines portfolio analytics, decision operations, data model controls, code generation visibility, and audit integrity.

### 7.1 Main Data Loaded

- Applications list
- Manual review queue
- High-risk queue
- Regional analytics
- Servicing totals
- Model metadata and features
- Data model registry (entities and typelists)
- Generated Java/Gosu artifact summary
- Recent audit chain events and chain verification status

### 7.2 Core Admin Actions

- Manual application decision updates
- Retrain ML model
- Create entity
- Create typelist/typecode
- Create entity extensions (EIX/ETX metadata)
- Regenerate Java/Gosu artifacts
- Access specialized module pages (KYC, underwriting, fraud, integrations, compliance, observability, etc.)

### 7.3 Module Directory

The Admin modules include PolicyCenter, ClaimCenter, BillingCenter, KYC Dashboard, Underwriting Dashboard, Rules Engine, Typelist Manager, Entity Explorer, Codegen Console, Audit Explorer, Security Center, SSO/MFA, Fraud Graph, Notification Orchestration, Warehouse Export, and Observability among others.

## 8. KYC Verification Workflow (Detailed)

KYC is modeled as a multi-step journey with document intelligence and underwriting synthesis.

### 8.1 KYC Steps

1. Personal details
2. Employment details
3. Document upload
4. OCR verification
5. Risk review
6. Final decision

### 8.2 Required Document Set

Default required categories include:

- PAN Card
- Salary Slip 1
- Salary Slip 2
- Salary Slip 3
- Joining Letter
- Bank Statement (6 months)
- Selfie Image

### 8.3 Document Processing

On upload:

1. Bytes are stored to static/generated_docs.
2. Text extraction uses decode heuristics and parsing logic.
3. Quality analysis computes blur/noise/contrast/skew/text-density signals.
4. Parsed fields are extracted (name/company/salary/PAN/salary credits, etc.).
5. Verification breakdown compares uploaded content against KYC profile.
6. A verification score and mismatch flags are produced.
7. OCR/manual status is set and case status updated.
8. Audit timeline event is logged.

### 8.4 Extended Underwriting over KYC Case

Underwriting review calculates:

- safe_loan = max(0, (0.4 * monthly_salary * 48) - (existing_emi * 12))
- eligible amount and suggested safer amount
- risk level and approval status using OCR score, mismatch indicators, EMI burden, and experience
- recommendation confidence score
- explanation narrative persisted in underwriting_reviews

Decision outputs:

- approved
- manual_review
- rejected

### 8.5 Admin KYC Intervention

Admin can:

- approve / reject / send to manual review
- generate and attach demo docs for case simulation
- trigger downstream underwriting refresh

## 9. Whole Platform Workflow (End-to-End)

### 9.1 Origination to Servicing

1. User authenticates and submits loan application.
2. ML + policy rules produce provisional decision.
3. KYC hashes and external checks are recorded.
4. KYC case and workflow tasks are created.
5. OCR + underwriting review enriches decision confidence.
6. Fraud, quote, and compliance records are created.
7. If approved, disbursement and EMI schedule are generated.
8. Policy and billing artifacts are created.
9. Notifications are sent and audit chain updated.
10. Admin can override or manually route any case.
11. Servicing ledger and delinquency workflows continue lifecycle operations.

### 9.2 Audit and Integrity Layer

Every key event is appended to audit_chain with:

- previous hash linkage
- payload digest
- nonce
- timestamp
- current hash

Chain verification recalculates expected hashes to detect tampering.

## 10. Credit Score Calculation

There are two score constructs in the system:

### 10.1 System-Calculated Credit Score (300-900)

When user does not provide a score, derive_application_credit_score computes it from:

- annual income
- monthly obligations (expenditure + EMI)
- requested amount
- employment years
- collateral coverage

Derived ratios:

- DTI = (monthly_expenditure + existing_emi) / monthly_income
- LTI = requested_amount / annual_income
- collateral_cover = collateral_value / requested_amount

Base score starts near 690 and is adjusted up/down using bounded contributions from income, employment, collateral, DTI, and LTI, then clipped to [300, 900].

### 10.2 Decision Risk Score (1-99)

In ML inference:

- ml_prob from classifier
- rule-based risk from credit, DTI, LTI, collateral, employment
- blended score = 45% rule risk + 55% ML-probability-scaled signal
- final clipped to [1, 99]

## 11. Tiering Logic

### 11.1 Decision Tier (Loan Decision)

- Prime:
  - risk_score >= 78
  - ml_prob >= 0.72
  - dti < 0.5
  - status Approved
- Standard:
  - risk_score >= 58
  - ml_prob >= 0.48
  - dti < 0.65
  - status Manual Review
- High Risk:
  - fallback or hard-rule failure
  - status Rejected

### 11.2 Borrower Segment Tier (Profile Tier)

A profile_score is computed using credit health, DTI, income buffer, collateral-to-loan ratio, and employment tenure.

Segments:

- AAA
- AA
- A
- BBB
- BB
- B
- C
- D

These represent borrower quality segmentation, separate from decision tier.

## 12. Loan Types, Products, and Policy Types

### 12.1 Loan Types (Form-level journey types)

- Car Loan
- Home Loan
- Furniture Loan
- Travel Loan
- Student Loan
- Personal Loan

Each type unlocks type-specific input fields (for example vehicle details for car loan, institution/course for student loan).

### 12.2 Product Types (Underwriting policy products)

Configured in loan_products/product_rules:

- MICRO
  - Range: 1,000 to 50,000
  - Verification: Minimal
- STANDARD
  - Range: 50,001 to 150,000
  - Verification: Standard
- PLUS
  - Range: 150,001 to 300,000
  - Verification: Enhanced
- PREMIUM
  - Range: 300,001 to 3,000,000
  - Verification: Comprehensive

Rule controls include:

- required collateral ratio
- min credit score
- max DTI
- required document list

### 12.3 Policy Types (Coverage flavor)

- BASIC
- STANDARD
- FAMILY
- PREMIUM

These are user-selectable policy coverage categories and are tracked with the application/policy records.

## 13. Data Model Studio and Code Generation

The platform includes Guidewire-style metadata management:

- entity_definitions: entity + supertype/subtype
- entity_fields: extension metadata (EIX/ETX, relation type, typelist ref)
- typelists and typelist_entries: enum-like controlled codes

On updates, regenerate_model_code emits:

- Java model and typelist files
- Gosu model and typelist files

Generated paths are shown in Admin codegen views.

## 14. Security and Guardrails

- CSRF protection for mutable routes
- input sanitization and suspicious pattern checks
- parameterized SQL interactions
- login rate limit and lockout controls
- role/access-level route guards
- chain-based event integrity

## 15. Operational Notes

- Default admin credentials are environment configurable.
- DB schema is auto-initialized and shape-guarded.
- Some docs reference PostgreSQL/FastAPI architecture, while current integrated portal runtime is Flask + SQLite.

## 16. Quick Route Map

### User Side

- /login
- /login/verify
- /user/dashboard
- /user/apply
- /user/kyc-onboarding
- /user/claim/create

### Admin Side

- /admin/login
- /admin/dashboard
- /admin/kyc-dashboard
- /admin/underwriting-dashboard
- /admin/modules
- /admin/datamodel/entity
- /admin/datamodel/typelist
- /admin/datamodel/extension

---

Prepared as a comprehensive implementation guide for the current repository state.