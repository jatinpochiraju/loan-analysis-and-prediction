# LoanShield - Architecture & Implementation Guide

## Overview
LoanShield is a comprehensive loan management system inspired by Guidewire's insurance platform architecture. It implements a modular, secure, and scalable solution for loan origination, servicing, and recovery across three distinct logical centers.

---

## 1. Technical Stack

### Backend
- **Framework:** FastAPI (async-first, modern Python)
- **Database:** PostgreSQL with SQLAlchemy ORM
- **Security:** 
  - Fernet (cryptography library) for PII encryption
  - SHA-256 hashing for blockchain-lite ledger integrity
- **ML/Intelligence:** Scikit-Learn (credit decision engine)
- **OCR:** Pytesseract + Tesseract (document verification)

### Frontend
- **UI Framework:** React 19.2
- **CSS:** Tailwind CSS with custom dark mode configuration
- **Design Pattern:** Glassmorphism UI
- **HTTP Client:** Axios

### Infrastructure
- **Container:** Docker + Docker Compose
- **Database:** PostgreSQL 14+
- **Ports:** 
  - Backend API: 8000
  - Frontend (Vite): 5173
  - PostgreSQL: 5432

---

## 2. Project Structure

```
┌─ backend/                    # Python API server (FastAPI)
│  ├─ __init__.py
│  ├─ main.py                  # FastAPI app & routes
│  ├─ models.py                # SQLAlchemy ORM models
│  ├─ database.py              # DB connection & session management
│  ├─ security.py              # Encryption & hashing functions
│  └─ logic.py                 # Decision engine & business logic
├─ frontend/                   # React + Tailwind CSS
│  ├─ src/
│  │  ├─ pages/
│  │  │  └─ Dashboard.jsx      # Main dashboard with glassmorphism
│  │  ├─ App.jsx               # Root component
│  │  ├─ main.jsx              # Entry point
│  │  ├─ index.css             # Tailwind imports + global styles
│  │  └─ App.css               # Component-specific styles
│  ├─ tailwind.config.js       # Tailwind configuration
│  ├─ postcss.config.js        # PostCSS plugins
│  └─ package.json             # Dependencies
├─ docker-compose.yml          # Multi-container orchestration
├─ Dockerfile                  # Backend image definition
└─ requirements.txt            # Python dependencies
```

---

## 3. Architecture Deep Dive

### A. Database Models (`backend/models.py`)

#### User Table (PII Encrypted)
```sql
Table: users
├─ id (PK)
├─ name_encrypted (Fernet cipher)
├─ pan_encrypted (Fernet cipher)
├─ salary_encrypted (Fernet cipher)
└─ relationships: policies, ledger_entries
```

**Security Feature:** All PII fields use column-level encryption with Fernet symmetric encryption. Decryption happens at the property level: `user.name` automatically decrypts on read.

#### LoanPolicy Table
```sql
Table: loan_policies
├─ id (PK)
├─ user_id (FK → users)
├─ amount (Float)
├─ status (Approved|Rejected)
├─ tier (Platinum|Gold|Silver)
├─ applied_at (DateTime)
```

#### Ledger Table (Blockchain-Lite)
```sql
Table: ledger
├─ id (PK)
├─ user_id (FK → users)
├─ amount (Float)
├─ transaction_type (EMI|Disbursement|Penalty)
├─ timestamp (DateTime)
├─ previous_hash (String|NULL for genesis)
└─ current_hash (SHA-256)
```

**Blockchain Pattern:** Each row contains the hash of the previous row, creating an immutable chain. Any tampering is immediately detectable by rehashing and comparing.

---

### B. Security Module (`backend/security.py`)

#### Encryption Functions
```python
def encrypt_pii(data: str) -> str
  Input: Plaintext string (name, salary, PAN)
  Output: Base64-encoded Fernet cipher token
  Use: Protects sensitive data at rest

def decrypt_pii(token: str) -> str
  Input: Fernet cipher token
  Output: Plaintext string
  Use: On-demand decryption for authorized reads
```

#### Ledger Hashing
```python
def generate_block_hash(prev_hash, user_id, amount, timestamp) -> str
  Payload: "{prev_hash}|{user_id}|{amount}|{timestamp}"
  Algorithm: SHA-256
  Output: 64-character hex string
```

---

### C. Decision Engine (`backend/logic.py`)

#### Credit Scoring Algorithm
```python
def predict_loan_status(income, expense, loan_amount):
  Calculate:
    • DTI = expense / income
    • LTV = loan_amount / income
  
  Tier Assignment:
    • DTI < 0.2 → Platinum (best)
    • DTI < 0.35 → Gold
    • DTI ≥ 0.35 → Silver
  
  Decision:
    • Approved if: DTI < 0.4 AND loan_amount < income * 5
    • Rejected otherwise
  
  Return: {status, tier, dti, ltv}
```

#### Guidewire Sync
```python
def sync_with_guidewire():
  Simulates REST call to external PolicyCenter
  Returns: Boolean (success/failure)
  Pattern: Fire-and-forget for asynchronous integration
```

---

### D. API Endpoints (`backend/main.py`)

#### POST `/api/apply`
```
Request Body:
{
  "name": "John Doe",           # plaintext (encrypted by client ideally)
  "pan": "AAAPA1234A",
  "salary": "₹ 60,000",
  "loan_amount": 500000,
  "expense": 15000
}

Response:
{
  "status": "Approved",
  "tier": "Gold"
}

Process Flow:
1. Decrypt encrypted payload
2. Run predict_loan_status()
3. Store encrypted User record
4. Store LoanPolicy decision
5. Async: sync_with_guidewire()
```

#### POST `/api/payment`
```
Request Body:
{
  "user_id": 1,
  "amount": 8500,
  "transaction_type": "EMI"
}

Response:
{
  "transaction_id": 42,
  "hash": "a1b2c3d4..."
}

Process Flow:
1. Fetch previous Ledger entry
2. Calculate current_hash = SHA256(prev_hash | user_id | amount | timestamp)
3. Store new Ledger entry with blockchain link
4. Return transaction ID and hash for verification
```

---

### E. Frontend Dashboard (`frontend/src/pages/Dashboard.jsx`)

#### Design Philosophy: Glassmorphism
- **Background:** Slate-900 (#0f172a)
- **Cards:** Semi-transparent Slate-800 with backdrop blur
- **Accents:** Cyan-400 (#22d3ee) for highlights
- **Borders:** Subtle slate-700/50 with transparency

#### Components

##### Credit Health Gauge
- Radial SVG progress circle
- Dynamic color based on score:
  - Green (800+) → Excellent
  - Cyan (700-799) → Good
  - Yellow (600-699) → Fair
  - Red (<600) → Poor

##### Recent Transactions Table
- Responsive design (stacks on mobile)
- Status badges (Approved, Completed, Pending, Rejected)
- Tier badges (Platinum, Gold, Silver)
- Hover effects with slate-700/30 background

##### Quick Stats Grid
- Active Loans, Total Outstanding, EMI Due, Credit Utilization
- Glassmorphic cards with 4-column layout on desktop

---

## 4. Module Responsibilities (Centers)

### PolicyCenter (Origination)
**File:** `policy_center/__init__.py`

Handles:
- Loan application intake
- OCR verification of documents (salary slips, identity)
- ML-based approval/rejection decision
- Tier assignment based on creditworthiness

**API Routes:**
- `POST /api/apply` → decision engine

---

### BillingCenter (Servicing)
**File:** `billing_center/__init__.py`

Handles:
- EMI collection management
- Immutable blockchain-lite ledger
- Payment transaction recording
- Ledger integrity verification (hash validation)

**API Routes:**
- `POST /api/payment` → blockchain ledger

---

### RecoveryCenter (Collections)
**File:** `recovery_center/__init__.py` (to be implemented)

Handles:
- Defaulter tracking
- Alert escalation
- Recovery case management
- Collections strategy

---

## 5. Security Considerations

### PII Encryption
- **At Rest:** Column-level Fernet encryption
- **In Transit:** HTTPS/TLS (configure in production)
- **Key Management:** Stored in `.env` file (rotate regularly)
- **Decryption:** Only on authorized request paths

### Ledger Integrity
- **Blockchain Pattern:** SHA-256 hash chain prevents tampering
- **Audit Trail:** Immutable transaction log
- **Verification:** Rehash and compare to detect alterations

### Input Validation
- Pydantic BaseModel schemas validate request structure
- FastAPI auto-validates types and constraints

---

## 6. Deployment

### Local Development
```bash
# Install backend dependencies
pip install -r requirements.txt

# Run FastAPI server
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# In another terminal, run frontend
cd frontend
npm install
npm run dev
```

### Docker Compose
```bash
docker-compose up -d
# Builds backend image, starts PostgreSQL, front-end
```

---

## 7. PEP8 Compliance & Best Practices

✅ All Python code follows PEP8:
- 4-space indentation
- Docstrings for all functions
- Type hints for function parameters
- Dependency injection for database sessions
- No magic numbers (use constants)

✅ React best practices:
- Functional components with hooks
- Props validation
- Memoization where appropriate
- Event handlers properly bound

---

## 8. Testing Strategy (Next Phase)

```
tests/
├─ test_models.py         # ORM model validation
├─ test_security.py       # Encryption/hashing
├─ test_logic.py          # Decision engine
├─ test_api.py            # Endpoint integration
└─ test_ledger.py         # Blockchain integrity
```

---

## 9. Future Enhancements

1. **Advanced ML Models:** Scikit-Learn pipelines for DTI, LTV optimization
2. **Tesseract OCR:** Real document verification
3. **Recovery Center:** Collections workflow automation
4. **GraphQL API:** For frontend flexibility
5. **Monitoring:** Prometheus + Grafana for observability
6. **CI/CD:** GitHub Actions for automated testing

---

**Architecture designed for scalability, security, and maintainability.**
**Ready for capstone project evaluation! 🚀**
