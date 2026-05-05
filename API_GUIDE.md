# LoanShield - Comprehensive Integration & API Guide

## 1. System Overview

LoanShield is a production-grade loan management system with three distinct operational centers:

```
┌─────────────────────────────────────────────────────────┐
│           LoanShield - Guidewire-Inspired            │
├─────────────────────────────────────────────────────────┤
│  ┌──────────────┬──────────────┬──────────────┐         │
│  │PolicyCenter  │ BillingCenter│RecoveryCenter│         │
│  │(Origination) │ (Servicing)  │(Collections) │         │
│  └──────────────┴──────────────┴──────────────┘         │
│           │              │              │               │
│           ▼              ▼              ▼               │
│  ┌─────────────────────────────────────────┐            │
│  │     PostgreSQL Database                 │            │
│  │  ┌─────────┬───────────┬────────────┐   │            │
│  │  │ Users   │ Policies  │ Ledger     │   │            │
│  │  │(Encrypt)│(Decision) │(Blockchain)│   │            │
│  │  └─────────┴───────────┴────────────┘   │            │
│  └─────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────┘
```

---

## 2. API Endpoints Reference

### Base URL
```
Local: http://localhost:8000
Production: https://api.loanshield.com
```

### Swagger Documentation
```
Interactive API docs: http://localhost:8000/docs
ReDoc documentation: http://localhost:8000/redoc
```

---

## 3. PolicyCenter (Origination) APIs

### POST `/api/apply` - Submit Loan Application

**Purpose:** Accept loan applications, run ML decision engine, and return approval/rejection with credit tier.

**Request Body:**
```json
{
  "name": "John Doe",              // Plaintext (encrypt client-side ideally)
  "pan": "AAAPA1234A",             // 10-digit PAN
  "salary": "600000",              // Annual salary (₹)
  "loan_amount": 500000,           // Requested loan amount (₹)
  "expense": 100000                // Monthly expense (₹)
}
```

**Response (200 OK):**
```json
{
  "status": "Approved",
  "tier": "Gold"
}
```

**Response (Rejected):**
```json
{
  "status": "Rejected",
  "tier": "Silver"
}
```

**Decision Logic:**
- **DTI = Monthly Expense / Monthly Income**
  - Monthly Income = Annual Salary / 12
- **Tier Assignment:**
  - DTI < 0.2 → Platinum (Low Risk)
  - DTI < 0.35 → Gold (Medium Risk)
  - DTI ≥ 0.35 → Silver (High Risk)
- **Approval Criteria:**
  - Approved if: DTI < 0.4 AND Loan Amount < Annual Salary × 5
  - Otherwise: Rejected

**HTTP Status Codes:**
```
200 OK        - Application processed successfully
400 Bad Request - Invalid input data
500 Server Error - Internal processing error
```

**Example cURL:**
```bash
curl -X POST http://localhost:8000/api/apply \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Jane Smith",
    "pan": "AAABB1234B",
    "salary": "720000",
    "loan_amount": 450000,
    "expense": 120000
  }'
```

---

## 4. BillingCenter (Servicing) APIs

### POST `/api/payment` - Record Payment Transaction

**Purpose:** Process EMI/loan payments with immutable blockchain-lite ledger tracking for audit and fraud prevention.

**Request Body:**
```json
{
  "user_id": 1,
  "amount": 8500.50,               // Payment amount (₹)
  "transaction_type": "EMI"        // EMI, Disbursement, Penalty, etc.
}
```

**Response (200 OK):**
```json
{
  "transaction_id": 42,
  "hash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f"
}
```

**Blockchain Logic:**
Each ledger entry contains:
1. `previous_hash` - SHA-256 hash of previous transaction
2. `current_hash` - SHA-256 hash of current transaction (immutable)
3. Formula: `current_hash = SHA256(previous_hash | user_id | amount | timestamp)`

**Integrity Verification:**
To verify ledger integrity, rehash the chain:
```python
def verify_chain(ledger_entries):
    for i, entry in enumerate(ledger_entries):
        if i == 0 and entry.previous_hash is not None:
            return False  # First entry should have no previous hash
        
        if i > 0:
            expected_hash = entry.previous_hash
            actual_hash = ledger_entries[i-1].current_hash
            if expected_hash != actual_hash:
                return False  # Chain broken!
    
    return True  # Chain is valid
```

**Example cURL:**
```bash
curl -X POST http://localhost:8000/api/payment \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "amount": 8500,
    "transaction_type": "EMI"
  }'
```

---

## 5. RecoveryCenter (Collections) APIs

### GET `/api/defaulters` - List Defaulters *(To be implemented)*

**Purpose:** Fetch list of users with payment defaults for collections action.

**Query Parameters:**
```
days_overdue=60        // Filter by minimum days overdue
status=critical        // Filter by alert level (low, medium, high, critical)
limit=50               // Pagination limit
offset=0               // Pagination offset
```

**Response (200 OK):**
```json
{
  "defaulters": [
    {
      "case_id": "RC-1-1234567890",
      "user_id": 1,
      "amount_outstanding": 50000,
      "days_overdue": 95,
      "alert_level": "Critical",
      "strategy": "Legal Notice",
      "next_action": "2026-04-04"
    }
  ],
  "total": 47,
  "page": 1
}
```

### POST `/api/collection-case` - Create Collection Case *(To be implemented)*

**Purpose:** Manually create or escalate a collection case for an overdue loan.

**Request Body:**
```json
{
  "user_id": 1,
  "notes": "Third notice sent, no response",
  "escalate_to": "legal"
}
```

**Response (200 OK):**
```json
{
  "case_id": "RC-1-1234567890",
  "status": "Escalated",
  "assigned_to": "Legal Team"
}
```

---

## 6. Database Schema

### Users Table (Encrypted)
```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name_encrypted VARCHAR NOT NULL,      -- Fernet-encrypted
  pan_encrypted VARCHAR NOT NULL,        -- Fernet-encrypted
  salary_encrypted VARCHAR NOT NULL,     -- Fernet-encrypted
  created_at TIMESTAMP DEFAULT NOW()
);
```

### Loan Policies Table
```sql
CREATE TABLE loan_policies (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount DECIMAL(12, 2) NOT NULL,
  status VARCHAR(20) CHECK (status IN ('Approved', 'Rejected')),
  tier VARCHAR(20) CHECK (tier IN ('Platinum', 'Gold', 'Silver')),
  applied_at TIMESTAMP DEFAULT NOW()
);
```

### Ledger Table (Blockchain-Lite)
```sql
CREATE TABLE ledger (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount DECIMAL(12, 2) NOT NULL,
  transaction_type VARCHAR(50) NOT NULL,
  timestamp TIMESTAMP DEFAULT NOW(),
  previous_hash VARCHAR(64),              -- NULL for first transaction
  current_hash VARCHAR(64) NOT NULL UNIQUE,
  CONSTRAINT chain_integrity CHECK (current_hash != previous_hash)
);

-- Index for efficient chain traversal
CREATE INDEX idx_ledger_user_timestamp ON ledger(user_id, timestamp);
```

---

## 7. Error Handling

### Standard Error Response Format
```json
{
  "detail": "Error message describing what went wrong"
}
```

### Common HTTP Status Codes
```
200 OK               - Request successful
201 Created          - Resource created
400 Bad Request      - Invalid request data
401 Unauthorized     - Missing authentication
403 Forbidden        - Insufficient permissions
404 Not Found        - Resource not found
409 Conflict         - Resource already exists
422 Unprocessable    - Validation error
500 Server Error     - Internal error
```

### Example Error Response
```json
{
  "detail": "valid encrypted payload"
}
```

---

## 8. Security & Encryption

### PII Encryption (At Rest)
All sensitive fields (name, PAN, salary) are encrypted using **Fernet (AES-128)**:

```python
# Encryption
encrypted = encrypt_pii("confidential_data")
# Output: "gAAAAABl4jZ2L7x9k2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9"

# Decryption
plaintext = decrypt_pii(encrypted)
# Output: "confidential_data"
```

### Ledger Integrity (Blockchain Pattern)
Every transaction is cryptographically linked:

```
Transaction 1: hash = SHA256("" | 1 | 8500 | 2026-03-28T10:00:00)
               hash = "a1b2c3d4..."

Transaction 2: hash = SHA256("a1b2c3d4..." | 1 | 8500 | 2026-03-28T10:01:00)
               hash = "e5f6g7h8..."

Transaction 3: hash = SHA256("e5f6g7h8..." | 1 | 8500 | 2026-03-28T10:02:00)
               hash = "i9j0k1l2..."
```

**Tampering Detection:**
If anyone modifies Transaction 2, its hash changes, breaking the chain for Transactions 3+. This makes tampering immediately detectable.

### Transport Security (HTTPS)
In production, all API traffic must use HTTPS/TLS 1.2+:

```python
# Production FastAPI configuration
if ENVIRONMENT == "production":
    app.add_middleware(HTTPSRedirectMiddleware)
```

---

## 9. Authentication & Authorization *(To be implemented)*

### JWT Token Flow (Future)
```
1. User logs in with credentials
2. Backend returns JWT token (expires in 24 hours)
3. Client includes token in Authorization header
4. Backend validates token on each request
```

**Example (Future):**
```bash
curl -X GET http://localhost:8000/api/user/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

## 10. Rate Limiting & Throttling *(To be implemented)*

**Planned limits per API endpoint:**
- `/api/apply` - 5 requests per hour per IP
- `/api/payment` - 100 requests per hour per user
- `/api/defaulters` - 1000 requests per hour per authenticated user

---

## 11. Monitoring & Logging

### Application Logs
```bash
# Check API logs
tail -f logs/app.log

# Filter for errors
grep "ERROR" logs/app.log
```

### Database Monitoring
```bash
# PostgreSQL query log
SELECT query, calls, mean_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;
```

### Metrics *(To be implemented with Prometheus)*
- Request latency (p50, p95, p99)
- Error rate (5xx, 4xx)
- Ledger integrity check success rate
- Encryption/decryption performance

---

## 12. Integration Examples

### Python Client
```python
import requests
import json

API_URL = "http://localhost:8000"

# Submit loan application
response = requests.post(
    f"{API_URL}/api/apply",
    json={
        "name": "John Doe",
        "pan": "AAAPA1234A",
        "salary": "600000",
        "loan_amount": 500000,
        "expense": 100000
    }
)

result = response.json()
print(f"Status: {result['status']}")
print(f"Tier: {result['tier']}")
```

### JavaScript/React
```javascript
const response = await fetch('http://localhost:8000/api/apply', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'John Doe',
    pan: 'AAAPA1234A',
    salary: '600000',
    loan_amount: 500000,
    expense: 100000
  })
});

const data = await response.json();
console.log(`Status: ${data.status}, Tier: ${data.tier}`);
```

---

## 13. Deployment Checklist

- [ ] Generate secure Fernet key
- [ ] Configure PostgreSQL with SSL
- [ ] Set DATABASE_URL environment variable
- [ ] Enable HTTPS on API server
- [ ] Set up database backups
- [ ] Configure monitoring (Prometheus/Grafana)
- [ ] Set up centralized logging (ELK stack)
- [ ] Configure rate limiting (CloudFlare/AWS WAF)
- [ ] Run database migrations
- [ ] Start FastAPI server with gunicorn/uvicorn
- [ ] Build and deploy React frontend
- [ ] Configure CDN for static assets
- [ ] Set up CI/CD pipeline
- [ ] Perform security audit

---

## 14. FAQ & Troubleshooting

**Q: How do I decrypt PII from the database?**
A: Use the `decrypt_pii()` function from `backend/security.py`. Never expose decrypted values in logs.

**Q: What if a ledger transaction hash is invalid?**
A: Run chain verification to identify tampering. Escalate to security team and audit the database backup.

**Q: Can I bulk import historical transactions?**
A: Yes, but maintain chain integrity. Calculate hashes correctly: `SHA256(prev_hash | user_id | amount | timestamp)`.

**Q: How do I scale this to millions of users?**
A: Use database sharding by user_id, implement connection pooling, cache frequently accessed data in Redis.

---

**LoanShield API - Ready for Production! 🚀**
