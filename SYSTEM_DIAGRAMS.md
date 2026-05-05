# LoanShield - System Architecture Diagrams

## High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    LoanShield Platform                       │
│                  Enterprise Loan Management                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┼─────────────┐
                │             │             │
        ┌───────▼──────┐  ┌──▼──────────┐ ┌┴───────────────┐
        │ PolicyCenter │  │ BillingCenter│ │ RecoveryCenter │
        │(Origination) │  │(Servicing)   │ │(Collections)   │
        └───────┬──────┘  └──────┬───────┘ └┬───────────────┘
                │                │         │
    ┌───────────┼────────────────┼─────────┼──────────┐
    │ ┌─────────▼──────────┐ ┌───▼────────────────┐  │
    │ │  FastAPI Backend   │ │  API Routes        │  │
    │ ├────────────────────┤ ├────────────────────┤  │
    │ │ POST /api/apply    │ │ - Decision Engine  │  │
    │ │ POST /api/payment  │ │ - Ledger Handling  │  │
    │ │ POST /api/recovery │ │ - Collections      │  │
    │ └────────────────────┘ └────────────────────┘  │
    │                                                  │
    │ ┌──────────────────────────────────────────┐   │
    │ │     Dependency Injection (Session)       │   │
    │ └─────────────────────┬────────────────────┘   │
    │                       │                         │
    │ ┌─────────────────────▼────────────────────┐   │
    │ │    PostgreSQL Database                   │   │
    │ ├──────────────────────────────────────────┤   │
    │ │ ┌──────────┐ ┌────────────┐ ┌─────────┐ │   │
    │ │ │  Users   │ │  Policies  │ │ Ledger  │ │   │
    │ │ │(Encrypted)│ │(Decision)  │ │(Chain)  │ │   │
    │ │ └──────────┘ └────────────┘ └─────────┘ │   │
    │ └──────────────────────────────────────────┘   │
    └──────────────────────────────────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            │                                   │
      ┌─────▼─────────┐           ┌────────────▼─────┐
      │ React Frontend │           │ Swagger / ReDoc  │
      │                │           │                  │
      │ ┌────────────┐ │           │ /docs            │
      │ │ Dashboard  │ │           │ /redoc           │
      │ │(Dark Mode) │ │           │                  │
      │ └────────────┘ │           │ Interactive API  │
      │                │           │ Documentation    │
      │ ┌────────────┐ │           │                  │
      │ │ App Form   │ │           │                  │
      │ │(Glassmorp.)│ │           │                  │
      │ └────────────┘ │           │                  │
      │                │           │                  │
      │ Tailwind CSS   │           │                  │
      │ (Slate+Cyan)   │           │                  │
      └────────────────┘           └──────────────────┘
            10000: 5173                    8000: /docs
```

---

## Request Flow: Loan Application

```
┌─────────────────────────────────────────────────────────────┐
│  User submits loan application via React Form               │
└────────────────────────────┬────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │ Validate input  │
                    │ (Pydantic)      │
                    └────────┬────────┘
                             │
                ┌────────────▼────────────┐
                │  POST /api/apply        │
                │  {name, pan, salary...} │
                └────────────┬────────────┘
                             │
              ┌──────────────▼──────────────┐
              │ Decrypt PII (Fernet)       │
              │ - name                     │
              │ - PAN                      │
              │ - salary                   │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │ Run Decision Engine         │
              │ predict_loan_status()       │
              │ ├─ Calculate DTI            │
              │ ├─ Calculate LTV            │
              │ ├─ Assign Tier              │
              │ └─ Determine Status         │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │ Create Database Records     │
              │ ├─ User (Encrypted)         │
              │ └─ LoanPolicy (Decision)    │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │ Async: Sync with Guidewire  │
              │ (Fire-and-forget)           │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │ Return Response             │
              │ {status, tier}              │
              └──────────────┬──────────────┘
                             │
            ┌────────────────▼────────────────┐
            │ Display Result to User          │
            │ ✅ Approved / Tier: Gold        │
            │ or                              │
            │ ❌ Rejected / Try Again Later   │
            └─────────────────────────────────┘
```

---

## Request Flow: Payment Transaction (Blockchain)

```
┌──────────────────────────────────────────────┐
│ User pays EMI via Dashboard                  │
└──────────────────────┬───────────────────────┘
                       │
            ┌──────────▼──────────┐
            │  POST /api/payment   │
            │  {user_id, amount}   │
            └──────────┬───────────┘
                       │
        ┌──────────────▼──────────────┐
        │ Fetch Previous Ledger Entry  │
        │ Get: previous_hash           │
        │ Get: current_hash            │
        └──────────────┬───────────────┘
                       │
        ┌──────────────▼──────────────────────┐
        │ Calculate New Hash (SHA-256)        │
        │                                     │
        │ payload = "|".join([                │
        │   prev_hash,      # Chain link      │
        │   user_id,        # Identity        │
        │   amount,         # Value           │
        │   timestamp       # Timelock        │
        │ ])                                  │
        │                                     │
        │ current_hash = SHA256(payload)      │
        └──────────────┬──────────────────────┘
                       │
        ┌──────────────▼──────────────────────┐
        │ Create Ledger Entry                 │
        │ ├─ id: auto                         │
        │ ├─ user_id: <value>                 │
        │ ├─ amount: <value>                  │
        │ ├─ transaction_type: "EMI"          │
        │ ├─ timestamp: NOW()                 │
        │ ├─ previous_hash: <parent_hash>     │
        │ └─ current_hash: <calculated>       │
        └──────────────┬──────────────────────┘
                       │
        ┌──────────────▼──────────────────────┐
        │ Commit to Database                  │
        │ Chain integrity maintained ✓        │
        └──────────────┬──────────────────────┘
                       │
        ┌──────────────▼──────────────────────┐
        │ Return Response                     │
        │ {                                   │
        │   "transaction_id": 42,             │
        │   "hash": "a1b2c3d4e5..."           │
        │ }                                   │
        └──────────────┬──────────────────────┘
                       │
        ┌──────────────▼──────────────────────┐
        │ Update Dashboard in Real-Time       │
        │ ✅ Payment recorded                 │
        │ ✅ Blockchain hash verified         │
        └───────────────────────────────────────┘
```

---

## Database Schema Relationships

```
┌──────────────┐                ┌─────────────────┐
│    Users     │                │  Loan_Policies  │
│              │      1:N       │                 │
├──────────────┤◄───────────────┤─────────────────┤
│ id (PK)      │                │ id (PK)         │
│ name_enc*    │                │ user_id (FK)    │
│ pan_enc*     │                │ amount          │
│ salary_enc*  │                │ status          │
│ created_at   │                │ tier            │
└──────────────┘                │ applied_at      │
       │                        └─────────────────┘
       │
       │ 1:N
       │
       └───────────────────┐
                           │
              ┌────────────▼──────────┐
              │     Ledger           │
              │                      │
              ├─────────────────────┤
              │ id (PK)              │
              │ user_id (FK)         │
              │ amount               │
              │ transaction_type     │
              │ timestamp            │
              │ previous_hash ◄──┐   │
              │ current_hash  ────┼──┼─ Chain link
              │                   │  │
              └────────────────────┘  │
                                      │
              ┌─────────────────────────┘
              │ (Blockchain-style)
              │ Each row links to previous
              │
              Example Chain:
              TX#1: {prev: NULL, curr: hash_1}
              TX#2: {prev: hash_1, curr: hash_2}
              TX#3: {prev: hash_2, curr: hash_3}
              
              ✓ Tamper-proof
              ✓ Immutable
              ✓ Audit trail
```

---

## PII Encryption at Column Level

```
Data Flow:

Original Data              User Table             Decryption
┌──────────────┐          ┌──────────────────┐   ┌──────────────┐
│ John Doe     │          │ name_encrypted   │   │ John Doe     │
│ AAAPA1234A   │   ───►   │ gAAAAABl4jZ...   │   │ AAAPPA1234A  │
│ 600000       │   enc    │ gAAAAABl5kA...   │   │ 600000       │
└──────────────┘    (Fernet) gAAAAABl6lB...   │   └──────────────┘
                          └──────────────────┘
                                      ▲
                                      │ decrypt_pii()
                                      │ (On SQL SELECT)

Encryption Algorithm:
┌─────────────────────────────────────┐
│ Input: "John Doe"                   │
│ Key: FERNET_KEY (env variable)      │
│ Algorithm: AES-128 (Symmetric)      │
│ Output: gAAAAABl4jZ2L7x9k2m3n4o5...│
│         (URL-safe Base64)           │
└─────────────────────────────────────┘

Security Properties:
✓ Reversible (can decrypt)
✓ Key-based (environment variable)
✓ Deterministic (same input = same output)
✓ NOT searchable (requires decryption)
✓ Unique per row (initialization vector)
```

---

## Blockchain-Lite Ledger (Integrity)

```
SHA-256 Hash Chain:

TX 1:
┌──────────────────┐
│ previous_hash:   │◄──── Genesis (NULL)
│ user_id: 1       │
│ amount: 8500     │
│ timestamp: T1    │
│ current_hash:    │
│  "hash_1"        │
└─────────┬────────┘
          │
          ├─ SHA256("NULL|1|8500|T1")
          └─ hash_1 = "a1b2c3d4..."

TX 2:
┌──────────────────┐
│ previous_hash:   │◄──── Linked to TX1
│  "hash_1"        │
│ user_id: 1       │
│ amount: 8500     │
│ timestamp: T2    │
│ current_hash:    │
│  "hash_2"        │
└─────────┬────────┘
          │
          ├─ SHA256("hash_1|1|8500|T2")
          └─ hash_2 = "e5f6g7h8..."

TX 3:
┌──────────────────┐
│ previous_hash:   │◄──── Linked to TX2
│  "hash_2"        │
│ user_id: 1       │
│ amount: 8500     │
│ timestamp: T3    │
│ current_hash:    │
│  "hash_3"        │
└──────────────────┘
          │
          ├─ SHA256("hash_2|1|8500|T3")
          └─ hash_3 = "i9j0k1l2..."


Tamper Detection:

Normal Chain:
TX1[hash_1] ──► TX2[prev:hash_1, curr:hash_2] ──► TX3[prev:hash_2]
✓ Valid        ✓ Valid                            ✓ Valid


If TX2 is modified:
TX1[hash_1] ──► TX2[modified, hash changed] ─X─► TX3[prev:hash_2]
✓ Valid        ❌ Invalid                         ❌ Broken!

Why?
- TX2's hash changes → hash_2' ≠ hash_2
- TX3 expects prev:hash_2 but gets hash_2'
- Chain breaks immediately → Tampering detected!
```

---

## Credit Decision Logic Flow

```
Input: income, expense, loan_amount

┌─────────────────────────────────────┐
│ Step 1: Normalize Income            │
│ Monthly Income = Annual / 12        │
│ Example: 600000 / 12 = 50000        │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│ Step 2: Calculate Ratios            │
│ DTI = expense / monthly_income      │
│ LTV = loan_amount / annual_income   │
│                                      │
│ Example:                             │
│ DTI = 100000 / 50000 = 2.0          │
│ LTV = 500000 / 600000 = 0.833       │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│ Step 3: Assign Tier                 │
│                                      │
│ if DTI < 0.2:                       │
│    tier = "Platinum"                │
│ elif DTI < 0.35:                    │
│    tier = "Gold"                    │
│ else:                               │
│    tier = "Silver"                  │
└────────────────┬────────────────────┘
                 │
   ┌─────────────┴─────────────┐
   │                           │
┌──▼──────────────────┐  ┌────▼──────────────────┐
│ Step 4a: Check DTI  │  │ Step 4b: Check LTV    │
│                     │  │                       │
│ if DTI < 0.4:       │  │ if loan < income*5:   │
│   ✓ Can proceed     │  │   ✓ Can proceed       │
│ else:               │  │ else:                 │
│   ❌ Reject         │  │   ❌ Reject           │
└──┬─────────────────┘  └────┬──────────────────┘
   │                         │
   └───────────────┬─────────┘
                   │
         ┌─────────▼─────────┐
         │ Step 5: Decision  │
         │                   │
         │ if DTI<0.4 AND    │
         │    LTV<5:         │
         │  ✅ Approved      │
         │ else:             │
         │  ❌ Rejected      │
         └─────────┬─────────┘
                   │
         ┌─────────▼────────────────┐
         │ Return to API            │
         │ {                         │
         │   "status": "Approved",   │
         │   "tier": "Gold",         │
         │   "dti": 2.0,             │
         │   "ltv": 0.833            │
         │ }                         │
         └──────────────────────────┘
```

---

## Collections Workflow (RecoveryCenter)

```
Payment Due        Default Detection      Alert Escalation
    │                    │                       │
    ├─ Expected: Jan 1    │                       │
    │                     │                       │
    ├─ Actual: No Pay  ────┼─► Days Overdue: 0     │
    │                     │         ┌─────────────┘
    ├─ No Pay    ─────────┼────────► Days Overdue: 30
    │ (30 days)           │         Alert: LOW
    │                     │         Strategy: SMS
    │ No Pay    ──────────┼────────► Days Overdue: 60
    │ (60 days)           │         Alert: MEDIUM
    │                     │         Strategy: Collections Team
    │ No Pay    ──────────┼────────► Days Overdue: 90
    │ (90 days)           │         Alert: HIGH
    │                     │         Strategy: Legal Notice
    │ No Pay    ──────────┼────────► Days Overdue: 120
    │ (120 days)          │         Alert: CRITICAL
    │                     │         Strategy: Arbitration
    └─────────────────────┼─────────────────────────┘
                          │
            ┌─────────────▼──────────────┐
            │ Collection Case Generated  │
            │ {                          │
            │   case_id: "RC-1-12345",   │
            │   amount: 50000,           │
            │   days_overdue: 90,        │
            │   alert_level: "HIGH",     │
            │   strategy: "Legal Notice" │
            │ }                          │
            └────────────────────────────┘
```

---

## Dark Mode Color System

```
Primary Backgrounds       Secondary Elements         Accents & Call-to-Action
┌──────────────────┐     ┌──────────────────┐      ┌──────────────────┐
│ Slate-900        │     │ Slate-800        │      │ Cyan-400         │
│ #0f172a          │     │ #1e293b          │      │ #22d3ee          │
│ (Page BG)        │     │ (Card BG)        │      │ (Button, Label)  │
└──────────────────┘     └──────────────────┘      └──────────────────┘
     Dark, almost             Rich, dark          Bright, pop-out
     black. Primary            blue-gray.         visibility
     background for             Cards and          accent.
     entire page.              containers.

Text Hierarchy
┌──────────────────────────────────────────────────────────┐
│ Level 1: Primary Text (Slate-100)                        │
│ "Dashboard" headings, content bodies                     │
│                                                          │
│ Level 2: Secondary Text (Slate-300)                     │
│ "Credit Health" label, metadata                         │
│                                                          │
│ Level 3: Tertiary Text (Slate-400)                      │
│ Hints, descriptions, fine print                         │
│                                                          │
│ Accent Text (Cyan-400)                                  │
│ Stats, important values, clickable elements             │
└──────────────────────────────────────────────────────────┘

Glassmorphism Example
┌────────────────────────────────────────────────────────┐
│ <div class="backdrop-blur-xl bg-slate-800/40          │
│              border border-slate-700/50                │
│              rounded-2xl p-8 shadow-2xl">              │
│   backdrop-blur-xl ──► Frosted glass effect            │
│   bg-slate-800/40  ──► 40% opacity (semi-transparent) │
│   border-slate-700/50 ──► Subtle 50% opacity border   │
│   shadow-2xl ──► Depth & elevation                     │
│   rounded-2xl ──► Soft, modern corners                 │
│ </div>                                                 │
└────────────────────────────────────────────────────────┘
```

---

These diagrams provide a visual understanding of the system architecture,
data flows, security mechanisms, and UI design principles of LoanShield.

**For implementation details, see ARCHITECTURE.md**
**For API documentation, see API_GUIDE.md**
