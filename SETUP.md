# LoanShield Setup & Launch Guide

## Quick Start

### 1. Prerequisites
- Python 3.9+ 
- Node.js 18+
- PostgreSQL 14+ (or Docker)
- pip & npm

### 2. Backend Setup

```bash
# Navigate to project root
cd "Loan Analysis & Prediction"

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Database Configuration

**Option A: Local PostgreSQL**
```bash
# Create database
createdb loanshield

# Set environment variable
export DATABASE_URL="postgresql://yourusername:yourpassword@localhost/loanshield"
```

**Option B: Docker (Recommended)**
```bash
docker-compose up -d postgresql
# Connection string: postgresql://loanshield:password123@localhost:5432/loanshield
```

### 4. Run Backend API

```bash
# Navigate to project root
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Backend should now be at: http://localhost:8000
# Interactive docs: http://localhost:8000/docs
```

### 5. Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Frontend runs at: http://localhost:5173
```

### 6. Access the Application

- **Dashboard:** http://localhost:5173
- **API Docs (Swagger):** http://localhost:8000/docs
- **Database (if using Docker):** postgresql://localhost:5432/loanshield

---

## Docker Compose Deployment

```bash
# From project root
docker-compose up -d

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Stop services
docker-compose down
```

---

## Testing the API

### Using cURL

#### Test Loan Application
```bash
curl -X POST "http://localhost:8000/api/apply" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "pan": "AAAPA1234A",
    "salary": "600000",
    "loan_amount": 500000,
    "expense": 100000
  }'
```

#### Test Payment Transaction
```bash
curl -X POST "http://localhost:8000/api/payment" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "amount": 8500,
    "transaction_type": "EMI"
  }'
```

### Using Swagger UI
1. Navigate to http://localhost:8000/docs
2. Try out endpoints directly in the browser

---

## Environment Variables

Create a `.env` file in project root:

```env
# Database
DATABASE_URL=postgresql://loanshield:password123@localhost:5432/loanshield

# Encryption Key
FERNET_KEY=your-fernet-key-here

# Frontend API
REACT_APP_API_URL=http://localhost:8000

# Flask (legacy)
FLASK_ENV=development
```

**Generate Fernet Key:**
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Troubleshooting

### Backend Won't Start
```bash
# Check if port 8000 is in use
lsof -i :8000

# Kill process
kill -9 <PID>

# Verify dependencies
pip check
```

### Database Connection Error
```bash
# Test PostgreSQL connection
psql postgresql://loanshield:password123@localhost:5432/loanshield

# Reset database
dropdb loanshield
createdb loanshield
```

### Frontend Won't Load
```bash
# Clear npm cache
npm cache clean --force

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Rebuild
npm run build
```

---

## Project File Checklist

- [x] **Backend Core**
  - [x] `backend/main.py` - FastAPI app with routes
  - [x] `backend/models.py` - SQLAlchemy models
  - [x] `backend/security.py` - Encryption functions
  - [x] `backend/logic.py` - Decision engine
  - [x] `backend/database.py` - DB setup

- [x] **Frontend**
  - [x] `frontend/src/pages/Dashboard.jsx` - Main dashboard
  - [x] `frontend/src/App.jsx` - React app root
  - [x] `frontend/tailwind.config.js` - Tailwind setup
  - [x] `frontend/package.json` - Dependencies

- [x] **Documentation**
  - [x] `ARCHITECTURE.md` - System design
  - [x] `SETUP.md` - This file

- [x] **Configuration**
  - [x] `requirements.txt` - Python packages
  - [x] `docker-compose.yml` - Container orchestration
  - [x] `Dockerfile` - Backend image

---

## Next Steps

1. ✅ Run backend and frontend locally
2. ✅ Test endpoints using Swagger
3. ✅ Verify dashboard renders with glassmorphism
4. ✅ Test PII encryption/decryption
5. ✅ Verify blockchainledger hash chain
6. ⬜ Deploy to cloud (AWS/GCP)
7. ⬜ Add authentication (JWT)
8. ⬜ Implement Recovery Center
9. ⬜ Add comprehensive tests

---

**Happy Coding! 🚀**
