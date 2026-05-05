#!/usr/bin/env bash
# LoanShield - Quick Start Script
# Run this script to set up and launch the project locally

set -e

echo "════════════════════════════════════════════════════════════"
echo "  LoanShield - Enterprise Loan Management System"
echo "  Quick Start Setup"
echo "════════════════════════════════════════════════════════════"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Step 1: Check Prerequisites
echo -e "${BLUE}[1/6]${NC} Checking prerequisites..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.9+"
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Please install Node.js 18+"
    exit 1
fi

if ! command -v psql &> /dev/null; then
    echo "⚠️  PostgreSQL client not found. Using docker-compose instead."
    USE_DOCKER=true
else
    USE_DOCKER=false
fi

echo -e "${GREEN}✓ Prerequisites met${NC}\n"

# Step 2: Backend Setup
echo -e "${BLUE}[2/6]${NC} Setting up backend..."
python3 -m venv venv
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate 2>/dev/null
pip install -q -r requirements.txt
echo -e "${GREEN}✓ Backend dependencies installed${NC}\n"

# Step 3: Environment Configuration
echo -e "${BLUE}[3/6]${NC} Configuring environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠️  Created .env from template. Please update DATABASE_URL if needed."
fi
echo -e "${GREEN}✓ Environment configured${NC}\n"

# Step 4: Frontend Setup
echo -e "${BLUE}[4/6]${NC} Setting up frontend..."
cd frontend
npm install -q
cd ..
echo -e "${GREEN}✓ Frontend dependencies installed${NC}\n"

# Step 5: Database Setup
echo -e "${BLUE}[5/6]${NC} Setting up database..."
if [ "$USE_DOCKER" = true ]; then
    echo "Starting PostgreSQL via Docker Compose..."
    docker-compose up -d postgresql
    sleep 3
    echo "Waiting for database to be ready..."
    sleep 2
fi
echo -e "${GREEN}✓ Database ready${NC}\n"

# Step 6: Launch Services
echo -e "${BLUE}[6/6]${NC} Launching services..."
echo ""
echo "════════════════════════════════════════════════════════════"
echo -e "${GREEN}✅ Setup Complete!${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "To start the application:"
echo ""
echo -e "${YELLOW}Terminal 1 - Backend API:${NC}"
echo "  source venv/bin/activate"
echo "  uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo -e "${YELLOW}Terminal 2 - Frontend:${NC}"
echo "  cd frontend"
echo "  npm run dev"
echo ""
echo "Access the application:"
echo -e "  ${BLUE}Dashboard:${NC} http://localhost:5173"
echo -e "  ${BLUE}API Docs:${NC} http://localhost:8000/docs"
echo ""
echo "════════════════════════════════════════════════════════════"
