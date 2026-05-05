"""Comprehensive test suite for LoanShield backend."""

import pytest
from datetime import datetime
from backend.database import SessionLocal
from backend import models, security, logic
from backend.main import app
from fastapi.testclient import TestClient


client = TestClient(app)


class TestSecurityModule:
    """Test encryption and hashing functions."""

    def test_encrypt_decrypt_pii(self):
        """Test PII encryption and decryption."""
        original = "John Doe"
        encrypted = security.encrypt_pii(original)
        
        assert encrypted != original
        assert isinstance(encrypted, str)
        
        decrypted = security.decrypt_pii(encrypted)
        assert decrypted == original

    def test_encrypt_decrypt_salary(self):
        """Test salary encryption."""
        salary = "600000"
        encrypted = security.encrypt_pii(salary)
        decrypted = security.decrypt_pii(encrypted)
        
        assert decrypted == salary

    def test_generate_block_hash(self):
        """Test SHA-256 hash generation."""
        hash1 = security.generate_block_hash(None, 1, 8500, "2026-03-28T10:00:00")
        hash2 = security.generate_block_hash(None, 1, 8500, "2026-03-28T10:00:00")
        
        # Same inputs should produce same hash
        assert hash1 == hash2
        # Should be 64 characters (SHA-256 hex)
        assert len(hash1) == 64

    def test_block_hash_chain(self):
        """Test blockchain integrity: prev_hash affects current_hash."""
        prev = "abc123"
        curr1 = security.generate_block_hash(prev, 1, 8500, "2026-03-28T10:00:00")
        
        prev2 = "def456"
        curr2 = security.generate_block_hash(prev2, 1, 8500, "2026-03-28T10:00:00")
        
        # Different previous hashes should produce different current hashes
        assert curr1 != curr2


class TestLogicModule:
    """Test business logic and decision engine."""

    def test_platinum_tier_dti_low(self):
        """Test Platinum tier with low debt-to-income."""
        result = logic.predict_loan_status(
            income=600000,
            expense=100000,
            loan_amount=300000
        )
        
        assert result["status"] == "Approved"
        assert result["tier"] == "Platinum"
        assert result["dti"] < 0.2

    def test_gold_tier_dti_medium(self):
        """Test Gold tier with medium DTI."""
        result = logic.predict_loan_status(
            income=600000,
            expense=200000,
            loan_amount=300000
        )
        
        assert result["status"] == "Approved"
        assert result["tier"] == "Gold"
        assert 0.2 <= result["dti"] < 0.35

    def test_silver_tier_dti_high(self):
        """Test Silver tier with high DTI."""
        result = logic.predict_loan_status(
            income=600000,
            expense=300000,
            loan_amount=300000
        )
        
        assert result["status"] == "Rejected"
        assert result["tier"] == "Silver"
        assert result["dti"] >= 0.35

    def test_loan_amount_validation(self):
        """Test loan amount against income cap."""
        # Loan amount > income * 5 should be rejected
        result = logic.predict_loan_status(
            income=100000,
            expense=50000,
            loan_amount=1000000  # > 100000 * 5
        )
        
        assert result["status"] == "Rejected"

    def test_sync_with_guidewire(self):
        """Test Guidewire sync returns boolean."""
        result = logic.sync_with_guidewire()
        assert isinstance(result, bool)


class TestAPI:
    """Test FastAPI endpoints."""

    def test_apply_endpoint_valid(self):
        """Test loan application endpoint."""
        payload = {
            "name": "Jane Smith",
            "pan": "AAAPP1234P",
            "salary": "500000",
            "loan_amount": 400000,
            "expense": 80000
        }
        
        response = client.post("/api/apply", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "tier" in data
        assert data["status"] in ["Approved", "Rejected"]

    def test_apply_endpoint_validation(self):
        """Test endpoint validation."""
        payload = {
            "name": "Invalid",
            # Missing required fields
        }
        
        response = client.post("/api/apply", json=payload)
        # Should fail validation
        assert response.status_code != 200

    def test_payment_endpoint(self):
        """Test payment transaction endpoint."""
        payload = {
            "user_id": 1,
            "amount": 8500,
            "transaction_type": "EMI"
        }
        
        response = client.post("/api/payment", json=payload)
        
        # Status 200 or error with valid HTTP code
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert "transaction_id" in data
            assert "hash" in data
            assert len(data["hash"]) == 64  # SHA-256


class TestModels:
    """Test SQLAlchemy models."""

    def test_user_model_pii_encryption(self):
        """Test User model PII property encryption."""
        user = models.User()
        user.name = "Test User"
        user.pan = "AAABB1234B"
        user.salary = "450000"
        
        # Encrypted fields should not match plaintext
        assert user.name_encrypted != "Test User"
        assert user.pan_encrypted != "AAABB1234B"
        assert user.salary_encrypted != "450000"
        
        # Properties should decrypt correctly
        assert user.name == "Test User"
        assert user.pan == "AAABB1234B"
        assert float(user.salary) == 450000.0

    def test_ledger_model(self):
        """Test Ledger model structure."""
        ledger = models.Ledger(
            user_id=1,
            amount=8500.0,
            transaction_type="EMI",
            previous_hash="prev123abc",
            current_hash="current456def"
        )
        
        assert ledger.user_id == 1
        assert ledger.amount == 8500.0
        assert ledger.transaction_type == "EMI"
        assert ledger.previous_hash == "prev123abc"


class TestLoanPolicy:
    """Test LoanPolicy model."""

    def test_loan_policy_creation(self):
        """Test LoanPolicy model fields."""
        policy = models.LoanPolicy(
            user_id=1,
            amount=500000,
            status="Approved",
            tier="Gold"
        )
        
        assert policy.user_id == 1
        assert policy.amount == 500000
        assert policy.status == "Approved"
        assert policy.tier == "Gold"


class TestRecoveryCenter:
    """Test Recovery Center functionality."""

    def test_days_past_due_calculation(self):
        """Test past due calculation."""
        from recovery_center.collections import calculate_days_past_due
        
        now = datetime.utcnow()
        last_payment = now
        expected_date = datetime(2026, 1, 1)
        
        days = calculate_days_past_due(last_payment, expected_date)
        assert days >= 87  # Approximately 3 months

    def test_alert_level_assignment(self):
        """Test alert level determination."""
        from recovery_center.collections import determine_alert_level, CollectionAlert
        
        assert determine_alert_level(15) == CollectionAlert.LOW
        assert determine_alert_level(45) == CollectionAlert.MEDIUM
        assert determine_alert_level(75) == CollectionAlert.HIGH
        assert determine_alert_level(120) == CollectionAlert.CRITICAL

    def test_recovery_strategy_assignment(self):
        """Test strategy assignment."""
        from recovery_center.collections import (
            assign_recovery_strategy,
            CollectionAlert,
            RecoveryStrategy
        )
        
        strategy = assign_recovery_strategy(
            CollectionAlert.CRITICAL,
            "Silver"
        )
        assert strategy == RecoveryStrategy.ARBITRATION

    def test_collection_case_generation(self):
        """Test collection case generation."""
        from recovery_center.collections import generate_collection_case
        
        case = generate_collection_case(
            user_id=1,
            amount_outstanding=50000,
            days_overdue=95,
            user_tier="Gold"
        )
        
        assert case["user_id"] == 1
        assert case["amount"] == 50000
        assert case["days_overdue"] == 95
        assert "case_id" in case
        assert "alert_level" in case
        assert "strategy" in case


# ============================================================================
# Run Tests
# ============================================================================
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
