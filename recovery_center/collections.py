"""
Recovery Center - Collections and Defaulter Management

This module handles:
- Defaulter tracking and alerts
- Collections strategy routing
- Case escalation workflows
"""

from enum import Enum
from datetime import datetime, timedelta
from typing import List, Dict, Optional


class CollectionAlert(Enum):
    """Alert severity levels for defaulters."""
    LOW = "Low"          # 0-30 days past due
    MEDIUM = "Medium"    # 31-60 days past due
    HIGH = "High"        # 61-90 days past due
    CRITICAL = "Critical"  # >90 days past due


class RecoveryStrategy(Enum):
    """Collections routing strategies."""
    AUTOMATED_SMS = "Automated SMS"
    COLLECTIONS_TEAM = "Collections Team"
    LEGAL_NOTICE = "Legal Notice"
    ARBITRATION = "Arbitration"


def calculate_days_past_due(
    last_payment_date: datetime,
    expected_payment_date: datetime
) -> int:
    """Calculate number of days past due.
    
    Args:
        last_payment_date: DateTime of last successful payment
        expected_payment_date: DateTime when next payment was due
    
    Returns:
        Number of days past due (0 if on schedule)
    """
    days_overdue = (datetime.utcnow() - expected_payment_date).days
    return max(0, days_overdue)


def determine_alert_level(days_past_due: int) -> CollectionAlert:
    """Map days past due to alert level.
    
    Args:
        days_past_due: Number of days past due
    
    Returns:
        CollectionAlert severity level
    """
    if days_past_due <= 30:
        return CollectionAlert.LOW
    elif days_past_due <= 60:
        return CollectionAlert.MEDIUM
    elif days_past_due <= 90:
        return CollectionAlert.HIGH
    else:
        return CollectionAlert.CRITICAL


def assign_recovery_strategy(
    alert_level: CollectionAlert,
    user_tier: str
) -> RecoveryStrategy:
    """Assign recovery strategy based on alert level and user tier.
    
    Args:
        alert_level: CollectionAlert severity
        user_tier: User credit tier (Platinum, Gold, Silver)
    
    Returns:
        Assigned RecoveryStrategy
        
    Strategy Logic:
    - Platinum users: escalate slower (SMS → Collections)
    - Silver users: escalate faster (SMS → Legal Notice)
    - High alerts: always escalate to Collections Team minimum
    """
    if alert_level == CollectionAlert.LOW:
        return RecoveryStrategy.AUTOMATED_SMS
    elif alert_level == CollectionAlert.MEDIUM:
        if user_tier == "Platinum":
            return RecoveryStrategy.AUTOMATED_SMS
        else:
            return RecoveryStrategy.COLLECTIONS_TEAM
    elif alert_level == CollectionAlert.HIGH:
        return RecoveryStrategy.LEGAL_NOTICE
    else:  # CRITICAL
        return RecoveryStrategy.ARBITRATION


def generate_collection_case(
    user_id: int,
    amount_outstanding: float,
    days_overdue: int,
    user_tier: str
) -> Dict:
    """Generate a collection case with recommended strategy.
    
    Args:
        user_id: User ID
        amount_outstanding: Amount still owed (₹)
        days_overdue: Days past due
        user_tier: Credit tier
    
    Returns:
        Dictionary with case details
    """
    alert_level = determine_alert_level(days_overdue)
    strategy = assign_recovery_strategy(alert_level, user_tier)
    
    return {
        "user_id": user_id,
        "case_id": f"RC-{user_id}-{datetime.utcnow().timestamp()}",
        "amount": amount_outstanding,
        "days_overdue": days_overdue,
        "alert_level": alert_level.value,
        "strategy": strategy.value,
        "created_at": datetime.utcnow().isoformat(),
        "next_action_date": (
            datetime.utcnow() + timedelta(days=7)
        ).isoformat(),
    }


def batch_scan_defaulters(
    ledger_entries: List[Dict]
) -> List[Dict]:
    """Scan ledger for defaulters and generate collection cases.
    
    Args:
        ledger_entries: List of ledger transaction dictionaries
                        Must include: user_id, amount, days_overdue, tier
    
    Returns:
        List of collection cases for defaulters
    """
    default_threshold = 60  # days
    cases = []
    
    for entry in ledger_entries:
        if entry.get("days_overdue", 0) > default_threshold:
            case = generate_collection_case(
                user_id=entry["user_id"],
                amount_outstanding=entry.get("amount", 0),
                days_overdue=entry.get("days_overdue", 0),
                user_tier=entry.get("tier", "Silver"),
            )
            cases.append(case)
    
    return cases
