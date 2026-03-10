import requests


def predict_loan_status(income: float, expense: float, loan_amount: float) -> dict:
    """Return a simple loan decision with tier based on debt-to-income ratios.

    The function calculates:
    * DTI = expense / income
    * LTV = loan_amount / income

    Tiers:
    * Platinum: DTI < 0.2
    * Gold: DTI < 0.35
    * Silver: otherwise

    Status is approved if DTI < 0.4 and requested amount is reasonable.
    """
    dti = expense / income if income else 0
    ltv = loan_amount / income if income else 0

    if dti < 0.2:
        tier = "Platinum"
    elif dti < 0.35:
        tier = "Gold"
    else:
        tier = "Silver"

    status = "Approved" if dti < 0.4 and loan_amount < income * 5 else "Rejected"
    return {"status": status, "tier": tier, "dti": dti, "ltv": ltv}


def sync_with_guidewire() -> bool:
    """Dummy method simulating a REST call to an external PolicyCenter.

    Returns True on a 200-like response; swallows exceptions.
    """
    try:
        # placeholder URL
        response = requests.get("https://example.com/policycenter/sync", timeout=3)
        return response.status_code == 200
    except requests.RequestException:
        return False
