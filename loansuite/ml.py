from __future__ import annotations

import json
import math
import os
import pickle
from dataclasses import dataclass
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

MODEL_FILENAME = "approval_model.pkl"

FEATURES = [
    "region",
    "current_salary",
    "monthly_expenditure",
    "existing_emi",
    "requested_amount",
    "loan_term_months",
    "employment_years",
    "credit_score",
    "collateral_value",
]

NUMERIC_FEATURES = [
    "current_salary",
    "monthly_expenditure",
    "existing_emi",
    "requested_amount",
    "loan_term_months",
    "employment_years",
    "credit_score",
    "collateral_value",
]

CATEGORICAL_FEATURES = ["region"]


@dataclass
class ModelBundle:
    version: str
    pipeline: Pipeline
    accuracy: float
    roc_auc: float
    sample_count: int


def synthetic_historical_data(n: int = 600) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    regions = np.array(["North", "South", "East", "West", "Central"])

    region = rng.choice(regions, size=n, p=[0.2, 0.2, 0.2, 0.25, 0.15])
    salary = np.clip(rng.normal(90000, 32000, n), 25000, 260000)
    expenditure = np.clip(salary / 12 * rng.uniform(0.18, 0.7, n), 500, 18000)
    emi = np.clip(rng.normal(900, 700, n), 0, 5000)
    requested = np.clip(salary * rng.uniform(0.3, 4.5, n), 5000, 650000)
    term = rng.integers(12, 360, n)
    employment = np.clip(rng.normal(5.5, 3.2, n), 0.2, 34)
    credit = np.clip(rng.normal(690, 90, n), 320, 890)
    collateral = np.clip(requested * rng.uniform(0.0, 1.6, n), 0, 700000)

    dti = (expenditure + emi) / (salary / 12)
    lti = requested / salary
    coll_cov = np.divide(collateral, requested, out=np.zeros_like(collateral), where=requested > 0)

    region_adj = np.where(region == "West", 0.04, 0.0) + np.where(region == "Central", -0.03, 0.0)
    score = (
        (credit - 650) / 130
        - (dti - 0.4) * 1.8
        - (lti - 2.6) * 0.34
        + (employment - 4) * 0.08
        + (coll_cov - 0.25) * 0.28
        + region_adj
    )
    prob = 1 / (1 + np.exp(-score))
    approved = (prob > 0.53).astype(int)

    df = pd.DataFrame(
        {
            "region": region,
            "current_salary": salary,
            "monthly_expenditure": expenditure,
            "existing_emi": emi,
            "requested_amount": requested,
            "loan_term_months": term,
            "employment_years": employment,
            "credit_score": credit,
            "collateral_value": collateral,
            "approved": approved,
        }
    )
    return df


def train_model(historical_rows: List[Dict], model_dir: str, version: str) -> ModelBundle:
    os.makedirs(model_dir, exist_ok=True)

    seed_df = synthetic_historical_data(600)
    if historical_rows:
        hist = pd.DataFrame(historical_rows)
        hist = hist[[*FEATURES, "status"]].copy()
        hist["approved"] = (hist["status"] == "Approved").astype(int)
        hist = hist.drop(columns=["status"])
        df = pd.concat([seed_df, hist], ignore_index=True)
    else:
        df = seed_df

    X = df[FEATURES]
    y = df["approved"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pre = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERIC_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ]
    )

    clf = RandomForestClassifier(
        n_estimators=250,
        max_depth=11,
        min_samples_leaf=3,
        random_state=42,
        class_weight="balanced",
    )

    pipe = Pipeline([("pre", pre), ("clf", clf)])
    pipe.fit(X_train, y_train)

    pred = pipe.predict(X_test)
    proba = pipe.predict_proba(X_test)[:, 1]
    accuracy = float(accuracy_score(y_test, pred))
    roc = float(roc_auc_score(y_test, proba)) if len(np.unique(y_test)) > 1 else 0.5

    bundle = ModelBundle(
        version=version,
        pipeline=pipe,
        accuracy=accuracy,
        roc_auc=roc,
        sample_count=int(len(df)),
    )

    path = os.path.join(model_dir, MODEL_FILENAME)
    with open(path, "wb") as f:
        pickle.dump(bundle, f)

    return bundle


def load_model(model_dir: str) -> ModelBundle | None:
    path = os.path.join(model_dir, MODEL_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return pickle.load(f)


def infer(bundle: ModelBundle, payload: Dict, policy: Dict | None = None) -> Dict:
    record = {k: payload[k] for k in FEATURES}
    x = pd.DataFrame([record])
    ml_prob = float(bundle.pipeline.predict_proba(x)[0][1])

    monthly_income = payload["current_salary"] / 12
    dti = (payload["monthly_expenditure"] + payload["existing_emi"]) / monthly_income if monthly_income else 1.0
    lti = payload["requested_amount"] / payload["current_salary"] if payload["current_salary"] else 999
    collateral_cover = payload["collateral_value"] / payload["requested_amount"] if payload["requested_amount"] else 0

    base_rate = float(policy["base_rate"]) if policy and "base_rate" in policy else 0.09
    if payload["credit_score"] > 760:
        base_rate -= 0.012
    elif payload["credit_score"] < 650:
        base_rate += 0.014

    monthly_rate = base_rate / 12
    term = payload["loan_term_months"]
    principal = payload["requested_amount"]
    if monthly_rate == 0:
        emi = principal / term
    else:
        factor = (1 + monthly_rate) ** term
        emi = principal * monthly_rate * factor / (factor - 1)

    rule_risk = 100
    rule_risk -= int(max(0, (700 - payload["credit_score"]) * 0.18))
    rule_risk -= int(max(0, (dti - 0.4) * 120))
    rule_risk -= int(max(0, (lti - 2.7) * 12))
    rule_risk += int(min(10, max(0, collateral_cover * 8)))
    rule_risk += int(min(6, payload["employment_years"] * 0.8))
    risk_score = max(1, min(99, int(rule_risk * 0.45 + ml_prob * 100 * 0.55)))

    if risk_score >= 78 and ml_prob >= 0.72 and dti < 0.5:
        status = "Approved"
        tier = "Prime"
    elif risk_score >= 58 and ml_prob >= 0.48 and dti < 0.65:
        status = "Manual Review"
        tier = "Standard"
    else:
        status = "Rejected"
        tier = "High Risk"

    safe_emi = max(0, (monthly_income - payload["monthly_expenditure"] - payload["existing_emi"]) * 0.58)
    if monthly_rate == 0:
        rec_amount = safe_emi * term
    else:
        factor = (1 + monthly_rate) ** term
        rec_amount = safe_emi * (factor - 1) / (monthly_rate * factor)

    factors = {
        "dti": round(dti, 3),
        "lti": round(lti, 3),
        "collateral_cover": round(collateral_cover, 3),
        "employment_years": payload["employment_years"],
        "credit_score": payload["credit_score"],
        "region": payload["region"],
    }

    # Borrower segmentation (AAA..D) using earnings/assets/expenditure and credit health.
    annual_income = float(payload["current_salary"])
    annual_obligations = float(payload["monthly_expenditure"] + payload["existing_emi"]) * 12
    net_annual_buffer = max(0.0, annual_income - annual_obligations)
    buffer_ratio = (net_annual_buffer / annual_income) if annual_income else 0.0
    asset_to_loan = collateral_cover

    profile_score = 0.0
    profile_score += min(30.0, max(0.0, (payload["credit_score"] - 550) / 350 * 30.0))
    profile_score += min(20.0, max(0.0, (1.0 - min(dti, 1.0)) * 20.0))
    profile_score += min(15.0, max(0.0, buffer_ratio * 30.0))
    profile_score += min(20.0, max(0.0, min(asset_to_loan, 1.4) / 1.4 * 20.0))
    profile_score += min(15.0, max(0.0, min(payload["employment_years"], 10.0) / 10.0 * 15.0))

    if profile_score >= 88:
        borrower_segment = "AAA"
    elif profile_score >= 80:
        borrower_segment = "AA"
    elif profile_score >= 72:
        borrower_segment = "A"
    elif profile_score >= 64:
        borrower_segment = "BBB"
    elif profile_score >= 56:
        borrower_segment = "BB"
    elif profile_score >= 48:
        borrower_segment = "B"
    elif profile_score >= 38:
        borrower_segment = "C"
    else:
        borrower_segment = "D"

    requested = payload["requested_amount"]
    if policy:
        verification_level = policy["verification_level"]
        required_documents = list(policy["required_documents"])
        required_collateral_ratio = float(policy["required_collateral_ratio"])
    elif requested <= 50000:
        verification_level = "Minimal"
        required_documents = ["Government ID", "Basic Income Proof"]
        required_collateral_ratio = 0.0
    elif requested <= 150000:
        verification_level = "Standard"
        required_documents = ["Government ID", "Income Proof", "Bank Statements (3 months)"]
        required_collateral_ratio = 0.0
    elif requested <= 300000:
        verification_level = "Enhanced"
        required_documents = [
            "Government ID",
            "Income Proof",
            "Bank Statements (6 months)",
            "Employment Verification",
            "Tax Returns (1 year)",
        ]
        required_collateral_ratio = 0.15
    else:
        verification_level = "Comprehensive"
        required_documents = [
            "Government ID",
            "Income Proof",
            "Bank Statements (12 months)",
            "Employment Verification",
            "Tax Returns (2 years)",
            "Asset & Liability Statement",
        ]
        required_collateral_ratio = 0.30

    collateral_required = required_collateral_ratio > 0
    required_collateral_value = requested * required_collateral_ratio
    collateral_shortfall = max(0.0, required_collateral_value - payload["collateral_value"])

    # Policy enforcement by requested amount:
    # high-ticket loans must satisfy stricter collateral and verification conditions.
    if requested > 300000 and collateral_shortfall > 0:
        status = "Rejected"
        tier = "High Risk"
    elif requested > 150000 and collateral_shortfall > 0 and status == "Approved":
        status = "Manual Review"
        tier = "Standard"
    if policy:
        if payload["credit_score"] < int(policy["min_credit_score"]) and status == "Approved":
            status = "Manual Review"
            tier = "Standard"
        if dti > float(policy["max_dti"]):
            status = "Rejected"
            tier = "High Risk"

    return {
        "status": status,
        "tier": tier,
        "approval_probability": ml_prob,
        "risk_score": risk_score,
        "interest_rate": base_rate,
        "monthly_payment_est": emi,
        "recommended_amount": max(0.0, rec_amount),
        "decision_factors": json.dumps(
            {
                **factors,
                "verification_level": verification_level,
                "required_documents": required_documents,
                "required_collateral_ratio": round(required_collateral_ratio, 2),
                "required_collateral_value": round(required_collateral_value, 2),
                "collateral_required": collateral_required,
                "collateral_shortfall": round(collateral_shortfall, 2),
                "product_code": policy["product_code"] if policy else payload.get("product_code", ""),
                "product_name": policy["product_name"] if policy else "",
                "borrower_segment": borrower_segment,
                "profile_score": round(profile_score, 2),
                "loan_type": payload.get("loan_type", "PERSONAL"),
                "preferred_currencies": payload.get("preferred_currencies", ["USD"]),
                "loan_profile": payload.get("loan_profile", {}),
            },
            separators=(",", ":"),
        ),
        "model_version": bundle.version,
    }
