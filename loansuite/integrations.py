from __future__ import annotations

import json
import os
from typing import Any, Dict

try:
    import requests
except Exception:  # pragma: no cover
    requests = None


def _simulate_enabled() -> bool:
    return os.getenv("INTEGRATION_SIMULATE", "1").strip() in {"1", "true", "TRUE", "yes", "YES"}


def integration_status() -> Dict[str, bool]:
    return {
        "sendgrid": bool(os.getenv("SENDGRID_API_KEY")),
        "twilio": bool(os.getenv("TWILIO_ACCOUNT_SID") and os.getenv("TWILIO_AUTH_TOKEN")),
        "stripe": bool(os.getenv("STRIPE_API_KEY")),
        "kyc": bool(os.getenv("KYC_API_KEY")),
        "mapbox": bool(os.getenv("MAPBOX_API_KEY")),
        "sentry": bool(os.getenv("SENTRY_DSN")),
        "openai": bool(os.getenv("OPENAI_API_KEY")),
        "gemini": bool(os.getenv("GEMINI_API_KEY")),
    }


def gemini_chat(prompt: str, system_context: str = "") -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    if not api_key or not requests:
        if _simulate_enabled():
            return {"ok": True, "provider": "gemini-simulated", "text": "Simulation mode: Gemini response unavailable in offline mode."}
        return {"ok": False, "provider": "gemini", "reason": "missing_api_or_requests"}

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    user_text = prompt.strip()[:1800]
    if system_context:
        user_text = f"{system_context.strip()[:1200]}\n\nUser:\n{user_text}"
    payload = {
        "contents": [{"parts": [{"text": user_text}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 300},
    }
    try:
        resp = requests.post(url, headers={"Content-Type": "application/json"}, data=json.dumps(payload), timeout=12)
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code >= 300:
            return {"ok": False, "provider": "gemini", "status_code": resp.status_code, "reason": str(data)[:400]}
        text = ""
        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "\n".join([p.get("text", "") for p in parts if p.get("text")]).strip()
        return {"ok": bool(text), "provider": "gemini", "text": text or "No response returned."}
    except Exception as exc:
        return {"ok": False, "provider": "gemini", "reason": str(exc)}


def send_email(recipient: str, subject: str, message: str) -> Dict[str, Any]:
    key = os.getenv("SENDGRID_API_KEY")
    sender = os.getenv("SENDGRID_FROM_EMAIL", "noreply@loanshield.local")
    if not key or not requests:
        if _simulate_enabled():
            return {"ok": True, "provider": "sendgrid-simulated", "reason": "simulated_delivery"}
        return {"ok": False, "provider": "sendgrid", "reason": "missing_api_or_requests"}

    payload = {
        "personalizations": [{"to": [{"email": recipient}]}],
        "from": {"email": sender},
        "subject": subject,
        "content": [{"type": "text/plain", "value": message}],
    }
    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=8,
        )
        return {"ok": resp.status_code < 300, "provider": "sendgrid", "status_code": resp.status_code}
    except Exception as exc:
        return {"ok": False, "provider": "sendgrid", "reason": str(exc)}


def send_sms(phone: str, message: str) -> Dict[str, Any]:
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    from_phone = os.getenv("TWILIO_FROM_PHONE")
    if not sid or not token or not from_phone or not requests:
        if _simulate_enabled():
            return {"ok": True, "provider": "twilio-simulated", "reason": "simulated_delivery"}
        return {"ok": False, "provider": "twilio", "reason": "missing_api_or_requests"}
    try:
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        resp = requests.post(
            url,
            data={"From": from_phone, "To": phone, "Body": message},
            auth=(sid, token),
            timeout=8,
        )
        return {"ok": resp.status_code < 300, "provider": "twilio", "status_code": resp.status_code}
    except Exception as exc:
        return {"ok": False, "provider": "twilio", "reason": str(exc)}


def create_payment_intent(amount: float, currency: str = "usd") -> Dict[str, Any]:
    key = os.getenv("STRIPE_API_KEY")
    if not key or not requests:
        if _simulate_enabled():
            return {
                "ok": True,
                "provider": "stripe-simulated",
                "reason": "simulated_payment_intent",
                "id": f"pi_sim_{int(amount*100)}",
                "client_secret": "pi_simulated_secret",
            }
        return {"ok": False, "provider": "stripe", "reason": "missing_api_or_requests"}
    try:
        resp = requests.post(
            "https://api.stripe.com/v1/payment_intents",
            data={"amount": int(amount * 100), "currency": currency},
            auth=(key, ""),
            timeout=8,
        )
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        return {
            "ok": resp.status_code < 300,
            "provider": "stripe",
            "status_code": resp.status_code,
            "id": body.get("id"),
            "client_secret": body.get("client_secret"),
        }
    except Exception as exc:
        return {"ok": False, "provider": "stripe", "reason": str(exc)}


def verify_kyc_external(kyc_id: str) -> Dict[str, Any]:
    key = os.getenv("KYC_API_KEY")
    if not key:
        return {"ok": False, "provider": "kyc", "reason": "missing_api_key"}
    # Placeholder integration contract for KYC provider sandbox.
    return {"ok": True, "provider": "kyc", "verified": True, "reference": f"KYC-{kyc_id[-6:]}"}


def address_validate(address_text: str) -> Dict[str, Any]:
    key = os.getenv("MAPBOX_API_KEY")
    if not key:
        return {"ok": False, "provider": "mapbox", "reason": "missing_api_key"}
    return {"ok": True, "provider": "mapbox", "normalized": address_text.strip()}


def integration_smoke_report() -> Dict[str, Dict[str, Any]]:
    flags = integration_status()
    report: Dict[str, Dict[str, Any]] = {}
    report["sendgrid"] = {
        "configured": flags["sendgrid"],
        "mode": "live" if os.getenv("TEST_EMAIL_RECIPIENT") else "config-only",
        "result": send_email(
            os.getenv("TEST_EMAIL_RECIPIENT", "nobody@example.local"),
            "LoanShield Integration Test",
            "SendGrid integration test message.",
        ) if flags["sendgrid"] and os.getenv("TEST_EMAIL_RECIPIENT") else {"ok": flags["sendgrid"], "reason": "set TEST_EMAIL_RECIPIENT for live check"},
    }
    report["twilio"] = {
        "configured": flags["twilio"],
        "mode": "live" if os.getenv("TEST_SMS_TO") else "config-only",
        "result": send_sms(
            os.getenv("TEST_SMS_TO", "+10000000000"),
            "LoanShield Twilio integration test.",
        ) if flags["twilio"] and os.getenv("TEST_SMS_TO") else {"ok": flags["twilio"], "reason": "set TEST_SMS_TO for live check"},
    }
    report["stripe"] = {
        "configured": flags["stripe"],
        "mode": "live",
        "result": create_payment_intent(1.0, "usd") if flags["stripe"] else {"ok": False, "reason": "missing_api_key"},
    }
    report["kyc"] = {
        "configured": flags["kyc"],
        "mode": "live-stub",
        "result": verify_kyc_external("KYC_TEST_001"),
    }
    report["mapbox"] = {
        "configured": flags["mapbox"],
        "mode": "live-stub",
        "result": address_validate("1600 Pennsylvania Ave NW Washington"),
    }
    report["sentry"] = {
        "configured": flags["sentry"],
        "mode": "config-only",
        "result": {"ok": flags["sentry"], "reason": "Sentry emits on runtime exceptions"},
    }
    report["openai"] = {
        "configured": flags["openai"],
        "mode": "config-only",
        "result": {"ok": flags["openai"], "reason": "Chatbot currently rule-based with guardrails"},
    }
    report["gemini"] = {
        "configured": flags["gemini"],
        "mode": "live" if flags["gemini"] else "config-only",
        "result": gemini_chat("Health-check: reply with 'ok'.") if flags["gemini"] else {"ok": False, "reason": "missing_api_key"},
    }
    return report
