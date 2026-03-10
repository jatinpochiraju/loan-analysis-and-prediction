from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from functools import wraps
from typing import Dict, List

from flask import flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

SUSPICIOUS_RE = re.compile(
    r"(--|/\*|\*/|;|\\bunion\\b|\\bselect\\b|\\binsert\\b|\\bdelete\\b|"
    r"\\bdrop\\b|\\bupdate\\b|\\balter\\b|\\bor\\s+1=1|\\bbenchmark\\b|\\bsleep\\b)",
    re.IGNORECASE,
)

_request_log: Dict[str, List[float]] = {}


def password_hash(password: str) -> str:
    return generate_password_hash(password)


def verify_password(pw_hash: str, password: str) -> bool:
    return check_password_hash(pw_hash, password)


def password_policy_errors(password: str) -> List[str]:
    errors: List[str] = []
    if len(password or "") < 10:
        errors.append("Password must be at least 10 characters.")
    if not re.search(r"[A-Z]", password or ""):
        errors.append("Password must include an uppercase letter.")
    if not re.search(r"[a-z]", password or ""):
        errors.append("Password must include a lowercase letter.")
    if not re.search(r"[0-9]", password or ""):
        errors.append("Password must include a number.")
    if not re.search(r"[^A-Za-z0-9]", password or ""):
        errors.append("Password must include a special character.")
    return errors


def hmac_sha256(secret: str, value: str) -> str:
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def sanitize_text(value: str, max_len: int = 80) -> str:
    value = " ".join((value or "").strip().split())
    if len(value) > max_len:
        value = value[:max_len]
    return value


def suspicious(value: str) -> bool:
    return bool(value and SUSPICIOUS_RE.search(value))


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(24)
        session["csrf_token"] = token
    return token


def verify_csrf(token: str) -> bool:
    current = session.get("csrf_token")
    return bool(token and current and token == current)


def rate_limit_ok(client_id: str, window_sec: int, max_count: int) -> bool:
    now = time.time()
    entries = _request_log.get(client_id, [])
    entries = [x for x in entries if now - x < window_sec]
    if len(entries) >= max_count:
        _request_log[client_id] = entries
        return False
    entries.append(now)
    _request_log[client_id] = entries
    return True


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.")
            return redirect(url_for("user_login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(role: str):
    def deco(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in first.")
                return redirect(url_for("admin_login" if role == "admin" else "user_login"))
            if session.get("role") != role:
                flash("Unauthorized access.")
                return redirect(url_for("home"))
            return view(*args, **kwargs)

        return wrapped

    return deco


def client_id() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
