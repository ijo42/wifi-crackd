"""Сессия админа (подписанная cookie itsdangerous) и API-токены (wfk_…, sha256)."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import config as cfg

SESSION_COOKIE = "crackd_session"
SESSION_MAX_AGE = 12 * 3600

_serializer: URLSafeTimedSerializer | None = None


def _ser() -> URLSafeTimedSerializer:
    global _serializer
    if _serializer is None:
        if not cfg.SECRET_KEY:
            raise RuntimeError("SECRET_KEY is not set")
        _serializer = URLSafeTimedSerializer(cfg.SECRET_KEY, salt="crackd-admin")
    return _serializer


# ---------- сессия ----------

def make_session_token() -> str:
    return _ser().dumps({"role": "admin", "iat": int(time.time())})


def verify_session_token(token: str) -> bool:
    try:
        data = _ser().loads(token, max_age=SESSION_MAX_AGE)
        return isinstance(data, dict) and data.get("role") == "admin"
    except BadSignature:
        return False


def check_admin_password(password: str) -> bool:
    if not cfg.ADMIN_PASSWORD:
        return False
    return hmac.compare_digest(password.encode(), cfg.ADMIN_PASSWORD.encode())


# ---------- API-токены ----------

def token_key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_token_key() -> str:
    return "wfk_" + secrets.token_hex(16)


# ---------- job secret ----------

def job_secret_hash(secret: str) -> str:
    return token_key_hash("job:" + secret)


def new_job_secret() -> str:
    return secrets.token_hex(24)


# ---------- вспомогательное ----------

def client_ip(request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
