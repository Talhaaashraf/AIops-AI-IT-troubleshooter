"""Shared-password session auth for the dashboard.

This is a single-operator local tool, not a multi-user system, so there is
no user table — just one shared password gating the whole dashboard. When
DASHBOARD_PASSWORD (or, as a fallback, ADMIN_API_KEY) is set in .env, a
signed session cookie is required to reach the UI and its APIs. When neither
is set, the dashboard stays open exactly as it always has, so a fresh clone
still works out of the box.
"""

import hashlib
import hmac
import os

SESSION_COOKIE_NAME = "sentinel_session"


def _dashboard_password():
    return os.getenv("DASHBOARD_PASSWORD", "").strip() or os.getenv("ADMIN_API_KEY", "").strip()


def auth_enabled():
    return bool(_dashboard_password())


def session_token():
    password = _dashboard_password()
    return hmac.new(password.encode("utf-8"), b"sentinel-dashboard-session", hashlib.sha256).hexdigest()


def _same(provided, expected):
    """Constant-time comparison of bytes: compare_digest raises TypeError (a 500) on non-ASCII strings."""
    return hmac.compare_digest(provided.encode("utf-8", "surrogateescape"), expected.encode("utf-8", "surrogateescape"))


def check_password(candidate):
    password = _dashboard_password()
    return bool(password) and _same(candidate.strip(), password)


def has_valid_session(cookies):
    if not auth_enabled():
        return True
    return _same(cookies.get(SESSION_COOKIE_NAME, ""), session_token())


# Agent-facing endpoints authenticate with their own agent/enrollment token, not the
# dashboard cookie, so the session gate must let them through.
# Exact paths, plus prefixes that end in "/": a device id such as "report1" must never make
# /api/agents/report1/... public by sharing a prefix with an agent route.
PUBLIC_PATHS = frozenset({"/login", "/logout", "/api/agents/register", "/api/agents/report", "/api/agents/bundle"})
PUBLIC_PATH_PREFIXES = ("/static/", "/install/", "/api/agents/tasks/", "/api/agents/binary/")


def is_public_path(path):
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PATH_PREFIXES)
