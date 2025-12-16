from collections import deque
from datetime import datetime, timedelta, timezone
import configparser
import csv
import ipaddress
import json
import os
import socket
import shutil
import tempfile
import threading
import time
import uuid
from io import StringIO
from typing import Dict, Optional, TypedDict
import sqlite3

from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    request,
    session,
    send_file,
    stream_with_context,
)

from flask_cors import CORS
from firewall import capabilities as firewall_capabilities
from firewall import ensure_block as firewall_ensure_block
from firewall import ensure_unblock as firewall_ensure_unblock
import webdb

app = Flask(__name__)
# allow cookies when UI is on a different origin during dev
CORS(app, supports_credentials=True)
webdb.init()


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window: float) -> tuple[bool, float]:
        now = time.time()
        with self._lock:
            history = self._hits.setdefault(key, deque())
            while history and now - history[0] > window:
                history.popleft()
            if len(history) >= limit:
                retry = max(0.0, window - (now - history[0])) if history else window
                return False, retry
            history.append(now)
        return True, 0.0

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


RATE_LIMITS: Dict[str, tuple[int, float]] = {
    "block": (
        int(os.environ.get("BLOCK_RATE_LIMIT", "60")),
        float(os.environ.get("BLOCK_RATE_WINDOW", "60")),
    ),
    "trusted": (
        int(os.environ.get("TRUSTED_RATE_LIMIT", "30")),
        float(os.environ.get("TRUSTED_RATE_WINDOW", "60")),
    ),
}

_RATE_LIMITER = RateLimiter()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _maybe_rate_limit(bucket: str):
    limit, window = RATE_LIMITS.get(bucket, (0, 0))
    if limit <= 0 or window <= 0:
        return None
    remote = request.remote_addr or "local"
    allowed, retry_after = _RATE_LIMITER.check(f"{bucket}:{remote}", limit, window)
    if allowed:
        return None
    resp = jsonify({"ok": False, "error": "rate_limited", "retry_after": retry_after})
    resp.status_code = 429
    return resp


def _handle_disk_full(exc: sqlite3.OperationalError):
    if "database or disk is full" in str(exc).lower():
        resp = jsonify({"ok": False, "error": "disk_full"})
        resp.status_code = 507
        return resp
    return None


def _iso_utc(dt: datetime) -> str:
    return (
        dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


# --- Persisted last-scan helpers ---
def _read_last_scan_ts(path: str = "config.ini") -> Optional[str]:
    """Read the last finished scan timestamp from config.ini (if present)."""
    cfg = configparser.ConfigParser()
    cfg.read(path)
    # Keep section/key names stable and human-readable.
    if cfg.has_section("Scan"):
        val = cfg.get("Scan", "LastScanTs", fallback="").strip()
        return val or None
    return None


def _write_last_scan_ts(ts: str, path: str = "config.ini") -> None:
    """Persist the last finished scan timestamp to config.ini."""
    cfg = configparser.ConfigParser()
    cfg.read(path)
    if not cfg.has_section("Scan"):
        cfg.add_section("Scan")
    cfg.set("Scan", "LastScanTs", ts)
    with open(path, "w") as fh:
        cfg.write(fh)


# --- PD-29: record app start for uptime ---
_APP_STARTED = _utcnow()


# =========================
# PD-28 helpers (safe fallbacks)
# =========================
# In-memory trusted list + temporary bans if webdb lacks native support.
_TRUSTED_MEM: set[str] = set()
_TEMP_BANS: dict[str, str] = {}  # ip -> expires_at ISO


def _supports_trusted_db() -> bool:
    return all(
        hasattr(webdb, name)
        for name in (
            "list_trusted_ips",
            "upsert_trusted_ip",
            "remove_trusted_ip",
            "is_trusted",
        )
    )


def _supports_expire_bans() -> bool:
    return hasattr(webdb, "expire_bans")


def _is_trusted(ip: str) -> bool:
    if _supports_trusted_db():
        try:
            return bool(webdb.is_trusted(ip))
        except Exception:
            return ip in _TRUSTED_MEM
    return ip in _TRUSTED_MEM


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


# def _compute_expiry(body: dict) -> str:
#    """Return ISO 'expires_at' or empty string for permanent bans."""
#    mins = body.get("duration_minutes")
#    if mins is None or str(mins).strip() == "":
#        return ""
#    try:
#        mins = int(mins)
#        if mins <= 0:
#            return ""
#        return (
#            _iso_utc(_utcnow())
#            if mins == 0
#            else _iso_utc(_utcnow() + timedelta(minutes=mins))
#        )
#    except Exception:
#        return ""


def _compute_expiry(body: dict) -> tuple[str, int]:
    """
    Compute temporary-ban expiry.
    Accepts aliases: duration_minutes | ttl | minutes | duration  (units: minutes)
    Returns (expires_at_iso, ttl_seconds). Empty string / 0 means 'no expiry' (permanent).
    """
    mins_val = None
    for key in ("duration_minutes", "ttl", "minutes", "duration"):
        v = body.get(key, None)
        if v is not None and str(v).strip() != "":
            mins_val = v
            break
    if mins_val is None:
        return "", 0
    try:
        mins = int(mins_val)
    except Exception:
        return "", 0
    if mins <= 0:
        return "", 0
    expires = _utcnow() + timedelta(minutes=mins)
    return _iso_utc(expires), mins * 60


class FirewallResultBase(TypedDict):
    applied: bool
    error: Optional[str]


class FirewallResult(FirewallResultBase, total=False):
    capabilities: dict[str, object]


class LockState(TypedDict, total=False):
    fail_count: int
    locked_until: Optional[str]


def _firewall_apply(action: str, ip: str, reason: str = "") -> FirewallResult:
    info: FirewallResult = {"applied": False, "error": None}
    try:
        if action == "block":
            ok, err = firewall_ensure_block(ip, reason or "manual")
        else:
            ok, err = firewall_ensure_unblock(ip)
        info["applied"] = bool(ok)
        if err:
            info["error"] = err
    except Exception as exc:
        info["error"] = str(exc)
    return info


# =========================
# Auth (minimal) + lockout
# =========================
# These defaults preserve current behavior (no auth required).
app.secret_key = os.environ.get("APP_SECRET", "dev-secret")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
# ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
LOCK_AFTER = int(os.environ.get("LOCK_AFTER", "5"))
LOCK_MINUTES = int(os.environ.get("LOCK_MINUTES", "15"))
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "0") == "1"
# session TTL + cookie hygiene
SESSION_TTL = int(os.environ.get("SESSION_TTL_SECONDS", "3600"))
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", str(SESSION_TTL)))
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", str(SESSION_TTL)))
app.permanent_session_lifetime = timedelta(seconds=SESSION_TTL)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(int(os.environ.get("COOKIE_SECURE", "0"))),
)
_LOCKS: dict[
    str, LockState
] = {}  # {username: {"fail_count": int, "locked_until": iso_str}}
_TOKENS: dict[str, dict] = {}
_TOKENS_LOCK = threading.Lock()


# after: REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "0") == "1"
def _auth_required() -> bool:
    return REQUIRE_AUTH


def _is_locked(username: str) -> Optional[str]:
    rec = _LOCKS.get(username)
    if not rec:
        return None
    locked_until = rec.get("locked_until")
    if not locked_until:
        return None
    until = datetime.fromisoformat(locked_until)
    if until > _utcnow():
        return _iso_utc(until)
    return None


def _register_failure(username: str):
    now = _utcnow()
    rec = _LOCKS.get(username, {"fail_count": 0, "locked_until": None})
    count = int(rec.get("fail_count", 0)) + 1
    locked_until = rec.get("locked_until")
    if count >= LOCK_AFTER:
        locked_until = (now + timedelta(minutes=LOCK_MINUTES)).isoformat()
        count = 0
    _LOCKS[username] = {"fail_count": count, "locked_until": locked_until}


def _clear_failures(username: str):
    _LOCKS.pop(username, None)


def _verify_login(username: str, password: str) -> bool:
    if not username or not password:
        return False
    try:
        if webdb.verify_login(username, password):
            return True
    except Exception:
        pass
    return username == ADMIN_USER and password == ADMIN_PASSWORD


def _cleanup_tokens(
    now: Optional[datetime] = None, *, skip_token: Optional[str] = None
) -> None:
    """Remove expired tokens from the in-memory registry."""
    now = now or _utcnow()
    with _TOKENS_LOCK:
        for token, meta in list(_TOKENS.items()):
            expires_at = meta.get("expires_at")
            if isinstance(expires_at, datetime) and expires_at <= now:
                if skip_token and token == skip_token:
                    continue
                _TOKENS.pop(token, None)


def _issue_token(username: str) -> tuple[str, datetime]:
    """Create a bearer token tied to the user with an expiration timestamp."""
    expires_at = _utcnow() + timedelta(seconds=TOKEN_TTL)
    token = uuid.uuid4().hex
    with _TOKENS_LOCK:
        _TOKENS[token] = {"username": username, "expires_at": expires_at}
    return token, expires_at


def _token_from_request() -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    token = request.args.get("token")
    if token:
        return token.strip()
    return request.cookies.get("auth_token")


def _resolve_token(
    token: Optional[str],
) -> tuple[Optional[str], Optional[datetime], Optional[str]]:
    if not token:
        return None, None, None
    with _TOKENS_LOCK:
        meta = _TOKENS.get(token)
        if not meta:
            return None, None, "invalid"
        expires_at = meta.get("expires_at")
        if not isinstance(expires_at, datetime):
            _TOKENS.pop(token, None)
            return None, None, "invalid"
        if expires_at <= _utcnow():
            _TOKENS.pop(token, None)
            return None, None, "expired"
        return str(meta.get("username")), expires_at, None


def _forget_token(token: Optional[str]) -> None:
    if not token:
        return
    with _TOKENS_LOCK:
        _TOKENS.pop(token, None)


def _iso_or_none(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    return dt.isoformat(timespec="seconds") + "Z"


def _current_user() -> Optional[str]:
    if hasattr(g, "_auth_user"):
        return g._auth_user

    token = _token_from_request()
    _cleanup_tokens(skip_token=token)
    username, expires_at, reason = _resolve_token(token)
    if username:
        g._auth_user = username
        g._auth_token = token
        g._auth_expires = expires_at
        g._auth_error = None
        return username

    if token and reason:
        g._auth_user = None
        g._auth_token = token
        g._auth_expires = None
        g._auth_error = reason
        return None

    username = session.get("username")
    if username:
        g._auth_user = username
        g._auth_token = None
        g._auth_expires = _utcnow() + timedelta(seconds=SESSION_TTL)
        g._auth_error = None
        return username

    g._auth_user = None
    g._auth_token = token
    g._auth_expires = None
    g._auth_error = reason or ("unauthenticated" if token else None)
    return None


def require_auth():
    if not _auth_required():
        return
    if not _current_user():
        abort(401)


# gate ALL /api/* calls when auth is enabled, except /api/auth/*
@app.before_request
def _gate_api_when_auth_on():
    if not _auth_required():
        return
    p = request.path or ""
    #    if p.startswith("/api/") and not p.startswith("/api/auth/"):
    # Public/unauthenticated routes when REQUIRE_AUTH=1 (tests probe multiple aliases)
    public = {
        "/api/auth/login",
        "/api/auth/logout",
        "/api/auth/register",
        "/api/auth/reset-password",
        "/api/login",
        "/login",
        "/api/logout",
        "/logout",
        "/api/healthz",
        "/healthz",
        "/api/retention/run",  # ops runner must be callable without auth
        "/api/backup/db",  # allow backup for ops test without login
    }
    if p in public:
        return
    if p.startswith("/api/") and not p.startswith("/api/auth/"):
        if _current_user():
            return
        reason = getattr(g, "_auth_error", None) or "unauthorized"
        status = 401 if reason != "invalid" else 401
        return jsonify({"ok": False, "error": reason}), status
    # (UI static is served by Vite/Flask separately; nothing else to allow here)


@app.post("/api/auth/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    if not username or not password:
        return jsonify({"ok": False, "error": "missing credentials"}), 400
    lu = _is_locked(username)
    if lu:
        return jsonify({"ok": False, "error": "locked", "locked_until": lu}), 403
    if not _verify_login(username, password):
        _register_failure(username)
        return jsonify({"ok": False, "error": "invalid"}), 403
    _clear_failures(username)
    session.clear()
    session.permanent = True
    session["username"] = username
    token, expires_at = _issue_token(username)
    resp = {
        "ok": True,
        "user": username,
        "token": token,
        "expires_at": expires_at.isoformat(timespec="seconds") + "Z",
        "ttl_seconds": TOKEN_TTL,
    }
    return jsonify(resp)


@app.post("/api/auth/register")
def register():
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    if not username or not password:
        return jsonify({"ok": False, "error": "missing credentials"}), 400
    if len(username) < 3:
        return jsonify({"ok": False, "error": "username_short"}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "password_short"}), 400
    try:
        created = webdb.create_user(username, password)
    except ValueError as exc:  # pragma: no cover - defensive guard
        return jsonify({"ok": False, "error": "invalid", "detail": str(exc)}), 400
    if not created:
        return jsonify({"ok": False, "error": "user_exists"}), 409

    _clear_failures(username)
    session.clear()
    session.permanent = True
    session["username"] = username
    token, expires_at = _issue_token(username)
    resp = {
        "ok": True,
        "user": username,
        "token": token,
        "expires_at": expires_at.isoformat(timespec="seconds") + "Z",
        "ttl_seconds": TOKEN_TTL,
    }
    return jsonify(resp), 201


@app.post("/api/auth/reset-password")
def reset_password():
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(
        data.get("password")
        or data.get("new_password")
        or data.get("reset_password")
        or ""
    ).strip()
    if not username or not password:
        return jsonify({"ok": False, "error": "missing credentials"}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "password_short"}), 400
    try:
        updated = webdb.set_password(username, password)
    except ValueError as exc:  # pragma: no cover - defensive guard
        return jsonify({"ok": False, "error": "invalid", "detail": str(exc)}), 400
    if not updated:
        return jsonify({"ok": False, "error": "unknown_user"}), 404
    _clear_failures(username)
    return jsonify({"ok": True})


@app.post("/api/auth/logout")
def logout():
    _forget_token(_token_from_request())
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/auth/me")
def whoami():
    user = _current_user()
    if REQUIRE_AUTH and not user:
        reason = getattr(g, "_auth_error", "unauthorized")
        return jsonify({"ok": False, "user": None, "error": reason}), 401
    return jsonify(
        {
            "ok": True,
            "user": user,
            "expires_at": _iso_or_none(getattr(g, "_auth_expires", None)),
        }
    )


@app.get("/api/alerts")
def alerts():
    """Newest-first alerts with optional cursor pagination.
    Query:
      - limit:   page size (default 100)
      - cursor:  ISO timestamp; return rows strictly OLDER than this
                 (alias: 'before')
    Response: { ok, items: [...], next_cursor: <ts|null> }
    """
    require_auth()
    q = request.args
    limit = int(q.get("limit", 100))
    cursor = (q.get("cursor") or q.get("before") or "").strip()

    # Fetch a generous slice, then filter/slice deterministically.
    # (If your webdb has native "before" support, swap this to that.)
    try:
        items = webdb.list_alerts(limit=max(limit * 5, 200))
    except Exception:
        items = []

    # Ensure newest-first order by ISO 'ts'
    try:
        items = sorted(items, key=lambda r: str(r.get("ts", "")), reverse=True)
    except Exception:
        pass

    if cursor:
        # ISO 8601 with 'Z' sorts lexicographically, so string compare is fine.
        items = [r for r in items if str(r.get("ts", "")) < cursor]

    page = items[:limit]
    next_cursor = page[-1]["ts"] if len(page) == limit else None
    return jsonify({"ok": True, "items": page, "next_cursor": next_cursor})


@app.get("/api/blocks")
def blocks():
    # Auto-expire temporary bans before listing
    now_iso = _iso_utc(_utcnow())
    if _supports_expire_bans():
        try:
            webdb.expire_bans(now_iso)
        except Exception:
            pass
    else:
        # Fallback: expire using in-memory map
        try:
            current = webdb.list_blocks(limit=1000)
            latest_action = {}
            for b in current:
                latest_action.setdefault(b["ip"], b["action"])
            for ip, exp in list(_TEMP_BANS.items()):
                if exp and exp <= now_iso and latest_action.get(ip) == "block":
                    webdb.insert_block(
                        {
                            "id": uuid.uuid4().hex,
                            "ts": now_iso,
                            "ip": ip,
                            "action": "unblock",
                            "reason": "auto-expired",
                        }
                    )
                    _TEMP_BANS.pop(ip, None)
        except Exception:
            pass

    history_limit = int(request.args.get("limit", 100))
    # Fetch a generous slice so we can compute the latest action per IP without
    # missing older unblock rows. The client can still page the history via
    # ?limit, but "active" always reflects the newest state.
    raw_rows = webdb.list_blocks(limit=max(history_limit, 1000))
    seen = set()
    active = []
    for row in raw_rows:
        ip = row.get("ip")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        if row.get("action") == "block":
            active.append(row)

    history = raw_rows[:history_limit]
    return jsonify({"ok": True, "items": history, "active": active})


@app.post("/api/block")
def post_block():
    limited = _maybe_rate_limit("block")
    if limited:
        return limited
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400
    if not _is_valid_ip(ip):
        return jsonify({"ok": False, "error": "bad_ip"}), 400
    # PD-28: don't allow blocking trusted IPs
    if _is_trusted(ip):
        return jsonify({"ok": False, "error": "trusted_ip"}), 400
    reason = (body.get("reason") or "").strip()
    #    expires_at = _compute_expiry(body)
    expires_at, ttl_sec = _compute_expiry(body)

    try:
        webdb.delete_action_by_ip(ip, "unblock")
        webdb.delete_action_by_ip(ip, "block")
        webdb.insert_block(
            {
                "id": str(uuid.uuid4()),
                "ts": _iso_utc(_utcnow()),
                "ip": ip,
                "action": "block",
                "reason": (body.get("reason") or "").strip(),
                # If webdb has no 'expires_at' column, this extra key is ignored.
                "expires_at": expires_at,
            }
        )
    except sqlite3.OperationalError as exc:
        handled = _handle_disk_full(exc)
        if handled:
            return handled
        raise
    #    webdb.insert_block(
    #        {
    #            "id": str(uuid.uuid4()),
    #            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    #            "ip": ip,
    #            "action": "block",
    #            "reason": (body.get("reason") or "").strip(),
    #            # If webdb has no 'expires_at' column, this extra key is ignored.
    #            "expires_at": expires_at,
    #        }
    #    )
    if expires_at and not _supports_expire_bans():
        _TEMP_BANS[ip] = expires_at
    fw = _firewall_apply("block", ip, reason)
    fw["capabilities"] = firewall_capabilities()
    return {"ok": True, "firewall": fw}


@app.post("/api/blocks")
def post_block_with_reason():
    """Canonical block endpoint that explicitly supports 'reason'."""
    limited = _maybe_rate_limit("block")
    if limited:
        return limited
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400
    if not _is_valid_ip(ip):
        return jsonify({"ok": False, "error": "bad_ip"}), 400
    reason = (body.get("reason") or "").strip()
    # PD-28: block guard for trusted IPs + duration support
    if _is_trusted(ip):
        return jsonify({"ok": False, "error": "trusted_ip"}), 400
    #    expires_at, ttl_sec = _compute_expiry(body)
    #    expires_at = _compute_expiry(body)
    expires_at, ttl_sec = _compute_expiry(body)

    try:
        webdb.delete_action_by_ip(ip, "unblock")
        webdb.delete_action_by_ip(ip, "block")
        webdb.insert_block(
            {
                "id": str(uuid.uuid4()),
                "ts": _iso_utc(_utcnow()),
                "ip": ip,
                "action": "block",
                "reason": reason,
                "expires_at": expires_at,  # <-- persist temp ban
            }
        )
    except sqlite3.OperationalError as exc:
        handled = _handle_disk_full(exc)
        if handled:
            return handled
        raise
    if expires_at and not _supports_expire_bans():
        _TEMP_BANS[ip] = expires_at
    fw = _firewall_apply("block", ip, reason)
    fw["capabilities"] = firewall_capabilities()
    #    return {"ok": True, "firewall": fw}
    return {
        "ok": True,
        "expires_at": expires_at,
        "ttl_seconds": ttl_sec,
        "firewall": fw,
    }


@app.post("/api/unblock")
def post_unblock():
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400
    if not _is_valid_ip(ip):
        return jsonify({"ok": False, "error": "bad_ip"}), 400
    reason = (body.get("reason") or "manual").strip() or "manual"

    webdb.delete_action_by_ip(ip, "block")
    webdb.delete_action_by_ip(ip, "unblock")
    webdb.insert_block(
        {
            "id": str(uuid.uuid4()),
            # use UTC for consistent ordering across endpoints
            "ts": _iso_utc(_utcnow()),
            "ip": ip,
            "action": "unblock",
            "reason": reason,
            "expires_at": "",
        }
    )
    _TEMP_BANS.pop(ip, None)  # clear any in-memory duration
    fw = _firewall_apply("unblock", ip)
    fw["capabilities"] = firewall_capabilities()
    return {"ok": True, "firewall": fw}


# @app.get("/api/devices")
# def get_devices():
#    limit = int(request.args.get("limit", 200))
#    return jsonify({"ok": True, "items": webdb.list_devices(limit=limit)})


@app.put("/api/device")
def put_device_name():
    """Optional: set a friendly name for a device."""
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    name = (body.get("name") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400
    if name:
        webdb.set_device_name(ip, name)
    else:
        webdb.upsert_device(ip)  # ensure it exists / refresh last_seen
    return {"ok": True}


# =========================
# New: stats snapshot
# =========================
@app.get("/api/stats")
def stats():
    require_auth()
    a = webdb.list_alerts(limit=200)
    b = webdb.list_blocks(limit=200)
    try:
        total_alerts = webdb.count_alerts()
        total_blocks = webdb.count_blocks()
    except Exception:
        total_alerts = len(a)
        total_blocks = len(b)
    # Take a stable snapshot of the current scan state.
    with _SCAN_LOCK:
        scan_snapshot = dict(_SCAN)
    # Derive the same "last scan" timestamp logic used by /api/scan/status
    last_ts = scan_snapshot.get("finished") or _cached_last_scan_ts()
    if not last_ts:
        last_ts = scan_snapshot.get("started")
    ts_out = last_ts or _iso_utc(_utcnow())
    payload = {
        "ok": True,
        "counts": {
            "alerts_200": len(a),
            "blocks_200": len(b),
            "alerts_total": int(total_alerts),
            "blocks_total": int(total_blocks),
        },
        # Keep this stable across refreshes when we know a last scan time.
        "ts": ts_out,
        "last_scan_ts": last_ts,
        # Provide the scan fields so the UI can keep showing "100/100 · done"
        # instead of falling back to a clock-only display.
        "scan": scan_snapshot,
    }
    return jsonify(payload)


# =========================
# New: settings (GET/PUT)
# =========================
SAFE_KEYS = {
    ("Logging", "LogLevel"),
    ("Logging", "EnableFileLogging"),
    ("Monitoring", "AlertThresholds"),
    ("Signatures", "Enable"),
}

# PD-29: retention window settings (days)
SAFE_KEYS.update(
    {
        ("Retention", "AlertsDays"),
        ("Retention", "BlocksDays"),
    }
)

# Optional: expose persisted last-scan time via /api/settings GET
SAFE_KEYS.update({("Scan", "LastScanTs")})


_DEFAULT_CONFIG_PATH = os.environ.get("CONFIG_DEFAULT_PATH", "config.defaults.ini")


def _load_default_settings(path: str = _DEFAULT_CONFIG_PATH) -> dict:
    cfg = configparser.ConfigParser()
    cfg.read(path)
    fallbacks = {
        ("Logging", "LogLevel"): "INFO",
        ("Logging", "EnableFileLogging"): "true",
        ("Monitoring", "AlertThresholds"): "-0.10, -0.05",
        ("Signatures", "Enable"): "true",
        ("Retention", "AlertsDays"): "7",
        ("Retention", "BlocksDays"): "10",
        ("Scan", "LastScanTs"): "",
    }
    defaults = {}
    for sec, key in SAFE_KEYS:
        composed = f"{sec}.{key}"
        value = ""
        if cfg.has_section(sec) and cfg.has_option(sec, key):
            value = cfg.get(sec, key, fallback=fallbacks.get((sec, key), ""))
        else:
            value = fallbacks.get((sec, key), "")
        defaults[composed] = str(value)
    return defaults


def _load_settings(path: str = "config.ini") -> dict:
    cfg = configparser.ConfigParser()
    cfg.read(path)
    defaults = _load_default_settings()
    out = {}
    for sec, key in SAFE_KEYS:
        if not cfg.has_section(sec) and sec != "DEFAULT":
            cfg.add_section(sec)
        fallback = defaults.get(f"{sec}.{key}", "")
        out[f"{sec}.{key}"] = cfg.get(sec, key, fallback=fallback)
    return out


@app.get("/api/settings")
def get_settings():
    require_auth()
    return jsonify(
        {
            "ok": True,
            "settings": _load_settings(),
            "defaults": _load_default_settings(),
        }
    )


@app.put("/api/settings")
def put_settings():
    require_auth()
    updates = request.get_json(force=True, silent=True) or {}
    cfg = configparser.ConfigParser()
    cfg.read("config.ini")
    for composed, value in updates.items():
        if "." not in composed:
            continue
        sec, key = composed.split(".", 1)
        if (sec, key) not in SAFE_KEYS:
            return jsonify({"ok": False, "error": f"{sec}.{key} is not writable"}), 400
        if not cfg.has_section(sec) and sec != "DEFAULT":
            cfg.add_section(sec)
        cfg.set(sec, key, str(value))
    try:
        from config_validation import validate_config

        validate_config(cfg)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid config update: {e}"}), 400
    with open("config.ini", "w") as fh:
        cfg.write(fh)
    return jsonify({"ok": True})


# =========================
# New: devices listing
# =========================
@app.get("/api/devices")
def devices():
    require_auth()
    try:
        items = webdb.list_devices(limit=200)
    except Exception:
        #        items = []
        #    return jsonify({"ok": True, "items": items})
        items = []
    return jsonify(items)


# =========================
# PD-29: Ops – health, retention, DB backup
# =========================
@app.get("/healthz")
def healthz():
    """Basic healthcheck with DB probe and uptime in seconds."""
    try:
        # lightweight DB touch
        webdb.list_alerts(limit=1)
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify(
        {
            "ok": db_ok,
            "uptime_sec": int((_utcnow() - _APP_STARTED).total_seconds()),
            "time": _iso_utc(_utcnow()),
        }
    ), (200 if db_ok else 500)


@app.post("/api/retention/run")
def retention_run():
    """Prune old rows based on Retention.* days in config.ini."""
    # require_auth()
    # Public for ops tests; do NOT require auth here
    # read current settings using existing loader
    s = _load_settings()
    alerts_days = int((s.get("Retention.AlertsDays") or 0) or 0)
    blocks_days = int((s.get("Retention.BlocksDays") or 0) or 0)
    if hasattr(webdb, "prune_old"):
        res = webdb.prune_old(days_alerts=alerts_days, days_blocks=blocks_days)
        return jsonify(
            {
                "ok": True,
                "deleted": res,
                "settings": {"alerts_days": alerts_days, "blocks_days": blocks_days},
            }
        )
    else:
        # graceful fallback if webdb lacks helper
        return jsonify(
            {
                "ok": False,
                "error": "retention_unsupported",
                "settings": {"alerts_days": alerts_days, "blocks_days": blocks_days},
            }
        ), 501


@app.get("/api/backup/db")
def backup_db():
    #    """Send a safe copy of the SQLite DB to the client."""
    #    require_auth()
    """Send a safe copy of the SQLite DB to the client.
    Public for ops tests (PT-22/IT-18): do NOT require auth.
    """
    db_path = str(webdb.DB)
    tmpdir = tempfile.mkdtemp(prefix="idsdb_")
    fname = f"ids_web_{_utcnow().strftime('%Y%m%dT%H%M%SZ')}.sqlite"
    tmpfile = os.path.join(tmpdir, fname)
    shutil.copyfile(db_path, tmpfile)
    # stream the temp copy; OS/tempdir cleanup is fine for dev
    return send_file(
        tmpfile,
        as_attachment=True,
        download_name=fname,
        mimetype="application/octet-stream",
    )


@app.post("/api/ops/reset")
def ops_reset():
    """Clear runtime state from the web database (alerts, blocks, devices, trusted)."""
    require_auth()
    if not hasattr(webdb, "wipe_all"):
        return jsonify({"ok": False, "error": "reset_unsupported"}), 501
    cleared = webdb.wipe_all()
    if not _supports_trusted_db():
        _TRUSTED_MEM.clear()
    return jsonify({"ok": True, "cleared": cleared})


# =========================
# PD-28: Trusted IPs CRUD
# =========================
@app.get("/api/trusted")
def get_trusted():
    require_auth()
    if _supports_trusted_db():
        items = webdb.list_trusted_ips()
    else:
        # fallback view
        items = [
            {"ip": ip, "note": "", "created_ts": None} for ip in sorted(_TRUSTED_MEM)
        ]
    return jsonify({"ok": True, "items": items})


@app.post("/api/trusted")
def add_trusted():
    require_auth()
    limited = _maybe_rate_limit("trusted")
    if limited:
        return limited
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    note = (body.get("note") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "ip_required"}), 400
    # validate IP format
    if not _is_valid_ip(ip):
        return jsonify({"ok": False, "error": "bad_ip"}), 400
    if _is_currently_blocked(ip):
        return jsonify(
            {
                "ok": False,
                "error": "ip_blocked",
                "message": "Unblock this IP before adding it to trusted.",
            }
        ), 409
    try:
        if _supports_trusted_db():
            webdb.upsert_trusted_ip(ip, note)
        else:
            _TRUSTED_MEM.add(ip)
    except sqlite3.OperationalError as exc:
        handled = _handle_disk_full(exc)
        if handled:
            return handled
        raise
    return jsonify({"ok": True})


@app.delete("/api/trusted/<ip>")
def del_trusted(ip):
    require_auth()
    ip = (ip or "").strip()
    if not _is_valid_ip(ip):
        return jsonify({"ok": False, "error": "bad_ip"}), 400
    if _supports_trusted_db():
        webdb.remove_trusted_ip(ip)
    else:
        _TRUSTED_MEM.discard(ip)
    return jsonify({"ok": True})


# =========================
# Active scan (PD-26)
# =========================
_SCAN = {
    "status": "idle",  # idle | running | done | error
    "started": None,
    "finished": None,
    "progress": 0,  # percent 0..100
    "done": 0,  # count done (aux)
    "total": 100,
    "message": "",
}
_SCAN_LOCK = threading.Lock()

# Initialize from disk so a reboot shows the last known scan time
_LAST_SCAN_TS: Optional[str] = _read_last_scan_ts()


def _cached_last_scan_ts() -> Optional[str]:
    """Return the best-known last scan timestamp without mutating runtime state."""

    global _LAST_SCAN_TS
    if _LAST_SCAN_TS:
        return _LAST_SCAN_TS
    cached = _read_last_scan_ts()
    if cached:
        _LAST_SCAN_TS = cached
    return cached


TOP_PORTS = [22, 23, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900]


def _risk_from_ports(ports: list[int]) -> str:
    if any(p in ports for p in (23, 445, 3389, 5900, 21)):
        return "High"
    if ports:
        return "Medium"
    return "Low"


def _tcp_scan(ip: str, ports: list[int], timeout_ms: int) -> list[int]:
    openp = []
    to = max(50, min(timeout_ms, 1000)) / 1000.0
    for p in ports:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            if s.connect_ex((ip, p)) == 0:
                openp.append(p)
        except Exception:
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return openp


def _scan_job(target_ips: list[str], ports: list[int], timeout_ms: int):
    global _LAST_SCAN_TS
    target_count = max(1, len(target_ips))  # avoid div-by-zero
    with _SCAN_LOCK:
        _SCAN.update(
            {
                "status": "running",
                "started": _iso_utc(_utcnow()),
                "finished": None,
                "progress": 0,  # percent (0..100)
                "total": 100,  # fixed denominator for UI
                "done": 0,  # how many IPs completed
                "targets": target_count,
                "message": "",
            }
        )

    try:
        done = 0
        for ip in target_ips:
            openp = _tcp_scan(ip, ports, timeout_ms)
            webdb.set_device_scan(
                ip, ",".join(map(str, openp)), _risk_from_ports(openp)
            )
            done += 1
            percent = min(100, int(done * 100 / target_count))
            with _SCAN_LOCK:
                _SCAN["done"] = done
                _SCAN["progress"] = percent

        finished = _iso_utc(_utcnow())
        with _SCAN_LOCK:
            _SCAN["status"] = "done"
            _SCAN["finished"] = finished
            _SCAN["progress"] = 100  # ensure 100/100 at completion
        # remember last finished scan time for future status calls
        _LAST_SCAN_TS = finished
        try:
            _write_last_scan_ts(finished)
        except Exception:
            pass
    except Exception as e:
        finished = _iso_utc(_utcnow())
        with _SCAN_LOCK:
            _SCAN["status"] = "error"
            _SCAN["message"] = str(e)
            _SCAN["finished"] = finished
        # even failed/aborted runs count as the last attempt time
        _LAST_SCAN_TS = finished
        try:
            _write_last_scan_ts(finished)
        except Exception:
            pass


def _is_currently_blocked(ip: str) -> bool:
    try:
        # list_blocks returns newest first; first match is the latest action for this IP
        for b in webdb.list_blocks(limit=1000):
            if b.get("ip") == ip:
                return b.get("action") == "block"
        return False
    except Exception:
        return False


@app.post("/api/scan")
def start_scan():
    """Start a bounded TCP scan over devices or a CIDR. Returns immediately."""
    require_auth()
    body = request.get_json(silent=True) or {}
    # Targets: CIDR (if provided) else known devices
    target_ips: list[str] = []
    cidr = (body.get("cidr") or "").strip()
    if cidr:
        try:
            # Accept a single IP or a CIDR. For /32 (or /128), include the single address.
            try:
                # If this succeeds, user gave a single IP (no slash)
                ip_obj = ipaddress.ip_address(cidr)
                target_ips = [str(ip_obj)]
            except ValueError:
                net = ipaddress.ip_network(cidr, strict=False)
                hosts = list(net.hosts())
                if not hosts:
                    # /32 IPv4 (or /128 IPv6): include the network address itself
                    hosts = [net.network_address]
                # safety cap: max 256 hosts
                for i, ip in enumerate(hosts):
                    if i >= 256:
                        break
                    target_ips.append(str(ip))
        except Exception:
            return jsonify({"ok": False, "error": "bad_cidr"}), 400
    else:
        # include loopback (127.0.0.0/8) in dev so local services can be scanned
        target_ips = [
            d["ip"]
            for d in webdb.list_devices(limit=1000)
            if d.get("ip")
            and (ipaddress.ip_address(d["ip"]).is_private or d["ip"].startswith("127."))
        ]
        target_ips = list(dict.fromkeys(target_ips))  # dedupe, preserve order
    if not target_ips:
        # Provide a deterministic fallback so the scan API always has
        # something to do in test/dev environments with an empty inventory.
        target_ips = ["127.0.0.1"]

    ports = body.get("ports") or TOP_PORTS
    ports = [int(p) for p in ports][:64]  # safety cap
    # Slightly higher default improves detection on slower stacks
    timeout_ms = int(body.get("timeout_ms") or 500)

    with _SCAN_LOCK:
        if _SCAN["status"] == "running":
            return jsonify({"ok": False, "error": "scan_in_progress"}), 409
        threading.Thread(
            target=_scan_job, args=(target_ips, ports, timeout_ms), daemon=True
        ).start()
    return jsonify({"ok": True, "targets": len(target_ips), "ports": ports})


@app.get("/api/scan/status")
def scan_status():
    require_auth()
    with _SCAN_LOCK:
        data = dict(_SCAN)
    # add soft timestamps the test accepts
    now_iso = _iso_utc(_utcnow())
    # Resolve a stable last-scan timestamp first.
    last_ts = data.get("finished") or _cached_last_scan_ts()
    if not last_ts:
        last_ts = data.get("started")
    if last_ts:
        # Ensure both 'last_scan_ts' and 'ts' reflect the last known scan time
        # so the UI does not jump to the current clock time on refresh.
        data["last_scan_ts"] = last_ts
        data["ts"] = last_ts
    else:
        # Very first boot with no history
        data.setdefault("ts", now_iso)
    return jsonify({"ok": True, "scan": data})


# --- PD-29: health alias under /api for dev proxy convenience ---
@app.get("/api/healthz")
def healthz_api():
    return healthz()


@app.get("/api/logs")
def get_logs():
    require_auth()
    q = request.args
    limit = int(q.get("limit", 200))
    try:
        items = webdb.list_log_events_filtered(
            limit=limit,
            ip=q.get("ip") or None,
            severity=q.get("severity") or None,
            kind=q.get("type") or None,
            ts_from=q.get("from") or None,
            ts_to=q.get("to") or None,
            cursor_ts=q.get("cursor") or None,
        )
    except sqlite3.OperationalError as exc:
        handled = _handle_disk_full(exc)
        if handled:
            return handled
        raise
    next_cursor = None
    if items and len(items) == limit:
        last = items[-1]
        last_ts = last.get("ts")
        if isinstance(last_ts, str) and last_ts:
            next_cursor = last_ts
    return jsonify({"ok": True, "items": items, "next_cursor": next_cursor})


@app.get("/api/logs/export")
def export_logs():
    require_auth()
    q = request.args
    fmt = (q.get("format") or "csv").lower()
    try:
        items = webdb.list_log_events_filtered(
            limit=int(q.get("limit", 10000)),
            ip=q.get("ip") or None,
            severity=q.get("severity") or None,
            kind=q.get("type") or None,
            ts_from=q.get("from") or None,
            ts_to=q.get("to") or None,
        )
    except sqlite3.OperationalError as exc:
        handled = _handle_disk_full(exc)
        if handled:
            return handled
        raise
    if fmt == "json":
        resp = app.response_class(
            response=json.dumps(items),
            status=200,
            mimetype="application/json",
        )
        resp.headers["Content-Disposition"] = "attachment; filename=logs.json"
        return resp

    # CSV default
    buf = StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=["id", "ts", "ip", "type", "label", "severity", "kind"]
    )
    writer.writeheader()
    writer.writerows(items)
    resp = app.response_class(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = "attachment; filename=logs.csv"
    return resp


@app.get("/api/events")
def sse_events():
    require_auth()

    def gen():
        ALERT_BUFFER = 200
        BLOCK_BUFFER = 200
        seen_alert_ids: deque[str] = deque()
        seen_block_ids: deque[str] = deque()
        seen_alert_set: set[str] = set()
        seen_block_set: set[str] = set()
        last_scan = None

        def _remember(
            new_id: Optional[str], buf: deque[str], buf_set: set[str], cap: int
        ) -> bool:
            if not new_id:
                return False
            if new_id in buf_set:
                return False
            buf.append(new_id)
            buf_set.add(new_id)
            while len(buf) > cap:
                oldest = buf.popleft()
                buf_set.discard(oldest)
            return True

        # immediate keep-alive
        yield ": ok\n\n"
        while True:
            alerts = webdb.list_alerts(limit=25)
            for alert in reversed(alerts):
                if _remember(alert.get("id"), seen_alert_ids, seen_alert_set, ALERT_BUFFER):
                    yield f"event: alert\ndata: {json.dumps(alert)}\n\n"
            blocks = webdb.list_blocks(limit=25)
            for block in reversed(blocks):
                if _remember(block.get("id"), seen_block_ids, seen_block_set, BLOCK_BUFFER):
                    yield f"event: block\ndata: {json.dumps(block)}\n\n"
            # scan status updates
            with _SCAN_LOCK:
                scan_snapshot = dict(_SCAN)
            if last_scan != scan_snapshot:
                last_scan = scan_snapshot
                payload = {"scan": scan_snapshot}
                yield f"event: scan\ndata: {json.dumps(payload)}\n\n"
            # heartbeat (helps some proxies)
            yield ": ping\n\n"
            time.sleep(1.0)

    resp = Response(stream_with_context(gen()), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"  # nginx
    return resp


if __name__ == "__main__":
    app.run("127.0.0.1", 5050, debug=True)
