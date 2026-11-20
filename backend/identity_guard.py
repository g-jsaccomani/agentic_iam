"""Agentic IAM Accelerator — Verified Google Identity & Session Isolation Guard.

Enforces cryptographic Google identity verification for any authenticated Google user (`*` by default,
or restricted domains if `ALLOWED_IAP_DOMAINS` is explicitly set):
1. Cloud Run Identity-Aware Proxy (IAP) ES256 JWT (`X-Goog-IAP-JWT-Assertion`) with exact audience
   verification and 1-hour public key caching. IAP always takes precedence over browser cookies.
2. Signed HMAC-SHA256 `HttpOnly` session cookie (`iam_consultant_ticket`) carrying both the user's
   deterministic isolated workspace ID (`ws`) and a unique revocable per-cookie session ID (`sid`),
   minted ONLY after server-side verification of a Google OIDC ID token, Google OAuth2 access token,
   or Cloud Run IAP JWT.
3. Verified `Authorization: Bearer <token>` header with strict `aud`/`azp` allowlist validation and
   short-lived (<= 60s) SHA-256 hash-keyed verification caching.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from fastapi import HTTPException, Request, status
from google.auth import jwt as google_jwt
from google.auth.transport import requests as google_auth_requests
from google.oauth2 import id_token as google_id_token

from backend.workspace_store import (
    derive_workspace_id,
    get_master_secret_bytes,
    load_revoked_session_ids,
    save_revoked_session_ids,
)

logger = logging.getLogger(__name__)

GOOGLE_TOKENINFO_URI = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_USERINFO_URI = "https://openidconnect.googleapis.com/v1/userinfo"

IAM_SESSION_COOKIE = "iam_consultant_ticket"


def _configured_session_ttl_seconds() -> int:
    """Browser session cookie lifetime (`IAM_SESSION_TTL_SECONDS`, default 8 hours, bounded 5 minutes..30 days)."""
    try:
        val = int(os.getenv("IAM_SESSION_TTL_SECONDS", "28800"))
    except (TypeError, ValueError):
        val = 28800
    return max(300, min(30 * 24 * 3600, val))


# 8 hours by default. A short cookie costs nothing: the workspace is restored from the verified identity.
IAM_SESSION_TTL_SECONDS = _configured_session_ttl_seconds()
DEFAULT_OAUTH_CLIENT_ID = ""
IAP_CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"
IAP_ISSUER = "https://cloud.google.com/iap"

IAP_CERTS_CACHE_TTL_SECONDS = 3600.0  # Cache IAP public keys for 1 hour
IAP_CERTS_REFRESH_COOLDOWN_SECONDS = 60.0
BEARER_VERIFY_CACHE_TTL_SECONDS = 60.0  # Cache successful Bearer verifications up to 60s
BEARER_VERIFY_CACHE_MAX_SIZE = 2048
REVOKED_SIDS_MAX_SIZE = 8192

_HTTPS_ORIGIN_RE = re.compile(r"^https://([a-zA-Z0-9.-]+)(:\d+)?$")
_LOCAL_HTTP_ORIGIN_RE = re.compile(r"^http://(localhost|127\.0\.0\.1|testserver)(:\d+)?$")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "testserver"})

# Thread-safe in-memory revocation registry: cookie_sid -> unix epoch expiration
_REVOKED_SIDS_LOCK = threading.Lock()
_REVOKED_SIDS: Dict[str, float] = {}
# `workspace_id -> (fetched_monotonic, {sid: cookie_exp_epoch})`: revocations persisted in the user's workspace
# so that a logout survives a restart or redeploy. Re-read from the store at most once per minute per user.
_PERSISTED_REVOKED_CACHE: Dict[str, Tuple[float, Dict[str, float]]] = {}
PERSISTED_REVOKED_CACHE_TTL_SECONDS = 60.0

# Thread-safe 1h cache for Cloud IAP ES256 public keys: (expires_monotonic, fetched_monotonic, certs_dict)
_IAP_CERTS_LOCK = threading.Lock()
_IAP_CERTS_CACHE: Tuple[float, float, Dict[str, Any]] = (0.0, 0.0, {})

# Thread-safe <=60s cache for successful Bearer token verifications: sha256(token) -> (expires_monotonic, identity)
_BEARER_CACHE_LOCK = threading.Lock()
_BEARER_VERIFY_CACHE: Dict[str, Tuple[float, "IamConsultantIdentity"]] = {}


@dataclass(frozen=True)
class IamConsultantIdentity:
    """Verified identity and isolated persistent workspace ID of the authenticated Google user."""

    email: str
    display_name: str
    domain: str
    subject: str
    auth_channel: str
    session_id: str = field(default_factory=lambda: secrets.token_hex(16))
    cookie_sid: str = ""


def clear_auth_caches_for_tests() -> None:
    """Clears revocation, IAP cert, and Bearer caches (intended strictly for test isolation)."""
    global _IAP_CERTS_CACHE
    with _REVOKED_SIDS_LOCK:
        _REVOKED_SIDS.clear()
        _PERSISTED_REVOKED_CACHE.clear()
    with _IAP_CERTS_LOCK:
        _IAP_CERTS_CACHE = (0.0, 0.0, {})
    with _BEARER_CACHE_LOCK:
        _BEARER_VERIFY_CACHE.clear()


def configured_oauth_client_id() -> str:
    return (
        os.getenv("IAM_OAUTH_CLIENT_ID", "").strip()
        or os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
        or DEFAULT_OAUTH_CLIENT_ID
    )


def allowed_token_azps() -> Set[str]:
    """Returns the configured allowlist of OAuth2 client IDs (`azp`/`aud`) accepted for access tokens."""
    allowed: Set[str] = set()
    cid = configured_oauth_client_id()
    if cid:
        allowed.add(cid)
    raw_list = os.getenv("IAM_ALLOWED_TOKEN_AZP", "")
    for item in re.split(r"[,;\s]+", raw_list.strip()):
        cleaned = item.strip()
        if cleaned:
            allowed.add(cleaned)
    return allowed


def _is_valid_service_origin(origin: str, *, on_cloud_run: bool) -> bool:
    cand = (origin or "").strip().rstrip("/")
    if not cand:
        return False
    m_https = _HTTPS_ORIGIN_RE.match(cand)
    if m_https:
        host = m_https.group(1).lower()
        if on_cloud_run and host in _LOCAL_HOSTS:
            return False
        return True
    if not on_cloud_run and _LOCAL_HTTP_ORIGIN_RE.match(cand):
        return True
    return False


def resolve_service_public_origin(request: Request) -> str:
    """Resolves the service's own origin for OAuth bridge `postMessage`, ignoring all query parameters.

    Precedence:
    1. Explicit `IAM_PUBLIC_ORIGIN` environment variable (validated).
    2. Derived from the incoming request URL (`https://` forced on Cloud Run; `localhost` allowed
       only outside Cloud Run).
    """
    on_cloud_run = bool(os.getenv("K_SERVICE"))
    configured = (os.getenv("IAM_PUBLIC_ORIGIN") or "").strip().rstrip("/")
    if configured:
        if _is_valid_service_origin(configured, on_cloud_run=on_cloud_run):
            return configured
        logger.warning(
            "Ignoring invalid IAM_PUBLIC_ORIGIN=%r (on_cloud_run=%s).",
            configured,
            on_cloud_run,
        )
        return ""

    netloc = (request.url.netloc or "").strip()
    if not netloc:
        return ""
    scheme = "https" if on_cloud_run else (request.url.scheme or "http").strip().lower()
    candidate = f"{scheme}://{netloc}".rstrip("/")
    if _is_valid_service_origin(candidate, on_cloud_run=on_cloud_run):
        return candidate
    return ""


def allowed_domains_list() -> List[str]:
    return sorted(_allowed_domains())


def _allowed_domains() -> Set[str]:
    raw = os.getenv("ALLOWED_IAP_DOMAINS", "") or os.getenv("ALLOWED_DOMAINS", "")
    if not raw.strip():
        raw = "*"
    normalized = raw.replace(":", ",")
    return {d.strip().lower() for d in normalized.split(",") if d.strip()}


def _signing_key() -> bytes:
    return get_master_secret_bytes()


def _deterministic_session_id(email: str, subject: str = "") -> str:
    return derive_workspace_id(email)


def _check_email_authorized(email: str) -> str:
    normalized = (email or "").strip().lower()
    if "@" not in normalized:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identity is missing a valid email address.",
        )
    domain = normalized.rsplit("@", 1)[-1]
    domains = _allowed_domains()
    if "*" in domains or domain in domains:
        return domain
    logger.warning("Rejected sign-in from unauthorized domain '@%s'.", domain)
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied: your account domain is not authorized for this deployment.",
    )


def _prune_revoked_sids_locked(now: float) -> None:
    expired = [sid for sid, exp_ts in _REVOKED_SIDS.items() if exp_ts <= now]
    for sid in expired:
        _REVOKED_SIDS.pop(sid, None)
    if len(_REVOKED_SIDS) > REVOKED_SIDS_MAX_SIZE:
        # Evict entries closest to expiration first
        by_exp = sorted(_REVOKED_SIDS.items(), key=lambda item: item[1])
        excess = len(_REVOKED_SIDS) - REVOKED_SIDS_MAX_SIZE
        for sid, _ in by_exp[:excess]:
            _REVOKED_SIDS.pop(sid, None)


def revoke_session_id(sid: str, expires_at: Optional[float] = None) -> None:
    """Adds a cookie session ID (`sid`) to the revocation set until its natural expiration."""
    clean_sid = (sid or "").strip()
    if not clean_sid:
        return
    now = time.time()
    exp_ts = float(expires_at) if expires_at is not None else (now + IAM_SESSION_TTL_SECONDS)
    if exp_ts <= now:
        return
    with _REVOKED_SIDS_LOCK:
        _prune_revoked_sids_locked(now)
        _REVOKED_SIDS[clean_sid] = exp_ts


def is_session_revoked(sid: str) -> bool:
    """Checks whether a cookie session ID (`sid`) has been revoked and is still within its TTL."""
    clean_sid = (sid or "").strip()
    if not clean_sid:
        return False
    now = time.time()
    with _REVOKED_SIDS_LOCK:
        exp_ts = _REVOKED_SIDS.get(clean_sid)
        if exp_ts is None:
            return False
        if exp_ts <= now:
            _REVOKED_SIDS.pop(clean_sid, None)
            return False
        return True


def _load_persisted_revoked_sids(workspace_sid: str, email: str, *, force: bool = False) -> Dict[str, float]:
    """Returns the revoked `sid`s persisted for this user (cached for `PERSISTED_REVOKED_CACHE_TTL_SECONDS`)."""
    now_mono = time.monotonic()
    with _REVOKED_SIDS_LOCK:
        cached = _PERSISTED_REVOKED_CACHE.get(workspace_sid)
    if not force and cached is not None and (now_mono - cached[0]) < PERSISTED_REVOKED_CACHE_TTL_SECONDS:
        return cached[1]
    try:
        revoked = load_revoked_session_ids(workspace_sid, email)
    except Exception as exc:
        logger.warning("Unable to load persisted session revocations: %s", type(exc).__name__)
        revoked = cached[1] if cached is not None else {}
    with _REVOKED_SIDS_LOCK:
        _PERSISTED_REVOKED_CACHE[workspace_sid] = (now_mono, revoked)
    return revoked


def _persist_revoked_sid(email: str, subject: str, cookie_sid: str, exp_ts: float) -> None:
    """Records a revoked `sid` in the user's workspace until the cookie's natural expiration (best effort)."""
    try:
        workspace_sid = _deterministic_session_id(email, subject)
        now = time.time()
        revoked = {
            sid: exp
            for sid, exp in _load_persisted_revoked_sids(workspace_sid, email, force=True).items()
            if exp > now
        }
        revoked[cookie_sid] = float(exp_ts)
        save_revoked_session_ids(
            workspace_sid,
            email,
            revoked,
            ttl_seconds=max(revoked.values()) - now,
        )
        with _REVOKED_SIDS_LOCK:
            _PERSISTED_REVOKED_CACHE[workspace_sid] = (time.monotonic(), revoked)
    except Exception as exc:
        logger.warning("Unable to persist session revocation: %s", type(exc).__name__)


def _decode_signed_cookie_payload(ticket: str) -> Optional[Dict[str, Any]]:
    """Verifies the HMAC-SHA256 signature of a session cookie and returns its JSON payload."""
    if not ticket or "." not in ticket or not ticket.isascii():
        return None
    body_b64, given_sig = ticket.rsplit(".", 1)
    try:
        expected_sig = hmac.new(_signing_key(), body_b64.encode("ascii"), hashlib.sha256).hexdigest()
    except UnicodeEncodeError:
        return None
    if not hmac.compare_digest(given_sig, expected_sig):
        return None
    pad = "=" * ((4 - len(body_b64) % 4) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode((body_b64 + pad).encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeEncodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def revoke_consultant_cookie(ticket: str) -> Optional[str]:
    """Revokes a signed consultant cookie by recording its `sid` until its `exp` timestamp.

    The revocation is kept in memory and also persisted in the user's workspace, so a copied cookie stays
    rejected after a restart or redeploy.
    """
    data = _decode_signed_cookie_payload((ticket or "").strip())
    if data is None:
        return None
    cookie_sid = str(data.get("sid") or "").strip()
    if not cookie_sid:
        return None
    exp_ts = float(int(data.get("exp") or 0))
    revoke_session_id(cookie_sid, expires_at=exp_ts if exp_ts > 0 else None)
    email = str(data.get("em") or "").strip().lower()
    if email and exp_ts > time.time():
        _persist_revoked_sid(email, str(data.get("sb") or email), cookie_sid, exp_ts)
    return cookie_sid


def mint_consultant_cookie(identity: IamConsultantIdentity) -> str:
    """Creates an HMAC-SHA256 signed session ticket with a fresh revocable `sid` and persistent workspace `ws`."""
    now = int(time.time())
    workspace_sid = _deterministic_session_id(identity.email, identity.subject)
    cookie_sid = secrets.token_hex(16)
    payload = {
        "em": identity.email,
        "dn": identity.display_name,
        "dm": identity.domain,
        "sb": identity.subject,
        "ch": identity.auth_channel,
        "ws": workspace_sid,
        "sid": cookie_sid,
        "iat": now,
        "exp": now + IAM_SESSION_TTL_SECONDS,
    }
    body_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    sig = hmac.new(_signing_key(), body_b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body_b64}.{sig}"


def verify_consultant_cookie(ticket: str) -> Optional[IamConsultantIdentity]:
    """Verifies an HMAC-SHA256 session cookie, enforces revocation, and resolves the user's isolated workspace ID."""
    data = _decode_signed_cookie_payload((ticket or "").strip())
    if data is None:
        return None
    if int(data.get("exp") or 0) < int(time.time()):
        return None
    cookie_sid = str(data.get("sid") or "").strip()
    if not cookie_sid or is_session_revoked(cookie_sid):
        return None
    email = str(data.get("em") or "").strip().lower()
    if not email:
        return None
    try:
        domain = _check_email_authorized(email)
    except HTTPException:
        return None
    subj = str(data.get("sb") or email)
    workspace_sid = _deterministic_session_id(email, subj)
    if cookie_sid in _load_persisted_revoked_sids(workspace_sid, email):
        # Revoked before a restart: remember it in memory again and reject
        revoke_session_id(cookie_sid, expires_at=float(int(data.get("exp") or 0)) or None)
        return None
    return IamConsultantIdentity(
        email=email,
        display_name=str(data.get("dn") or email.split("@", 1)[0]),
        domain=domain,
        subject=subj,
        auth_channel=str(data.get("ch") or "verified_google_cookie"),
        session_id=workspace_sid,
        cookie_sid=cookie_sid,
    )


def _is_truthy_claim(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() == "true"


def _verify_google_token_with_ttl(
    token: str,
) -> Tuple[IamConsultantIdentity, float]:
    """Verifies a Google OIDC ID token or OAuth2 access token and returns `(identity, remaining_ttl_seconds)`."""
    raw = (token or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing Google credential.")

    # 1. OIDC ID Token (3-segment JWT, never an opaque ya29.* access token)
    if raw.count(".") == 2 and not raw.startswith("ya29."):
        client_id = configured_oauth_client_id()
        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OIDC ID tokens are rejected when IAM_OAUTH_CLIENT_ID is not configured.",
            )
        try:
            claims = google_id_token.verify_oauth2_token(
                raw,
                google_auth_requests.Request(),
                audience=client_id,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google ID token or audience mismatch.",
            ) from exc

        if not isinstance(claims, dict):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Google ID token payload.")
        token_aud = str(claims.get("aud") or "").strip()
        if token_aud != client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OIDC ID token audience does not match IAM_OAUTH_CLIENT_ID.",
            )
        if not _is_truthy_claim(claims.get("email_verified")):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OIDC email is not verified.")

        email = str(claims.get("email") or "").strip().lower()
        domain = _check_email_authorized(email)
        subj = str(claims.get("sub") or email)
        exp_raw = claims.get("exp")
        remaining_ttl = BEARER_VERIFY_CACHE_TTL_SECONDS
        if exp_raw is not None:
            try:
                remaining_ttl = float(int(exp_raw) - int(time.time()))
            except (TypeError, ValueError):
                remaining_ttl = BEARER_VERIFY_CACHE_TTL_SECONDS

        return (
            IamConsultantIdentity(
                email=email,
                display_name=str(claims.get("name") or email.split("@", 1)[0]),
                domain=domain,
                subject=subj,
                auth_channel="google_oidc_token",
                session_id=_deterministic_session_id(email, subj),
            ),
            remaining_ttl,
        )

    # 2. OAuth2 Access Token verified via Google tokeninfo with strict azp/aud allowlist
    allowlist = allowed_token_azps()
    if not allowlist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OAuth2 access tokens require IAM_OAUTH_CLIENT_ID or IAM_ALLOWED_TOKEN_AZP to be configured.",
        )

    try:
        resp = httpx.get(GOOGLE_TOKENINFO_URI, params={"access_token": raw}, timeout=8.0)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Failed to verify Google token: {exc}")

    if resp.status_code != 200:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired Google token.")
    info = resp.json()
    if not isinstance(info, dict):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Google tokeninfo response.")

    token_azp = str(info.get("azp") or "").strip()
    token_aud = str(info.get("aud") or "").strip()
    if token_azp:
        client_allowed = token_azp in allowlist
    else:
        client_allowed = bool(token_aud and token_aud in allowlist)

    if not client_allowed:
        logger.warning(
            "Rejected Google OAuth access token with unauthorized azp=%r aud=%r.",
            token_azp or None,
            token_aud or None,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OAuth access token client (azp/aud) is not authorized.",
        )

    if not _is_truthy_claim(info.get("email_verified")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OAuth token does not contain a verified email.")
    email = str(info.get("email") or "").strip().lower()
    domain = _check_email_authorized(email)

    display_name = email.split("@", 1)[0].replace(".", " ").title()
    try:
        ui_resp = httpx.get(
            GOOGLE_USERINFO_URI,
            headers={"Authorization": f"Bearer {raw}"},
            timeout=5.0,
        )
        if ui_resp.status_code == 200:
            ui_data = ui_resp.json()
            if isinstance(ui_data, dict) and ui_data.get("name"):
                display_name = str(ui_data["name"])
    except httpx.HTTPError:
        pass

    remaining_ttl = BEARER_VERIFY_CACHE_TTL_SECONDS
    if info.get("expires_in") is not None:
        try:
            remaining_ttl = float(info["expires_in"])
        except (TypeError, ValueError):
            remaining_ttl = BEARER_VERIFY_CACHE_TTL_SECONDS
    elif info.get("exp") is not None:
        try:
            remaining_ttl = float(int(info["exp"]) - int(time.time()))
        except (TypeError, ValueError):
            remaining_ttl = BEARER_VERIFY_CACHE_TTL_SECONDS

    subj = str(info.get("sub") or email)
    return (
        IamConsultantIdentity(
            email=email,
            display_name=display_name,
            domain=domain,
            subject=subj,
            auth_channel="google_oauth_access_token",
            session_id=_deterministic_session_id(email, subj),
        ),
        remaining_ttl,
    )


def verify_google_token(token: str) -> IamConsultantIdentity:
    """Verifies a Google OIDC ID token or OAuth2 access token against Google endpoints."""
    ident, _ = _verify_google_token_with_ttl(token)
    return ident


def verify_google_token_cached(token: str) -> IamConsultantIdentity:
    """Verifies a Bearer Google token with up to 60s caching keyed strictly by SHA-256 token hash."""
    raw = (token or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing Google credential.")

    tok_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    now_mono = time.monotonic()
    with _BEARER_CACHE_LOCK:
        cached = _BEARER_VERIFY_CACHE.get(tok_hash)
        if cached is not None:
            exp_mono, cached_ident = cached
            if now_mono < exp_mono:
                return cached_ident
            _BEARER_VERIFY_CACHE.pop(tok_hash, None)

    ident, remaining_ttl = _verify_google_token_with_ttl(raw)
    cache_ttl = min(BEARER_VERIFY_CACHE_TTL_SECONDS, remaining_ttl)
    if cache_ttl > 0:
        now_mono = time.monotonic()
        with _BEARER_CACHE_LOCK:
            expired_keys = [k for k, (exp_m, _) in _BEARER_VERIFY_CACHE.items() if exp_m <= now_mono]
            for k in expired_keys:
                _BEARER_VERIFY_CACHE.pop(k, None)
            if len(_BEARER_VERIFY_CACHE) >= BEARER_VERIFY_CACHE_MAX_SIZE:
                oldest = sorted(_BEARER_VERIFY_CACHE.items(), key=lambda item: item[1][0])
                for k, _ in oldest[: max(1, len(_BEARER_VERIFY_CACHE) - BEARER_VERIFY_CACHE_MAX_SIZE + 1)]:
                    _BEARER_VERIFY_CACHE.pop(k, None)
            _BEARER_VERIFY_CACHE[tok_hash] = (now_mono + cache_ttl, ident)
    return ident


def _fetch_iap_public_keys() -> Dict[str, Any]:
    """Downloads Cloud IAP public keys from Google's official endpoint."""
    resp = httpx.get(IAP_CERTS_URL, timeout=8.0)
    if resp.status_code != 200:
        raise ValueError(f"Failed to fetch IAP public keys (HTTP {resp.status_code}).")
    data = resp.json()
    if not isinstance(data, dict) or not data:
        raise ValueError("Empty or invalid IAP public keys payload.")
    return data


def _get_iap_public_keys(force_refresh: bool = False) -> Dict[str, Any]:
    """Returns Cloud IAP public keys cached for 1 hour (`IAP_CERTS_CACHE_TTL_SECONDS`)."""
    global _IAP_CERTS_CACHE
    now_mono = time.monotonic()
    with _IAP_CERTS_LOCK:
        exp_mono, fetched_mono, cached_certs = _IAP_CERTS_CACHE
        if cached_certs and now_mono < exp_mono:
            if not force_refresh or (now_mono - fetched_mono) < IAP_CERTS_REFRESH_COOLDOWN_SECONDS:
                return cached_certs

    fresh_certs = _fetch_iap_public_keys()
    now_mono = time.monotonic()
    with _IAP_CERTS_LOCK:
        _IAP_CERTS_CACHE = (now_mono + IAP_CERTS_CACHE_TTL_SECONDS, now_mono, fresh_certs)
    return fresh_certs


def _extract_unverified_jwt_kid(token: str) -> str:
    try:
        header = google_jwt.decode_header(token)
        if isinstance(header, dict):
            return str(header.get("kid") or "").strip()
    except Exception:
        pass
    return ""


def verify_iap_jwt_token(assertion: str) -> Optional[IamConsultantIdentity]:
    """Cryptographically verifies Cloud Run IAP ES256 `X-Goog-IAP-JWT-Assertion` with exact audience matching."""
    tok = (assertion or "").strip()
    if not tok:
        return None
    expected_aud = (os.getenv("IAM_IAP_AUDIENCE") or os.getenv("GOOGLE_IAP_AUDIENCE") or "").strip()
    if not expected_aud:
        if os.getenv("K_SERVICE"):
            logger.warning(
                "Ignoring X-Goog-IAP-JWT-Assertion on Cloud Run because IAM_IAP_AUDIENCE is not configured."
            )
        else:
            logger.warning(
                "Ignoring X-Goog-IAP-JWT-Assertion because IAM_IAP_AUDIENCE is not configured."
            )
        return None

    try:
        certs = _get_iap_public_keys(force_refresh=False)
    except Exception as exc:
        logger.warning("Failed to fetch Cloud IAP public keys: %s", exc)
        return None

    claims: Optional[Dict[str, Any]] = None
    try:
        decoded = google_jwt.decode(tok, certs=certs, verify=True, audience=expected_aud)
        claims = dict(decoded) if isinstance(decoded, dict) else None
    except Exception as first_exc:
        kid = _extract_unverified_jwt_kid(tok)
        if kid and kid not in certs:
            try:
                refreshed = _get_iap_public_keys(force_refresh=True)
                if refreshed is not certs:
                    decoded = google_jwt.decode(tok, certs=refreshed, verify=True, audience=expected_aud)
                    claims = dict(decoded) if isinstance(decoded, dict) else None
            except Exception as retry_exc:
                logger.warning("Rejected Cloud IAP JWT assertion after key refresh: %s", retry_exc)
                return None
        if claims is None:
            logger.warning("Rejected Cloud IAP JWT assertion: %s", first_exc)
            return None

    if not isinstance(claims, dict):
        return None
    if claims.get("iss") != IAP_ISSUER:
        logger.warning("Rejected Cloud IAP JWT assertion due to unexpected issuer: %r", claims.get("iss"))
        return None
    actual_aud = str(claims.get("aud") or "").strip()
    if actual_aud != expected_aud:
        logger.warning(
            "Rejected Cloud IAP JWT assertion due to audience mismatch: received=%r expected=%r",
            actual_aud,
            expected_aud,
        )
        return None

    email = str(claims.get("email") or "").strip().lower()
    if email.startswith("accounts.google.com:"):
        email = email.split(":", 1)[1].strip()
    if not email:
        return None
    try:
        domain = _check_email_authorized(email)
    except HTTPException:
        return None
    subj = str(claims.get("sub") or email)
    return IamConsultantIdentity(
        email=email,
        display_name=email.split("@", 1)[0].replace(".", " ").title(),
        domain=domain,
        subject=subj,
        auth_channel="cloud_run_iap",
        session_id=_deterministic_session_id(email, subj),
    )


def resolve_request_identity_with_status(request: Request) -> Tuple[Optional[IamConsultantIdentity], bool]:
    """Resolves verified user identity with strict precedence and signals whether a fresh cookie must be minted.

    Precedence order:
    1. Cloud Run IAP (`X-Goog-IAP-JWT-Assertion`): if valid, any existing session cookie is honored
       ONLY when its verified email matches the IAP email; otherwise the cookie is discarded and
       `needs_new_cookie=True` instructs the middleware to issue a new cookie with a fresh `sid`.
    2. Signed session cookie (`iam_consultant_ticket`), checked against HMAC, expiry, and revocation set.
    3. `Authorization: Bearer <token>` (cached up to 60s by SHA-256 hash).
    4. Optional local workstation dev identity (disabled unconditionally on Cloud Run).
    """
    cookie_ticket = (request.cookies.get(IAM_SESSION_COOKIE) or "").strip()

    # 1. Cloud Run IAP takes strict precedence over browser cookies
    iap_assertion = (request.headers.get("x-goog-iap-jwt-assertion") or "").strip()
    if iap_assertion:
        iap_ident = verify_iap_jwt_token(iap_assertion)
        if iap_ident is not None:
            raw_iap_email = (request.headers.get("x-goog-authenticated-user-email") or "").strip()
            iap_header_consistent = True
            if raw_iap_email:
                hdr_email = raw_iap_email.split(":", 1)[-1].strip().lower()
                if hdr_email and hdr_email != iap_ident.email:
                    iap_header_consistent = False
            if iap_header_consistent:
                if cookie_ticket:
                    cookie_ident = verify_consultant_cookie(cookie_ticket)
                    if cookie_ident is not None and cookie_ident.email == iap_ident.email:
                        return cookie_ident, False
                # Cookie missing, invalid, revoked, or belongs to a different user -> discard & mint fresh sid
                return iap_ident, True
            return None, False

    # 2. Signed consultant cookie (when no valid IAP assertion is present)
    if cookie_ticket:
        verified = verify_consultant_cookie(cookie_ticket)
        if verified is not None:
            return verified, False

    # 3. Authorization: Bearer <token> (cached up to 60s by token SHA-256 hash)
    auth_header = (request.headers.get("authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        raw_tok = auth_header[7:].strip()
        if raw_tok:
            try:
                ident = verify_google_token_cached(raw_tok)
                return (
                    IamConsultantIdentity(
                        email=ident.email,
                        display_name=ident.display_name,
                        domain=ident.domain,
                        subject=ident.subject,
                        auth_channel=ident.auth_channel,
                        session_id=_deterministic_session_id(ident.email, ident.subject),
                    ),
                    False,
                )
            except HTTPException:
                return None, False

    # 4. Optional local workstation dev identity (requires explicit IAM_ENABLE_LOCAL_DEV_IDENTITY=true; never active on Cloud Run)
    if not os.getenv("K_SERVICE") and os.getenv("IAM_ENABLE_LOCAL_DEV_IDENTITY", "").lower() == "true":
        dev_email = os.getenv("IAM_DEV_USER", "developer@localhost").strip().lower()
        return (
            IamConsultantIdentity(
                email=dev_email,
                display_name=f"{dev_email.split('@', 1)[0]} (Local Dev)",
                domain=dev_email.split("@")[-1],
                subject=f"local:{dev_email}",
                auth_channel="local_workstation",
                session_id=_deterministic_session_id(dev_email, f"local:{dev_email}"),
            ),
            False,
        )

    return None, False


def resolve_request_identity(request: Request) -> Optional[IamConsultantIdentity]:
    """Resolves verified user identity from IAP, signed cookie, Bearer token, or local dev."""
    ident, _ = resolve_request_identity_with_status(request)
    return ident

