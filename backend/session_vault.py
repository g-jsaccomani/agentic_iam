"""Per-User Zero-Trust Persistent Inspection Session Vault & Auto-Renewing SA Impersonation Engine (`session_vault.py`).

Enforces strict separation between:
1. AI Compute & Encrypted State Plane (`Vertex AI` + dedicated per-user encrypted GCS workspace bucket
   — ZERO target Customer Organization IAM roles).
2. Target Inspection Plane (authenticated user's OAuth2 token OR short-lived Service Account
   impersonation token minted via `iamcredentials.googleapis.com/...:generateAccessToken`).

Guarantees:
- Brand-new users start with a 100% clean console (zero default Organization or Project data).
- Once a user connects a target Organization, their connection profile, AES-256-GCM encrypted tokens,
  Organization hierarchy, readiness probes, and pinned scans persist durably per verified `owner_email`
  across browser closes, page refreshes, Cloud Run restarts, scale-to-zero, and multi-instance routing.
- When `roles/iam.serviceAccountTokenCreator` is also delegated to the platform runtime SA for an
  owner-verified `sa-iam-assessor`, short-lived impersonation tokens auto-renew seamlessly across
  days/weeks without ever storing static JSON keys.
- Even if a 1-hour OAuth token expires without auto-renew delegation, the user's connection metadata
  and all pinned scan results/reports remain 100% fixed, visible, and downloadable until explicitly wiped.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import contextvars
import datetime
import logging
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple, TypeVar

import httpx

from backend.workspace_store import (
    apply_workspace_retention,
    default_retention_days,
    load_workspace_connection,
    normalize_retention_days,
    persistence_backend_label,
    purge_expired_workspace_objects,
    save_workspace_connection,
    set_workspace_retention_days,
    update_workspace_connection_fields,
    wipe_workspace,
)

logger = logging.getLogger(__name__)

SESSION_TOKEN_LIFETIME_SECONDS = 3600.0
_SESSION_ROOT_DIR = Path(tempfile.gettempdir()) / "agentic_iam_sessions"


def session_export_dir_for_id(session_id: str) -> Path:
    """Returns the per-session local export root directory under `_SESSION_ROOT_DIR`."""
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "", (session_id or ""))[:64] or "ephemeral"
    return _SESSION_ROOT_DIR / safe_id

T = TypeVar("T")
R = TypeVar("R")


def persistent_delegation_enabled() -> bool:
    """Deployment-level opt-in for runtime-SA token auto-renew (`IAM_ENABLE_PERSISTENT_DELEGATION`, default off).

    When off, the platform runtime Service Account is never used to mint tokens for a customer SA and the
    onboarding kit never grants it any role.
    """
    return (os.getenv("IAM_ENABLE_PERSISTENT_DELEGATION") or "").strip().lower() in ("1", "true", "yes", "on")


def platform_runtime_sa_email() -> str:
    """Returns the platform runtime SA email, regardless of whether persistent delegation is enabled.

    Used only to render the offboarding revoke command for customers that granted it with an older kit.
    """
    explicit = (os.getenv("PERSISTENT_DELEGATION_SA") or "").strip()
    if explicit:
        return explicit
    proj = (os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip()
    if not proj:
        return ""
    return f"sa-agentic-iam-engine@{proj}.iam.gserviceaccount.com"


def configured_delegation_sa_email() -> str:
    """Returns the platform runtime SA email eligible for optional persistent SA auto-renew delegation.

    Empty unless the deployment explicitly enabled `IAM_ENABLE_PERSISTENT_DELEGATION`.
    """
    if not persistent_delegation_enabled():
        return ""
    return platform_runtime_sa_email()


@dataclass
class InspectionSession:
    """Persistent isolated target GCP inspection context belonging to a single verified user workspace."""

    session_id: str
    owner_email: str
    connection_mode: str  # "impersonated_sa" | "direct_user" | "local_cli_adc"
    base_user_access_token: str
    impersonated_sa_email: str
    effective_access_token: str
    token_expires_at: float  # Wall-clock UTC epoch seconds (`time.time()`)
    organization_id: str = ""
    organization_domain: str = ""
    organization_domains: List[str] = field(default_factory=list)
    customer_name: str = ""
    optional_customer_bq_table: str = ""
    quota_project_id: str = ""
    persistent_sa_delegation: bool = False
    selected_scope: str = ""
    project_scope_mode: str = "ORG_ALL"
    selected_project_ids: List[str] = field(default_factory=list)
    has_pinned_book: bool = False
    has_pinned_inventory: bool = False
    pinned_scope: str = ""
    pinned_generated_at: str = ""
    # Consultant-selected retention for persisted workspace data, in days (0 = nothing is persisted)
    retention_days: int = field(default_factory=default_retention_days)
    last_bq_export_status: Optional[Dict[str, Any]] = None
    last_renewal_attempt_at: float = 0.0
    last_activity_at: float = field(default_factory=time.time)
    created_at_iso: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    @property
    def session_export_dir(self) -> Path:
        p = session_export_dir_for_id(self.session_id)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def is_live_token_valid(self) -> bool:
        return bool(self.effective_access_token) and time.time() < (self.token_expires_at - 30.0)

    @property
    def effective_identity_label(self) -> str:
        if self.impersonated_sa_email:
            return f"impersonated:{self.impersonated_sa_email}"
        return f"user:{self.owner_email}"

    @property
    def cache_namespace(self) -> str:
        ident = self.impersonated_sa_email or self.owner_email
        return f"{self.session_id}:{ident}:{self.organization_id}"

    def to_persisted_record(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "owner_email": self.owner_email,
            "connection_mode": self.connection_mode,
            "impersonated_sa_email": self.impersonated_sa_email,
            "token_expires_at": self.token_expires_at,
            "organization_id": self.organization_id,
            "organization_domain": self.organization_domain,
            "organization_domains": list(self.organization_domains),
            "customer_name": self.customer_name,
            "optional_customer_bq_table": self.optional_customer_bq_table,
            "quota_project_id": self.quota_project_id,
            "persistent_sa_delegation": self.persistent_sa_delegation,
            "selected_scope": self.selected_scope,
            "project_scope_mode": self.project_scope_mode,
            "selected_project_ids": list(self.selected_project_ids),
            "has_pinned_book": self.has_pinned_book,
            "has_pinned_inventory": self.has_pinned_inventory,
            "pinned_scope": self.pinned_scope,
            "pinned_generated_at": self.pinned_generated_at,
            "retention_days": self.retention_days,
            "created_at_iso": self.created_at_iso,
        }

    def to_public_metadata(self) -> Dict[str, Any]:
        live_valid = self.is_live_token_valid
        remaining = max(0, int(self.token_expires_at - time.time())) if live_valid else 0
        persisted = self.retention_days > 0
        if not persisted:
            storage_mode = "SESSION_ONLY_NOT_PERSISTED"
        elif self.optional_customer_bq_table:
            storage_mode = "PERSISTENT_WORKSPACE_AND_BIGQUERY"
        else:
            storage_mode = "PERSISTENT_ENCRYPTED_WORKSPACE"
        return {
            "connected": True,
            "workspace_persisted": persisted,
            "workspace_retention_days": self.retention_days,
            "persistence_backend": persistence_backend_label(),
            "live_token_valid": live_valid,
            "token_expired": not live_valid,
            "persistent_sa_delegation": self.persistent_sa_delegation,
            "delegation_sa_email": configured_delegation_sa_email(),
            "owner_email": self.owner_email,
            "connection_mode": self.connection_mode,
            "impersonated_sa_email": self.impersonated_sa_email or None,
            "effective_principal": self.impersonated_sa_email or self.owner_email,
            "effective_identity": self.effective_identity_label,
            "storage_mode": storage_mode,
            "organization_id": self.organization_id,
            "organization_scope": f"organizations/{self.organization_id}" if self.organization_id else "",
            "organization_domain": self.organization_domain,
            "organization_domains": list(self.organization_domains),
            "customer_name": self.customer_name,
            "optional_customer_bq_table": self.optional_customer_bq_table or None,
            "bigquery_export_status": dict(self.last_bq_export_status) if isinstance(self.last_bq_export_status, dict) else None,
            "selected_scope": self.selected_scope,
            "project_scope_mode": self.project_scope_mode,
            "selected_project_ids": list(self.selected_project_ids),
            "has_pinned_book": self.has_pinned_book,
            "has_pinned_inventory": self.has_pinned_inventory,
            "pinned_scope": self.pinned_scope,
            "pinned_generated_at": self.pinned_generated_at,
            "ttl_remaining_seconds": remaining,
            "token_expires_at_epoch": int(self.token_expires_at),
            "created_at": self.created_at_iso,
        }


DEFAULT_PENDING_OAUTH_TTL_SECONDS = 900.0
DEFAULT_SESSION_IDLE_TTL_SECONDS = 28800.0

_VAULT_LOCK = threading.Lock()
_SESSION_VAULT: Dict[str, InspectionSession] = {}
# Pending sign-in OAuth tokens strictly bound to `(session_id, owner_email_lower) -> (expires_monotonic, token)`
_PENDING_OAUTH_TOKENS: Dict[Tuple[str, str], Tuple[float, str]] = {}
_CACHE_PURGE_HOOKS: List[Callable[[str], None]] = []
# `session_id -> monotonic deadline`: recent "no stored workspace" lookups (avoids one store read per request)
_HYDRATE_MISS_UNTIL: Dict[str, float] = {}
HYDRATE_MISS_TTL_SECONDS = 60.0

_ACTIVE_SESSION_CTX: contextvars.ContextVar[Optional[InspectionSession]] = contextvars.ContextVar(
    "active_inspection_session", default=None
)


def register_cache_purge_hook(hook: Callable[[str], None]) -> None:
    """Registers a callback invoked with `session_id` whenever a user workspace is explicitly wiped."""
    _CACHE_PURGE_HOOKS.append(hook)


def store_pending_oauth_token(
    session_id: str,
    owner_email: str,
    access_token: str,
    *,
    ttl_seconds: Optional[float] = None,
) -> None:
    """Stores a short-lived pending sign-in OAuth token strictly bound to `(session_id, owner_email)`."""
    sid = (session_id or "").strip()
    owner = (owner_email or "").strip().lower()
    tok = (access_token or "").strip()
    if not sid or not owner or not tok:
        return
    ttl = float(
        ttl_seconds
        if ttl_seconds is not None
        else float(os.getenv("IAM_PENDING_OAUTH_TTL_SECONDS", str(DEFAULT_PENDING_OAUTH_TTL_SECONDS)))
    )
    with _VAULT_LOCK:
        _PENDING_OAUTH_TOKENS[(sid, owner)] = (time.monotonic() + max(0.05, ttl), tok)


def get_pending_oauth_token(session_id: str, owner_email: str) -> Optional[str]:
    """Returns a non-expired pending OAuth token for `(session_id, owner_email)`, evicting if expired."""
    sid = (session_id or "").strip()
    owner = (owner_email or "").strip().lower()
    if not sid or not owner:
        return None
    now = time.monotonic()
    with _VAULT_LOCK:
        entry = _PENDING_OAUTH_TOKENS.get((sid, owner))
        if entry is None:
            return None
        exp_ts, tok = entry
        if now >= exp_ts:
            _PENDING_OAUTH_TOKENS.pop((sid, owner), None)
            return None
        return tok


def pop_pending_oauth_token(session_id: str, owner_email: str) -> Optional[str]:
    """Atomically pops and returns a non-expired pending OAuth token for `(session_id, owner_email)`."""
    sid = (session_id or "").strip()
    owner = (owner_email or "").strip().lower()
    if not sid or not owner:
        return None
    now = time.monotonic()
    with _VAULT_LOCK:
        entry = _PENDING_OAUTH_TOKENS.pop((sid, owner), None)
    if entry is None:
        return None
    exp_ts, tok = entry
    return tok if now < exp_ts else None


def has_pending_oauth_token(session_id: str, owner_email: str) -> bool:
    return get_pending_oauth_token(session_id, owner_email) is not None


def purge_pending_oauth_tokens(
    session_id: Optional[str] = None,
    owner_email: Optional[str] = None,
    *,
    expired_only: bool = False,
) -> int:
    """Purges pending OAuth tokens matching filter (or all expired tokens when `expired_only=True`)."""
    sid_filter = (session_id or "").strip()
    owner_filter = (owner_email or "").strip().lower()
    now = time.monotonic()
    removed = 0
    with _VAULT_LOCK:
        for key, (exp_ts, _) in list(_PENDING_OAUTH_TOKENS.items()):
            k_sid, k_owner = key
            if sid_filter and k_sid != sid_filter:
                continue
            if owner_filter and k_owner != owner_filter:
                continue
            if expired_only and now < exp_ts:
                continue
            _PENDING_OAUTH_TOKENS.pop(key, None)
            removed += 1
    return removed


def _extract_sa_project_id(sa_email: str) -> str:
    m = re.search(r"@([a-z][a-z0-9-]{4,29})\.iam\.gserviceaccount\.com$", sa_email.strip().lower())
    return m.group(1) if m else ""


def mint_impersonated_sa_token(
    user_access_token: str,
    target_sa_email: str,
    caller_email: str = "",
    lifetime_seconds: int = 3600,
) -> Tuple[str, float]:
    """Mints a short-lived Service Account access token via IAM Credentials API using the user's OAuth token."""
    from backend.validators import quote_path_segment, validate_sa_email

    clean_user_tok = (user_access_token or "").strip()
    if clean_user_tok.lower().startswith("bearer "):
        clean_user_tok = clean_user_tok[7:].strip()
    if not clean_user_tok:
        raise PermissionError("A valid Google user OAuth2 access token is required to initiate impersonation.")
    clean_sa = validate_sa_email(target_sa_email)

    url = (
        f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
        f"{quote_path_segment(clean_sa)}:generateAccessToken"
    )
    body = {
        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
        "lifetime": f"{max(300, min(3600, lifetime_seconds))}s",
    }
    headers = {
        "Authorization": f"Bearer {clean_user_tok}",
        "Content-Type": "application/json",
    }
    sa_proj = _extract_sa_project_id(clean_sa)
    if sa_proj:
        headers["x-goog-user-project"] = sa_proj

    resp = httpx.post(url, headers=headers, json=body, timeout=15.0)
    if resp.status_code == 403 and "x-goog-user-project" in headers and (
        "USER_PROJECT_DENIED" in resp.text or "serviceusage.services.use" in resp.text
    ):
        headers.pop("x-goog-user-project", None)
        resp = httpx.post(url, headers=headers, json=body, timeout=15.0)

    if resp.status_code != 200:
        try:
            err_msg = (resp.json().get("error") or {}).get("message", resp.text[:240])
        except Exception:
            err_msg = resp.text[:240]
        who = caller_email or "<YOUR_EMAIL>"
        raise PermissionError(
            f"Service Account impersonation failed on '{clean_sa}' (HTTP {resp.status_code}: {err_msg}). "
            f"Ensure 'iamcredentials.googleapis.com' is enabled and grant Token Creator to your user: "
            f'gcloud iam service-accounts add-iam-policy-binding {clean_sa} --member="user:{who}" '
            f'--role="roles/iam.serviceAccountTokenCreator"'
        )

    payload = resp.json()
    access_token = payload.get("accessToken", "").strip()
    if not access_token:
        raise PermissionError(f"IAM Credentials API returned an empty accessToken for '{clean_sa}'.")

    return access_token, time.time() + (lifetime_seconds - 60)


def mint_delegated_sa_token_via_runtime_sa(
    target_sa_email: str,
    lifetime_seconds: int = 3600,
) -> Tuple[str, float]:
    """Renews a short-lived impersonation token for an owner-verified target SA using platform runtime delegation."""
    from backend.validators import quote_path_segment, validate_sa_email

    if not persistent_delegation_enabled():
        raise PermissionError("Persistent runtime-SA delegation is disabled on this deployment.")

    clean_sa = validate_sa_email(target_sa_email)

    import google.auth
    import google.auth.transport.requests

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    if not getattr(creds, "token", None) or getattr(creds, "expired", False):
        creds.refresh(google.auth.transport.requests.Request())
    runtime_tok = str(getattr(creds, "token", "") or "")
    if not runtime_tok:
        raise PermissionError("Runtime Service Account token unavailable for persistent delegation.")

    url = (
        f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
        f"{quote_path_segment(clean_sa)}:generateAccessToken"
    )
    body = {
        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
        "lifetime": f"{max(300, min(3600, lifetime_seconds))}s",
    }
    headers = {
        "Authorization": f"Bearer {runtime_tok}",
        "Content-Type": "application/json",
    }
    sa_proj = _extract_sa_project_id(clean_sa)
    if sa_proj:
        headers["x-goog-user-project"] = sa_proj

    resp = httpx.post(url, headers=headers, json=body, timeout=12.0)
    if resp.status_code == 403 and "x-goog-user-project" in headers and (
        "USER_PROJECT_DENIED" in resp.text or "serviceusage.services.use" in resp.text
    ):
        headers.pop("x-goog-user-project", None)
        resp = httpx.post(url, headers=headers, json=body, timeout=12.0)

    if resp.status_code != 200:
        raise PermissionError(f"Runtime SA persistent delegation unavailable for '{clean_sa}' (HTTP {resp.status_code}).")

    payload = resp.json()
    access_token = payload.get("accessToken", "").strip()
    if not access_token:
        raise PermissionError("Empty delegated accessToken returned.")
    return access_token, time.time() + (lifetime_seconds - 60)


def _persist_session(sess: InspectionSession, *, replace_existing: bool = False) -> None:
    if sess.connection_mode == "local_cli_adc":
        return
    try:
        save_workspace_connection(
            workspace_id=sess.session_id,
            owner_email=sess.owner_email,
            record=sess.to_persisted_record(),
            replace_existing=replace_existing,
            secret_tokens={
                "base_user_access_token": sess.base_user_access_token,
                "effective_access_token": sess.effective_access_token,
                "token_expires_at": sess.token_expires_at,
            },
        )
    except Exception as exc:
        logger.warning("Failed persisting workspace connection for %s: %s", sess.owner_email, exc)


GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
DIRECT_TOKEN_FALLBACK_TTL_SECONDS = 300.0


def resolve_direct_user_token_expiry(access_token: str) -> float:
    """Resolves real UTC epoch expiration for a `direct_user` OAuth2 access token via Google tokeninfo."""
    clean_tok = (access_token or "").strip()
    if clean_tok.lower().startswith("bearer "):
        clean_tok = clean_tok[7:].strip()
    if not clean_tok:
        raise PermissionError("A valid Google OAuth2 access token is required.")

    now = time.time()
    try:
        resp = httpx.post(
            GOOGLE_TOKENINFO_URL,
            data={"access_token": clean_tok},
            timeout=6.0,
        )
    except httpx.HTTPError as exc:
        logger.warning("Direct user tokeninfo lookup failed (%s); capping token TTL conservatively.", exc)
        return now + DIRECT_TOKEN_FALLBACK_TTL_SECONDS

    if resp.status_code in (400, 401):
        raise PermissionError("Google OAuth2 access token is invalid or expired according to tokeninfo.")
    if resp.status_code != 200:
        logger.warning("Direct user tokeninfo returned HTTP %s; capping token TTL conservatively.", resp.status_code)
        return now + DIRECT_TOKEN_FALLBACK_TTL_SECONDS

    try:
        info = resp.json()
    except Exception:
        return now + DIRECT_TOKEN_FALLBACK_TTL_SECONDS
    if not isinstance(info, dict):
        return now + DIRECT_TOKEN_FALLBACK_TTL_SECONDS

    real_exp: Optional[float] = None
    if info.get("expires_in") is not None:
        try:
            expires_in = float(info["expires_in"])
            if expires_in <= 0:
                raise PermissionError("Google OAuth2 access token has already expired.")
            real_exp = now + expires_in
        except PermissionError:
            raise
        except (TypeError, ValueError):
            real_exp = None
    elif info.get("exp") is not None:
        try:
            exp_ts = float(info["exp"])
            if exp_ts <= now:
                raise PermissionError("Google OAuth2 access token has already expired.")
            real_exp = exp_ts
        except PermissionError:
            raise
        except (TypeError, ValueError):
            real_exp = None

    if real_exp is None:
        return now + DIRECT_TOKEN_FALLBACK_TTL_SECONDS
    return min(real_exp, now + SESSION_TOKEN_LIFETIME_SECONDS)


def _try_renew_session_token(sess: InspectionSession, *, force: bool = False) -> bool:
    """Attempts short-lived SA token renewal ONLY when explicit runtime SA delegation is active."""
    if (
        sess.connection_mode != "impersonated_sa"
        or not sess.impersonated_sa_email
        or not sess.persistent_sa_delegation
        or not persistent_delegation_enabled()
    ):
        return sess.is_live_token_valid

    now = time.time()
    if not force and sess.last_renewal_attempt_at and (now - sess.last_renewal_attempt_at) < 60.0:
        return sess.is_live_token_valid
    sess.last_renewal_attempt_at = now

    try:
        new_tok, new_exp = mint_delegated_sa_token_via_runtime_sa(sess.impersonated_sa_email)
        sess.effective_access_token = new_tok
        sess.token_expires_at = new_exp
        _persist_session(sess)
    except Exception:
        pass
    return sess.is_live_token_valid


def _hydrate_session_from_store(session_id: str, owner_email: str) -> Optional[InspectionSession]:
    """Hydrates an `InspectionSession` from persistent GCS/local workspace store after restart or scale-to-zero."""
    loaded = load_workspace_connection(session_id, owner_email)
    if loaded is None:
        return None
    rec, tokens = loaded
    try:
        rec_retention = normalize_retention_days(rec.get("retention_days"))
    except ValueError:
        rec_retention = default_retention_days()
    set_workspace_retention_days(session_id, rec_retention)
    raw_exp = float(tokens.get("token_expires_at") or rec.get("token_expires_at") or 0.0)
    # Guard against any legacy monotonic timestamps (< 1e9 epoch)
    if raw_exp < 1_000_000_000.0:
        raw_exp = 0.0

    sess = InspectionSession(
        session_id=session_id,
        owner_email=owner_email.strip().lower(),
        connection_mode=str(rec.get("connection_mode") or "impersonated_sa"),
        base_user_access_token=str(tokens.get("base_user_access_token") or ""),
        impersonated_sa_email=str(rec.get("impersonated_sa_email") or ""),
        effective_access_token=str(tokens.get("effective_access_token") or ""),
        token_expires_at=raw_exp,
        organization_id=str(rec.get("organization_id") or ""),
        organization_domain=str(rec.get("organization_domain") or ""),
        customer_name=str(rec.get("customer_name") or ""),
        optional_customer_bq_table=str(rec.get("optional_customer_bq_table") or ""),
        quota_project_id=str(rec.get("quota_project_id") or ""),
        persistent_sa_delegation=bool(rec.get("persistent_sa_delegation", False)),
        selected_scope=str(rec.get("selected_scope") or ""),
        project_scope_mode=str(rec.get("project_scope_mode") or "ORG_ALL"),
        selected_project_ids=list(rec.get("selected_project_ids") or []),
        has_pinned_book=bool(rec.get("has_pinned_book", False)),
        has_pinned_inventory=bool(rec.get("has_pinned_inventory", False)),
        pinned_scope=str(rec.get("pinned_scope") or ""),
        pinned_generated_at=str(rec.get("pinned_generated_at") or ""),
        retention_days=rec_retention,
        created_at_iso=str(rec.get("created_at_iso") or datetime.datetime.now(datetime.timezone.utc).isoformat()),
    )
    return sess


def store_inspection_session(
    *,
    session_id: str,
    owner_email: str,
    user_access_token: str = "",
    connection_mode: str = "impersonated_sa",
    target_sa_email: str = "",
    organization_id: str = "",
    organization_domain: str = "",
    customer_name: str = "",
    optional_customer_bq_table: str = "",
    token_expires_at: Optional[float] = None,
    retention_days: Optional[int] = None,
) -> InspectionSession:
    """Creates or updates a persistent isolated `InspectionSession` for `(session_id, owner_email)`.

    `retention_days` is the consultant-selected retention for persisted workspace data (0 = persist nothing).
    When omitted, the workspace keeps its current retention (or the deployment default on first connection).
    """
    from backend.validators import validate_bq_table_id, validate_org_id, validate_sa_email

    clean_tok = (user_access_token or "").strip()
    if clean_tok.lower().startswith("bearer "):
        clean_tok = clean_tok[7:].strip()

    clean_owner = owner_email.strip().lower()
    clean_org = validate_org_id(organization_id, allow_empty=True)
    clean_sa = validate_sa_email(target_sa_email, allow_empty=True)
    clean_bq = (optional_customer_bq_table or "").strip()
    if clean_bq:
        p, d, t = validate_bq_table_id(clean_bq.replace(":", "."))
        clean_bq = f"{p}.{d}.{t}"
        optional_customer_bq_table = clean_bq
    mode = "impersonated_sa" if (connection_mode == "impersonated_sa" or clean_sa) else "direct_user"

    existing = get_inspection_session(session_id, clean_owner)
    persistent_delegation = False
    if retention_days is None:
        clean_retention = existing.retention_days if existing is not None else default_retention_days()
    else:
        clean_retention = normalize_retention_days(retention_days)

    if mode == "impersonated_sa":
        if clean_tok:
            eff_tok, tok_exp = mint_impersonated_sa_token(
                user_access_token=clean_tok,
                target_sa_email=clean_sa,
                caller_email=clean_owner,
            )
            # Only when the deployment opted in: detect whether the customer granted runtime-SA auto-renew
            if persistent_delegation_enabled():
                try:
                    mint_delegated_sa_token_via_runtime_sa(clean_sa)
                    persistent_delegation = True
                except Exception:
                    persistent_delegation = False
        elif (
            persistent_delegation_enabled()
            and existing is not None
            and existing.persistent_sa_delegation
            and existing.impersonated_sa_email.lower() == clean_sa.lower()
            and existing.owner_email == clean_owner
        ):
            # Reconnecting an already owner-verified target SA via persistent runtime delegation
            eff_tok, tok_exp = mint_delegated_sa_token_via_runtime_sa(clean_sa)
            persistent_delegation = True
        else:
            raise PermissionError(
                "A valid Google OAuth2 access token (`ya29...`) is required to prove authorization on initial connection."
            )
        quota_proj = _extract_sa_project_id(clean_sa)
    else:
        if not clean_tok:
            raise PermissionError("A valid Google OAuth2 access token (`ya29...`) is required for Direct User Access.")
        eff_tok = clean_tok
        tok_exp = (
            float(token_expires_at)
            if token_expires_at is not None
            else resolve_direct_user_token_expiry(clean_tok)
        )
        quota_proj = ""

    # Preserve customer metadata and pinned scans ONLY when reconnecting to the same customer target.
    # A different Service Account (or, for direct user access, an Organization that is not explicitly the
    # same) is a different customer: it must never inherit the previous Organization, name, scope or pins.
    if existing is None or existing.connection_mode != mode:
        preserve_pins = False
    elif mode == "impersonated_sa":
        preserve_pins = existing.impersonated_sa_email.lower() == clean_sa.lower() and (
            not clean_org or not existing.organization_id or existing.organization_id == clean_org
        )
    else:
        preserve_pins = bool(clean_org) and existing.organization_id == clean_org

    sess = InspectionSession(
        session_id=session_id,
        owner_email=clean_owner,
        connection_mode=mode,
        base_user_access_token=clean_tok or (existing.base_user_access_token if existing else ""),
        impersonated_sa_email=clean_sa if mode == "impersonated_sa" else "",
        effective_access_token=eff_tok,
        token_expires_at=tok_exp,
        organization_id=clean_org or (existing.organization_id if preserve_pins and existing else ""),
        organization_domain=organization_domain.strip() or (existing.organization_domain if preserve_pins and existing else ""),
        customer_name=customer_name.strip() or (existing.customer_name if preserve_pins and existing else ""),
        optional_customer_bq_table=optional_customer_bq_table.strip(),
        quota_project_id=quota_proj,
        persistent_sa_delegation=persistent_delegation,
        selected_scope=existing.selected_scope if preserve_pins and existing else "",
        project_scope_mode=existing.project_scope_mode if preserve_pins and existing else "ORG_ALL",
        selected_project_ids=list(existing.selected_project_ids) if preserve_pins and existing else [],
        has_pinned_book=existing.has_pinned_book if preserve_pins and existing else False,
        has_pinned_inventory=existing.has_pinned_inventory if preserve_pins and existing else False,
        pinned_scope=existing.pinned_scope if preserve_pins and existing else "",
        pinned_generated_at=existing.pinned_generated_at if preserve_pins and existing else "",
        retention_days=clean_retention,
    )

    # Clear any prior local export files and in-memory caches for this session_id before recording the new session
    export_dir = session_export_dir_for_id(session_id)
    shutil.rmtree(export_dir, ignore_errors=True)
    export_dir.mkdir(parents=True, exist_ok=True)
    for hook in list(_CACHE_PURGE_HOOKS):
        try:
            hook(session_id)
        except Exception:
            pass

    with _VAULT_LOCK:
        _SESSION_VAULT[session_id] = sess
        _HYDRATE_MISS_UNTIL.pop(session_id, None)

    # Apply the consultant-selected retention to anything already stored, then persist the new record
    try:
        if existing is None or existing.retention_days != clean_retention or clean_retention <= 0:
            apply_workspace_retention(session_id, clean_owner, clean_retention)
        else:
            set_workspace_retention_days(session_id, clean_retention)
    except Exception as exc:
        logger.warning("Failed applying workspace retention for %s: %s", clean_owner, exc)

    # A different customer starts from a clean stored record (no inherited hierarchy, readiness or pins)
    _persist_session(sess, replace_existing=not preserve_pins)
    return sess


def update_session_organization_metadata(
    session_id: str,
    owner_email: str,
    *,
    organization_id: Optional[str] = None,
    organization_domain: Optional[str] = None,
    customer_name: Optional[str] = None,
    quota_project_id: Optional[str] = None,
    selected_scope: Optional[str] = None,
    project_scope_mode: Optional[str] = None,
    selected_project_ids: Optional[List[str]] = None,
    has_pinned_book: Optional[bool] = None,
    has_pinned_inventory: Optional[bool] = None,
    pinned_scope: Optional[str] = None,
    pinned_generated_at: Optional[str] = None,
) -> Optional[InspectionSession]:
    """Updates Organization / Scope / Pin metadata on the active `InspectionSession` and persists it durably."""
    clean_owner = owner_email.strip().lower()
    sess = get_inspection_session(session_id, clean_owner)
    if sess is None:
        return None
    updates: Dict[str, Any] = {}
    with _VAULT_LOCK:
        if organization_id is not None and organization_id.strip():
            sess.organization_id = organization_id.strip().replace("organizations/", "").strip("/")
            updates["organization_id"] = sess.organization_id
        if organization_domain is not None and organization_domain.strip():
            sess.organization_domain = organization_domain.strip()
            updates["organization_domain"] = sess.organization_domain
        if customer_name is not None and customer_name.strip():
            sess.customer_name = customer_name.strip()
            updates["customer_name"] = sess.customer_name
        if quota_project_id is not None and quota_project_id.strip():
            sess.quota_project_id = quota_project_id.strip()
            updates["quota_project_id"] = sess.quota_project_id
        if selected_scope is not None:
            sess.selected_scope = selected_scope.strip()
            updates["selected_scope"] = sess.selected_scope
        if project_scope_mode is not None and project_scope_mode.strip():
            sess.project_scope_mode = project_scope_mode.strip()
            updates["project_scope_mode"] = sess.project_scope_mode
        if selected_project_ids is not None:
            sess.selected_project_ids = [str(p).strip() for p in selected_project_ids if str(p).strip()]
            updates["selected_project_ids"] = list(sess.selected_project_ids)
        if has_pinned_book is not None:
            sess.has_pinned_book = bool(has_pinned_book)
            updates["has_pinned_book"] = sess.has_pinned_book
        if has_pinned_inventory is not None:
            sess.has_pinned_inventory = bool(has_pinned_inventory)
            updates["has_pinned_inventory"] = sess.has_pinned_inventory
        if pinned_scope is not None:
            sess.pinned_scope = pinned_scope.strip()
            updates["pinned_scope"] = sess.pinned_scope
        if pinned_generated_at is not None:
            sess.pinned_generated_at = pinned_generated_at.strip()
            updates["pinned_generated_at"] = sess.pinned_generated_at

    if updates and sess.connection_mode != "local_cli_adc":
        try:
            update_workspace_connection_fields(session_id, clean_owner, updates)
        except Exception as exc:
            logger.warning("Failed updating persisted workspace metadata for %s: %s", clean_owner, exc)
    return sess


def get_inspection_session(session_id: str, owner_email: str) -> Optional[InspectionSession]:
    """Retrieves (or hydrates from persistent GCS/local store) the user's isolated `InspectionSession`."""
    if not session_id or not owner_email:
        return None
    clean_owner = owner_email.strip().lower()
    with _VAULT_LOCK:
        sess = _SESSION_VAULT.get(session_id)
        if sess is not None and sess.owner_email != clean_owner:
            sess = None

    if sess is None:
        with _VAULT_LOCK:
            miss_until = _HYDRATE_MISS_UNTIL.get(session_id, 0.0)
        if time.monotonic() < miss_until:
            return None
        hydrated = _hydrate_session_from_store(session_id, clean_owner)
        if hydrated is None:
            miss_ttl = float(os.getenv("IAM_HYDRATE_MISS_TTL_SECONDS", str(HYDRATE_MISS_TTL_SECONDS)))
            if miss_ttl > 0:
                with _VAULT_LOCK:
                    _HYDRATE_MISS_UNTIL[session_id] = time.monotonic() + miss_ttl
            return None
        with _VAULT_LOCK:
            _SESSION_VAULT[session_id] = hydrated
            sess = hydrated

    sess.last_activity_at = time.time()

    # Auto-refresh short-lived impersonated SA token when nearing or past expiry
    if sess.connection_mode == "impersonated_sa" and time.time() >= (sess.token_expires_at - 120.0):
        _try_renew_session_token(sess)

    return sess


def wipe_inspection_session(
    session_id: str,
    owner_email: str = "",
    *,
    wipe_persistent: bool = True,
) -> bool:
    """Destroys RAM session, pending tokens, caches, temp files, and durable workspace ONLY when owner matches."""
    if not session_id:
        return False
    clean_owner = (owner_email or "").strip().lower()
    removed = False
    with _VAULT_LOCK:
        sess = _SESSION_VAULT.get(session_id)
        if sess is not None:
            if clean_owner and sess.owner_email != clean_owner:
                logger.warning(
                    "Refused wipe_inspection_session for sid='%s': owner mismatch (caller='%s')",
                    session_id,
                    clean_owner,
                )
                return False
            _SESSION_VAULT.pop(session_id, None)
            removed = True
        elif clean_owner:
            # Verify no other owner's pending tokens or persisted workspace are deleted on mismatch
            other_pending = any(
                k_sid == session_id and k_owner != clean_owner
                for (k_sid, k_owner) in _PENDING_OAUTH_TOKENS.keys()
            )
            if other_pending:
                logger.warning(
                    "Refused wipe_inspection_session for sid='%s': pending token belongs to another owner",
                    session_id,
                )
                return False

    # Owner verified: purge pending tokens, sanitized export directory, all cache hooks (incl. chat), and workspace
    with _VAULT_LOCK:
        _HYDRATE_MISS_UNTIL.pop(session_id, None)
    purged_tokens = purge_pending_oauth_tokens(session_id=session_id)
    if purged_tokens > 0:
        removed = True

    shutil.rmtree(session_export_dir_for_id(session_id), ignore_errors=True)
    for hook in list(_CACHE_PURGE_HOOKS):
        try:
            hook(session_id)
        except Exception:
            pass
    if wipe_persistent:
        try:
            deleted = wipe_workspace(session_id)
            if deleted > 0:
                removed = True
        except Exception as exc:
            logger.warning("Error wiping persistent workspace %s: %s", session_id, exc)
    return removed


def purge_expired_state(
    *,
    session_idle_ttl_seconds: Optional[float] = None,
) -> Dict[str, int]:
    """Sweeps expired pending OAuth tokens and idle/expired RAM sessions even without incoming traffic."""
    idle_ttl = float(
        session_idle_ttl_seconds
        if session_idle_ttl_seconds is not None
        else float(os.getenv("IAM_SESSION_IDLE_TTL_SECONDS", str(DEFAULT_SESSION_IDLE_TTL_SECONDS)))
    )
    now_wall = time.time()
    expired_sids: List[str] = []
    with _VAULT_LOCK:
        for sid, sess in list(_SESSION_VAULT.items()):
            idle_age = now_wall - float(getattr(sess, "last_activity_at", now_wall) or now_wall)
            token_long_expired = (
                sess.connection_mode != "impersonated_sa"
                and sess.token_expires_at > 0
                and now_wall > (sess.token_expires_at + 3600.0)
            )
            if idle_age >= idle_ttl or token_long_expired:
                _SESSION_VAULT.pop(sid, None)
                expired_sids.append(sid)

    for sid in expired_sids:
        purge_pending_oauth_tokens(session_id=sid)
        shutil.rmtree(session_export_dir_for_id(sid), ignore_errors=True)
        for hook in list(_CACHE_PURGE_HOOKS):
            try:
                hook(sid)
            except Exception:
                pass

    expired_tokens = purge_pending_oauth_tokens(expired_only=True)
    try:
        expired_objects = purge_expired_workspace_objects()
    except Exception as exc:
        logger.warning("Workspace retention sweep failed: %s", exc)
        expired_objects = 0
    return {
        "expired_sessions_purged": len(expired_sids),
        "expired_pending_tokens_purged": expired_tokens,
        "expired_workspace_objects_purged": expired_objects,
    }


@contextlib.contextmanager
def bind_inspection_session_context(sess: Optional[InspectionSession]) -> Iterator[None]:
    """Binds `sess` as the active target inspection context for the current async task and child worker threads."""
    token = _ACTIVE_SESSION_CTX.set(sess)
    try:
        yield
    finally:
        _ACTIVE_SESSION_CTX.reset(token)


@contextlib.contextmanager
def allow_local_cli_adc_context(
    organization_id: str = "",
    organization_domain: str = "",
    export_dir: Optional[Path] = None,
) -> Iterator[InspectionSession]:
    """Explicit opt-in context ONLY for local CLI (`scripts/generate_reports.py`) — never used by web/API routes."""
    import google.auth
    import google.auth.transport.requests

    creds, proj = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    if not getattr(creds, "token", None) or getattr(creds, "expired", False):
        creds.refresh(google.auth.transport.requests.Request())
    tok = getattr(creds, "token", None) or ""
    if not tok:
        raise PermissionError("Unable to obtain local ADC token for CLI execution.")

    cli_sid = f"cli_{secrets.token_hex(8)}"
    sess = InspectionSession(
        session_id=cli_sid,
        owner_email="local-cli@workstation",
        connection_mode="local_cli_adc",
        base_user_access_token=tok,
        impersonated_sa_email="",
        effective_access_token=tok,
        token_expires_at=time.time() + 3600.0,
        organization_id=organization_id.replace("organizations/", "").strip(),
        organization_domain=organization_domain.strip(),
        quota_project_id=proj or "",
    )
    tok_ref = _ACTIVE_SESSION_CTX.set(sess)
    try:
        yield sess
    finally:
        _ACTIVE_SESSION_CTX.reset(tok_ref)
        if export_dir is None:
            shutil.rmtree(session_export_dir_for_id(sess.session_id), ignore_errors=True)


def get_active_inspection_session() -> Optional[InspectionSession]:
    """Returns the currently bound `InspectionSession` in this request/agent execution context, or `None`."""
    return _ACTIVE_SESSION_CTX.get()


def require_active_inspection_session() -> InspectionSession:
    """Returns the active `InspectionSession` with a valid live token (attempting silent renewal first)."""
    sess = _ACTIVE_SESSION_CTX.get()
    if sess is None:
        raise PermissionError(
            "No target GCP Organization is connected in your workspace. "
            "Open 'Customer Onboarding' -> 'Connect Target Organization' to authenticate or impersonate a read-only Service Account."
        )
    if not sess.is_live_token_valid:
        if not _try_renew_session_token(sess, force=True):
            raise PermissionError(
                "Your saved workspace and pinned scan results remain intact, but your 1-hour live GCP OAuth token has expired. "
                "Open 'Customer Onboarding' to refresh your token (or grant Token Creator to the platform runtime SA for permanent auto-renew) "
                "before running a new live GCP scan."
            )
    return sess


def run_pool_map_with_context(
    fn: Callable[[T], R],
    items: Iterable[T],
    max_workers: int = 8,
) -> List[R]:
    """Executes `fn` over `items` in a `ThreadPoolExecutor` while preserving `contextvars` in every worker thread."""
    item_list = list(items)
    if not item_list:
        return []
    workers = max(1, min(max_workers, len(item_list)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(contextvars.copy_context().run, fn, item) for item in item_list]
        return [f.result() for f in futs]
