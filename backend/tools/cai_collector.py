"""Cloud Asset Inventory (CAI) & Resource Manager Read-Only Live Collector (`cai_collector.py`).

Zero-Trust Multi-User Isolation:
- NEVER falls back to the Cloud Run host Service Account (`google.auth.default()`).
- Requires an active per-user `InspectionSession` (`backend/session_vault.py`) carrying either
  a short-lived Service Account impersonation token (`generateAccessToken`) or the user's OAuth token.
- Partitions all in-memory telemetry caches and deliverable exports by `session_id`.
- Never writes findings to the host project's BigQuery; supports optional customer-owned BigQuery export.
"""

from __future__ import annotations

import contextlib
import contextvars
import datetime
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

import httpx

from backend.config import settings
from backend.models.findings import GcpIamPostureFinding
from backend.session_vault import (
    get_active_inspection_session,
    register_cache_purge_hook,
    require_active_inspection_session,
    run_pool_map_with_context,
)
from backend.validators import (
    assert_read_only_gcp_request,
    quote_gcp_resource_path,
    quote_path_segment,
    validate_bq_table_id,
    validate_folder_id,
    validate_org_id,
    validate_project_id,
    validate_sa_email,
)

logger = logging.getLogger(__name__)

_TELEMETRY_CACHE_TTL_SECONDS = 60.0
_BINDINGS_CACHE: Dict[Tuple[str, str], Tuple[float, List[Dict[str, Any]]]] = {}
_RESOURCES_CACHE: Dict[Tuple[str, str], Tuple[float, List[Dict[str, Any]]]] = {}
_ORG_POLICIES_CACHE: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}
_ACTIVE_ORG_PROJECTS_CACHE: Dict[Tuple[str, str], Tuple[float, Tuple[List[str], Set[str]]]] = {}
_ORG_PROJECT_META_CACHE: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}
_SA_KEYS_CACHE: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}
_COVERAGE_CACHE: Dict[Tuple[str, str], Dict[str, "CollectionStatus"]] = {}
_COVERAGE_LOCK = threading.Lock()
_HTTP_CLIENT = httpx.Client(timeout=25.0)

DEFAULT_PAGINATOR_MAX_PAGES = int(os.getenv("IAM_PAGINATOR_MAX_PAGES", "50"))
DEFAULT_PAGINATOR_MAX_ITEMS = int(os.getenv("IAM_PAGINATOR_MAX_ITEMS", "25000"))
DEFAULT_PAGINATOR_TIME_BUDGET_SECONDS = float(os.getenv("IAM_PAGINATOR_TIME_BUDGET_SECONDS", "30.0"))
DEFAULT_MAX_SA_KEY_CHECKS = int(os.getenv("IAM_MAX_SA_KEY_CHECKS", "500"))

_EPHEMERAL_OAUTH_TOKEN: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "ephemeral_oauth_token", default=None
)
_ALLOWED_SCOPE_CTX: contextvars.ContextVar[Optional["ParsedAssessmentScope"]] = contextvars.ContextVar(
    "allowed_assessment_scope", default=None
)


@dataclass
class CollectionStatus:
    """Explicit collection completeness and error telemetry for a single GCP API collector."""

    collector: str
    scope: str
    complete: bool = True
    pages_fetched: int = 0
    items_collected: int = 0
    http_status: int = 200
    error: Optional[str] = None
    cutoff_reason: Optional[str] = None
    evaluated_count: Optional[int] = None
    total_candidates: Optional[int] = None

    def warning_message(self) -> Optional[str]:
        if self.complete:
            return None
        if self.evaluated_count is not None and self.total_candidates is not None and self.evaluated_count < self.total_candidates:
            reason = f" ({self.cutoff_reason})" if self.cutoff_reason else ""
            return (
                f"{self.collector} [{self.scope}]: evaluated {self.evaluated_count} of "
                f"{self.total_candidates} items{reason}."
            )
        if self.cutoff_reason == "HTTP_ERROR" or self.http_status >= 400:
            err_snip = f" — {self.error}" if self.error else ""
            return f"{self.collector} [{self.scope}]: API error HTTP {self.http_status}{err_snip}."
        if self.cutoff_reason:
            return (
                f"{self.collector} [{self.scope}]: truncated after {self.items_collected} items "
                f"across {self.pages_fetched} page(s) ({self.cutoff_reason})."
            )
        return f"{self.collector} [{self.scope}]: incomplete telemetry ({self.error or 'unknown reason'})."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collector": self.collector,
            "scope": self.scope,
            "complete": self.complete,
            "pages_fetched": self.pages_fetched,
            "items_collected": self.items_collected,
            "http_status": self.http_status,
            "error": self.error,
            "cutoff_reason": self.cutoff_reason,
            "evaluated_count": self.evaluated_count,
            "total_candidates": self.total_candidates,
            "warning": self.warning_message(),
        }


def record_collection_status(scope: str, key: str, status_obj: CollectionStatus) -> None:
    """Records a collector's `CollectionStatus` in the per-session, per-scope scan coverage map."""
    try:
        canon = normalize_gcp_scope(scope)
    except Exception:
        canon = (scope or "").strip()
    ck = (active_cache_namespace(), canon)
    with _COVERAGE_LOCK:
        bucket = _COVERAGE_CACHE.setdefault(ck, {})
        bucket[key] = status_obj


def get_scan_coverage_map(scope: str = "") -> Dict[str, CollectionStatus]:
    """Returns a shallow copy of recorded `CollectionStatus` entries for `(session, scope)`."""
    try:
        canon = normalize_gcp_scope(scope)
    except Exception:
        canon = (scope or "").strip()
    ck = (active_cache_namespace(), canon)
    with _COVERAGE_LOCK:
        return dict(_COVERAGE_CACHE.get(ck, {}))


def summarize_scan_coverage(scope: str = "") -> Dict[str, Any]:
    """Summarizes coverage completeness percentage, warnings, and critical collector flags for a scan."""
    cmap = get_scan_coverage_map(scope)
    if not cmap:
        return {
            "data_completeness_pct": 100.0,
            "coverage_warnings": [],
            "collectors": {},
            "bindings_incomplete": False,
            "resources_incomplete": False,
            "sa_keys_incomplete": False,
        }

    total = len(cmap)
    complete_cnt = sum(1 for st in cmap.values() if st.complete)
    warnings: List[str] = []
    for key in sorted(cmap.keys()):
        msg = cmap[key].warning_message()
        if msg:
            warnings.append(msg)

    def _any_incomplete(prefix: str) -> bool:
        return any(not st.complete for k, st in cmap.items() if k == prefix or k.startswith(f"{prefix}:"))

    return {
        "data_completeness_pct": round((complete_cnt / max(total, 1)) * 100.0, 1),
        "coverage_warnings": warnings,
        "collectors": {k: v.to_dict() for k, v in sorted(cmap.items())},
        "bindings_incomplete": _any_incomplete("iam_bindings"),
        "resources_incomplete": _any_incomplete("cai_resources"),
        "sa_keys_incomplete": _any_incomplete("sa_keys"),
    }


def _purge_collector_caches_for_session(session_id: str) -> None:
    prefix = f"{session_id}:"
    for cache_dict in (
        _BINDINGS_CACHE,
        _RESOURCES_CACHE,
        _ORG_POLICIES_CACHE,
        _ACTIVE_ORG_PROJECTS_CACHE,
        _ORG_PROJECT_META_CACHE,
        _SA_KEYS_CACHE,
    ):
        stale = [k for k in list(cache_dict.keys()) if k[0].startswith(prefix)]
        for k in stale:
            cache_dict.pop(k, None)
    with _COVERAGE_LOCK:
        for k in [key for key in list(_COVERAGE_CACHE.keys()) if key[0].startswith(prefix)]:
            _COVERAGE_CACHE.pop(k, None)


register_cache_purge_hook(_purge_collector_caches_for_session)


def active_cache_namespace() -> str:
    sess = get_active_inspection_session()
    if sess is not None:
        return sess.cache_namespace
    eph = _EPHEMERAL_OAUTH_TOKEN.get()
    if eph:
        return f"ephemeral:{hash(eph)}"
    return "disconnected"


def active_organization_id() -> str:
    sess = get_active_inspection_session()
    if sess is not None:
        if sess.organization_id:
            return sess.organization_id
        if sess.connection_mode == "local_cli_adc":
            return (settings.organization_id or "").strip().replace("organizations/", "")
    return ""


def active_organization_domain() -> str:
    sess = get_active_inspection_session()
    if sess is not None:
        if sess.organization_domain:
            return sess.organization_domain
        if sess.connection_mode == "local_cli_adc":
            return (settings.organization_domain or "").strip()
    return ""


def active_organization_domains() -> Set[str]:
    """Returns the normalized lowercase set of organization domains configured for the active session."""
    domains: Set[str] = set()
    sess = get_active_inspection_session()
    if sess is not None:
        raw_set = getattr(sess, "organization_domains", None) or set()
        for d in raw_set:
            clean = str(d or "").strip().lower()
            if clean:
                domains.add(clean)
        if sess.organization_domain:
            for part in str(sess.organization_domain).split(","):
                clean = part.strip().lower()
                if clean:
                    domains.add(clean)
        if not domains and sess.connection_mode == "local_cli_adc" and settings.organization_domain:
            for part in str(settings.organization_domain).split(","):
                clean = part.strip().lower()
                if clean:
                    domains.add(clean)
    return domains


def active_export_dir() -> Path:
    sess = get_active_inspection_session()
    if sess is not None:
        return sess.session_export_dir
    raise PermissionError(
        "No active inspection session; refusing to fall back to the shared host export directory."
    )


KEY_IAM_ORG_CONSTRAINTS: Tuple[str, ...] = (
    "constraints/iam.allowedPolicyMemberDomains",
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/iam.disableServiceAccountKeyUpload",
    "constraints/iam.automaticIamGrantsForDefaultServiceAccounts",
    "constraints/storage.publicAccessPrevention",
    "constraints/compute.requireOsLogin",
)

# Platform-managed Google Service Agents only.
# Default Compute (`-compute@developer.gserviceaccount.com`), App Engine (`@appspot.gserviceaccount.com`),
# and Cloud Build (`@cloudbuild.gserviceaccount.com`) SAs are customer-usable default service accounts
# and are intentionally NOT excluded here.
GOOGLE_SERVICE_AGENT_PATTERNS: Tuple[str, ...] = (
    "@gcp-sa-",
    "@cloudservices.gserviceaccount.com",
    "@serverless-robot-prod.iam.gserviceaccount.com",
    "@container-engine-robot.iam.gserviceaccount.com",
    "@containerregistry.iam.gserviceaccount.com",
    "@container-analysis.iam.gserviceaccount.com",
    "@compute-system.iam.gserviceaccount.com",
)


@dataclass(frozen=True)
class ParsedAssessmentScope:
    """Structured representation of an Organization-wide or Multi-Project assessment scope."""

    canonical_scope: str
    mode: str  # "ORG_ALL" | "ORG_SELECTED_PROJECTS" | "FOLDER"
    organization_id: str
    organization_scope: str
    project_ids: Tuple[str, ...]
    leaf_scopes: Tuple[str, ...]
    org_policy_scope: str


@contextlib.contextmanager
def ephemeral_oauth_token_context(token: Optional[str]) -> Iterator[None]:
    """Binds an optional in-memory read-only OAuth2 access token for pre-connection readiness probes."""
    clean = (token or "").strip()
    if not clean:
        yield
        return
    tok_ref = _EPHEMERAL_OAUTH_TOKEN.set(clean)
    try:
        yield
    finally:
        _EPHEMERAL_OAUTH_TOKEN.reset(tok_ref)


def _clean_project_tokens(raw_projects_csv: str) -> List[str]:
    seen: Set[str] = set()
    cleaned: List[str] = []
    for part in re.split(r"[,;\s]+", raw_projects_csv.strip()):
        tok = part.strip()
        if not tok:
            continue
        if tok.upper() in ("ALL", "*"):
            return []
        if tok.startswith("projects/"):
            tok = tok[len("projects/") :]
        valid_pid = validate_project_id(tok)
        if valid_pid not in seen:
            seen.add(valid_pid)
            cleaned.append(valid_pid)
    return sorted(cleaned)


def parse_assessment_scope(scope: str = "") -> ParsedAssessmentScope:
    """Parses and strictly validates any Organization / Multi-Project / Folder scope string."""
    default_org_id = active_organization_id()
    if default_org_id:
        default_org_id = validate_org_id(default_org_id)
    raw = (scope or "").strip()
    if raw.endswith("/") and raw.count("/") > 1:
        raw = raw.rstrip("/")
    if not raw:
        if default_org_id:
            raw = f"organizations/{default_org_id}"
        else:
            require_active_inspection_session()
            raise ValueError(
                "Target GCP scope is empty. Connect a target Organization and select 1 or more projects first."
            )

    # Reject control characters, query strings, fragments, or path traversal immediately
    if any(ch in raw for ch in ("?", "#", "\\", "\n", "\r", "\x00")) or ".." in raw:
        raise ValueError(f"Invalid target GCP scope '{scope}'.")

    m_org_projs = re.match(
        r"^organizations/([^/]+)(?:/|\|;)projects[:=/](.+)$",
        raw,
        flags=re.IGNORECASE,
    )
    if not m_org_projs:
        m_org_projs = re.match(r"^organizations/([^/]+)/projects:(.+)$", raw, flags=re.IGNORECASE)

    if m_org_projs:
        org_id = validate_org_id(m_org_projs.group(1).strip())
        proj_str = m_org_projs.group(2).strip()
        org_scope = f"organizations/{org_id}"
        if proj_str.upper() in ("ALL", "*", ""):
            return ParsedAssessmentScope(
                canonical_scope=org_scope,
                mode="ORG_ALL",
                organization_id=org_id,
                organization_scope=org_scope,
                project_ids=(),
                leaf_scopes=(org_scope,),
                org_policy_scope=org_scope,
            )
        pids = _clean_project_tokens(proj_str)
        if not pids:
            return ParsedAssessmentScope(
                canonical_scope=org_scope,
                mode="ORG_ALL",
                organization_id=org_id,
                organization_scope=org_scope,
                project_ids=(),
                leaf_scopes=(org_scope,),
                org_policy_scope=org_scope,
            )
        canonical = f"{org_scope}/projects:{','.join(pids)}"
        leaves = tuple(f"projects/{p}" for p in pids)
        return ParsedAssessmentScope(
            canonical_scope=canonical,
            mode="ORG_SELECTED_PROJECTS",
            organization_id=org_id,
            organization_scope=org_scope,
            project_ids=tuple(pids),
            leaf_scopes=leaves,
            org_policy_scope=org_scope,
        )

    if raw.startswith("organizations/"):
        org_part = raw[len("organizations/") :]
        if "/" in org_part:
            raise ValueError(f"Invalid Organization scope '{scope}'.")
        org_id = validate_org_id(org_part)
        org_scope = f"organizations/{org_id}"
        return ParsedAssessmentScope(
            canonical_scope=org_scope,
            mode="ORG_ALL",
            organization_id=org_id,
            organization_scope=org_scope,
            project_ids=(),
            leaf_scopes=(org_scope,),
            org_policy_scope=org_scope,
        )

    if raw.isdigit():
        org_id = validate_org_id(raw)
        org_scope = f"organizations/{org_id}"
        return ParsedAssessmentScope(
            canonical_scope=org_scope,
            mode="ORG_ALL",
            organization_id=org_id,
            organization_scope=org_scope,
            project_ids=(),
            leaf_scopes=(org_scope,),
            org_policy_scope=org_scope,
        )

    if raw.startswith("folders/"):
        fld_part = raw[len("folders/") :]
        if "/" in fld_part:
            raise ValueError(f"Invalid Folder scope '{scope}'.")
        fld_id = validate_folder_id(fld_part)
        fld_scope = f"folders/{fld_id}"
        org_scope = f"organizations/{default_org_id}" if default_org_id else ""
        return ParsedAssessmentScope(
            canonical_scope=fld_scope,
            mode="FOLDER",
            organization_id=default_org_id,
            organization_scope=org_scope,
            project_ids=(),
            leaf_scopes=(fld_scope,),
            org_policy_scope=fld_scope,
        )

    stripped_proj = raw[len("projects:") :] if raw.lower().startswith("projects:") else raw
    pids = _clean_project_tokens(stripped_proj)
    if not pids:
        raise ValueError(f"Invalid target project scope '{scope}'.")

    leaves = tuple(f"projects/{p}" for p in pids)
    if default_org_id:
        org_scope = f"organizations/{default_org_id}"
        canonical = f"{org_scope}/projects:{','.join(pids)}"
        return ParsedAssessmentScope(
            canonical_scope=canonical,
            mode="ORG_SELECTED_PROJECTS",
            organization_id=default_org_id,
            organization_scope=org_scope,
            project_ids=tuple(pids),
            leaf_scopes=leaves,
            org_policy_scope=org_scope,
        )

    canonical = leaves[0] if len(leaves) == 1 else f"projects:{','.join(pids)}"
    return ParsedAssessmentScope(
        canonical_scope=canonical,
        mode="ORG_SELECTED_PROJECTS",
        organization_id="",
        organization_scope="",
        project_ids=tuple(pids),
        leaf_scopes=leaves,
        org_policy_scope=leaves[0],
    )


def normalize_gcp_scope(scope: str = "") -> str:
    """Normalizes a user-provided Organization / Multi-Project / Folder scope to its canonical string."""
    return parse_assessment_scope(scope).canonical_scope


def is_scope_contained(candidate: ParsedAssessmentScope, allowed: ParsedAssessmentScope) -> bool:
    """Returns True if `candidate` is equal to or strictly contained within `allowed`."""
    if candidate.canonical_scope == allowed.canonical_scope:
        return True
    if allowed.organization_id and candidate.organization_id and candidate.organization_id != allowed.organization_id:
        return False
    if allowed.mode == "ORG_ALL":
        if candidate.mode == "ORG_ALL":
            return candidate.organization_id == allowed.organization_id
        if candidate.mode == "ORG_SELECTED_PROJECTS":
            return (not candidate.organization_id) or candidate.organization_id == allowed.organization_id
        if candidate.mode == "FOLDER":
            return (not candidate.organization_id) or candidate.organization_id == allowed.organization_id
        return False
    if allowed.mode == "ORG_SELECTED_PROJECTS":
        if candidate.mode != "ORG_SELECTED_PROJECTS":
            return False
        return bool(candidate.project_ids) and set(candidate.project_ids).issubset(set(allowed.project_ids))
    if allowed.mode == "FOLDER":
        return candidate.canonical_scope == allowed.canonical_scope
    return False


@contextlib.contextmanager
def bind_allowed_scope_context(scope: str) -> Iterator[ParsedAssessmentScope]:
    """Binds the authorized assessment scope for the current request/ADK execution context."""
    parsed = parse_assessment_scope(scope)
    sess = get_active_inspection_session()
    if sess is not None and sess.organization_id and parsed.organization_id and parsed.organization_id != sess.organization_id:
        raise PermissionError(
            f"Requested scope '{parsed.canonical_scope}' does not match connected session organization 'organizations/{sess.organization_id}'."
        )
    tok = _ALLOWED_SCOPE_CTX.set(parsed)
    try:
        yield parsed
    finally:
        _ALLOWED_SCOPE_CTX.reset(tok)


def assert_scope_allowed(scope: str = "") -> ParsedAssessmentScope:
    """Validates scope syntax and enforces containment within the active request/session scope."""
    parsed = parse_assessment_scope(scope)
    allowed = _ALLOWED_SCOPE_CTX.get()
    if allowed is not None:
        if not is_scope_contained(parsed, allowed):
            raise PermissionError(
                f"Tool scope '{parsed.canonical_scope}' is outside the authorized request scope '{allowed.canonical_scope}'."
            )
    sess = get_active_inspection_session()
    if sess is not None and sess.organization_id and parsed.organization_id and parsed.organization_id != sess.organization_id:
        raise PermissionError(
            f"Tool scope organization 'organizations/{parsed.organization_id}' does not match active session organization 'organizations/{sess.organization_id}'."
        )
    return parsed


def get_gcp_access_token_and_headers(include_quota_project: bool = True) -> Tuple[str, Dict[str, str]]:
    """Returns the user's isolated inspection token & headers (NEVER falls back to host Cloud Run ADC)."""
    ephemeral_tok = _EPHEMERAL_OAUTH_TOKEN.get()
    if ephemeral_tok:
        return ephemeral_tok, {
            "Authorization": f"Bearer {ephemeral_tok}",
            "Content-Type": "application/json",
        }

    sess = require_active_inspection_session()
    headers = {
        "Authorization": f"Bearer {sess.effective_access_token}",
        "Content-Type": "application/json",
    }
    if include_quota_project and sess.quota_project_id:
        headers["x-goog-user-project"] = sess.quota_project_id
    return sess.effective_access_token, headers


def gcp_rest_request(
    method: str,
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: float = 20.0,
    quota_project: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Executes a read-only-guarded authenticated REST call strictly using the active user's inspection token."""
    # Enforce HTTPS host allowlist and read-only method/POST-suffix guardrails BEFORE any network call
    assert_read_only_gcp_request(method, url)

    _, headers = get_gcp_access_token_and_headers(include_quota_project=True)
    if quota_project and quota_project.strip():
        headers["x-goog-user-project"] = validate_project_id(quota_project.strip())

    resp = _HTTP_CLIENT.request(
        method=method.upper(),
        url=url,
        headers=headers,
        params=params,
        json=json_body,
        timeout=timeout,
    )

    # Case A: User token lacked x-goog-user-project on an API requiring a quota project (e.g. recommender.googleapis.com)
    if resp.status_code == 403 and "x-goog-user-project" not in headers and "quota project" in resp.text.lower():
        m_proj = re.search(r"/projects/([a-z][a-z0-9-]{4,29})(?:/|:|$)", url)
        inferred_proj = m_proj.group(1) if m_proj else ""
        if inferred_proj:
            q_headers = {**headers, "x-goog-user-project": inferred_proj}
            resp = _HTTP_CLIENT.request(
                method=method.upper(),
                url=url,
                headers=q_headers,
                params=params,
                json=json_body,
                timeout=timeout,
            )

    # Case B: Quota project lacked serviceusage.services.use -> retry without header when API permits
    if (
        resp.status_code == 403
        and "x-goog-user-project" in headers
        and ("USER_PROJECT_DENIED" in resp.text or "serviceusage.services.use" in resp.text)
    ):
        retry_headers = {k: v for k, v in headers.items() if k != "x-goog-user-project"}
        resp = _HTTP_CLIENT.request(
            method=method.upper(),
            url=url,
            headers=retry_headers,
            params=params,
            json=json_body,
            timeout=timeout,
        )
    try:
        data = resp.json() if resp.text.strip() else {}
    except Exception:
        data = {"raw_body": resp.text[:500]}
    return resp.status_code, data


def gcp_paginated_request(
    method: str,
    url: str,
    *,
    results_key: str,
    collector: str,
    scope: str,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    page_token_key: str = "pageToken",
    next_page_token_key: str = "nextPageToken",
    timeout: float = 18.0,
    quota_project: Optional[str] = None,
    max_pages: Optional[int] = None,
    max_items: Optional[int] = None,
    time_budget_seconds: Optional[float] = None,
    max_retries: int = 3,
    base_backoff_seconds: float = 0.25,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> Tuple[List[Dict[str, Any]], CollectionStatus]:
    """Central GCP REST paginator with configurable caps, time budget, 429/5xx retry, and explicit CollectionStatus."""
    eff_max_pages = max(1, int(max_pages if max_pages is not None else int(os.getenv("IAM_PAGINATOR_MAX_PAGES", str(DEFAULT_PAGINATOR_MAX_PAGES)))))
    eff_max_items = max(1, int(max_items if max_items is not None else int(os.getenv("IAM_PAGINATOR_MAX_ITEMS", str(DEFAULT_PAGINATOR_MAX_ITEMS)))))
    eff_budget = float(time_budget_seconds if time_budget_seconds is not None else float(os.getenv("IAM_PAGINATOR_TIME_BUDGET_SECONDS", str(DEFAULT_PAGINATOR_TIME_BUDGET_SECONDS))))

    items: List[Dict[str, Any]] = []
    status_obj = CollectionStatus(collector=collector, scope=scope, complete=True)
    deadline = time.monotonic() + eff_budget
    page_token: Optional[str] = None

    for page_idx in range(eff_max_pages):
        if page_idx > 0 and time.monotonic() >= deadline:
            status_obj.complete = False
            status_obj.cutoff_reason = "TIME_BUDGET"
            break

        req_params = dict(params) if params is not None else None
        req_body = dict(json_body) if json_body is not None else None
        if page_token:
            if method.upper() == "POST" and req_body is not None:
                req_body[page_token_key] = page_token
            else:
                req_params = dict(req_params or {})
                req_params[page_token_key] = page_token

        code = 0
        data: Dict[str, Any] = {}
        last_exc: Optional[Exception] = None
        for attempt in range(max_retries + 1):
            try:
                code, data = gcp_rest_request(
                    method,
                    url,
                    params=req_params,
                    json_body=req_body,
                    timeout=timeout,
                    quota_project=quota_project,
                )
                last_exc = None
            except Exception as exc:
                last_exc = exc
                code = 0
                data = {}

            is_retryable = last_exc is None and code in (429, 500, 502, 503, 504)
            if is_retryable and attempt < max_retries:
                delay = base_backoff_seconds * (2 ** attempt)
                remaining = deadline - time.monotonic()
                if remaining > 0.05:
                    sleep_fn(min(delay, remaining))
                    continue
            break

        if last_exc is not None:
            status_obj.complete = False
            status_obj.http_status = 0
            status_obj.error = f"{type(last_exc).__name__}: {last_exc}"
            status_obj.cutoff_reason = "EXCEPTION"
            break

        status_obj.http_status = code
        if code != 200 or not isinstance(data, dict):
            err_detail = ""
            if isinstance(data, dict):
                raw_err = data.get("error")
                if isinstance(raw_err, dict):
                    err_detail = str(raw_err.get("message") or json.dumps(raw_err)[:220])
                elif raw_err:
                    err_detail = str(raw_err)[:220]
                else:
                    err_detail = json.dumps(data)[:220]
            status_obj.complete = False
            status_obj.error = err_detail or f"HTTP_{code}"
            status_obj.cutoff_reason = "HTTP_ERROR"
            break

        status_obj.pages_fetched += 1
        batch = data.get(results_key) or []
        if isinstance(batch, list):
            for entry in batch:
                if len(items) >= eff_max_items:
                    status_obj.complete = False
                    status_obj.cutoff_reason = "MAX_ITEMS"
                    break
                items.append(entry)
        status_obj.items_collected = len(items)

        if status_obj.cutoff_reason == "MAX_ITEMS":
            break

        page_token = data.get(next_page_token_key)
        if not page_token:
            break
        if page_idx + 1 >= eff_max_pages:
            status_obj.complete = False
            status_obj.cutoff_reason = "MAX_PAGES"
            break

    status_obj.items_collected = len(items)
    return items, status_obj


def is_google_managed_service_agent(principal: str) -> bool:
    low = principal.lower()
    if not low.startswith("serviceaccount:"):
        return False
    if is_default_service_account_email(low):
        return False
    return any(pat in low for pat in GOOGLE_SERVICE_AGENT_PATTERNS)


def is_default_service_account_email(email_or_principal: str) -> bool:
    clean = email_or_principal.replace("serviceAccount:", "").replace("serviceaccount:", "").strip().lower()
    return (
        clean.endswith("-compute@developer.gserviceaccount.com")
        or clean.endswith("@appspot.gserviceaccount.com")
        or clean.endswith("@cloudbuild.gserviceaccount.com")
    )


def extract_sa_owning_project(email_or_principal: str) -> str:
    """Extracts the owning GCP project ID (or project number for Compute/Cloud Build default SAs) from an SA email."""
    clean = str(email_or_principal or "").strip()
    if clean.lower().startswith("serviceaccount:"):
        clean = clean.split(":", 1)[1].strip()
    low = clean.lower()
    m_iam = re.match(r"^[^@\s]+@([a-z][a-z0-9-]{4,29})\.iam\.gserviceaccount\.com$", low)
    if m_iam:
        return m_iam.group(1)
    m_app = re.match(r"^([a-z][a-z0-9-]{4,29})@appspot\.gserviceaccount\.com$", low)
    if m_app:
        return m_app.group(1)
    m_gce = re.match(r"^([0-9]+)-compute@developer\.gserviceaccount\.com$", low)
    if m_gce:
        return m_gce.group(1)
    m_cb = re.match(r"^([0-9]+)@cloudbuild\.gserviceaccount\.com$", low)
    if m_cb:
        return m_cb.group(1)
    return ""


def extract_attached_workload_service_accounts(resource: Dict[str, Any]) -> List[str]:
    """Shared helper extracting attached runtime Service Account emails from BOTH `additional_attributes` and `versioned_resource`."""
    attrs = resource.get("additional_attributes") or {}
    vres = resource.get("versioned_resource") or {}
    found: List[str] = []
    seen: Set[str] = set()

    def _add(val: Any) -> None:
        if isinstance(val, str):
            em = val.strip()
            if "@" in em and em.lower() not in seen:
                seen.add(em.lower())
                found.append(em)

    # Direct scalar fields across GCE, Cloud Run v2, and Knative/Cloud Run v1 specs
    tpl = vres.get("template") if isinstance(vres.get("template"), dict) else {}
    spec = vres.get("spec") if isinstance(vres.get("spec"), dict) else {}
    spec_tpl = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    spec_tpl_spec = spec_tpl.get("spec") if isinstance(spec_tpl.get("spec"), dict) else {}
    for cand in (
        attrs.get("serviceAccountEmail"),
        attrs.get("serviceAccount"),
        vres.get("serviceAccountEmail"),
        vres.get("serviceAccount"),
        tpl.get("serviceAccount"),
        spec_tpl_spec.get("serviceAccountName"),
    ):
        _add(cand)

    # List fields (GCE `serviceAccounts: [{"email": "..."}]` in additionalAttributes or versionedResource)
    for src_list in (attrs.get("serviceAccounts"), vres.get("serviceAccounts")):
        if isinstance(src_list, list):
            for item in src_list:
                if isinstance(item, dict):
                    _add(item.get("email"))
                else:
                    _add(item)

    return found


def classify_principal_domain_and_type(
    principal: str,
    *,
    org_project_identifiers: Optional[Set[str]] = None,
    org_projects_complete: Optional[bool] = None,
    coverage_scope: Optional[str] = None,
) -> Dict[str, Any]:
    """Classifies a real IAM member string relative to the connected Organization's domains & projects."""
    org_domains = active_organization_domains()
    p = principal.strip()
    low = p.lower()

    if low in ("allusers", "allauthenticatedusers"):
        return {
            "principal_type": "public",
            "domain": "public_internet",
            "is_external": True,
            "external_classification": "external",
            "is_consumer_account": False,
            "is_google_service_agent": False,
            "is_default_sa": False,
        }

    # Deleted principals (`deleted:user:...`, `deleted:serviceAccount:...`) are distinct & never external
    if low.startswith("deleted:"):
        rest = p.split(":", 1)[1]
        inner_id = rest.split(":", 1)[1] if ":" in rest else rest
        inner_id = inner_id.split("?", 1)[0]
        inner_dom = inner_id.rsplit("@", 1)[-1].lower() if "@" in inner_id else ""
        return {
            "principal_type": "deleted",
            "domain": inner_dom,
            "is_external": False,
            "external_classification": "deleted",
            "is_consumer_account": False,
            "is_google_service_agent": False,
            "is_default_sa": False,
        }

    if low.startswith(("projectowner:", "projecteditor:", "projectviewer:")):
        _, proj = p.split(":", 1)
        return {
            "principal_type": "project_convenience_member",
            "domain": proj,
            "is_external": False,
            "external_classification": "internal",
            "is_consumer_account": False,
            "is_google_service_agent": False,
            "is_default_sa": False,
        }

    prefix, identifier = (p.split(":", 1) + [""])[:2] if ":" in p else ("unknown", p)
    prefix_low = prefix.lower()
    email_domain = identifier.rsplit("@", 1)[-1].lower() if "@" in identifier else identifier.lower()

    if prefix_low == "serviceaccount":
        is_google_agent = is_google_managed_service_agent(p)
        is_default_sa = is_default_service_account_email(identifier)
        sa_owner = extract_sa_owning_project(identifier)
        is_ext = False
        ext_cls = "internal"
        if not is_google_agent:
            if org_projects_complete is True and org_project_identifiers:
                if sa_owner and sa_owner in org_project_identifiers:
                    is_ext = False
                    ext_cls = "internal"
                else:
                    is_ext = True
                    ext_cls = "external"
            elif org_projects_complete is False:
                if sa_owner and org_project_identifiers and sa_owner in org_project_identifiers:
                    is_ext = False
                    ext_cls = "internal"
                else:
                    is_ext = False
                    ext_cls = "unknown"
        return {
            "principal_type": "service_account",
            "domain": email_domain,
            "sa_owning_project": sa_owner,
            "is_external": is_ext,
            "external_classification": ext_cls,
            "is_consumer_account": False,
            "is_google_service_agent": is_google_agent,
            "is_default_sa": is_default_sa,
        }

    if prefix_low in ("principal", "principalset"):
        return {
            "principal_type": "workload_identity_federation",
            "domain": email_domain,
            "is_external": False,
            "external_classification": "internal",
            "is_consumer_account": False,
            "is_google_service_agent": False,
            "is_default_sa": False,
        }

    is_consumer = email_domain in ("gmail.com", "googlemail.com", "hotmail.com", "yahoo.com", "outlook.com")
    if is_consumer:
        is_external = True
        ext_cls = "external"
    elif org_domains:
        is_external = bool(email_domain and email_domain not in org_domains)
        ext_cls = "external" if is_external else "internal"
    else:
        # Never assume internal when no organization domain is configured; mark unknown and warn
        is_external = False
        ext_cls = "unknown"
        if coverage_scope:
            record_collection_status(
                coverage_scope,
                "organization_domains",
                CollectionStatus(
                    collector="organization_domains",
                    scope=coverage_scope,
                    complete=False,
                    http_status=200,
                    cutoff_reason="UNCONFIGURED",
                    error="No organization domains configured on session; user/group internal-vs-external classification marked unknown.",
                ),
            )

    return {
        "principal_type": prefix_low,
        "domain": email_domain,
        "is_external": is_external,
        "external_classification": ext_cls,
        "is_consumer_account": is_consumer,
        "is_google_service_agent": False,
        "is_default_sa": False,
    }


def _extract_project_id_from_resource(resource_uri: str, fallback_project: str) -> str:
    m = re.search(r"/projects/([a-z][a-z0-9-]{4,29})(?:/|$)", resource_uri)
    if m:
        return m.group(1)
    if "/organizations/" in resource_uri:
        org_part = resource_uri.rsplit("/organizations/", 1)[-1].split("/")[0]
        return f"organizations/{org_part}"
    if "/folders/" in resource_uri:
        fld_part = resource_uri.rsplit("/folders/", 1)[-1].split("/")[0]
        return f"folders/{fld_part}"
    if fallback_project:
        clean_fb = fallback_project.split("/")[-1]
        if not clean_fb.isdigit():
            return clean_fb
    return "unknown-project"


def get_org_project_membership_context(
    org_scope: str,
    *,
    coverage_scope: Optional[str] = None,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """Returns active project IDs, active ID+number identifiers, inactive tokens, folder ancestry map, and completeness."""
    ns = active_cache_namespace()
    ck = (ns, org_scope)
    now = time.monotonic()
    if not force_refresh and ck in _ORG_PROJECT_META_CACHE:
        ts, cached = _ORG_PROJECT_META_CACHE[ck]
        if (now - ts) < _TELEMETRY_CACHE_TTL_SECONDS:
            return cached

    quoted_org_scope = quote_gcp_resource_path(org_scope)
    active_ids: List[str] = []
    active_identifiers: Set[str] = set()
    inactive_tokens: Set[str] = set()
    project_folders: Dict[str, Set[str]] = {}
    rows, proj_status = gcp_paginated_request(
        "GET",
        f"https://cloudasset.googleapis.com/v1/{quoted_org_scope}:searchAllResources",
        results_key="results",
        collector="project_lifecycle",
        scope=org_scope,
        params={"assetTypes": "cloudresourcemanager.googleapis.com/Project", "pageSize": 500},
        timeout=15.0,
    )
    record_collection_status(coverage_scope or org_scope, "project_lifecycle", proj_status)

    for r in rows:
        name = r.get("name", "")
        pid = name.rsplit("/projects/", 1)[-1].split("/")[0] if "/projects/" in name else ""
        pnum = (r.get("project") or "").split("/")[-1]
        st = (r.get("state") or "ACTIVE").upper()
        if st == "ACTIVE" and pid:
            active_ids.append(pid)
            active_identifiers.add(pid)
            if pnum:
                active_identifiers.add(pnum)
            folders_set: Set[str] = set()
            for f_item in (r.get("folders") or []):
                f_str = str(f_item or "").strip()
                if f_str:
                    folders_set.add(f_str if f_str.startswith("folders/") else f"folders/{f_str}")
            parent_full = str(r.get("parentFullResourceName") or "")
            if "/folders/" in parent_full:
                fid = parent_full.rsplit("/folders/", 1)[-1].split("/")[0]
                if fid:
                    folders_set.add(f"folders/{fid}")
            project_folders[pid] = folders_set
        else:
            if pid:
                inactive_tokens.add(pid)
            if pnum:
                inactive_tokens.add(pnum)
                inactive_tokens.add(f"projects/{pnum}")

    sorted_active = sorted(set(active_ids))
    meta = {
        "active_ids": sorted_active,
        "active_identifiers": active_identifiers,
        "inactive_tokens": inactive_tokens,
        "project_folders": project_folders,
        "complete": bool(proj_status.complete),
    }
    if proj_status.complete:
        _ACTIVE_ORG_PROJECTS_CACHE[ck] = (now, (sorted_active, inactive_tokens))
        _ORG_PROJECT_META_CACHE[ck] = (now, meta)
    return meta


def _get_org_project_lifecycle_sets(
    org_scope: str,
    *,
    coverage_scope: Optional[str] = None,
    force_refresh: bool = False,
) -> Tuple[List[str], Set[str]]:
    ns = active_cache_namespace()
    ck = (ns, org_scope)
    now = time.monotonic()
    if not force_refresh and ck in _ACTIVE_ORG_PROJECTS_CACHE:
        ts, cached = _ACTIVE_ORG_PROJECTS_CACHE[ck]
        if (now - ts) < _TELEMETRY_CACHE_TTL_SECONDS:
            return cached
    meta = get_org_project_membership_context(
        org_scope,
        coverage_scope=coverage_scope,
        force_refresh=force_refresh,
    )
    return (meta["active_ids"], meta["inactive_tokens"])


def _collect_single_leaf_bindings(
    leaf_scope: str,
    inactive_projects: Optional[Set[str]] = None,
    coverage_scope: Optional[str] = None,
    org_project_identifiers: Optional[Set[str]] = None,
    org_projects_complete: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    bindings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str, Optional[str]]] = set()
    inactive = inactive_projects or set()
    cov_scope = coverage_scope or leaf_scope

    quoted_leaf = quote_gcp_resource_path(leaf_scope)
    cai_url = f"https://cloudasset.googleapis.com/v1/{quoted_leaf}:searchAllIamPolicies"
    raw_results, cai_status = gcp_paginated_request(
        "GET",
        cai_url,
        results_key="results",
        collector="iam_bindings",
        scope=leaf_scope,
        params={"pageSize": 500},
        timeout=18.0,
    )
    record_collection_status(cov_scope, f"iam_bindings:{leaf_scope}", cai_status)

    proj_num_to_id: Dict[str, str] = {}
    for item in raw_results:
        res_uri = item.get("resource", "")
        proj_num = item.get("project", "")
        if res_uri.startswith("//cloudresourcemanager.googleapis.com/projects/") and proj_num:
            pid = res_uri.rsplit("/projects/", 1)[-1].split("/")[0]
            proj_num_to_id[proj_num] = pid

    for item in raw_results:
        resource = item.get("resource", "")
        proj_ref = item.get("project", "")
        mapped_proj = proj_num_to_id.get(proj_ref, "")
        project_id = _extract_project_id_from_resource(resource, mapped_proj or proj_ref or leaf_scope)
        if inactive and (project_id in inactive or proj_ref in inactive):
            continue
        asset_type = item.get("assetType", "") or ""
        policy = item.get("policy") or {}
        for b in policy.get("bindings", []):
            role = b.get("role", "")
            cond_expr = (b.get("condition") or {}).get("expression") or None
            for member in b.get("members", []):
                dedup_key = (resource, role, member, cond_expr)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                meta = classify_principal_domain_and_type(
                    member,
                    org_project_identifiers=org_project_identifiers,
                    org_projects_complete=org_projects_complete,
                    coverage_scope=cov_scope,
                )
                bindings.append(
                    {
                        "resource": resource,
                        "asset_type": asset_type,
                        "project_id": project_id,
                        "role": role,
                        "principal": member,
                        "condition": cond_expr,
                        "source": "CLOUD_ASSET_INVENTORY_API",
                        **meta,
                    }
                )

    crm_url = f"https://cloudresourcemanager.googleapis.com/v3/{quoted_leaf}:getIamPolicy"
    crm_status, crm_data = gcp_rest_request("POST", crm_url, json_body={"options": {"requestedPolicyVersion": 3}})
    if crm_status == 200 and isinstance(crm_data, dict):
        scope_resource = f"//cloudresourcemanager.googleapis.com/{leaf_scope}"
        scope_proj = leaf_scope.split("/", 1)[-1] if leaf_scope.startswith("projects/") else leaf_scope
        for b in crm_data.get("bindings", []):
            role = b.get("role", "")
            cond = (b.get("condition") or {}).get("expression") or None
            for member in b.get("members", []):
                dedup_key = (scope_resource, role, member, cond)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                meta = classify_principal_domain_and_type(
                    member,
                    org_project_identifiers=org_project_identifiers,
                    org_projects_complete=org_projects_complete,
                    coverage_scope=cov_scope,
                )
                bindings.append(
                    {
                        "resource": scope_resource,
                        "asset_type": "cloudresourcemanager.googleapis.com/Resource",
                        "project_id": scope_proj,
                        "role": role,
                        "principal": member,
                        "condition": cond,
                        "source": "CLOUD_RESOURCE_MANAGER_V3_API",
                        **meta,
                    }
                )
    elif not bindings:
        raise RuntimeError(
            f"Failed to collect live IAM bindings for '{leaf_scope}'. "
            f"CAI: {cai_status.error or '0 results'}; Resource Manager HTTP {crm_status}: {json.dumps(crm_data)[:260]}"
        )

    return bindings


def collect_live_iam_bindings(scope: str = "", force_refresh: bool = False) -> List[Dict[str, Any]]:
    """Collects 100% real IAM policy bindings across an entire Organization or 1..N selected Projects."""
    parsed = assert_scope_allowed(scope)
    ck = (active_cache_namespace(), parsed.canonical_scope)
    now = time.monotonic()
    if not force_refresh and ck in _BINDINGS_CACHE:
        ts, cached = _BINDINGS_CACHE[ck]
        if (now - ts) < _TELEMETRY_CACHE_TTL_SECONDS:
            return cached

    if force_refresh:
        with _COVERAGE_LOCK:
            _COVERAGE_CACHE.pop(ck, None)

    merged: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str, Optional[str]]] = set()

    if parsed.mode == "ORG_ALL":
        proj_meta = get_org_project_membership_context(
            parsed.organization_scope,
            coverage_scope=parsed.canonical_scope,
            force_refresh=force_refresh,
        )
        merged.extend(
            _collect_single_leaf_bindings(
                parsed.organization_scope,
                inactive_projects=proj_meta["inactive_tokens"],
                coverage_scope=parsed.canonical_scope,
                org_project_identifiers=proj_meta["active_identifiers"],
                org_projects_complete=proj_meta["complete"],
            )
        )
    elif parsed.mode == "ORG_SELECTED_PROJECTS":
        org_proj_ids: Optional[Set[str]] = None
        org_proj_complete: Optional[bool] = None
        if parsed.organization_scope:
            proj_meta = get_org_project_membership_context(
                parsed.organization_scope,
                coverage_scope=parsed.canonical_scope,
                force_refresh=force_refresh,
            )
            org_proj_ids = proj_meta["active_identifiers"]
            org_proj_complete = proj_meta["complete"]

        per_proj_lists = run_pool_map_with_context(
            lambda leaf: _collect_single_leaf_bindings(
                leaf,
                coverage_scope=parsed.canonical_scope,
                org_project_identifiers=org_proj_ids,
                org_projects_complete=org_proj_complete,
            ),
            parsed.leaf_scopes,
            max_workers=8,
        )
        for plist in per_proj_lists:
            for b in plist:
                dk = (b["resource"], b["role"], b["principal"], b.get("condition"))
                if dk not in seen:
                    seen.add(dk)
                    merged.append(b)

        if parsed.organization_scope:
            quoted_org = quote_gcp_resource_path(parsed.organization_scope)
            org_crm_url = f"https://cloudresourcemanager.googleapis.com/v3/{quoted_org}:getIamPolicy"
            o_code, o_data = gcp_rest_request("POST", org_crm_url, json_body={"options": {"requestedPolicyVersion": 3}})
            if o_code == 200 and isinstance(o_data, dict):
                org_res = f"//cloudresourcemanager.googleapis.com/{parsed.organization_scope}"
                for b in o_data.get("bindings", []):
                    role = b.get("role", "")
                    cond = (b.get("condition") or {}).get("expression") or None
                    for member in b.get("members", []):
                        dk = (org_res, role, member, cond)
                        if dk in seen:
                            continue
                        seen.add(dk)
                        meta = classify_principal_domain_and_type(
                            member,
                            org_project_identifiers=org_proj_ids,
                            org_projects_complete=org_proj_complete,
                            coverage_scope=parsed.canonical_scope,
                        )
                        merged.append(
                            {
                                "resource": org_res,
                                "asset_type": "cloudresourcemanager.googleapis.com/Organization",
                                "project_id": parsed.organization_scope,
                                "role": role,
                                "principal": member,
                                "condition": cond,
                                "source": "CLOUD_RESOURCE_MANAGER_V3_ORG_INHERITED",
                                **meta,
                            }
                        )
    else:
        leaf = parsed.leaf_scopes[0]
        leaf_proj_ids = {leaf.split("/", 1)[1]} if leaf.startswith("projects/") else None
        merged = _collect_single_leaf_bindings(
            leaf,
            coverage_scope=parsed.canonical_scope,
            org_project_identifiers=leaf_proj_ids,
            org_projects_complete=False if leaf_proj_ids else None,
        )

    if not _EPHEMERAL_OAUTH_TOKEN.get():
        _BINDINGS_CACHE[ck] = (now, merged)
    return merged


def _collect_single_leaf_resources(
    leaf_scope: str,
    inactive_projects: Optional[Set[str]] = None,
    coverage_scope: Optional[str] = None,
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    inactive = inactive_projects or set()
    asset_types = [
        "iam.googleapis.com/ServiceAccount",
        "iam.googleapis.com/ServiceAccountKey",
        "iam.googleapis.com/Role",
        "iam.googleapis.com/WorkloadIdentityPool",
        "iam.googleapis.com/WorkloadIdentityPoolProvider",
        "secretmanager.googleapis.com/Secret",
        "secretmanager.googleapis.com/SecretVersion",
        "cloudkms.googleapis.com/KeyRing",
        "cloudkms.googleapis.com/CryptoKey",
        "apikeys.googleapis.com/Key",
        "compute.googleapis.com/Instance",
        "run.googleapis.com/Service",
        "storage.googleapis.com/Bucket",
        "bigquery.googleapis.com/Dataset",
    ]

    quoted_leaf = quote_gcp_resource_path(leaf_scope)
    cai_url = f"https://cloudasset.googleapis.com/v1/{quoted_leaf}:searchAllResources"
    raw_resources, res_status = gcp_paginated_request(
        "GET",
        cai_url,
        results_key="results",
        collector="cai_resources",
        scope=leaf_scope,
        params={"assetTypes": asset_types, "readMask": "*", "pageSize": 500},
        timeout=18.0,
    )
    record_collection_status(coverage_scope or leaf_scope, f"cai_resources:{leaf_scope}", res_status)
    cai_ok = res_status.http_status == 200 and res_status.pages_fetched > 0

    for res in raw_resources:
        res_name = res.get("name", "")
        proj_ref = res.get("project", "")
        parent_full = res.get("parentFullResourceName") or ""
        pid = _extract_project_id_from_resource(res_name, proj_ref)
        if (not pid or pid.isdigit() or pid == "unknown-project") and "/projects/" in parent_full:
            cand_pid = parent_full.rsplit("/projects/", 1)[-1].split("/")[0]
            if cand_pid and not cand_pid.isdigit():
                pid = cand_pid
        if inactive and (pid in inactive or proj_ref in inactive):
            continue
        ver_list = res.get("versionedResources") or []
        ver_res = (ver_list[0].get("resource") if ver_list and isinstance(ver_list[0], dict) else None) or {}
        items.append(
            {
                "name": res_name,
                "asset_type": res.get("assetType", ""),
                "display_name": res.get("displayName") or "",
                "project": proj_ref,
                "project_id": pid,
                "parent_full_resource_name": parent_full,
                "folders": list(res.get("folders") or []),
                "ancestors": list(res.get("ancestors") or []),
                "location": res.get("location") or "",
                "state": res.get("state") or "",
                "create_time": res.get("createTime"),
                "update_time": res.get("updateTime"),
                "kms_keys": res.get("kmsKeys") or [],
                "labels": res.get("labels") or {},
                "additional_attributes": res.get("additionalAttributes") or {},
                "versioned_resource": ver_res,
            }
        )

    if cai_ok or not leaf_scope.startswith("projects/"):
        return items

    proj_id = validate_project_id(leaf_scope.split("/", 1)[1])
    q_proj = quote_path_segment(proj_id)
    sa_code, sa_data = gcp_rest_request("GET", f"https://iam.googleapis.com/v1/projects/{q_proj}/serviceAccounts")
    if sa_code == 200:
        for sa in sa_data.get("accounts", []):
            email = sa.get("email", "")
            items.append(
                {
                    "name": f"//iam.googleapis.com/projects/{proj_id}/serviceAccounts/{email}",
                    "asset_type": "iam.googleapis.com/ServiceAccount",
                    "display_name": sa.get("displayName") or email,
                    "project": f"projects/{proj_id}",
                    "project_id": proj_id,
                    "location": "global",
                    "state": "DISABLED" if sa.get("disabled") else "ENABLED",
                    "create_time": None,
                    "additional_attributes": {"email": email, "uniqueId": sa.get("uniqueId", "")},
                }
            )

    wif_code, wif_data = gcp_rest_request(
        "GET", f"https://iam.googleapis.com/v1/projects/{q_proj}/locations/global/workloadIdentityPools"
    )
    if wif_code == 200:
        for wp in wif_data.get("workloadIdentityPools", []):
            items.append(
                {
                    "name": f"//iam.googleapis.com/{wp.get('name', '')}",
                    "asset_type": "iam.googleapis.com/WorkloadIdentityPool",
                    "display_name": wp.get("displayName") or wp.get("name", ""),
                    "project": f"projects/{proj_id}",
                    "project_id": proj_id,
                    "location": "global",
                    "state": wp.get("state", "ACTIVE"),
                    "create_time": None,
                    "additional_attributes": {},
                }
            )

    run_code, run_data = gcp_rest_request("GET", f"https://run.googleapis.com/v2/projects/{q_proj}/locations/-/services")
    if run_code == 200:
        for svc in run_data.get("services", []):
            raw_name = svc.get("name", "")
            svc_short = raw_name.rsplit("/", 1)[-1]
            tpl = svc.get("template") or {}
            sa_attached = tpl.get("serviceAccount") or ""
            items.append(
                {
                    "name": f"//run.googleapis.com/{raw_name}",
                    "asset_type": "run.googleapis.com/Service",
                    "display_name": svc_short,
                    "project": f"projects/{proj_id}",
                    "project_id": proj_id,
                    "location": raw_name.split("/locations/")[1].split("/")[0] if "/locations/" in raw_name else "",
                    "state": "ACTIVE",
                    "create_time": svc.get("createTime"),
                    "additional_attributes": {"serviceAccountEmail": sa_attached} if sa_attached else {},
                }
            )

    bq_code, bq_data = gcp_rest_request("GET", f"https://bigquery.googleapis.com/bigquery/v2/projects/{q_proj}/datasets")
    if bq_code == 200:
        for ds in bq_data.get("datasets", []):
            ds_ref = ds.get("datasetReference") or {}
            ds_id = ds_ref.get("datasetId", "")
            items.append(
                {
                    "name": f"//bigquery.googleapis.com/projects/{proj_id}/datasets/{ds_id}",
                    "asset_type": "bigquery.googleapis.com/Dataset",
                    "display_name": ds_id,
                    "project": f"projects/{proj_id}",
                    "project_id": proj_id,
                    "location": ds.get("location", ""),
                    "state": "ACTIVE",
                    "create_time": None,
                    "additional_attributes": {},
                }
            )

    return items


def collect_live_resources(scope: str = "", force_refresh: bool = False) -> List[Dict[str, Any]]:
    parsed = assert_scope_allowed(scope)
    ck = (active_cache_namespace(), parsed.canonical_scope)
    now = time.monotonic()
    if not force_refresh and ck in _RESOURCES_CACHE:
        ts, cached = _RESOURCES_CACHE[ck]
        if (now - ts) < _TELEMETRY_CACHE_TTL_SECONDS:
            return cached

    items: List[Dict[str, Any]] = []
    seen_names: Set[str] = set()

    if parsed.mode == "ORG_ALL":
        _, inactive = _get_org_project_lifecycle_sets(
            parsed.organization_scope,
            coverage_scope=parsed.canonical_scope,
            force_refresh=force_refresh,
        )
        items = _collect_single_leaf_resources(
            parsed.organization_scope,
            inactive_projects=inactive,
            coverage_scope=parsed.canonical_scope,
        )
    elif parsed.mode == "ORG_SELECTED_PROJECTS":
        batches = run_pool_map_with_context(
            lambda leaf: _collect_single_leaf_resources(leaf, coverage_scope=parsed.canonical_scope),
            parsed.leaf_scopes,
            max_workers=8,
        )
        for b in batches:
            for it in b:
                if it["name"] not in seen_names:
                    seen_names.add(it["name"])
                    items.append(it)
    else:
        items = _collect_single_leaf_resources(parsed.leaf_scopes[0], coverage_scope=parsed.canonical_scope)

    if not _EPHEMERAL_OAUTH_TOKEN.get():
        _RESOURCES_CACHE[ck] = (now, items)
    return items


def collect_live_org_policies(scope: str = "") -> Dict[str, Any]:
    parsed = assert_scope_allowed(scope)
    eval_target = parsed.org_policy_scope or parsed.leaf_scopes[0]
    fallback_leaf = parsed.leaf_scopes[0] if parsed.leaf_scopes else eval_target
    ck = (active_cache_namespace(), eval_target)
    now = time.monotonic()
    if not _EPHEMERAL_OAUTH_TOKEN.get() and ck in _ORG_POLICIES_CACHE:
        ts, cached_pols = _ORG_POLICIES_CACHE[ck]
        if (now - ts) < _TELEMETRY_CACHE_TTL_SECONDS:
            return cached_pols

    def _eval_constraint(constraint: str) -> Tuple[str, Dict[str, Any]]:
        last_err = ""
        for candidate in ([eval_target] if eval_target == fallback_leaf else [eval_target, fallback_leaf]):
            q_cand = quote_gcp_resource_path(candidate)
            url = f"https://cloudresourcemanager.googleapis.com/v1/{q_cand}:getEffectiveOrgPolicy"
            try:
                code, data = gcp_rest_request("POST", url, json_body={"constraint": constraint}, timeout=10.0)
                if code == 200:
                    bool_pol = data.get("booleanPolicy")
                    list_pol = data.get("listPolicy")
                    enforced = False
                    if isinstance(bool_pol, dict):
                        enforced = bool(bool_pol.get("enforced", False))
                    elif isinstance(list_pol, dict):
                        all_vals = list_pol.get("allValues", "")
                        allowed_vals = list_pol.get("allowedValues") or []
                        enforced = bool(allowed_vals) and all_vals != "ALLOW"
                    return constraint, {
                        "status": "LIVE_EVALUATED",
                        "evaluated_on": candidate,
                        "enforced": enforced,
                        "boolean_policy": bool_pol,
                        "list_policy": list_pol,
                    }
                last_err = f"HTTP_{code}: {(data.get('error') or {}).get('message', str(data)[:180])}"
            except Exception as exc:
                last_err = f"{type(exc).__name__}: {exc}"
        return constraint, {
            "status": "UNAVAILABLE",
            "evaluated_on": eval_target,
            "enforced": None,
            "error": last_err,
        }

    pairs = run_pool_map_with_context(_eval_constraint, KEY_IAM_ORG_CONSTRAINTS, max_workers=6)
    results: Dict[str, Any] = dict(pairs)
    if not _EPHEMERAL_OAUTH_TOKEN.get():
        _ORG_POLICIES_CACHE[ck] = (now, results)
    return results


def discover_accessible_projects_in_scope(scope: str = "") -> List[str]:
    parsed = assert_scope_allowed(scope)
    if parsed.mode == "ORG_SELECTED_PROJECTS" and parsed.project_ids:
        return list(parsed.project_ids)

    if parsed.mode == "ORG_ALL" and parsed.organization_scope:
        active_ids, _ = _get_org_project_lifecycle_sets(parsed.organization_scope)
        if active_ids:
            return active_ids

    projects: Set[str] = set()
    for b in collect_live_iam_bindings(parsed.canonical_scope):
        pid = b.get("project_id", "")
        if pid and not pid.startswith(("organizations/", "folders/", "projects/")) and not pid.isdigit() and pid != "unknown-project":
            projects.add(pid)
    return sorted(projects)


def get_canonical_iam_bindings(scope: str = "") -> List[Dict[str, Any]]:
    return collect_live_iam_bindings(scope)


def collect_cai_iam_bindings(scope: str = "") -> str:
    """Collects live IAM policy bindings and Organization Policy posture across an Organization or 1..N selected Projects.

    Args:
        scope: Target GCP scope (`organizations/<ORG_ID>` or `organizations/<ORG_ID>/projects:<p1>,<p2>`).

    Returns:
        JSON string containing live IAM policy bindings, project breakdown, and effective Organization Policies.
    """
    parsed = assert_scope_allowed(scope)
    bindings = collect_live_iam_bindings(parsed.canonical_scope)
    org_policies = collect_live_org_policies(parsed.canonical_scope)
    projects_in_scope = discover_accessible_projects_in_scope(parsed.canonical_scope)

    non_agent_bindings = [b for b in bindings if not b.get("is_google_service_agent")]
    primitive_bindings = [
        b
        for b in non_agent_bindings
        if b["role"] in ("roles/owner", "roles/editor")
        or b["principal"].startswith(("projectOwner:", "projectEditor:"))
    ]
    direct_user_bindings = [b for b in bindings if b["principal_type"] == "user"]
    group_bindings = [b for b in bindings if b["principal_type"] == "group"]
    external_or_public = [b for b in bindings if b.get("is_external")]
    customer_sa_bindings = [
        b for b in bindings if b["principal_type"] == "service_account" and not b.get("is_google_service_agent")
    ]

    per_project_counts: Dict[str, int] = {}
    for b in bindings:
        pid = b.get("project_id") or "organization"
        per_project_counts[pid] = per_project_counts.get(pid, 0) + 1

    def _binding_priority(item: Dict[str, Any]) -> Tuple[int, str]:
        if item.get("is_external"):
            return (0, item["role"])
        if item["role"] in ("roles/owner", "roles/editor") or item["principal"].startswith(("projectOwner:", "projectEditor:")):
            return (1, item["role"])
        if item["principal_type"] == "user":
            return (2, item["role"])
        if item.get("is_default_sa"):
            return (3, item["role"])
        return (4, item["role"])

    prioritized_non_agent = sorted(non_agent_bindings, key=_binding_priority)[:220]

    summary = {
        "scope": parsed.canonical_scope,
        "scope_mode": parsed.mode,
        "organization_id": parsed.organization_id,
        "organization_domain": active_organization_domain(),
        "projects_evaluated": projects_in_scope,
        "projects_evaluated_count": len(projects_in_scope),
        "per_project_binding_counts": per_project_counts,
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "telemetry_source": "LIVE_GCP_CLOUD_ASSET_INVENTORY_AND_RESOURCE_MANAGER",
        "total_bindings": len(bindings),
        "non_service_agent_bindings_count": len(non_agent_bindings),
        "google_managed_service_agent_bindings_count": len(bindings) - len(non_agent_bindings),
        "primitive_role_bindings_count": len(primitive_bindings),
        "direct_user_bindings_count": len(direct_user_bindings),
        "group_bindings_count": len(group_bindings),
        "external_or_public_bindings_count": len(external_or_public),
        "customer_or_default_sa_bindings_count": len(customer_sa_bindings),
        "effective_organization_policies": org_policies,
        "bindings": prioritized_non_agent,
    }
    return json.dumps(summary, indent=2)


def _parse_iso_age_days(ts: Optional[str], now_utc: datetime.datetime) -> int:
    if not ts:
        return 0
    try:
        dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return max(0, (now_utc - dt).days)
    except ValueError:
        return 0


def collect_unified_service_account_keys(
    scope: str = "",
    *,
    bindings: Optional[List[Dict[str, Any]]] = None,
    resources: Optional[List[Dict[str, Any]]] = None,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """Single canonical SA key collector shared by Scorecard and Asset Inventory.

    Combines CAI `ServiceAccountKey` resources with live IAM v1 `USER_MANAGED` key lookups across ALL
    candidate Service Accounts up to `IAM_MAX_SA_KEY_CHECKS` (default 500). Failed key queries are
    explicitly marked `UNKNOWN` (never treated as keyless) and recorded in the scan coverage map.
    """
    parsed = assert_scope_allowed(scope)
    ck = (active_cache_namespace(), parsed.canonical_scope)
    now_mono = time.monotonic()
    if not force_refresh and ck in _SA_KEYS_CACHE:
        ts, cached = _SA_KEYS_CACHE[ck]
        if (now_mono - ts) < _TELEMETRY_CACHE_TTL_SECONDS:
            return cached

    if bindings is None:
        bindings = collect_live_iam_bindings(parsed.canonical_scope, force_refresh=force_refresh)
    if resources is None:
        resources = collect_live_resources(parsed.canonical_scope, force_refresh=force_refresh)

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    sa_assets = [r for r in resources if r.get("asset_type") == "iam.googleapis.com/ServiceAccount"]

    # Build deduplicated candidate SA map from CAI assets + IAM bindings
    candidates: List[Dict[str, Any]] = []
    seen_emails: Set[str] = set()
    for sa in sa_assets:
        attrs = sa.get("additional_attributes") or {}
        ver = sa.get("versioned_resource") or {}
        email = str(attrs.get("email") or ver.get("email") or sa["name"].rsplit("/serviceAccounts/", 1)[-1]).strip().lower()
        if not email or email in seen_emails or is_google_managed_service_agent(f"serviceAccount:{email}"):
            continue
        seen_emails.add(email)
        sa_proj = sa.get("project_id") or ""
        if not sa_proj or sa_proj == "unknown-project":
            m_sa = re.search(r"@([a-z][a-z0-9-]{4,29})\.iam\.gserviceaccount\.com$", email)
            sa_proj = m_sa.group(1) if m_sa else "-"
        candidates.append({"sa": sa, "email": email, "proj_id": sa_proj})

    for b in bindings:
        if b.get("principal_type") == "service_account" and not b.get("is_google_service_agent"):
            email = b["principal"].split(":", 1)[-1].strip().lower()
            if not email or email in seen_emails or is_google_managed_service_agent(f"serviceAccount:{email}"):
                continue
            seen_emails.add(email)
            m_sa = re.search(r"@([a-z][a-z0-9-]{4,29})\.iam\.gserviceaccount\.com$", email)
            sa_proj = m_sa.group(1) if m_sa else (b.get("project_id") or "-")
            candidates.append(
                {
                    "sa": {"name": f"//iam.googleapis.com/projects/{sa_proj}/serviceAccounts/{email}", "display_name": email, "project_id": sa_proj},
                    "email": email,
                    "proj_id": sa_proj,
                }
            )

    # Extract any ServiceAccountKey records already discovered via CAI
    keys_dedup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in resources:
        if r.get("asset_type") != "iam.googleapis.com/ServiceAccountKey":
            continue
        rname = r.get("name", "")
        ver = r.get("versioned_resource") or {}
        attrs = r.get("additional_attributes") or {}
        key_id = rname.rsplit("/keys/", 1)[-1] if "/keys/" in rname else rname.rsplit("/", 1)[-1]
        m_sa = re.search(r"/serviceAccounts/([^/]+)/keys/", rname)
        sa_em = (m_sa.group(1) if m_sa else str(attrs.get("serviceAccountEmail") or "")).strip().lower()
        if not key_id or not sa_em or is_google_managed_service_agent(f"serviceAccount:{sa_em}"):
            continue
        raw_kt = str(ver.get("keyType") or attrs.get("keyType") or "").strip().upper()
        k_type = raw_kt if raw_kt in ("USER_MANAGED", "SYSTEM_MANAGED") else "UNKNOWN"
        k_origin = str(ver.get("keyOrigin") or attrs.get("keyOrigin") or ("GOOGLE_PROVIDED" if k_type == "SYSTEM_MANAGED" else "USER_PROVIDED"))
        k_alg = str(ver.get("keyAlgorithm") or attrs.get("keyAlgorithm") or "KEY_ALG_RSA_2048")
        valid_after = str(ver.get("validAfterTime") or r.get("create_time") or "")
        valid_before = str(ver.get("validBeforeTime") or "")
        age_d = _parse_iso_age_days(valid_after, now_utc)
        if k_type == "USER_MANAGED":
            krisk = "CRITICAL" if age_d > 90 else "HIGH"
        elif k_type == "UNKNOWN":
            krisk = "HIGH"
        else:
            krisk = "LOW"
        keys_dedup[(sa_em, key_id)] = {
            "key_id": key_id,
            "key_name": rname,
            "sa_email": sa_em,
            "project_id": r.get("project_id") or "-",
            "key_type": k_type,
            "key_origin": k_origin,
            "key_algorithm": k_alg,
            "valid_after_time": valid_after,
            "valid_before_time": valid_before,
            "age_days": age_d,
            "risk_level": krisk,
        }

    max_sa_checks = max(1, int(os.getenv("IAM_MAX_SA_KEY_CHECKS", str(DEFAULT_MAX_SA_KEY_CHECKS))))
    total_candidates = len(candidates)
    to_inspect = candidates[:max_sa_checks]
    capped_candidates = candidates[max_sa_checks:]

    def _query_one_sa(item: Dict[str, Any]) -> Dict[str, Any]:
        email = item["email"]
        proj_id = item["proj_id"]
        if not proj_id or proj_id in ("-", "organization", "external-or-org", "unknown-project"):
            return {
                "email": email,
                "proj_id": proj_id,
                "sa": item["sa"],
                "status": "UNKNOWN",
                "http_status": 0,
                "error": "UNRESOLVABLE_PROJECT",
                "keys": [],
            }
        q_proj = quote_path_segment(proj_id)
        q_email = quote_path_segment(email)
        keys_url = f"https://iam.googleapis.com/v1/projects/{q_proj}/serviceAccounts/{q_email}/keys"
        try:
            k_code, k_data = gcp_rest_request("GET", keys_url, params={"keyTypes": "USER_MANAGED"}, timeout=10.0)
            if k_code == 200 and isinstance(k_data, dict):
                found: List[Dict[str, Any]] = []
                for k in k_data.get("keys", []):
                    kname = str(k.get("name") or "")
                    kid = kname.rsplit("/", 1)[-1] if "/" in kname else kname
                    va = str(k.get("validAfterTime") or "")
                    vb = str(k.get("validBeforeTime") or "")
                    age_d = _parse_iso_age_days(va, now_utc)
                    found.append(
                        {
                            "key_id": kid,
                            "key_name": kname,
                            "sa_email": email,
                            "project_id": proj_id,
                            "key_type": "USER_MANAGED",
                            "key_origin": str(k.get("keyOrigin") or "GOOGLE_PROVIDED"),
                            "key_algorithm": str(k.get("keyAlgorithm") or ""),
                            "valid_after_time": va,
                            "valid_before_time": vb,
                            "age_days": age_d,
                            "risk_level": "CRITICAL" if age_d > 90 else "HIGH",
                        }
                    )
                return {
                    "email": email,
                    "proj_id": proj_id,
                    "sa": item["sa"],
                    "status": "LIVE_IAM_API_VERIFIED",
                    "http_status": 200,
                    "error": None,
                    "keys": found,
                }
            return {
                "email": email,
                "proj_id": proj_id,
                "sa": item["sa"],
                "status": "UNKNOWN",
                "http_status": k_code,
                "error": f"HTTP_{k_code}",
                "keys": [],
            }
        except Exception as exc:
            return {
                "email": email,
                "proj_id": proj_id,
                "sa": item["sa"],
                "status": "UNKNOWN",
                "http_status": 0,
                "error": f"ERR_{type(exc).__name__}",
                "keys": [],
            }

    inspected_results = run_pool_map_with_context(_query_one_sa, to_inspect, max_workers=10) if to_inspect else []

    by_sa: Dict[str, Dict[str, Any]] = {}
    failed_sa_count = 0
    first_err_code = 200
    first_err_msg: Optional[str] = None

    for res in inspected_results:
        em = res["email"]
        st = res["status"]
        if st != "LIVE_IAM_API_VERIFIED":
            failed_sa_count += 1
            if first_err_code == 200:
                first_err_code = int(res["http_status"] or 500)
                first_err_msg = res["error"]
        for kr in res["keys"]:
            keys_dedup[(em, kr["key_id"])] = kr
        by_sa[em] = {
            "email": em,
            "project_id": res["proj_id"],
            "sa": res["sa"],
            "key_inspection_status": st,
            "key_inspection_error": res["error"],
            "user_managed_keys": [],
            "system_managed_keys": [],
            "unknown_keys": [],
            "user_managed_keys_count": 0,
            "system_managed_keys_count": 0,
            "oldest_user_managed_key_age_days": 0,
        }

    for item in capped_candidates:
        em = item["email"]
        by_sa[em] = {
            "email": em,
            "project_id": item["proj_id"],
            "sa": item["sa"],
            "key_inspection_status": "UNKNOWN",
            "key_inspection_error": "CAP_EVALUATED",
            "user_managed_keys": [],
            "system_managed_keys": [],
            "unknown_keys": [],
            "user_managed_keys_count": 0,
            "system_managed_keys_count": 0,
            "oldest_user_managed_key_age_days": 0,
        }

    for kr in keys_dedup.values():
        em = kr["sa_email"]
        srec = by_sa.setdefault(
            em,
            {
                "email": em,
                "project_id": kr["project_id"],
                "sa": {"display_name": em, "project_id": kr["project_id"]},
                "key_inspection_status": "CAI_ONLY",
                "key_inspection_error": None,
                "user_managed_keys": [],
                "system_managed_keys": [],
                "unknown_keys": [],
                "user_managed_keys_count": 0,
                "system_managed_keys_count": 0,
                "oldest_user_managed_key_age_days": 0,
            },
        )
        if kr["key_type"] == "USER_MANAGED":
            srec["user_managed_keys"].append(kr)
            srec["user_managed_keys_count"] += 1
            srec["oldest_user_managed_key_age_days"] = max(
                srec["oldest_user_managed_key_age_days"], int(kr["age_days"])
            )
        elif kr["key_type"] == "SYSTEM_MANAGED":
            srec["system_managed_keys"].append(kr)
            srec["system_managed_keys_count"] += 1
        else:
            srec["unknown_keys"].append(kr)

    verified_count = sum(1 for r in by_sa.values() if r["key_inspection_status"] == "LIVE_IAM_API_VERIFIED")
    if capped_candidates:
        sa_cov_status = CollectionStatus(
            collector="sa_keys",
            scope=parsed.canonical_scope,
            complete=False,
            pages_fetched=len(to_inspect),
            items_collected=len(keys_dedup),
            http_status=first_err_code if failed_sa_count else 200,
            error=first_err_msg,
            cutoff_reason="CAP_EVALUATED",
            evaluated_count=len(to_inspect) - failed_sa_count,
            total_candidates=total_candidates,
        )
    elif failed_sa_count > 0:
        sa_cov_status = CollectionStatus(
            collector="sa_keys",
            scope=parsed.canonical_scope,
            complete=False,
            pages_fetched=len(to_inspect),
            items_collected=len(keys_dedup),
            http_status=first_err_code,
            error=f"{failed_sa_count} of {total_candidates} SA key lookups failed ({first_err_msg})",
            cutoff_reason="HTTP_ERROR",
            evaluated_count=verified_count,
            total_candidates=total_candidates,
        )
    else:
        sa_cov_status = CollectionStatus(
            collector="sa_keys",
            scope=parsed.canonical_scope,
            complete=True,
            pages_fetched=len(to_inspect),
            items_collected=len(keys_dedup),
            http_status=200,
            evaluated_count=total_candidates,
            total_candidates=total_candidates,
        )

    record_collection_status(parsed.canonical_scope, "sa_keys", sa_cov_status)

    all_keys = list(keys_dedup.values())
    user_keys_total = sum(1 for k in all_keys if k["key_type"] == "USER_MANAGED")
    result = {
        "scope": parsed.canonical_scope,
        "all_keys": all_keys,
        "user_managed_keys_total": user_keys_total,
        "system_managed_keys_total": sum(1 for k in all_keys if k["key_type"] == "SYSTEM_MANAGED"),
        "unknown_keys_total": sum(1 for k in all_keys if k["key_type"] == "UNKNOWN"),
        "by_sa": by_sa,
        "evaluated_count": sa_cov_status.evaluated_count,
        "total_candidates": total_candidates,
        "unknown_sa_count": sum(1 for r in by_sa.values() if r["key_inspection_status"] == "UNKNOWN"),
        "status": sa_cov_status.to_dict(),
    }
    if not _EPHEMERAL_OAUTH_TOKEN.get():
        _SA_KEYS_CACHE[ck] = (now_mono, result)
    return result


def collect_cai_service_account_inventory(scope: str = "") -> str:
    """Collects live Service Account inventory, user-managed key age, default SA grants, and Workload Identity Pools.

    Args:
        scope: Target GCP Organization or Multi-Project scope.

    Returns:
        JSON string detailing real Service Accounts, user-managed vs Google-managed keys, attached workloads, and WIF pools.
    """
    parsed = assert_scope_allowed(scope)
    bindings = collect_live_iam_bindings(parsed.canonical_scope)
    resources = collect_live_resources(parsed.canonical_scope)
    unified_keys = collect_unified_service_account_keys(
        parsed.canonical_scope,
        bindings=bindings,
        resources=resources,
    )
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    roles_by_sa: Dict[str, List[Dict[str, str]]] = {}
    for b in bindings:
        if b["principal"].startswith("serviceAccount:"):
            sa_email = b["principal"].split(":", 1)[1].strip().lower()
            roles_by_sa.setdefault(sa_email, []).append(
                {"role": b["role"], "resource": b["resource"], "project_id": b["project_id"]}
            )

    wif_pools = [r for r in resources if r["asset_type"] == "iam.googleapis.com/WorkloadIdentityPool"]
    wif_providers = [r for r in resources if r["asset_type"] == "iam.googleapis.com/WorkloadIdentityPoolProvider"]
    workloads = [
        r for r in resources if r["asset_type"] in ("compute.googleapis.com/Instance", "run.googleapis.com/Service")
    ]

    service_accounts_out: List[Dict[str, Any]] = []
    for email, srec in sorted(unified_keys["by_sa"].items()):
        sa = srec.get("sa") or {}
        granted = roles_by_sa.get(email, [])
        service_accounts_out.append(
            {
                "email": email,
                "project_id": srec["project_id"],
                "display_name": sa.get("display_name") or email,
                "is_default_service_account": is_default_service_account_email(email),
                "is_google_managed_service_agent": is_google_managed_service_agent(f"serviceAccount:{email}"),
                "key_inspection_status": srec["key_inspection_status"],
                "key_inspection_error": srec.get("key_inspection_error"),
                "user_managed_keys_count": srec["user_managed_keys_count"],
                "oldest_user_managed_key_age_days": srec["oldest_user_managed_key_age_days"],
                "user_managed_keys": srec["user_managed_keys"],
                "granted_roles": sorted({g["role"] for g in granted}),
                "granted_bindings_count": len(granted),
            }
        )

    payload = {
        "scope": parsed.canonical_scope,
        "scope_mode": parsed.mode,
        "collected_at": now_utc.isoformat(),
        "telemetry_source": "LIVE_GCP_CAI_AND_IAM_V1_API",
        "total_service_accounts_analyzed": len(service_accounts_out),
        "total_user_managed_keys": unified_keys["user_managed_keys_total"],
        "sa_keys_coverage": unified_keys["status"],
        "unknown_key_status_service_accounts": unified_keys["unknown_sa_count"],
        "service_accounts_with_user_managed_keys": sum(
            1 for s in service_accounts_out if s["user_managed_keys_count"] > 0
        ),
        "service_accounts_with_keys_over_90d": sum(
            1 for s in service_accounts_out if s["oldest_user_managed_key_age_days"] > 90
        ),
        "default_service_accounts_with_bindings": sum(
            1 for s in service_accounts_out if s["is_default_service_account"] and s["granted_bindings_count"] > 0
        ),
        "workload_identity_pools_count": len(wif_pools),
        "workload_identity_providers_count": len(wif_providers),
        "workload_identity_pools": [p["name"] for p in wif_pools],
        "active_compute_and_cloud_run_workloads": [
            {"name": w["name"], "asset_type": w["asset_type"], "project_id": w["project_id"], "location": w["location"]}
            # Payload-size cap only (this list is not scored); totals are reported below.
            for w in workloads[:60]
        ],
        "active_compute_and_cloud_run_workloads_total": len(workloads),
        "active_compute_and_cloud_run_workloads_listed_over_total": f"{min(len(workloads), 60)}/{len(workloads)}",
        "service_accounts": service_accounts_out,
    }
    return json.dumps(payload, indent=2)


def persist_findings_list_to_bigquery(findings: List[GcpIamPostureFinding], scope: str = "") -> Dict[str, Any]:
    """Writes findings JSONL strictly to the isolated session directory; optionally exports ONLY to a customer-specified BigQuery table."""
    import hashlib

    target_scope = assert_scope_allowed(scope).canonical_scope
    rows = [f.model_dump() for f in findings]
    out_dir = active_export_dir()
    out_path = out_dir / "iam_posture_findings.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    sess = get_active_inspection_session()
    customer_bq_table = (sess.optional_customer_bq_table if sess else "").strip()

    # Default: 100% Ephemeral Session Storage (Zero writes to host project BigQuery)
    if not customer_bq_table:
        return {
            "status": "EPHEMERAL_SESSION_ONLY",
            "scope": target_scope,
            "rows_written_jsonl": len(rows),
            "note": "Zero host BigQuery persistence (multi-user data isolation enforced).",
        }

    try:
        cust_proj, cust_ds, cust_tbl = validate_bq_table_id(customer_bq_table.replace(":", "."))
    except ValueError as exc:
        return {
            "status": "INVALID_CUSTOMER_BQ_TABLE",
            "scope": target_scope,
            "target_table": customer_bq_table,
            "error": str(exc),
        }

    insert_url = (
        f"https://bigquery.googleapis.com/bigquery/v2/projects/{quote_path_segment(cust_proj)}"
        f"/datasets/{quote_path_segment(cust_ds)}/tables/{quote_path_segment(cust_tbl)}/insertAll"
    )
    bq_rows = []
    for r in rows:
        dedup_seed = f"{target_scope}|{r.get('finding_id', '')}|{r.get('principal', '')}|{r.get('role', '')}|{r.get('resource', '')}"
        insert_id = hashlib.sha256(dedup_seed.encode("utf-8")).hexdigest()[:32]
        bq_rows.append({"insertId": insert_id, "json": r})
    body = {"rows": bq_rows}
    code, data = gcp_rest_request("POST", insert_url, json_body=body, timeout=20.0)
    if code == 200 and not data.get("insertErrors"):
        return {
            "status": "EXPORTED_TO_CUSTOMER_BIGQUERY",
            "scope": target_scope,
            "customer_table_id": customer_bq_table,
            "rows_inserted": len(rows),
            "session_jsonl_path": str(out_path),
        }
    return {
        "status": f"CUSTOMER_BIGQUERY_HTTP_{code}",
        "scope": target_scope,
        "customer_table_id": customer_bq_table,
        "session_jsonl_path": str(out_path),
        "detail": str(data)[:300],
    }
