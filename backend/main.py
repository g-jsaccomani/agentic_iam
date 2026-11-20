"""FastAPI Entrypoint for the Agentic IAM Accelerator (`backend/main.py`).

Zero-Trust Clean-Slate Multi-User Google ADK (`Runner`) + Vertex AI (`location='global'`) Architecture:
- Universal Google Sign-In Executive Console at `GET /` where every user starts with a 100% clean slate
  (zero preloaded Organization data and zero fallback to the Cloud Run host identity).
- Isolated Per-User Session Vault (`/api/v1/session/status`, `/api/v1/session/connect`, `/api/v1/session/disconnect`)
  supporting Service Account Impersonation (`iamcredentials.generateAccessToken`) and Direct User Read-Only Access.
- Standardized Vertex AI Global Engine (`gemini-3.1-pro-preview-customtools`, `location='global'`).
- Live ADK Multi-Agent REST API endpoints (`/api/v1/scorecard`, `/api/v1/triad`, `/api/v1/attack-graph`,
  `/api/v1/recommendations`, `/api/v1/iac-bundle`, `/api/v1/book`, `/api/v1/generate-deliverables`, `/api/v1/chat`)
  with strict per-session isolation and ZERO synthetic fallback.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import html
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.agents.coordinator import (
    run_attack_path_assessment,
    run_coordinator_chat,
    run_iac_assessment,
    run_posture_book_assessment,
    run_recommender_assessment,
    run_scorecard_assessment,
    run_triad_assessment,
)
from backend.agents.telemetry import AgentExecutionTimeoutError
from backend.config import (
    DEFAULT_VERTEX_LOCATION,
    DEFAULT_VERTEX_MODEL,
    SUPPORTED_VERTEX_MODELS,
    get_model_catalog_metadata,
    resolve_vertex_model,
    settings,
)
from backend.identity_guard import (
    IAM_SESSION_COOKIE,
    IAM_SESSION_TTL_SECONDS,
    IamConsultantIdentity,
    allowed_domains_list,
    configured_oauth_client_id,
    mint_consultant_cookie,
    resolve_request_identity,
    resolve_request_identity_with_status,
    resolve_service_public_origin,
    revoke_consultant_cookie,
    revoke_session_id,
    verify_google_token,
)
from backend.models.findings import (
    AccountsKeysSecretsInventory,
    PostureAccelerationBook,
)
from backend.report_generator import (
    DOCX_FILENAME,
    GRAPH_DARK_FILENAME,
    GRAPH_LIGHT_FILENAME,
    INVENTORY_JSON_FILENAME,
    PDF_FILENAME,
    TERRAFORM_ZIP_FILENAME,
    build_download_filename,
    generate_all_executive_deliverables_async,
    is_deliverable_fresh,
    load_persisted_book,
    persist_book_snapshot,
    render_deliverables_from_book,
    scoped_export_dir,
)
from backend.session_vault import (
    bind_inspection_session_context,
    configured_delegation_sa_email,
    get_active_inspection_session,
    get_inspection_session,
    get_pending_oauth_token,
    has_pending_oauth_token,
    purge_expired_state,
    purge_pending_oauth_tokens,
    register_cache_purge_hook,
    require_active_inspection_session,
    store_inspection_session,
    store_pending_oauth_token,
    update_session_organization_metadata,
    wipe_inspection_session,
)
from backend.tools.asset_key_secret_inventory import build_accounts_keys_secrets_inventory
from backend.tools.cai_collector import (
    active_export_dir,
    normalize_gcp_scope,
)
from backend.tools.graph_engine import render_attack_graph_png
from backend.tools.onboarding_manager import (
    ONBOARDING_CUSTOMER_NAME_PATTERN,
    ONBOARDING_DOMAIN_PATTERN,
    ONBOARDING_GCP_ID_PATTERN,
    ONBOARDING_IMPERSONATOR_PATTERN,
    ONBOARDING_MODE_PATTERN,
    ONBOARDING_ORG_ID_PATTERN,
    ONBOARDING_SEED_PROJECT_PATTERN,
    build_onboarding_kit_zip,
    discover_organization_hierarchy,
    generate_customer_onboarding_kit,
    verify_customer_onboarding_readiness,
)
from backend.tools.posture_scoring_engine import compute_iam_framework_baseline
from backend.session_vault import persistent_delegation_enabled
from backend.workspace_store import (
    default_retention_days,
    get_master_secret_bytes,
    load_pinned_book,
    load_pinned_inventory,
    load_scan_index,
    load_workspace_connection,
    max_retention_days,
    persistence_backend_label,
    save_pinned_book,
    save_pinned_inventory,
    save_workspace_artifact,
    update_workspace_connection_fields,
)

logger = logging.getLogger(__name__)

ALLOWED_IAP_DOMAINS = tuple(allowed_domains_list())


@contextlib.asynccontextmanager
async def _app_lifespan(_app: FastAPI):
    """Background sweeper purging expired sessions and pending OAuth tokens even without HTTP traffic (T09)."""
    if os.getenv("K_SERVICE"):
        # Fail fast: session cookies and the encrypted workspace both depend on the Secret Manager master secret
        get_master_secret_bytes()
    sweep_interval = max(0.05, float(os.getenv("IAM_SESSION_SWEEP_INTERVAL_SECONDS", "60.0")))
    stop_event = asyncio.Event()

    async def _periodic_expiry_sweeper() -> None:
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=sweep_interval)
                break
            except asyncio.TimeoutError:
                pass
            try:
                await asyncio.to_thread(purge_expired_state)
            except Exception as exc:
                logger.warning("Periodic session expiry sweep error: %s", exc)

    sweeper_task = asyncio.create_task(_periodic_expiry_sweeper())
    try:
        yield
    finally:
        stop_event.set()
        sweeper_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await sweeper_task


app = FastAPI(
    title="Agentic IAM Accelerator",
    description=(
        "Read-only multi-user IAM Posture Assessment, Modernization, and Least-Privilege Acceleration Engine. "
        "Hybrid pipeline: deterministic Python evidence collection and 18-control scoring, with Google ADK agents "
        "on Vertex AI (location=global) for findings, attack paths, recommendations and narrative. "
        "Per-user workspace persistence is encrypted and has a consultant-selected retention."
    ),
    version="2.2.0",
    docs_url=None if os.getenv("K_SERVICE") else "/api/docs",
    redoc_url=None if os.getenv("K_SERVICE") else "/api/redoc",
    openapi_url=None if os.getenv("K_SERVICE") else "/openapi.json",
    lifespan=_app_lifespan,
)

if not os.getenv("K_SERVICE"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8080",
            "http://localhost:8501",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8501",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )


_CSP_REPORT_ONLY_VALUE = (
    "default-src 'self'; "
    "img-src 'self' data: blob:; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "script-src 'self' https://accounts.google.com; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)

_SERVER_PATH_KEYS = frozenset(
    {
        "bundle_zip_path",
        "deliverable_paths",
        "session_jsonl_path",
        "manifest_json",
        "deliverables_manifest_json",
        "terraform_directory",
    }
)


def _apply_security_headers(response: Response) -> Response:
    """Applies baseline browser defense-in-depth headers to every HTTP response (T14)."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    response.headers.setdefault("Content-Security-Policy-Report-Only", _CSP_REPORT_ONLY_VALUE)
    if os.getenv("K_SERVICE"):
        acao = (response.headers.get("access-control-allow-origin") or "").lower()
        if "localhost" in acao or "127.0.0.1" in acao:
            del response.headers["access-control-allow-origin"]
    return response


def _strip_server_paths(obj: Any) -> Any:
    """Recursively strips local server filesystem path fields from public API JSON responses (T14)."""
    if isinstance(obj, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in obj.items():
            if k in _SERVER_PATH_KEYS:
                continue
            if k == "deliverables" and isinstance(v, dict):
                cleaned[k] = {
                    dk: True
                    for dk, dv in v.items()
                    if dv and dk != "terraform_directory"
                }
                continue
            cleaned[k] = _strip_server_paths(v)
        return cleaned
    if isinstance(obj, list):
        return [_strip_server_paths(item) for item in obj]
    return obj


def _opaque_server_error(status_code: int, public_message: str, exc: BaseException, *, log_context: str = "") -> HTTPException:
    """Logs detailed exception info server-side with a correlation ID and returns an opaque client error."""
    cid = uuid.uuid4().hex[:12]
    logger.exception("[correlation_id=%s] %s", cid, log_context or public_message, exc_info=exc)
    return HTTPException(
        status_code=status_code,
        detail=f"{public_message} (correlation_id={cid})",
        headers={"X-Correlation-ID": cid},
    )


_RATE_LIMIT_LOCK = threading.Lock()
_RATE_LIMIT_WINDOWS: Dict[Tuple[str, str], Deque[float]] = {}


def reset_rate_limiter_for_tests() -> None:
    """Clears sliding-window rate limiter buckets (intended strictly for test isolation)."""
    with _RATE_LIMIT_LOCK:
        _RATE_LIMIT_WINDOWS.clear()


def _enforce_rate_limit(bucket: str, user_email: str) -> None:
    """Enforces a configurable per-user sliding 60-second rate limit for expensive scan/chat endpoints (T14)."""
    env_var = "IAM_RATE_LIMIT_SCANS_PER_MINUTE" if bucket == "scans" else "IAM_RATE_LIMIT_CHAT_PER_MINUTE"
    default_limit = 10 if bucket == "scans" else 30
    try:
        limit = max(1, int(os.getenv(env_var, str(default_limit))))
    except ValueError:
        limit = default_limit

    key = (bucket, (user_email or "anonymous").strip().lower())
    now = time.monotonic()
    cutoff = now - 60.0
    with _RATE_LIMIT_LOCK:
        dq = _RATE_LIMIT_WINDOWS.setdefault(key, collections.deque())
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if len(dq) >= limit:
            retry_after = max(1, int(60.0 - (now - dq[0])) + 1)
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded for {bucket}. Try again in {retry_after}s.",
                headers={"Retry-After": str(retry_after)},
            )
        dq.append(now)


@app.exception_handler(ValueError)
async def _value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
    return _apply_security_headers(JSONResponse(status_code=400, content={"detail": str(exc)}))


@app.exception_handler(PermissionError)
async def _permission_error_handler(_request: Request, exc: PermissionError) -> JSONResponse:
    return _apply_security_headers(JSONResponse(status_code=403, content={"detail": str(exc)}))


@app.exception_handler(AgentExecutionTimeoutError)
async def _agent_timeout_handler(_request: Request, exc: AgentExecutionTimeoutError) -> JSONResponse:
    return _apply_security_headers(JSONResponse(status_code=504, content={"detail": str(exc)}))


@app.exception_handler(Exception)
async def _unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    cid = uuid.uuid4().hex[:12]
    logger.exception("[correlation_id=%s] Unhandled server exception", cid, exc_info=exc)
    return _apply_security_headers(
        JSONResponse(
            status_code=500,
            content={"detail": f"Internal server error (correlation_id={cid}).", "correlation_id": cid},
            headers={"X-Correlation-ID": cid},
        )
    )


_BACKGROUND_SCANS: Dict[str, Dict[str, Any]] = {}
_BACKGROUND_SCAN_TASKS: Dict[str, asyncio.Task[Any]] = {}


_BACKGROUND_SCAN_RESULT_TTL_SECONDS = 3600.0
_BACKGROUND_SCANS_MAX_FINISHED_PER_OWNER = 20


def _prune_background_scans(owner_email: str = "") -> None:
    """Drops finished scan records (which hold whole books) after 1 hour and caps them per owner."""
    now = time.monotonic()
    for scan_id, rec in list(_BACKGROUND_SCANS.items()):
        done_at = rec.get("finished_monotonic")
        if done_at is not None and (now - float(done_at)) > _BACKGROUND_SCAN_RESULT_TTL_SECONDS:
            _BACKGROUND_SCANS.pop(scan_id, None)
    if owner_email:
        finished = sorted(
            (
                (float(rec["finished_monotonic"]), scan_id)
                for scan_id, rec in _BACKGROUND_SCANS.items()
                if rec.get("owner_email") == owner_email and rec.get("finished_monotonic") is not None
            ),
        )
        for _done_at, scan_id in finished[: max(0, len(finished) - _BACKGROUND_SCANS_MAX_FINISHED_PER_OWNER)]:
            _BACKGROUND_SCANS.pop(scan_id, None)


def _purge_background_scans(session_id: str) -> None:
    for scan_id, rec in list(_BACKGROUND_SCANS.items()):
        if rec.get("session_id") == session_id:
            task = _BACKGROUND_SCAN_TASKS.pop(scan_id, None)
            if task is not None and not task.done():
                task.cancel()
            _BACKGROUND_SCANS.pop(scan_id, None)


register_cache_purge_hook(_purge_background_scans)


_PRE_CONNECT_ALLOWED_PREFIXES = (
    "/api/v1/auth/",
    "/api/v1/session/",
    "/api/v1/workspace/",
    "/api/v1/onboarding/",
    "/api/v1/models",
)

_CSRF_PROTECTED_POST_PATHS = frozenset(
    {
        "/api/v1/book",
        "/api/v1/scans",
        "/api/v1/chat",
        "/api/v1/generate-deliverables",
        "/api/v1/session/connect",
        "/api/v1/session/disconnect",
        "/api/v1/auth/logout",
        "/api/v1/workspace/preferences",
        "/api/v1/models/select",
        "/api/v1/onboarding/download-kit",
    }
)


@app.middleware("http")
async def zero_trust_session_isolation_middleware(request: Request, call_next: Any) -> Response:
    """Binds the caller's persistent isolated `InspectionSession`, enforces security headers, docs lock, and CSRF guard."""
    path = request.url.path

    # Disable OpenAPI/Swagger UI on Cloud Run (checked dynamically for runtime env safety)
    if os.getenv("K_SERVICE") and path in ("/api/docs", "/api/redoc", "/openapi.json"):
        return _apply_security_headers(JSONResponse(status_code=404, content={"detail": "Not Found"}))

    # Require custom X-Requested-With header on expensive or state-changing POST endpoints (CSRF mitigation)
    if request.method.upper() == "POST" and path in _CSRF_PROTECTED_POST_PATHS:
        if not (request.headers.get("x-requested-with") or "").strip():
            return _apply_security_headers(
                JSONResponse(
                    status_code=403,
                    content={"detail": "Missing required X-Requested-With header."},
                )
            )

    try:
        ident, needs_new_cookie = await asyncio.to_thread(resolve_request_identity_with_status, request)
    except HTTPException as exc:
        return _apply_security_headers(
            JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)
        )

    is_public = (
        path in ("/", "/health", "/favicon.ico", "/favicon.png", "/favicon-32x32.png", "/apple-touch-icon.png", "/brand-logo.png")
        or path.startswith("/static/")
        or path.startswith("/api/v1/auth/")
    )
    if path.startswith("/api/v1/") and not is_public and ident is None:
        return _apply_security_headers(
            JSONResponse(
                status_code=401,
                content={"detail": "Authentication required. Sign in with your Google Account first."},
            )
        )

    mint_new_cookie_ident: Optional[IamConsultantIdentity] = None
    if (
        ident is not None
        and needs_new_cookie
        and path not in ("/api/v1/auth/logout", "/api/v1/session/disconnect")
    ):
        # Emit a fresh cookie with a new `sid` (e.g., first IAP hit or IAP email mismatch with existing cookie)
        mint_new_cookie_ident = ident

    request.state.consultant_identity = ident
    sess = (
        await asyncio.to_thread(get_inspection_session, ident.session_id, ident.email)
        if ident is not None
        else None
    )

    if (
        path.startswith("/api/v1/")
        and not any(path.startswith(pref) for pref in _PRE_CONNECT_ALLOWED_PREFIXES)
        and sess is None
    ):
        return _apply_security_headers(
            JSONResponse(
                status_code=412,
                content={
                    "detail": (
                        "No target GCP Organization session connected. Connect your Organization via "
                        "Service Account Impersonation or Direct Read-Only Access first."
                    )
                },
            )
        )

    with bind_inspection_session_context(sess):
        response = await call_next(request)

    if mint_new_cookie_ident is not None:
        response.set_cookie(
            key=IAM_SESSION_COOKIE,
            value=mint_consultant_cookie(mint_new_cookie_ident),
            max_age=IAM_SESSION_TTL_SECONDS,
            httponly=True,
            secure=bool(os.getenv("K_SERVICE")),
            samesite="lax",
            path="/",
        )
    return _apply_security_headers(response)


STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    from fastapi.staticfiles import StaticFiles

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_ICON_CACHE_HEADERS = {"Cache-Control": "public, max-age=86400"}
_FAVICON_DATA_URI = ""
if (STATIC_DIR / "favicon.png").exists():
    import base64

    _FAVICON_DATA_URI = "data:image/png;base64," + base64.b64encode((STATIC_DIR / "favicon.png").read_bytes()).decode("ascii")


@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon_ico() -> FileResponse:
    return FileResponse(STATIC_DIR / "favicon.ico", media_type="image/x-icon", headers=_ICON_CACHE_HEADERS)


@app.get("/favicon.png", include_in_schema=False)
async def serve_favicon_png() -> FileResponse:
    return FileResponse(STATIC_DIR / "favicon.png", media_type="image/png", headers=_ICON_CACHE_HEADERS)


@app.get("/favicon-32x32.png", include_in_schema=False)
async def serve_favicon_32_png() -> FileResponse:
    return FileResponse(STATIC_DIR / "favicon-32x32.png", media_type="image/png", headers=_ICON_CACHE_HEADERS)


@app.get("/apple-touch-icon.png", include_in_schema=False)
async def serve_apple_touch_icon() -> FileResponse:
    return FileResponse(STATIC_DIR / "apple-touch-icon.png", media_type="image/png", headers=_ICON_CACHE_HEADERS)


@app.get("/brand-logo.png", include_in_schema=False)
async def serve_brand_logo() -> FileResponse:
    return FileResponse(STATIC_DIR / "logo_badge.png", media_type="image/png", headers=_ICON_CACHE_HEADERS)


def _get_resolved_request_identity(request: Request) -> Optional[IamConsultantIdentity]:
    """Returns the identity already resolved by middleware without re-invoking sync auth calls."""
    if hasattr(request.state, "consultant_identity"):
        return request.state.consultant_identity
    return resolve_request_identity(request)


def _extract_iap_principal(request: Request) -> Dict[str, str]:
    ident: Optional[IamConsultantIdentity] = _get_resolved_request_identity(request)
    if ident is not None:
        return {
            "email": ident.email,
            "display_name": ident.display_name,
            "domain": ident.domain,
            "session_id": ident.session_id,
            "authenticated": "true",
            "auth_channel": ident.auth_channel,
        }
    return {
        "email": "unauthenticated",
        "display_name": "Sign In Required",
        "domain": "",
        "session_id": "",
        "authenticated": "false",
        "auth_channel": "none",
    }


def _resolve_requested_model_or_400(model: Optional[str]) -> str:
    try:
        return resolve_vertex_model(model or settings.vertex_model_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class ModelSelectRequest(BaseModel):
    model: str = Field(..., description="Vertex AI global model ID")


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=2, max_length=8000)
    scope: str = Field(..., min_length=3, description="Connected target Organization or Project scope")
    session_id: Optional[str] = Field(default=None)
    model: Optional[str] = Field(default=None)


class AuthVerifyPayload(BaseModel):
    credential: Optional[str] = None
    id_token: Optional[str] = None
    access_token: Optional[str] = None


class SessionConnectRequest(BaseModel):
    connection_mode: str = Field(default="impersonated_sa", description="impersonated_sa or direct_user")
    user_access_token: Optional[str] = Field(default=None, description="User OAuth2 cloud-platform access token")
    target_sa_email: str = Field(default="", description="Target read-only Service Account to impersonate")
    organization_id: str = Field(default="", description="Optional numeric GCP Organization ID")
    organization_domain: str = Field(default="", description="Optional primary domain")
    customer_name: str = Field(default="", description="Customer or engagement label")
    optional_customer_bq_table: str = Field(default="", description="Optional customer-owned BigQuery project.dataset.table")
    workspace_retention_days: Optional[int] = Field(
        default=None,
        ge=0,
        le=3650,
        description=(
            "Consultant-selected retention for persisted workspace data, in days. 0 = persist nothing "
            "(session only). Omitted = keep the current workspace retention or the deployment default."
        ),
    )


class OnboardingKitRequest(BaseModel):
    customer_name: str = Field(
        default="Enterprise Customer",
        min_length=1,
        max_length=80,
        pattern=ONBOARDING_CUSTOMER_NAME_PATTERN,
    )
    organization_id: str = Field(
        default="",
        max_length=45,
        pattern=ONBOARDING_ORG_ID_PATTERN,
    )
    organization_domain: str = Field(
        default="",
        max_length=253,
        pattern=ONBOARDING_DOMAIN_PATTERN,
    )
    seed_project_id: str = Field(
        default="",
        max_length=30,
        pattern=ONBOARDING_SEED_PROJECT_PATTERN,
    )
    onboarding_mode: str = Field(
        default="impersonated_sa",
        max_length=20,
        pattern=ONBOARDING_MODE_PATTERN,
        description="impersonated_sa or direct_user",
    )
    impersonator_user_email: str = Field(
        default="",
        max_length=260,
        pattern=ONBOARDING_IMPERSONATOR_PATTERN,
    )
    sa_account_id: str = Field(
        default="sa-iam-assessor",
        min_length=6,
        max_length=30,
        pattern=ONBOARDING_GCP_ID_PATTERN,
    )
    enable_persistent_auto_renew: bool = Field(
        default=False,
        description=(
            "Explicit opt-in: also grant the platform runtime Service Account TokenCreator on the customer's "
            "assessor SA. Only honoured when the deployment sets IAM_ENABLE_PERSISTENT_DELEGATION=true."
        ),
    )


class WorkspacePreferencesRequest(BaseModel):
    selected_scope: Optional[str] = Field(default=None)
    project_scope_mode: Optional[str] = Field(default=None)
    selected_project_ids: Optional[list[str]] = Field(default=None)


@app.post("/api/v1/auth/verify")
async def verify_google_auth(payload: AuthVerifyPayload, request: Request, response: Response) -> Dict[str, Any]:
    """Verifies a Google OIDC ID token or OAuth2 access token and mints a persistent isolated workspace cookie."""
    raw = (payload.credential or payload.id_token or payload.access_token or "").strip()
    ident = await asyncio.to_thread(verify_google_token, raw)
    ticket = mint_consultant_cookie(ident)
    response.set_cookie(
        key=IAM_SESSION_COOKIE,
        value=ticket,
        max_age=IAM_SESSION_TTL_SECONDS,
        httponly=True,
        secure=bool(os.getenv("K_SERVICE")),
        samesite="lax",
        path="/",
    )
    has_oauth = False
    if payload.access_token and payload.access_token.strip():
        store_pending_oauth_token(ident.session_id, ident.email, payload.access_token.strip())
        has_oauth = True
    return {
        "authenticated": True,
        "email": ident.email,
        "display_name": ident.display_name,
        "domain": ident.domain,
        "auth_channel": ident.auth_channel,
        "has_user_access_token": has_oauth,
    }


@app.post("/api/v1/auth/logout")
async def logout_google_auth(
    request: Request,
    response: Response,
    wipe_workspace_data: bool = Query(default=False),
) -> Dict[str, Any]:
    raw_cookie = (request.cookies.get(IAM_SESSION_COOKIE) or "").strip()
    if raw_cookie:
        revoke_consultant_cookie(raw_cookie)
    ident = _get_resolved_request_identity(request)
    if ident is not None:
        if ident.cookie_sid:
            revoke_session_id(ident.cookie_sid)
        purge_pending_oauth_tokens(session_id=ident.session_id, owner_email=ident.email)
        if wipe_workspace_data:
            await asyncio.to_thread(wipe_inspection_session, ident.session_id, ident.email, wipe_persistent=True)
    response.delete_cookie(key=IAM_SESSION_COOKIE, path="/")
    return {"authenticated": False, "session_wiped": wipe_workspace_data}


@app.get("/api/v1/auth/bridge", response_class=HTMLResponse)
async def oauth_bridge_popup(request: Request) -> HTMLResponse:
    """Universal Google Sign-In & Cloud OAuth2 Token Bridge (strictly same-origin postMessage)."""
    service_origin = resolve_service_public_origin(request)
    cid = configured_oauth_client_id()
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Agentic IAM Accelerator | Sign in with Google</title>
<link rel="icon" type="image/png" sizes="64x64" href="{_FAVICON_DATA_URI or '/favicon.png?v=3'}">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png?v=3">
<link rel="shortcut icon" href="/favicon.ico?v=3">
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png?v=3">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #14161B;
    --surface: #1B1E26;
    --surface-variant: #232732;
    --border: #2C3240;
    --primary: #1A73E8;
    --primary-hover: #1557B0;
    --text-main: #F1F5F9;
    --text-muted: #94A3B8;
  }}
  body {{ margin:0; font-family:'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:var(--bg); color:var(--text-main); display:flex; align-items:center; justify-content:center; min-height:100vh; padding:16px; box-sizing:border-box; -webkit-font-smoothing:antialiased; }}
  .card {{ background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:28px 24px; width:100%; max-width:440px; text-align:center; box-shadow:0 24px 64px rgba(0,0,0,0.65); }}
  .brand-row {{ display:flex; align-items:center; justify-content:center; gap:10px; margin-bottom:14px; }}
  .brand-logo {{ width:36px; height:36px; background:transparent; border-radius:0; object-fit:contain; display:block; flex-shrink:0; }}
  .badge {{ display:inline-block; padding:4px 10px; border-radius:6px; font-size:0.72rem; font-weight:600; background:rgba(26,115,232,0.14); color:#8AB4F8; border:1px solid rgba(138,180,248,0.28); margin-bottom:12px; }}
  h2 {{ margin:0 0 8px 0; font-size:1.1rem; font-weight:700; color:#FFFFFF; }}
  p {{ margin:0 0 18px 0; font-size:0.84rem; color:var(--text-muted); line-height:1.5; }}
  .slot {{ display:flex; justify-content:center; min-height:44px; margin-bottom:12px; }}
  .btn {{ width:100%; padding:10px 14px; border-radius:6px; border:none; background:var(--primary); color:#ffffff; font-weight:600; font-size:0.84rem; font-family:inherit; cursor:pointer; transition:background 0.15s; }}
  .btn:hover {{ background:var(--primary-hover); }}
  .btn-secondary {{ background:var(--surface-variant); border:1px solid var(--border); color:var(--text-main); }}
  .btn-secondary:hover {{ background:#2F3543; }}
  .tok-wrap {{ margin-top:16px; padding-top:14px; border-top:1px solid var(--border); text-align:left; }}
  .tok-wrap label {{ display:block; font-size:0.75rem; color:var(--text-muted); margin-bottom:6px; font-weight:500; }}
  .tok-input {{ width:100%; box-sizing:border-box; padding:9px 11px; border-radius:6px; border:1px solid var(--border); background:#101216; color:var(--text-main); font-family:'JetBrains Mono', monospace; font-size:0.78rem; margin-bottom:8px; }}
  .tok-input:focus {{ outline:none; border-color:var(--primary); }}
  .err {{ color:#FFA8A8; background:rgba(224,49,49,0.14); border:1px solid rgba(224,49,49,0.35); padding:8px 10px; border-radius:6px; font-size:0.78rem; margin-top:12px; display:none; text-align:left; }}
</style>
<script src="https://accounts.google.com/gsi/client" async defer></script>
</head>
<body>
<div class="card">
  <div class="brand-row">
    <img class="brand-logo" src="/brand-logo.png?v=3" alt="Agentic IAM Accelerator" width="34" height="34" decoding="async" />
    <span style="font-weight:700; font-size:0.95rem; color:#FFFFFF;">Agentic IAM Accelerator</span>
  </div>
  <span class="badge">Zero-Trust Per-User Isolation</span>
  <h2>Sign in &amp; Authorize Google Cloud</h2>
  <p>Authenticate with your Google Account to open a clean-slate workspace and impersonate your target Organization's read-only Service Account.</p>
  <div id="gisSection">
    <button type="button" class="btn" onclick="openChooser()" style="margin-bottom:10px;">Authorize Google OAuth (Recommended)</button>
    <div id="gisSlot" class="slot"></div>
  </div>
  <div class="tok-wrap">
    <label>Or paste <code>gcloud auth print-access-token</code> (recommended for corporate SSO accounts):</label>
    <input id="cliTok" type="password" class="tok-input" placeholder="ya29.a0..." />
    <button type="button" class="btn btn-secondary" onclick="submitCliToken()">Verify CLI Access Token</button>
  </div>
  <div id="errBox" class="err"></div>
</div>
<script>
const TARGET_ORIGIN = {json.dumps(service_origin)};
const CLIENT_ID = {json.dumps(cid)};
function sendToOpener(payload) {{
  const msg = Object.assign({{ type: 'AGENTIC_GOOGLE_AUTH' }}, payload);
  if (window.opener && TARGET_ORIGIN) {{
    try {{ window.opener.postMessage(msg, TARGET_ORIGIN); }} catch (e) {{}}
    setTimeout(() => window.close(), 150);
  }}
}}
function showErr(m) {{
  const el = document.getElementById('errBox');
  el.textContent = m;
  el.style.display = 'block';
}}
function submitCliToken() {{
  const v = (document.getElementById('cliTok').value || '').trim();
  if (!v) {{ showErr('Paste a valid Google OAuth access token (ya29...).'); return; }}
  sendToOpener({{ access_token: v }});
}}
function openChooser() {{
  if (!CLIENT_ID) {{
    showErr('Paste gcloud auth print-access-token below to authenticate.');
    return;
  }}
  if (!window.google || !window.google.accounts || !window.google.accounts.oauth2) {{
    showErr('Google Identity Services is loading. Please try again in a second.');
    return;
  }}
  const tc = window.google.accounts.oauth2.initTokenClient({{
    client_id: CLIENT_ID,
    scope: 'openid email profile https://www.googleapis.com/auth/cloud-platform',
    prompt: 'select_account',
    callback: (resp) => {{
      if (resp && resp.access_token) {{
        sendToOpener({{ access_token: resp.access_token }});
      }} else if (resp && resp.error) {{
        showErr('Google OAuth: ' + resp.error);
      }}
    }}
  }});
  tc.requestAccessToken();
}}
window.addEventListener('load', () => {{
  if (!CLIENT_ID) {{
    const gs = document.getElementById('gisSection');
    if (gs) gs.style.display = 'none';
    return;
  }}
  const iv = setInterval(() => {{
    if (window.google && window.google.accounts && window.google.accounts.id) {{
      clearInterval(iv);
      window.google.accounts.id.initialize({{
        client_id: CLIENT_ID,
        callback: (resp) => {{
          if (resp && resp.credential) {{
            sendToOpener({{ credential: resp.credential }});
          }}
        }},
        auto_select: false,
        cancel_on_tap_outside: false
      }});
      const slot = document.getElementById('gisSlot');
      if (slot) {{
        window.google.accounts.id.renderButton(slot, {{
          theme: 'filled_blue',
          size: 'large',
          shape: 'pill',
          text: 'continue_with',
          width: 340
        }});
      }}
    }}
  }}, 100);
}});
</script>
</body>
</html>"""
    return HTMLResponse(content=html_doc)


@app.get("/health")
async def health_check() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/session/status")
async def get_session_status(request: Request) -> Dict[str, Any]:
    """Returns the caller's isolated persistent workspace connection state (Clean-Slate when disconnected)."""
    caller = _extract_iap_principal(request)
    sid = caller["session_id"]
    sess = get_active_inspection_session()
    has_pending = has_pending_oauth_token(sid, caller["email"])
    if sess is None:
        return {
            "connected": False,
            "workspace_persisted": False,
            "persistence_backend": persistence_backend_label(),
            "delegation_sa_email": configured_delegation_sa_email(),
            "caller_email": caller["email"],
            "has_signin_oauth_token": has_pending,
        }
    return {
        **sess.to_public_metadata(),
        "caller_email": caller["email"],
        "has_signin_oauth_token": bool(sess.is_live_token_valid or has_pending),
    }


@app.get("/api/v1/workspace/restore")
async def restore_user_workspace(
    request: Request,
    scope: str = Query(default=""),
) -> Dict[str, Any]:
    """Restores the authenticated user's persisted connection, org hierarchy, readiness probes, and pinned scans."""
    ident: Optional[IamConsultantIdentity] = _get_resolved_request_identity(request)
    if ident is None:
        return {
            "authenticated": False,
            "connected": False,
            "caller_email": "unauthenticated",
            "session": {"connected": False},
            "org_hierarchy": None,
            "readiness": None,
            "pinned_book": None,
            "pinned_inventory": None,
            "scan_history": [],
        }

    sid = ident.session_id
    has_pending = has_pending_oauth_token(sid, ident.email)

    sess = get_active_inspection_session() or get_inspection_session(sid, ident.email)
    if sess is None:
        return {
            "authenticated": True,
            "connected": False,
            "caller_email": ident.email,
            "has_signin_oauth_token": has_pending,
            "persistence_backend": persistence_backend_label(),
            "delegation_sa_email": configured_delegation_sa_email(),
            "session": {"connected": False},
            "org_hierarchy": None,
            "readiness": None,
            "pinned_book": None,
            "pinned_inventory": None,
            "scan_history": [],
        }

    def _load_bundle() -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]], list[Dict[str, Any]]]:
        conn_loaded = load_workspace_connection(sid, ident.email)
        rec = conn_loaded[0] if conn_loaded else {}
        org_h = rec.get("org_hierarchy") if isinstance(rec.get("org_hierarchy"), dict) else None
        rd = rec.get("readiness") if isinstance(rec.get("readiness"), dict) else None
        req_scope = (scope or "").strip() or sess.pinned_scope or sess.selected_scope
        # Never fall back to "latest pin of any scope": a book pinned for another customer must not surface
        # when a different scope (or a freshly connected customer with no scope yet) is being viewed.
        p_book = load_pinned_book(sid, ident.email, scope=req_scope) if req_scope else None
        p_inv = load_pinned_inventory(sid, ident.email, scope=req_scope) if req_scope else None
        if p_inv is None and isinstance(p_book, dict) and isinstance(p_book.get("asset_inventory"), dict):
            p_inv = p_book["asset_inventory"]
        scans = load_scan_index(sid, ident.email)
        return org_h, rd, p_book, p_inv, scans

    org_h, rd, p_book, p_inv, scans = await asyncio.to_thread(_load_bundle)

    # Only adopt the pin into the session when it was resolved from the session's own scope; explicitly
    # browsing another scope from the scan history must not re-point the current customer session.
    if p_book is not None and not sess.has_pinned_book and not (scope or "").strip():
        sess.has_pinned_book = True
        sess.pinned_scope = str(p_book.get("scope") or sess.pinned_scope)
        sess.pinned_generated_at = str(p_book.get("generated_at") or sess.pinned_generated_at)
    if p_inv is not None and not sess.has_pinned_inventory and not (scope or "").strip():
        sess.has_pinned_inventory = True

    return {
        "authenticated": True,
        "connected": True,
        "caller_email": ident.email,
        "has_signin_oauth_token": bool(sess.is_live_token_valid or has_pending),
        "session": sess.to_public_metadata(),
        "org_hierarchy": org_h,
        "readiness": rd,
        "pinned_book": _strip_server_paths(p_book),
        "pinned_inventory": p_inv,
        "scan_history": scans,
    }


@app.post("/api/v1/workspace/preferences")
async def save_workspace_preferences(payload: WorkspacePreferencesRequest, request: Request) -> Dict[str, Any]:
    """Persists the user's active scope & project checkbox selection so reopening the browser restores exact state."""
    ident: Optional[IamConsultantIdentity] = _get_resolved_request_identity(request)
    if ident is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    sess = update_session_organization_metadata(
        ident.session_id,
        ident.email,
        selected_scope=payload.selected_scope,
        project_scope_mode=payload.project_scope_mode,
        selected_project_ids=payload.selected_project_ids,
    )
    if sess is None:
        return {"saved": False}
    return {
        "saved": True,
        "selected_scope": sess.selected_scope,
        "project_scope_mode": sess.project_scope_mode,
        "selected_project_ids": sess.selected_project_ids,
    }


@app.post("/api/v1/session/connect")
async def connect_target_organization_session(payload: SessionConnectRequest, request: Request) -> Dict[str, Any]:
    """Connects & persists the user's isolated workspace via SA Impersonation (`generateAccessToken`) or Direct Access."""
    ident: Optional[IamConsultantIdentity] = _get_resolved_request_identity(request)
    if ident is None:
        raise HTTPException(status_code=401, detail="Sign in with your Google Account first.")

    user_tok = (payload.user_access_token or "").strip()
    existing_sess = get_inspection_session(ident.session_id, ident.email)
    if not user_tok:
        if existing_sess is not None and existing_sess.base_user_access_token:
            user_tok = existing_sess.base_user_access_token
        else:
            cached_tok = get_pending_oauth_token(ident.session_id, ident.email)
            if cached_tok:
                user_tok = cached_tok

    can_delegated_reconnect = bool(
        persistent_delegation_enabled()
        and payload.connection_mode == "impersonated_sa"
        and existing_sess is not None
        and existing_sess.persistent_sa_delegation
        and existing_sess.impersonated_sa_email
        and payload.target_sa_email
        and existing_sess.impersonated_sa_email.strip().lower() == payload.target_sa_email.strip().lower()
    )

    if not user_tok and not can_delegated_reconnect:
        raise HTTPException(
            status_code=400,
            detail=(
                "Google OAuth2 access token (`ya29...`) is required to connect or impersonate. "
                "Click 'Authorize Google OAuth' or paste `gcloud auth print-access-token`."
            ),
        )

    try:
        sess = await asyncio.to_thread(
            store_inspection_session,
            session_id=ident.session_id,
            owner_email=ident.email,
            user_access_token=user_tok,
            connection_mode=payload.connection_mode,
            target_sa_email=payload.target_sa_email,
            organization_id=payload.organization_id,
            organization_domain=payload.organization_domain,
            customer_name=payload.customer_name,
            optional_customer_bq_table=payload.optional_customer_bq_table,
            retention_days=payload.workspace_retention_days,
        )
        with bind_inspection_session_context(sess):
            readiness = await asyncio.to_thread(
                verify_customer_onboarding_readiness,
                organization_id=payload.organization_id,
                customer_name=payload.customer_name,
                organization_domain=payload.organization_domain,
            )
            resolved_org = readiness.get("organization_id", "") or payload.organization_id
            hierarchy = None
            try:
                hierarchy = await asyncio.to_thread(discover_organization_hierarchy, resolved_org)
            except Exception:
                hierarchy = None

        update_session_organization_metadata(
            ident.session_id,
            ident.email,
            organization_id=readiness.get("organization_id", ""),
            organization_domain=readiness.get("organization_display_name", ""),
            customer_name=readiness.get("customer_name", ""),
            quota_project_id=readiness.get("resolved_quota_project_id", ""),
        )
        persist_extra: Dict[str, Any] = {"readiness": readiness}
        if isinstance(hierarchy, dict):
            persist_extra["org_hierarchy"] = hierarchy
        await asyncio.to_thread(
            update_workspace_connection_fields,
            ident.session_id,
            ident.email,
            persist_extra,
        )
        return {
            "session": sess.to_public_metadata(),
            "readiness": readiness,
            "org_hierarchy": hierarchy,
        }
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "Failed to establish target GCP Organization connection.",
            exc,
            log_context="Target Organization connection failed",
        ) from exc


@app.post("/api/v1/session/disconnect")
async def disconnect_target_organization_session(request: Request, response: Response) -> Dict[str, Any]:
    """Explicitly destroys the caller's persisted workspace, revokes the active cookie sid, and wipes caches."""
    raw_cookie = (request.cookies.get(IAM_SESSION_COOKIE) or "").strip()
    if raw_cookie:
        revoke_consultant_cookie(raw_cookie)
    ident: Optional[IamConsultantIdentity] = _get_resolved_request_identity(request)
    if ident is not None:
        if ident.cookie_sid:
            revoke_session_id(ident.cookie_sid)
        purge_pending_oauth_tokens(session_id=ident.session_id, owner_email=ident.email)
        await asyncio.to_thread(wipe_inspection_session, ident.session_id, ident.email, wipe_persistent=True)
    response.delete_cookie(key=IAM_SESSION_COOKIE, path="/")
    return {"connected": False, "wiped": True, "session_revoked": True}


@app.get("/api/v1/models")
async def list_vertex_models() -> Dict[str, Any]:
    return {
        "default_model": DEFAULT_VERTEX_MODEL,
        "active_model": settings.vertex_model_id,
        "location": DEFAULT_VERTEX_LOCATION,
        "supported_models": list(SUPPORTED_VERTEX_MODELS),
        "catalog": get_model_catalog_metadata(),
    }


@app.post("/api/v1/models/select")
async def select_vertex_model(payload: ModelSelectRequest) -> Dict[str, Any]:
    # Validate requested model without mutating process-global settings (per-request model selection — T17 #8)
    try:
        selected = resolve_vertex_model(payload.model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "active_model": selected,
        "location": DEFAULT_VERTEX_LOCATION,
        "catalog": get_model_catalog_metadata(),
    }


@app.get("/api/v1/org/hierarchy")
async def get_organization_hierarchy(
    organization_id: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    """Discovers (or restores from persistent workspace) accessible GCP Organizations and ACTIVE projects."""
    sess = get_active_inspection_session()
    if sess is not None and (not refresh or not sess.is_live_token_valid):
        loaded = await asyncio.to_thread(load_workspace_connection, sess.session_id, sess.owner_email)
        cached_h = (loaded[0].get("org_hierarchy") if loaded else None)
        if isinstance(cached_h, dict) and (
            not organization_id
            or str(cached_h.get("organization_id") or "") == str(organization_id).replace("organizations/", "").strip()
        ):
            return cached_h
    try:
        data = await asyncio.to_thread(discover_organization_hierarchy, organization_id)
        if sess is not None and isinstance(data, dict):
            await asyncio.to_thread(
                update_workspace_connection_fields,
                sess.session_id,
                sess.owner_email,
                {"org_hierarchy": data},
            )
        return data
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "Failed to discover GCP organization hierarchy.",
            exc,
            log_context="Organization hierarchy discovery failed",
        ) from exc


@app.post("/api/v1/onboarding/kit")
async def create_onboarding_kit(payload: OnboardingKitRequest, request: Request) -> Dict[str, Any]:
    """Generates the Zero-Key Read-Only Customer Onboarding Kit scoped to the authenticated user's email."""
    caller = _extract_iap_principal(request)
    user_email = payload.impersonator_user_email.strip() or (caller["email"] if caller["authenticated"] == "true" else "")
    try:
        return generate_customer_onboarding_kit(
            customer_name=payload.customer_name,
            organization_id=payload.organization_id,
            organization_domain=payload.organization_domain,
            seed_project_id=payload.seed_project_id,
            onboarding_mode=payload.onboarding_mode,
            impersonator_user_email=user_email,
            sa_account_id=payload.sa_account_id,
            enable_persistent_auto_renew=payload.enable_persistent_auto_renew,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/onboarding/download-kit")
async def download_onboarding_kit_zip(
    payload: OnboardingKitRequest,
    request: Request,
) -> Response:
    """Builds and returns the Zero-Key Read-Only Customer Onboarding Kit (.zip) from a validated JSON payload."""
    caller = _extract_iap_principal(request)
    user_email = payload.impersonator_user_email.strip() or (caller["email"] if caller["authenticated"] == "true" else "")
    try:
        kit = generate_customer_onboarding_kit(
            customer_name=payload.customer_name,
            organization_id=payload.organization_id,
            organization_domain=payload.organization_domain,
            seed_project_id=payload.seed_project_id,
            onboarding_mode=payload.onboarding_mode,
            impersonator_user_email=user_email,
            sa_account_id=payload.sa_account_id,
            enable_persistent_auto_renew=payload.enable_persistent_auto_renew,
        )
        zip_bytes = build_onboarding_kit_zip(kit)
        safe_id = "".join(ch for ch in kit["organization_id"] if ch.isalnum()) or "customer"
        fname = f"agentic_iam_onboarding_{safe_id}.zip"
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/framework-scorecard")
async def get_framework_scorecard_baseline(
    request: Request,
    scope: str = Query(default=""),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    """Returns the 100% deterministic 18-control Framework Baseline across Google Cloud Blueprint, NIST, CIS, and CISA ZTMM."""
    # Live collection: needs the custom header (not sendable by a cross-site link) and is rate limited (T21)
    _require_explicit_client_for_live_get(request)
    _enforce_rate_limit("scans", _live_work_owner(request))
    try:
        return await asyncio.to_thread(compute_iam_framework_baseline, scope, refresh)
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "Framework scorecard baseline evaluation failed.",
            exc,
            log_context="Framework scorecard baseline evaluation failed",
        ) from exc


_LIVE_VIA_GET_DETAIL = (
    "Live scans and forced refreshes cannot be triggered via GET. "
    "Use POST /api/v1/scans or POST /api/v1/book with the X-Requested-With header."
)


def _reject_live_work_via_get(refresh: bool) -> None:
    """GET endpoints never run agents or live scans (T21): `refresh=true` is refused with 405."""
    if refresh:
        raise HTTPException(status_code=405, detail=_LIVE_VIA_GET_DETAIL, headers={"Allow": "POST"})


def _no_pinned_assessment_error() -> HTTPException:
    return HTTPException(
        status_code=409,
        detail="No pinned assessment exists for this scope. Run a scan first via POST /api/v1/scans.",
    )


def _require_explicit_client_for_live_get(request: Request) -> None:
    """Live collection through GET needs the custom `X-Requested-With` header (a cross-site link cannot send it)."""
    if not (request.headers.get("x-requested-with") or "").strip():
        raise HTTPException(status_code=403, detail="Missing required X-Requested-With header.")


def _live_work_owner(request: Request) -> str:
    sess = get_active_inspection_session()
    caller = _extract_iap_principal(request)
    return (sess.owner_email if sess is not None else caller["email"]).strip().lower()


def _retention_options_html() -> str:
    """`<option>` list for the consultant-selected workspace retention (0 = persist nothing)."""
    default_days = default_retention_days()
    upper = max_retention_days()
    labels = {
        0: "Do not persist (session only)",
        1: "1 day",
        7: "7 days",
        30: "30 days",
        90: "90 days",
        180: "180 days",
        365: "365 days",
    }
    choices = sorted({d for d in labels if d <= upper} | {default_days})
    return "".join(
        f'<option value="{d}"{" selected" if d == default_days else ""}>{html.escape(labels.get(d, f"{d} days"))}</option>'
        for d in choices
    )


def _load_pinned_book_for_session(scope: str = "") -> Optional[Dict[str, Any]]:
    sess = get_active_inspection_session()
    if sess is None or sess.connection_mode == "local_cli_adc":
        return None
    target = (scope or "").strip()
    if not target and sess.organization_id:
        target = sess.pinned_scope or sess.selected_scope or f"organizations/{sess.organization_id}"
    if not target:
        # No scope known for this session: never fall back to "latest pin of any scope" (T18)
        return None
    return load_pinned_book(sess.session_id, sess.owner_email, scope=target)


def _persist_book_and_base_artifacts(book: PostureAccelerationBook, out_dir: Path) -> None:
    """Persists `book.json` into the scope export directory, invalidates stale deliverables, and pins metadata."""
    persist_book_snapshot(book, out_dir, invalidate_deliverables=True)

    sess = get_active_inspection_session()
    if sess is None or sess.connection_mode == "local_cli_adc":
        return
    target_scope = book.scope
    if sess.optional_customer_bq_table and sess.is_live_token_valid:
        try:
            from backend.tools.cai_collector import persist_findings_list_to_bigquery

            bq_res = persist_findings_list_to_bigquery(book.triad_matrix.findings, target_scope)
            sess.last_bq_export_status = {
                k: v for k, v in bq_res.items() if k != "session_jsonl_path"
            }
        except Exception as exc:
            sess.last_bq_export_status = {
                "status": "CUSTOMER_BIGQUERY_ERROR",
                "customer_table_id": sess.optional_customer_bq_table,
                "detail": str(exc)[:300],
            }
    save_pinned_book(sess.session_id, sess.owner_email, target_scope, book.model_dump())
    if book.asset_inventory is not None:
        save_pinned_inventory(sess.session_id, sess.owner_email, target_scope, book.asset_inventory.model_dump())
    update_session_organization_metadata(
        sess.session_id,
        sess.owner_email,
        selected_scope=target_scope,
        has_pinned_book=True,
        has_pinned_inventory=book.asset_inventory is not None,
        pinned_scope=target_scope,
        pinned_generated_at=book.generated_at,
    )


@app.get("/api/v1/inventory")
async def get_accounts_keys_secrets_inventory(
    request: Request,
    scope: str = Query(default=""),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    """Returns live or pinned indicators & ledgers across Accounts, Service Accounts, Keys, Secrets, KMS, API Keys, Custom Roles, and WIF."""
    try:
        sess = get_active_inspection_session()
        target_scope = normalize_gcp_scope(scope)
        if not refresh and sess is not None and sess.connection_mode != "local_cli_adc":
            pinned_inv = await asyncio.to_thread(
                load_pinned_inventory, sess.session_id, sess.owner_email, target_scope
            )
            if isinstance(pinned_inv, dict):
                return pinned_inv
        # Live collection from here on (T21)
        _require_explicit_client_for_live_get(request)
        _enforce_rate_limit("scans", _live_work_owner(request))
        inv = await asyncio.to_thread(build_accounts_keys_secrets_inventory, target_scope, refresh)
        inv_dict = inv.model_dump()
        if sess is not None and sess.connection_mode != "local_cli_adc":
            await asyncio.to_thread(save_pinned_inventory, sess.session_id, sess.owner_email, target_scope, inv_dict)
            await asyncio.to_thread(
                save_workspace_artifact,
                sess.session_id,
                "accounts_keys_secrets_inventory.json",
                inv.model_dump_json(indent=2).encode("utf-8"),
                "application/json",
                target_scope,
            )
            update_session_organization_metadata(sess.session_id, sess.owner_email, has_pinned_inventory=True)
        return inv_dict
    except HTTPException:
        raise
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "Accounts, Keys & Secrets inventory collection failed.",
            exc,
            log_context="Accounts, Keys & Secrets inventory collection failed",
        ) from exc


@app.get("/api/v1/scorecard")
async def get_scorecard(
    scope: str = Query(default=""),
    model: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    _resolve_requested_model_or_400(model)
    _reject_live_work_via_get(refresh)
    try:
        target_scope = normalize_gcp_scope(scope)
        pinned = await asyncio.to_thread(_load_pinned_book_for_session, target_scope)
        if isinstance(pinned, dict) and isinstance(pinned.get("scorecard"), dict):
            out = dict(pinned["scorecard"])
            out["telemetry"] = pinned.get("telemetry")
            return _strip_server_paths(out)
        raise _no_pinned_assessment_error()
    except HTTPException:
        raise
    except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "ADK scorecard assessment failed.",
            exc,
            log_context="ADK scorecard assessment failed",
        ) from exc


@app.get("/api/v1/triad")
async def get_triad_matrix(
    scope: str = Query(default=""),
    model: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    _resolve_requested_model_or_400(model)
    _reject_live_work_via_get(refresh)
    try:
        target_scope = normalize_gcp_scope(scope)
        pinned = await asyncio.to_thread(_load_pinned_book_for_session, target_scope)
        if isinstance(pinned, dict) and isinstance(pinned.get("triad_matrix"), dict):
            out = dict(pinned["triad_matrix"])
            out["telemetry"] = pinned.get("telemetry")
            return _strip_server_paths(out)
        raise _no_pinned_assessment_error()
    except HTTPException:
        raise
    except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "ADK triad assessment failed.",
            exc,
            log_context="ADK triad assessment failed",
        ) from exc


@app.get("/api/v1/attack-graph")
async def get_attack_graph(
    scope: str = Query(default=""),
    model: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    _resolve_requested_model_or_400(model)
    _reject_live_work_via_get(refresh)
    try:
        target_scope = normalize_gcp_scope(scope)
        pinned = await asyncio.to_thread(_load_pinned_book_for_session, target_scope)
        if isinstance(pinned, dict) and isinstance(pinned.get("attack_graph"), dict):
            out = dict(pinned["attack_graph"])
            out["impersonation_resilience_score"] = (pinned.get("scorecard") or {}).get("impersonation_resilience_score")
            out["telemetry"] = pinned.get("telemetry")
            return _strip_server_paths(out)
        raise _no_pinned_assessment_error()
    except HTTPException:
        raise
    except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "ADK attack graph assessment failed.",
            exc,
            log_context="ADK attack graph assessment failed",
        ) from exc


@app.get("/api/v1/recommendations")
async def get_recommendations(
    scope: str = Query(default=""),
    model: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    _resolve_requested_model_or_400(model)
    _reject_live_work_via_get(refresh)
    try:
        target_scope = normalize_gcp_scope(scope)
        pinned = await asyncio.to_thread(_load_pinned_book_for_session, target_scope)
        if isinstance(pinned, dict) and isinstance(pinned.get("recommendations"), list):
            return _strip_server_paths(
                {
                    "scope": target_scope,
                    "count": len(pinned["recommendations"]),
                    "least_privilege_index": (pinned.get("scorecard") or {}).get("least_privilege_index"),
                    "recommendations": pinned["recommendations"],
                    "telemetry": pinned.get("telemetry"),
                }
            )
        raise _no_pinned_assessment_error()
    except HTTPException:
        raise
    except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "ADK least-privilege recommendations assessment failed.",
            exc,
            log_context="ADK recommendations assessment failed",
        ) from exc


@app.get("/api/v1/iac-bundle")
async def get_iac_bundle(
    scope: str = Query(default=""),
    model: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    _resolve_requested_model_or_400(model)
    _reject_live_work_via_get(refresh)
    try:
        target_scope = normalize_gcp_scope(scope)
        pinned = await asyncio.to_thread(_load_pinned_book_for_session, target_scope)
        if isinstance(pinned, dict) and isinstance(pinned.get("iac_bundle"), dict):
            out = dict(pinned["iac_bundle"])
            out["telemetry"] = pinned.get("telemetry")
            return _strip_server_paths(out)
        raise _no_pinned_assessment_error()
    except HTTPException:
        raise
    except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "ADK IaC bundle generation failed.",
            exc,
            log_context="ADK IaC bundle generation failed",
        ) from exc


@app.get("/api/v1/book")
async def get_posture_book(
    scope: str = Query(default=""),
    model: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
) -> Any:
    """Returns a previously persisted Posture Acceleration Book without triggering live scans (T14)."""
    _resolve_requested_model_or_400(model)
    if refresh:
        return JSONResponse(
            status_code=405,
            headers={"Allow": "POST"},
            content={
                "detail": (
                    "Live scans and forced refreshes cannot be triggered via GET. "
                    "Use POST /api/v1/scans or POST /api/v1/book with the X-Requested-With header."
                )
            },
        )
    try:
        target_scope = normalize_gcp_scope(scope)
        out_dir = scoped_export_dir(target_scope)
        disk_book = await asyncio.to_thread(load_persisted_book, out_dir)
        if disk_book is not None:
            return _strip_server_paths(disk_book.model_dump())
        pinned = await asyncio.to_thread(_load_pinned_book_for_session, target_scope)
        if isinstance(pinned, dict):
            pinned_obj = PostureAccelerationBook.model_validate(pinned)
            await asyncio.to_thread(
                persist_book_snapshot,
                pinned_obj,
                out_dir,
                invalidate_deliverables=False,
            )
            return _strip_server_paths(pinned)
        raise HTTPException(
            status_code=404,
            detail="No persisted posture book found for this scope. Trigger a scan via POST /api/v1/scans or POST /api/v1/book.",
        )
    except HTTPException:
        raise
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "Failed to load persisted posture book.",
            exc,
            log_context="Persisted posture book load failed",
        ) from exc


class BackgroundScanRequest(BaseModel):
    scope: str = ""
    model: Optional[str] = None
    refresh: bool = True


@app.post("/api/v1/book")
async def run_posture_book_post(
    request: Request,
    scope: str = Query(default=""),
    model: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    """Triggers a synchronous ADK posture book assessment via POST (requires X-Requested-With & rate-limited)."""
    resolved_model = _resolve_requested_model_or_400(model)
    caller = _extract_iap_principal(request)
    sess = get_active_inspection_session()
    owner = (sess.owner_email if sess is not None else caller["email"]).strip().lower()
    _enforce_rate_limit("scans", owner)
    try:
        target_scope = normalize_gcp_scope(scope)
        out_dir = scoped_export_dir(target_scope)
        if not refresh:
            disk_book = await asyncio.to_thread(load_persisted_book, out_dir)
            if disk_book is not None:
                return _strip_server_paths(disk_book.model_dump())
            pinned = await asyncio.to_thread(_load_pinned_book_for_session, target_scope)
            if isinstance(pinned, dict):
                pinned_obj = PostureAccelerationBook.model_validate(pinned)
                await asyncio.to_thread(
                    persist_book_snapshot,
                    pinned_obj,
                    out_dir,
                    invalidate_deliverables=False,
                )
                return _strip_server_paths(pinned)
        book = await run_posture_book_assessment(
            scope=target_scope,
            model_name=resolved_model,
            force_refresh=refresh,
        )
        await asyncio.to_thread(_persist_book_and_base_artifacts, book, out_dir)
        return _strip_server_paths(book.model_dump())
    except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "ADK posture book synthesis failed.",
            exc,
            log_context="ADK posture book synthesis failed",
        ) from exc


@app.post("/api/v1/scans", status_code=202)
async def start_background_scan(req: BackgroundScanRequest, request: Request) -> Dict[str, Any]:
    """Starts an asynchronous posture book scan in the background and immediately returns a `scan_id` (T08 Part B)."""
    resolved_model = _resolve_requested_model_or_400(req.model)
    target_scope = normalize_gcp_scope(req.scope)
    caller = _extract_iap_principal(request)
    sess = get_active_inspection_session()
    sid = sess.session_id if sess is not None else caller["session_id"]
    owner = (sess.owner_email if sess is not None else caller["email"]).strip().lower()
    _enforce_rate_limit("scans", owner)
    _prune_background_scans(owner)
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t0 = time.monotonic()

    record: Dict[str, Any] = {
        "scan_id": scan_id,
        "session_id": sid,
        "owner_email": owner,
        "scope": target_scope,
        "model": resolved_model,
        "refresh": bool(req.refresh),
        "status": "running",
        "started_at": now_iso,
        "finished_at": None,
        "elapsed_ms": 0.0,
        "error": None,
        "http_status": 202,
        "book": None,
    }
    _BACKGROUND_SCANS[scan_id] = record

    async def _run_job() -> None:
        try:
            with bind_inspection_session_context(sess):
                out_dir = scoped_export_dir(target_scope)
                book = await run_posture_book_assessment(
                    scope=target_scope,
                    model_name=resolved_model,
                    force_refresh=bool(req.refresh),
                )
                await asyncio.to_thread(_persist_book_and_base_artifacts, book, out_dir)
            record["status"] = "completed"
            record["http_status"] = 200
            record["book"] = _strip_server_paths(book.model_dump())
        except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
            record["status"] = "failed"
            record["http_status"] = 504
            record["error"] = str(exc)
        except PermissionError as exc:
            record["status"] = "failed"
            record["http_status"] = 412
            record["error"] = str(exc)
        except ValueError as exc:
            record["status"] = "failed"
            record["http_status"] = 400
            record["error"] = str(exc)
        except asyncio.CancelledError:
            record["status"] = "cancelled"
            record["http_status"] = 499
            record["error"] = "Scan cancelled after session wipe."
            raise
        except Exception as exc:
            cid = uuid.uuid4().hex[:12]
            logger.exception("[correlation_id=%s] Background scan '%s' failed", cid, scan_id, exc_info=exc)
            record["status"] = "failed"
            record["http_status"] = 502
            record["error"] = f"Background scan failed (correlation_id={cid})."
        finally:
            record["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            record["elapsed_ms"] = round((time.monotonic() - t0) * 1000.0, 1)
            record["finished_monotonic"] = time.monotonic()
            _BACKGROUND_SCAN_TASKS.pop(scan_id, None)

    _BACKGROUND_SCAN_TASKS[scan_id] = asyncio.create_task(_run_job())
    return {
        "scan_id": scan_id,
        "status": "running",
        "scope": target_scope,
        "model": resolved_model,
        "started_at": now_iso,
    }


@app.get("/api/v1/scans/{scan_id}")
async def get_background_scan_status(scan_id: str, request: Request) -> Dict[str, Any]:
    """Returns status and completed result for an owner-isolated background scan (T08 Part B)."""
    rec = _BACKGROUND_SCANS.get(scan_id)
    caller = _extract_iap_principal(request)
    sess = get_active_inspection_session()
    sid = sess.session_id if sess is not None else caller["session_id"]
    owner = (sess.owner_email if sess is not None else caller["email"]).strip().lower()
    if rec is None or rec.get("session_id") != sid or rec.get("owner_email") != owner:
        raise HTTPException(status_code=404, detail="Scan job not found for current session.")
    return {
        "scan_id": rec["scan_id"],
        "status": rec["status"],
        "scope": rec["scope"],
        "model": rec["model"],
        "started_at": rec["started_at"],
        "finished_at": rec["finished_at"],
        "elapsed_ms": rec["elapsed_ms"],
        "http_status": rec["http_status"],
        "error": rec["error"],
        "book": _strip_server_paths(rec["book"]),
    }


@app.post("/api/v1/generate-deliverables")
async def trigger_deliverable_generation(
    request: Request,
    scope: str = Query(default=""),
    model: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
) -> Dict[str, Any]:
    resolved_model = _resolve_requested_model_or_400(model)
    caller = _extract_iap_principal(request)
    sess = get_active_inspection_session()
    owner = (sess.owner_email if sess is not None else caller["email"]).strip().lower()
    _enforce_rate_limit("scans", owner)
    try:
        target_scope = normalize_gcp_scope(scope)
        out_dir = scoped_export_dir(target_scope)
        pinned_obj: Optional[PostureAccelerationBook] = None
        if not refresh:
            pinned_obj = await asyncio.to_thread(load_persisted_book, out_dir)
            if pinned_obj is None:
                pinned_dict = await asyncio.to_thread(_load_pinned_book_for_session, target_scope)
                if isinstance(pinned_dict, dict):
                    pinned_obj = PostureAccelerationBook.model_validate(pinned_dict)
        result = await generate_all_executive_deliverables_async(
            scope=target_scope,
            model_name=resolved_model,
            force_refresh=refresh,
            pinned_book=pinned_obj,
        )
        return _strip_server_paths(result)
    except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "ADK deliverable generation failed.",
            exc,
            log_context="ADK deliverable generation failed",
        ) from exc


@app.get("/api/v1/download/{artifact_type}")
async def download_deliverable(
    artifact_type: str,
    scope: str = Query(default=""),
    model: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
    theme: str = Query(default="light"),
) -> FileResponse:
    """Serves a deliverable rendered strictly from the pinned book of this scope; never runs a scan or the LLM (T21)."""
    _resolve_requested_model_or_400(model)
    _reject_live_work_via_get(refresh)
    try:
        target_scope = normalize_gcp_scope(scope)
        out_dir = scoped_export_dir(target_scope)
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    is_dark = theme.strip().lower() == "dark"
    graph_filename = GRAPH_DARK_FILENAME if is_dark else GRAPH_LIGHT_FILENAME

    mapping: Dict[str, tuple[Path, str]] = {
        "docx": (
            out_dir / DOCX_FILENAME,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        "pdf": (
            out_dir / PDF_FILENAME,
            "application/pdf",
        ),
        "terraform-zip": (
            out_dir / TERRAFORM_ZIP_FILENAME,
            "application/zip",
        ),
        "attack-graph-png": (
            out_dir / graph_filename,
            "image/png",
        ),
        "inventory-json": (
            out_dir / INVENTORY_JSON_FILENAME,
            "application/json",
        ),
    }

    if artifact_type not in mapping:
        raise HTTPException(status_code=404, detail=f"Unsupported artifact_type '{artifact_type}'.")

    file_path, media_type = mapping[artifact_type]
    sess = get_active_inspection_session()
    active_book: Optional[PostureAccelerationBook] = None

    try:
        active_book = await asyncio.to_thread(load_persisted_book, out_dir)
        if active_book is None:
            pinned_dict = await asyncio.to_thread(_load_pinned_book_for_session, target_scope)
            if isinstance(pinned_dict, dict):
                active_book = PostureAccelerationBook.model_validate(pinned_dict)
                await asyncio.to_thread(
                    persist_book_snapshot,
                    active_book,
                    out_dir,
                    invalidate_deliverables=False,
                )

        if active_book is not None:
            # Render strictly from persisted book.json without invoking the ADK runner / LLM
            if not is_deliverable_fresh(out_dir, file_path.name, active_book):
                await asyncio.to_thread(render_deliverables_from_book, active_book, out_dir)
        elif artifact_type == "inventory-json":
            inv_dict = None
            if sess is not None and sess.connection_mode != "local_cli_adc":
                inv_dict = await asyncio.to_thread(
                    load_pinned_inventory, sess.session_id, sess.owner_email, target_scope
                )
            if not isinstance(inv_dict, dict):
                raise _no_pinned_assessment_error()
            inv_obj = AccountsKeysSecretsInventory.model_validate(inv_dict)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(inv_obj.model_dump_json(indent=2).encode("utf-8"))
        else:
            raise _no_pinned_assessment_error()

        if not file_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Deliverable '{artifact_type}' is not available for this scope.",
            )
    except HTTPException:
        raise
    except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            f"Failed generating '{artifact_type}' deliverable.",
            exc,
            log_context=f"Failed generating artifact '{artifact_type}'",
        ) from exc

    download_name = build_download_filename(
        artifact_type,
        target_scope,
        generated_at=active_book.generated_at if active_book is not None else "",
        fallback_org_id=sess.organization_id if sess is not None else "",
        dark_mode=is_dark,
    )
    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=download_name,
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/v1/chat")
async def invoke_coordinator_chat(req: ChatRequest, request: Request) -> Dict[str, Any]:
    """Invokes the Google ADK `iam_coordinator` strictly over the caller's connected target session."""
    resolved_model = _resolve_requested_model_or_400(req.model)
    caller = _extract_iap_principal(request)
    sess = get_active_inspection_session()
    owner = (sess.owner_email if sess is not None else caller["email"]).strip().lower()
    _enforce_rate_limit("chat", owner)
    try:
        target_scope = normalize_gcp_scope(req.scope)
        scoped_chat_sid = f"{caller['session_id']}_{req.session_id or 'default'}"
        return await run_coordinator_chat(
            prompt=req.prompt,
            scope=target_scope,
            caller_email=caller["email"],
            model_name=resolved_model,
            session_id=scoped_chat_sid,
        )
    except (AgentExecutionTimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise _opaque_server_error(
            502,
            "ADK Coordinator execution failed.",
            exc,
            log_context="Google ADK Coordinator chat failed",
        ) from exc


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def serve_executive_dashboard(request: Request) -> HTMLResponse:
    """Renders the IAP-protected Executive Console styled with the AISPR minimalist design system."""
    caller = _extract_iap_principal(request)
    is_authenticated = caller.get("authenticated") == "true"

    template = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agentic IAM Accelerator - IAM Security Posture Review | Google Cloud Consulting</title>
  <link rel="icon" type="image/png" sizes="64x64" href="__FAVICON_DATA_URI__">
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png?v=3">
  <link rel="shortcut icon" href="/favicon.ico?v=3">
  <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png?v=3">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://accounts.google.com/gsi/client" async defer></script>
  <style>
    :root {
      --bg: #14161B;
      --surface: #1B1E26;
      --surface-variant: #232732;
      --border: #2C3240;
      --primary: #1A73E8;
      --primary-hover: #1557B0;
      --text-main: #F1F5F9;
      --text-muted: #94A3B8;
      --text-subtle: #64748B;
      --success: #2B8A3E;
      --success-bg: rgba(43, 138, 62, 0.15);
      --warning: #F59F00;
      --warning-bg: rgba(245, 159, 0, 0.15);
      --danger: #E03131;
      --danger-bg: rgba(224, 49, 49, 0.15);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
    }

    /* Header — AISPR Signature Minimalist Top Bar */
    .header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-logo {
      width: 38px;
      height: 38px;
      background: transparent;
      border-radius: 0;
      object-fit: contain;
      display: block;
      flex-shrink: 0;
    }
    .brand-title { font-size: 1.08rem; font-weight: 700; color: #FFFFFF; letter-spacing: -0.01em; }
    .brand-subtitle { font-size: 0.75rem; color: var(--text-muted); margin-top: 1px; }
    .header-meta { display: flex; align-items: center; gap: 0.65rem; flex-wrap: wrap; }
    .consultant-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
      background: rgba(26, 115, 232, 0.14);
      border: 1px solid rgba(138, 180, 248, 0.28);
      font-size: 0.75rem;
      color: var(--text-main);
    }
    .status-dot { width: 7px; height: 7px; border-radius: 50%; background: #34A853; display: inline-block; }
    .mode-badge {
      padding: 4px 11px;
      border-radius: 16px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border: 1px solid var(--primary);
      color: #8AB4F8;
      background: rgba(26, 115, 232, 0.14);
    }
    .client-badge {
      background: var(--surface-variant);
      border: 1px solid var(--border);
      padding: 4px 12px;
      border-radius: 6px;
      font-size: 0.76rem;
      font-weight: 600;
      color: #8AB4F8;
      font-family: 'JetBrains Mono', monospace;
    }

    /* Navigation Tabs */
    .nav-bar {
      background: #181B22;
      border-bottom: 1px solid var(--border);
      padding: 0.42rem 2rem;
      display: flex;
      gap: 0.45rem;
      overflow-x: auto;
    }
    .nav-item {
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--text-muted);
      cursor: pointer;
      border: 1px solid transparent;
      background: transparent;
      font-family: inherit;
      transition: all 0.15s ease;
      white-space: nowrap;
    }
    .nav-item:hover { color: #FFFFFF; background: var(--surface); }
    .nav-item.active {
      color: #FFFFFF;
      background: var(--surface);
      border-color: var(--border);
    }

    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 1.4rem 2rem 2rem;
      width: 100%;
      flex: 1;
    }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }

    /* Compact Horizontal Control Submenu Bar */
    .filter-submenu-bar {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.6rem 1rem;
      margin-bottom: 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
    }
    .filter-submenu-controls {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .filter-pill-label {
      font-size: 0.7rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .filter-pill-input, .filter-pill-select {
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 5px 10px;
      border-radius: 6px;
      font-size: 0.78rem;
      height: 31px;
      font-family: 'JetBrains Mono', monospace;
    }
    .filter-pill-input { min-width: 210px; }
    .filter-pill-select { min-width: 225px; font-family: 'Inter', sans-serif; }
    .filter-pill-input:focus, .filter-pill-select:focus { outline: none; border-color: var(--primary); }

    /* Organization Multi-Project Scope Picker Popover */
    .proj-picker-wrap { position: relative; display: inline-block; }
    .proj-picker-btn {
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 5px 11px;
      border-radius: 6px;
      font-size: 0.78rem;
      height: 31px;
      min-width: 265px;
      display: inline-flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      cursor: pointer;
      font-family: 'Inter', sans-serif;
      font-weight: 500;
    }
    .proj-picker-btn:hover, .proj-picker-btn.open { border-color: var(--primary); }
    .proj-picker-popover {
      display: none;
      position: absolute;
      top: calc(100% + 6px);
      left: 0;
      width: 440px;
      max-width: 92vw;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      z-index: 950;
      box-shadow: 0 20px 48px rgba(0, 0, 0, 0.72);
    }
    .proj-picker-popover.open { display: block; }
    .proj-mode-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
      margin-bottom: 10px;
    }
    .proj-mode-btn {
      padding: 6px 10px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text-muted);
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
      font-family: inherit;
    }
    .proj-mode-btn.active {
      background: rgba(26, 115, 232, 0.16);
      border-color: var(--primary);
      color: #8AB4F8;
    }
    .proj-list-box {
      max-height: 250px;
      overflow-y: auto;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      padding: 4px;
      margin: 8px 0;
    }
    .proj-item-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 6px 8px;
      border-radius: 5px;
      cursor: pointer;
      font-size: 0.78rem;
    }
    .proj-item-row:hover { background: var(--surface-variant); }
    .proj-item-left { display: flex; align-items: center; gap: 8px; min-width: 0; }
    .proj-item-name { font-weight: 600; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .proj-item-id { font-family: 'JetBrains Mono', monospace; font-size: 0.71rem; color: #8AB4F8; flex-shrink: 0; }

    /* Customer Onboarding Grid & Form */
    .onboard-grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1.25fr);
      gap: 1.25rem;
      margin-bottom: 1.25rem;
    }
    .onboard-grid > .card { min-width: 0; }
    @media (max-width: 980px) {
      .onboard-grid { grid-template-columns: minmax(0, 1fr); }
    }
    .form-group { margin-bottom: 0.85rem; }
    .form-group label {
      display: block;
      font-size: 0.73rem;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 5px;
      text-transform: uppercase;
      letter-spacing: 0.4px;
    }
    .form-control {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 8px 11px;
      border-radius: 6px;
      font-size: 0.82rem;
      font-family: inherit;
    }
    .form-control:focus { outline: none; border-color: var(--primary); }

    .telemetry-strip {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      font-size: 0.74rem;
      color: var(--text-muted);
    }
    .telemetry-strip code {
      font-family: 'JetBrains Mono', monospace;
      color: #8AB4F8;
      font-size: 0.73rem;
    }

    /* KPI Stat Cards */
    .grid-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 1.25rem;
    }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.1rem 1.25rem;
      transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .stat-card:hover, .stat-card:focus-visible { border-color: var(--primary); transform: translateY(-2px); outline: none; }
    .stat-title-row { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
    .stat-title { font-size: 0.72rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
    .kpi-info-cue {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 0.66rem;
      font-weight: 600;
      color: #8AB4F8;
      background: rgba(138, 180, 248, 0.1);
      border: 1px solid rgba(138, 180, 248, 0.24);
      border-radius: 999px;
      padding: 1px 7px;
      letter-spacing: 0.2px;
      opacity: 0.82;
      transition: opacity 0.15s ease, background 0.15s ease, border-color 0.15s ease;
      white-space: nowrap;
    }
    .stat-card:hover .kpi-info-cue,
    .stat-card:focus-visible .kpi-info-cue {
      opacity: 1;
      background: rgba(138, 180, 248, 0.2);
      border-color: rgba(138, 180, 248, 0.5);
    }
    .stat-value { font-size: 1.75rem; font-weight: 800; margin-top: 0.25rem; letter-spacing: -0.02em; }
    .stat-desc { font-size: 0.78rem; color: var(--text-subtle); margin-top: 0.2rem; }

    /* Floating Accessible KPI Calculation Rationale Popover */
    .kpi-rationale-popover {
      position: fixed;
      top: 0;
      left: 0;
      z-index: 1200;
      width: 420px;
      max-width: calc(100vw - 24px);
      max-height: min(76vh, 540px);
      overflow-y: auto;
      background: #141923;
      border: 1px solid rgba(138, 180, 248, 0.42);
      border-radius: 10px;
      padding: 14px 16px;
      box-shadow: 0 20px 48px rgba(0, 0, 0, 0.78);
      color: var(--text-main);
      font-size: 0.76rem;
      line-height: 1.5;
      opacity: 0;
      visibility: hidden;
      pointer-events: none;
      transform: translateY(4px);
      transition: opacity 0.14s ease, transform 0.14s ease, visibility 0.14s ease;
    }
    .kpi-rationale-popover.visible {
      opacity: 1;
      visibility: visible;
      pointer-events: auto;
      transform: translateY(0);
    }
    .kpi-pop-hdr {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      padding-bottom: 8px;
      margin-bottom: 9px;
    }
    .kpi-pop-title {
      font-size: 0.8rem;
      font-weight: 700;
      color: #FFFFFF;
      letter-spacing: 0.2px;
    }
    .kpi-pop-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 999px;
      background: rgba(138, 180, 248, 0.14);
      border: 1px solid rgba(138, 180, 248, 0.3);
      color: #8AB4F8;
      white-space: nowrap;
    }
    .kpi-pop-label {
      font-size: 0.67rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #8AB4F8;
      margin: 8px 0 4px;
    }
    .kpi-pop-formula {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.71rem;
      color: #E2E8F0;
      background: rgba(11, 14, 20, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 6px;
      padding: 6px 9px;
      word-break: break-word;
    }
    .kpi-pop-rows {
      display: flex;
      flex-direction: column;
      gap: 4px;
      margin-top: 4px;
    }
    .kpi-pop-row {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 10px;
      padding: 3px 0;
      border-bottom: 1px dashed rgba(255, 255, 255, 0.06);
    }
    .kpi-pop-row:last-child { border-bottom: none; }
    .kpi-pop-row-k { color: var(--text-muted); flex: 1; min-width: 0; }
    .kpi-pop-row-v {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      color: var(--text-main);
      font-weight: 600;
      text-align: right;
      white-space: nowrap;
    }
    .kpi-pop-note {
      margin-top: 9px;
      padding: 7px 9px;
      border-radius: 6px;
      background: rgba(138, 180, 248, 0.08);
      border-left: 2px solid #8AB4F8;
      color: var(--text-muted);
      font-size: 0.72rem;
      line-height: 1.45;
    }
    .kpi-pop-list {
      margin: 4px 0 0 1rem;
      padding: 0;
      color: var(--text-muted);
      font-size: 0.72rem;
    }
    .kpi-pop-list li { margin-top: 3px; }

    /* Cards & Charts */
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 1.25rem;
    }
    .card-title {
      font-size: 0.96rem;
      font-weight: 700;
      color: #FFFFFF;
      margin-bottom: 0.85rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }
    .charts-grid {
      display: grid;
      grid-template-columns: 1fr 1.25fr;
      gap: 1.25rem;
      margin-bottom: 1.25rem;
    }
    @media (max-width: 920px) {
      .charts-grid { grid-template-columns: 1fr; }
    }

    /* Donut Chart */
    .donut-wrapper {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 2rem;
      flex-wrap: wrap;
      padding: 0.5rem 0;
    }
    .donut-svg-box { position: relative; width: 144px; height: 144px; }
    .donut-center-text {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }
    .donut-pct { font-size: 1.4rem; font-weight: 800; }
    .donut-sub { font-size: 0.66rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.4px; }
    .donut-legend { display: flex; flex-direction: column; gap: 8px; font-size: 0.82rem; }
    .legend-row { display: flex; align-items: center; gap: 8px; padding: 4px 6px; border-radius: 4px; cursor: pointer; }
    .legend-row:hover { background: var(--surface-variant); }
    .legend-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }

    /* Maturity Pillar Horizontal Bar Chart */
    .pillar-chart { display: flex; flex-direction: column; gap: 11px; }
    .pillar-row { padding: 4px 6px; border-radius: 6px; transition: background 0.15s; cursor: pointer; }
    .pillar-row:hover { background: var(--surface-variant); }
    .pillar-header { display: flex; justify-content: space-between; font-size: 0.8rem; font-weight: 600; margin-bottom: 5px; }
    .pillar-bar-bg { width: 100%; height: 6px; background: var(--surface-variant); border-radius: 3px; overflow: hidden; }
    .pillar-bar-fill { height: 100%; border-radius: 3px; transition: width 0.4s ease; }

    /* Interactive Finding Cards Grid */
    .asset-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
      gap: 1rem;
      margin-top: 0.5rem;
    }
    .asset-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.1rem 1.2rem;
      cursor: pointer;
      transition: all 0.18s ease;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .asset-card:hover {
      border-color: var(--primary);
      transform: translateY(-2px);
      box-shadow: 0 6px 16px rgba(0, 0, 0, 0.28);
    }
    .asset-card-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 6px; }
    .asset-card-title { font-weight: 700; font-size: 0.88rem; color: #FFFFFF; line-height: 1.35; }
    .asset-card-meta { font-size: 0.78rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 10px; }
    .asset-card-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
      padding-top: 8px;
      font-size: 0.73rem;
      color: var(--text-subtle);
      font-family: 'JetBrains Mono', monospace;
    }

    /* Flow Pipeline Cards */
    .flow-pipeline {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.9rem;
      margin-bottom: 1.25rem;
    }
    .flow-card {
      background: var(--surface-variant);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
    }
    .flow-step-num { font-size: 0.68rem; font-weight: 700; color: #8AB4F8; text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 4px; }
    .flow-title { font-size: 0.92rem; font-weight: 700; color: #FFFFFF; margin-bottom: 4px; }
    .flow-desc { font-size: 0.77rem; color: var(--text-muted); line-height: 1.45; }

    /* Domain / File Filter Pills */
    .domain-select {
      display: flex;
      gap: 6px;
      overflow-x: auto;
      margin-bottom: 1rem;
      padding-bottom: 2px;
    }
    .domain-btn {
      padding: 5px 12px;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      font-family: inherit;
      background: var(--surface-variant);
      border: 1px solid var(--border);
      color: var(--text-muted);
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.15s;
    }
    .domain-btn:hover { color: #FFFFFF; }
    .domain-btn.active {
      background: var(--primary);
      color: #FFFFFF;
      border-color: var(--primary);
    }

    /* Tags & Buttons */
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; white-space: nowrap; }
    .tag-gcp { background: rgba(66, 133, 244, 0.15); color: #8AB4F8; }
    .tag-high { background: var(--danger-bg); color: #FFA8A8; }
    .tag-med { background: var(--warning-bg); color: #FFD43B; }
    .tag-low { background: var(--success-bg); color: #8CE99A; }

    .btn {
      background: var(--primary);
      color: #FFFFFF;
      border: none;
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      font-family: inherit;
      cursor: pointer;
      transition: background 0.15s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
      height: 31px;
    }
    .btn:hover { background: var(--primary-hover); }
    .btn:disabled { opacity: 0.6; cursor: wait; }
    .btn-secondary {
      background: var(--surface-variant);
      color: var(--text-main);
      border: 1px solid var(--border);
    }
    .btn-secondary:hover { background: #2E3442; color: #FFFFFF; }

    /* Tables */
    .table-container { overflow-x: auto; margin-top: 0.4rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
    th {
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.7rem;
      letter-spacing: 0.4px;
      background: var(--surface-variant);
    }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; }

    /* Code & Output Box */
    .code-box, .code-block {
      background: #101216;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem 1.15rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.79rem;
      color: #A8C7FA;
      max-height: 460px;
      overflow-y: auto;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.55;
      margin: 0;
    }
    .prompt-input {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 9px 12px;
      color: var(--text-main);
      font-size: 0.84rem;
      font-family: inherit;
    }
    .prompt-input:focus { outline: none; border-color: var(--primary); }

    /* Advisory Note */
    .advisory-note {
      background: rgba(26, 115, 232, 0.07);
      border-left: 3px solid var(--primary);
      padding: 8px 12px;
      border-radius: 0 6px 6px 0;
      font-size: 0.76rem;
      color: var(--text-muted);
      margin-top: 1.25rem;
      line-height: 1.5;
    }

    /* Slide-over Inspector Drawer */
    .drawer-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(2px);
      z-index: 1000;
      opacity: 0;
      visibility: hidden;
      transition: all 0.22s ease;
    }
    .drawer-overlay.active { opacity: 1; visibility: visible; }
    .drawer-panel {
      position: fixed;
      top: 0;
      right: -540px;
      width: 490px;
      max-width: 92vw;
      height: 100vh;
      background: var(--surface);
      border-left: 1px solid var(--border);
      z-index: 1001;
      overflow-y: auto;
      padding: 1.65rem;
      transition: right 0.28s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: -8px 0 24px rgba(0, 0, 0, 0.5);
    }
    .drawer-panel.active { right: 0; }
    .drawer-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1rem;
      margin-bottom: 1.2rem;
    }
    .drawer-title { font-size: 1.05rem; font-weight: 700; color: #FFFFFF; line-height: 1.35; }
    .drawer-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 1.35rem;
      cursor: pointer;
      line-height: 1;
      padding: 2px 6px;
    }
    .drawer-close:hover { color: #FFFFFF; }
    .drawer-section { margin-bottom: 1.2rem; }
    .drawer-section-title {
      font-size: 0.72rem;
      font-weight: 700;
      color: #8AB4F8;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }
    .drawer-meta-table { width: 100%; font-size: 0.79rem; border-collapse: collapse; }
    .drawer-meta-table td { padding: 6px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
    .drawer-meta-table td:first-child { color: var(--text-muted); width: 34%; font-weight: 600; }

    /* Google Cloud Executive Document Layout (Tab 6) */
    .gcp-report-wrapper {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 2.25rem;
      color: var(--text-main);
      line-height: 1.65;
    }
    .gcp-accent-bar {
      display: flex;
      height: 4px;
      width: 100%;
      border-radius: 2px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }
    .gcp-blue { background: #4285F4; flex: 1; }
    .gcp-red { background: #EA4335; flex: 1; }
    .gcp-yellow { background: #FBBC04; flex: 1; }
    .gcp-green { background: #34A853; flex: 1; }
    .report-cover-page {
      padding-bottom: 2rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
    }
    .cover-org { font-size: 0.78rem; font-weight: 700; color: #4285F4; text-transform: uppercase; letter-spacing: 1.4px; margin-bottom: 0.4rem; }
    .cover-title { font-size: 1.85rem; font-weight: 800; color: #FFFFFF; line-height: 1.2; margin-bottom: 0.45rem; }
    .cover-subtitle { font-size: 0.95rem; color: var(--text-muted); margin-bottom: 1.4rem; }
    .report-meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem;
      background: var(--surface-variant);
      padding: 1.15rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      font-size: 0.82rem;
    }
    .meta-item strong { color: var(--text-muted); display: block; font-size: 0.7rem; text-transform: uppercase; margin-bottom: 3px; }
    .chapter-h2 { font-size: 1.05rem; font-weight: 700; color: #8AB4F8; margin: 1.4rem 0 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 5px; }

    /* IAP Sign-In Modal (AISPR Dialog Style) */
    .auth-overlay {
      position: fixed;
      inset: 0;
      z-index: 1100;
      background: rgba(10, 12, 16, 0.78);
      backdrop-filter: blur(3px);
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }
    .auth-dialog-box {
      border: 1px solid rgba(138, 180, 248, 0.28);
      border-radius: 14px;
      background: #16181D;
      color: var(--text-main);
      padding: 28px;
      max-width: 460px;
      width: 100%;
      box-shadow: 0 24px 64px rgba(0, 0, 0, 0.72);
    }

    .footer {
      border-top: 1px solid var(--border);
      padding: 0.95rem 2rem;
      text-align: center;
      font-size: 0.72rem;
      color: var(--text-subtle);
    }

    @media print {
      body { background: #FFFFFF !important; color: #202124 !important; font-size: 9.5pt !important; }
      .header, .nav-bar, .filter-submenu-bar, .footer, .drawer-overlay, .drawer-panel, .auth-overlay, .kpi-rationale-popover, .no-print { display: none !important; }
      .container { max-width: 100% !important; padding: 0 !important; }
      .tab-panel { display: none !important; }
      #tab-report { display: block !important; }
      .gcp-report-wrapper { background: #FFFFFF !important; color: #202124 !important; border: none !important; padding: 0 !important; }
      .cover-title { color: #202124 !important; }
      .cover-subtitle { color: #5F6368 !important; }
      .chapter-h2 { color: #1A73E8 !important; border-bottom: 2px solid #1A73E8 !important; }
      .report-meta-grid { background: #F8F9FA !important; border: 1px solid #DADCE0 !important; color: #202124 !important; }
    }
  </style>
</head>
<body>

  <!-- Universal Google Sign-In & Zero-Trust Session Modal -->
  <div id="iapAuthGate" class="auth-overlay" style="display:__AUTH_DISPLAY__;">
    <div class="auth-dialog-box">
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:14px;">
        <div style="display:flex; align-items:center; gap:12px;">
          <img class="brand-logo" src="/brand-logo.png?v=3" alt="Agentic IAM Accelerator" width="36" height="36" fetchpriority="high" decoding="async" />
          <div>
            <h3 style="margin:0; font-size:1.08rem; font-weight:700; color:#FFFFFF;">Agentic IAM • Clean-Slate Workspace</h3>
            <div style="font-size:0.76rem; color:#8AB4F8; font-weight:600; margin-top:2px;">Zero-Trust Per-User Session Isolation</div>
          </div>
        </div>
        <button onclick="document.getElementById('iapAuthGate').style.display='none'" class="drawer-close" title="Close">&times;</button>
      </div>
      <p style="margin:0 0 14px 0; font-size:0.84rem; color:var(--text-muted); line-height:1.5;">
        Active identity: <strong style="color:#8CE99A;">__CALLER_EMAIL__</strong>. Every user starts with <strong style="color:#F1F5F9;">zero preloaded Organization data</strong> and connects their target GCP Organization in an isolated session.
      </p>
      <div id="authErrorMsg" style="display:none; margin-bottom:14px; padding:10px 12px; border-radius:8px; background:rgba(224,49,49,0.14); border:1px solid rgba(224,49,49,0.35); color:#FFA8A8; font-size:0.78rem;"></div>
      <button type="button" onclick="openOAuthBridgePopup()" style="width:100%; display:__JS_OAUTH_DISPLAY__; align-items:center; justify-content:center; gap:10px; padding:11px 16px; border-radius:8px; border:1px solid #DADCE0; background:#FFFFFF; color:#1F1F1F; font-size:0.88rem; font-weight:600; font-family:inherit; cursor:pointer; margin-bottom:12px;">
        <svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
        <span>Sign in with Google &amp; Authorize Cloud Access</span>
      </button>
      <div style="border-top:1px solid rgba(255,255,255,0.08); padding-top:12px;">
        <div style="font-size:0.76rem; color:#8AB4F8; font-weight:600; margin-bottom:8px;">
          Sign in or switch identity with Google OAuth2 Token (<code>gcloud auth print-access-token</code>):
        </div>
        <div style="display:flex; gap:8px;">
          <input id="cliTokenInput" type="password" placeholder="ya29.a0..." autocomplete="off" style="flex:1; padding:8px 10px; border-radius:6px; border:1px solid var(--border); background:#0F1115; color:#F1F5F9; font-family:'JetBrains Mono', monospace; font-size:0.78rem;" />
          <button type="button" onclick="verifyCliAccessToken()" class="btn">Verify</button>
        </div>
      </div>
      <div style="margin-top:12px; display:flex; justify-content:space-between; align-items:center;">
        <a href="https://shell.cloud.google.com/?show=terminal" target="_blank" rel="noopener" style="color:#8AB4F8; font-size:0.74rem; text-decoration:underline;">Open Google Cloud Shell &nearr;</a>
        <button type="button" onclick="logoutAndWipeAll()" style="background:transparent; border:none; color:var(--text-muted); font-size:0.74rem; cursor:pointer; text-decoration:underline;">Wipe Active Session</button>
      </div>
    </div>
  </div>

  <!-- Optional Read-Only Service Account Setup Guide Modal -->
  <div id="saSetupModal" class="auth-overlay" style="display:none;" onclick="if(event.target===this)closeSaSetupModal()">
    <div class="auth-dialog-box" style="max-width:680px;">
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
        <div>
          <h3 style="margin:0; font-size:1.02rem; font-weight:700; color:#FFFFFF;">1-Line Read-Only Service Account Setup</h3>
          <div style="font-size:0.75rem; color:var(--text-muted); margin-top:3px;">Paste in Google Cloud Shell as Org Admin — automatically detects your active Project &amp; Organization ID</div>
        </div>
        <button type="button" onclick="closeSaSetupModal()" class="drawer-close" title="Close">&times;</button>
      </div>
      <div style="font-size:0.72rem; font-weight:600; color:#8AB4F8; margin-bottom:5px;">1-Line Provisioning Command (creates SA + grants 6 read-only Org roles + Token Creator):</div>
      <pre id="saModalPreview" class="code-box" style="white-space:pre; word-break:normal; max-height:95px; font-size:0.73rem; padding:0.7rem 0.9rem; margin:0 0 12px 0;"></pre>
      <div style="font-size:0.72rem; font-weight:600; color:var(--text-muted); margin-bottom:5px;">Optional 1-Line Post-Assessment Cleanup (revokes roles &amp; deletes SA):</div>
      <pre id="saModalRevokePreview" class="code-box" style="white-space:pre; word-break:normal; max-height:95px; font-size:0.72rem; padding:0.65rem 0.9rem; margin:0 0 14px 0; color:var(--text-muted);"></pre>
      <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <button type="button" id="modalCopySaFullBtn" class="btn" onclick="copyInlineSaGuide('oneliner', 'modalCopySaFullBtn')">Copy 1-Line Setup</button>
          <button type="button" id="modalCopySaRevokeBtn" class="btn btn-secondary" onclick="copyInlineSaGuide('revoke', 'modalCopySaRevokeBtn')">Copy 1-Line Cleanup</button>
          <a href="https://shell.cloud.google.com/?show=terminal" target="_blank" rel="noopener" class="btn btn-secondary" style="text-decoration:none;">Cloud Shell &nearr;</a>
        </div>
        <button type="button" class="btn btn-secondary" onclick="closeSaSetupModal()">Close</button>
      </div>
    </div>
  </div>

  <!-- Header -->
  <header class="header">
    <div class="brand">
      <img class="brand-logo" src="/brand-logo.png?v=3" alt="Agentic IAM Accelerator" width="36" height="36" fetchpriority="high" decoding="async" />
      <div>
        <div class="brand-title">Agentic IAM - Identity Security Posture Review</div>
        <div class="brand-subtitle">Google Cloud Security Consulting | Zero-Trust Clean-Slate IAM Modernization</div>
      </div>
    </div>
    <div class="header-meta">
      <div class="consultant-pill">
        <span class="status-dot"></span>
        <span id="callerBadgeText" style="font-weight:600;">__CALLER_EMAIL__</span>
        <button type="button" onclick="document.getElementById('iapAuthGate').style.display='flex'" style="background:transparent; border:none; color:#8AB4F8; font-size:0.72rem; font-weight:600; cursor:pointer; text-decoration:underline; margin-left:4px;">Account</button>
      </div>
      <div class="mode-badge">ADK • GLOBAL</div>
      <div class="client-badge" id="headerScopeBadge">No Organization Connected</div>
      <button type="button" id="disconnectSessionBtn" class="btn btn-secondary" style="display:none; border-color:rgba(224,49,49,0.5); color:#FFA8A8; padding:4px 10px; font-size:0.74rem;" onclick="disconnectTargetSession()">Disconnect &amp; Wipe</button>
    </div>
  </header>

  <!-- Minimalist Tab Bar (Starts on Connect & Onboard Org for Clean-Slate Isolation) -->
  <nav class="nav-bar">
    <button type="button" class="nav-item active" data-tab="onboarding" onclick="showTab('onboarding')">Connect &amp; Onboard Org</button>
    <button type="button" class="nav-item" data-tab="dashboard" onclick="showTab('dashboard')">Posture Health Dashboard</button>
    <button type="button" class="nav-item" data-tab="triad" onclick="showTab('triad')">Identity Triad &amp; Findings</button>
    <button type="button" class="nav-item" data-tab="inventory" onclick="showTab('inventory')">Accounts, Keys &amp; Secrets</button>
    <button type="button" class="nav-item" data-tab="graph" onclick="showTab('graph')">Attack Path Topology</button>
    <button type="button" class="nav-item" data-tab="iac" onclick="showTab('iac')">Least-Privilege &amp; Terraform</button>
    <button type="button" class="nav-item" data-tab="copilot" onclick="showTab('copilot')">ADK Copilot</button>
    <button type="button" class="nav-item" data-tab="report" onclick="showTab('report')">Executive Report</button>
  </nav>

  <main class="container">

    <!-- Persistent Organization & Multi-Project Scope Bar (Clean-Slate Until Connected) -->
    <div class="filter-submenu-bar">
      <div class="filter-submenu-controls">
        <span class="filter-pill-label">Organization:</span>
        <select id="orgSelector" class="filter-pill-select" onchange="onOrgChange()" disabled>
          <option value="">Not connected — connect an Org below</option>
        </select>

        <span class="filter-pill-label" style="margin-left:2px;">Projects:</span>
        <div class="proj-picker-wrap" id="projPickerWrap">
          <button type="button" class="proj-picker-btn" id="projPickerBtn" onclick="toggleProjPopover(event)" disabled>
            <span id="projPickerLabel">Connect an Organization first</span>
            <span style="color:#8AB4F8; font-size:0.7rem;">&#9662;</span>
          </button>

          <div class="proj-picker-popover" id="projPickerPopover" onclick="event.stopPropagation()">
            <div class="proj-mode-row">
              <button type="button" class="proj-mode-btn" id="modeBtnOrgAll" onclick="setProjectScopeMode('ORG_ALL')">
                Entire Organization (All Projects)
              </button>
              <button type="button" class="proj-mode-btn active" id="modeBtnSelected" onclick="setProjectScopeMode('SELECTED')">
                Select 1 or More Projects
              </button>
            </div>

            <div id="projSelectionArea">
              <div style="display:flex; align-items:center; gap:6px;">
                <input id="projSearchInput" type="text" class="filter-pill-input" style="flex:1; min-width:0; font-family:'Inter',sans-serif;" placeholder="Filter by name or project_id..." oninput="renderProjectCheckboxes()" />
                <button type="button" class="btn btn-secondary" style="padding:4px 8px; font-size:0.72rem;" onclick="selectAllProjects(true)">All</button>
                <button type="button" class="btn btn-secondary" style="padding:4px 8px; font-size:0.72rem;" onclick="selectAllProjects(false)">Clear</button>
              </div>
              <div class="proj-list-box" id="projCheckList"></div>
            </div>

            <div style="border-top:1px solid var(--border); padding-top:8px; margin-top:6px; display:flex; align-items:center; justify-content:space-between; gap:8px;">
              <div class="mono" id="projCanonicalPreview" style="font-size:0.7rem; color:var(--text-muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:255px;">Not connected</div>
              <button type="button" class="btn" style="padding:5px 12px; font-size:0.76rem;" onclick="applyProjectSelectionAndScan()">Apply &amp; Scan</button>
            </div>
          </div>
        </div>

        <input id="scopeInput" type="hidden" value="" />

        <button type="button" class="btn" id="assessBtn" onclick="loadLivePostureBook(true)" disabled>Run ADK Scan</button>
        <select id="pinnedScanSelector" class="filter-pill-select" style="display:none; border-color:rgba(43,138,62,0.5); color:#8CE99A; max-width:260px;" onchange="switchToPinnedScan(this.value)" title="Switch between fixed/pinned scan snapshots">
        </select>
        <button type="button" class="btn btn-secondary" onclick="showTab('onboarding')" title="Connect or onboard a target GCP Organization">Connect / Switch Org</button>
      </div>

      <div class="telemetry-strip">
        <span>Engine: <code id="telModelVersion">__ACTIVE_MODEL__</code></span>
        <span>Tokens: <code id="telTokens">—</code></span>
        <span>Tools: <code id="telToolCalls">—</code></span>
        <span>Latency: <code id="telLatency">—</code></span>
        <span id="assessmentStatusBadge" style="color:var(--text-subtle);">Clean-Slate (Disconnected)</span>
        <span id="bqTelemetryStatus" style="display:none; color:var(--text-subtle);"></span>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 0: CONNECT & ONBOARD TARGET GCP ORGANIZATION (PERSISTENT ZERO-TRUST) -->
    <!-- ========================================================================= -->
    <div id="tab-onboarding" class="tab-panel active">
      <div class="flow-pipeline" style="margin-bottom:1.25rem;">
        <div class="flow-card">
          <div class="flow-step-num">Step 1 • Zero-Key Onboarding</div>
          <div class="flow-title">Provision Read-Only Assessor SA (Zero Keys)</div>
          <div class="flow-desc">Need read-only access on a new customer Org? Generate a Cloud Shell <code>.sh</code> or Terraform <code>.tf</code> kit creating <code>sa-iam-assessor</code> with 6 read-only Org roles and optional persistent auto-renew delegation.</div>
        </div>
        <div class="flow-card">
          <div class="flow-step-num">Step 2 • Persistent Encrypted Workspace</div>
          <div class="flow-title">Connect Once — Persists Across Page Closes</div>
          <div class="flow-desc">Your connection profile and short-lived impersonation tokens are encrypted with <strong>AES-256-GCM</strong> strictly for your verified Google email, surviving browser closes, page refreshes, and Cloud Run restarts.</div>
        </div>
        <div class="flow-card">
          <div class="flow-step-num">Step 3 • Pinned Scans &amp; Deliverables</div>
          <div class="flow-title">Fixed Scanned Data &amp; Instant Reports</div>
          <div class="flow-desc">Every ADK scan, Vault Inventory (Accounts, Keys, KMS &amp; Secrets), Attack Graph, Terraform HCL bundle, and Word/PDF report stays <strong>fixed and pinned</strong> in your private workspace until you run a new scan or wipe it.</div>
        </div>
      </div>

      <div class="onboard-grid">
        <!-- Left Column: Connect Target GCP Organization (Persistent Per-User Workspace) -->
        <div class="card" style="margin-bottom:0;">
          <div class="card-title">
            <span>1. Connect Target GCP Organization</span>
            <span class="tag tag-low" id="connPersistenceBadge">Persistent Encrypted Workspace</span>
          </div>

          <div class="form-group">
            <label>Connection Mode</label>
            <select id="connMode" class="form-control" onchange="onConnectionModeChange()">
              <option value="impersonated_sa">Service Account Impersonation (Recommended — keyless 1-hour generateAccessToken)</option>
              <option value="direct_user">Direct User Read-Only Access (Use my own GCP Viewer roles)</option>
            </select>
          </div>

          <div class="form-group" id="connSaGroup">
            <label style="display:flex; justify-content:space-between; align-items:center; gap:6px; flex-wrap:wrap;">
              <span>Target Read-Only Service Account Email (to Impersonate)</span>
              <span style="font-size:0.7rem; color:var(--text-subtle); font-weight:600;">Auto-detects Project &amp; Org ID</span>
            </label>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
              <input id="connTargetSa" name="iam_target_sa_identifier" type="text" class="form-control mono" style="flex:1; min-width:200px;" value="" placeholder="sa-iam-assessor@your-seed-project.iam.gserviceaccount.com" autocomplete="new-password" data-lpignore="true" spellcheck="false" oninput="refreshInlineSaSetupGuide()" />
              <button type="button" id="copySaFullGuideBtn" class="btn btn-secondary" onclick="copyInlineSaGuide('oneliner', 'copySaFullGuideBtn')" style="white-space:nowrap;" title="Copy single-line gcloud command that auto-detects active Project & Org ID">Copy Setup Cmd</button>
              <button type="button" class="btn btn-secondary" onclick="openSaSetupModal()" style="white-space:nowrap;" title="View 1-line setup & cleanup commands">View Cmd</button>
            </div>
          </div>

          <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
            <div class="form-group">
              <label>Target GCP Organization ID (Digits Only, Optional)</label>
              <input id="connOrgId" name="iam_target_numeric_org" type="text" class="form-control mono" value="" placeholder="Numeric ID (auto-discovered if blank)" autocomplete="new-password" data-lpignore="true" spellcheck="false" oninput="refreshInlineSaSetupGuide()" />
            </div>
            <div class="form-group">
              <label>Customer / Engagement Label (Optional)</label>
              <input id="connCustomerName" name="iam_engagement_label" type="text" class="form-control" value="" placeholder="e.g., Acme Financial Corp" autocomplete="new-password" data-lpignore="true" oninput="refreshInlineSaSetupGuide()" />
            </div>
          </div>

          <div class="form-group">
            <label>Workspace Data Retention (connection, pinned scans &amp; inventory for this customer)</label>
            <select id="connRetentionDays" class="form-control">__RETENTION_OPTIONS_HTML__</select>
            <div style="font-size:0.72rem; color:var(--text-subtle); margin-top:4px;">Stored data is AES-256-GCM encrypted per user and deleted automatically after this period. &ldquo;Do not persist&rdquo; keeps everything in memory for this session only.</div>
          </div>

          <div class="form-group">
            <label style="display:flex; justify-content:space-between; align-items:center; gap:6px; flex-wrap:wrap;">
              <span>Google OAuth2 Access Token (<code>cloud-platform</code> scope)</span>
              <span id="connTokenStatus" style="font-size:0.7rem; color:var(--text-subtle); font-weight:600;">Run: gcloud auth print-access-token</span>
            </label>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
              <input id="connUserToken" type="password" class="form-control mono" style="flex:1; min-width:200px;" placeholder="ya29.a0... (gcloud auth print-access-token)" autocomplete="off" />
              <button type="button" id="copyTokCmdBtn" class="btn btn-secondary" onclick="copyGcloudTokenCmd()" style="white-space:nowrap;" title="Copy 'gcloud auth print-access-token' to clipboard">Copy Token Cmd</button>
              <a href="https://shell.cloud.google.com/?show=terminal" target="_blank" rel="noopener" class="btn btn-secondary" style="white-space:nowrap; text-decoration:none;">Cloud Shell &nearr;</a>
              <button type="button" class="btn btn-secondary" onclick="openOAuthBridgePopup()" style="display:__JS_OAUTH_DISPLAY__; white-space:nowrap;">Authorize OAuth</button>
            </div>
          </div>

          <div class="form-group">
            <label>Optional Customer BigQuery Export Table (Blank = Encrypted Per-User Workspace Store)</label>
            <input id="connBqTable" type="text" class="form-control mono" value="" placeholder="Optional: customer-project.dataset.iam_findings" autocomplete="off" />
            <div id="bqExportStatusBadge" style="margin-top:5px; font-size:0.74rem; color:var(--text-subtle);">BigQuery Export: Ephemeral Session Only (no customer table configured)</div>
          </div>

          <div id="connFeedbackBox" style="display:none; margin-bottom:10px; padding:9px 11px; border-radius:6px; font-size:0.78rem;"></div>

          <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:0.5rem;">
            <button type="button" class="btn" id="connConnectBtn" onclick="connectTargetSession()">Connect, Impersonate &amp; Persist Workspace</button>
            <button type="button" class="btn btn-secondary" id="obActivateBtn" style="display:none; border-color:#2B8A3E; color:#8CE99A;" onclick="activateVerifiedOrgInScanner()">Select Projects &amp; Run Scan &rarr;</button>
          </div>

          <div class="advisory-note" style="margin-top:1rem;">
            <strong style="color:#F1F5F9;">Zero-Trust Per-User Persistence Guarantee:</strong> Your connection profile, AES-256-GCM encrypted session token, and pinned scan snapshots are strictly isolated to your verified Google email (<code>__CALLER_EMAIL__</code>). Closing or refreshing the browser keeps your connection and scanned data fixed until you click <strong>Disconnect &amp; Wipe</strong>.
          </div>
        </div>

        <!-- Right Column: Customer Onboarding Kit Generator (Zero Keys, Blank Clean-Slate Inputs) -->
        <div class="card" style="margin-bottom:0;">
          <div class="card-title">
            <span>2. Need to Onboard a New Organization First? (Zero-Key Kit)</span>
            <span class="tag tag-low">100% Read-Only</span>
          </div>

          <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
            <div class="form-group">
              <label>Customer Name</label>
              <input id="obCustomerName" type="text" class="form-control" value="" placeholder="e.g., Acme Financial Corp" autocomplete="off" />
            </div>
            <div class="form-group">
              <label>Customer GCP Organization ID</label>
              <input id="obOrgId" type="text" class="form-control mono" value="" placeholder="e.g., 123456789012" autocomplete="off" />
            </div>
          </div>

          <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
            <div class="form-group">
              <label>Primary Domain (Workspace / CI)</label>
              <input id="obOrgDomain" type="text" class="form-control mono" value="" placeholder="e.g., acme.com" autocomplete="off" />
            </div>
            <div class="form-group">
              <label>Customer Seed Project ID</label>
              <input id="obSeedProject" type="text" class="form-control mono" value="" placeholder="e.g., prj-sec-governance" autocomplete="off" />
            </div>
          </div>

          <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
            <div class="form-group">
              <label>Authorized User Email (Impersonator)</label>
              <input id="obUserEmail" type="text" class="form-control mono" value="__CALLER_EMAIL_CLEAN__" placeholder="you@company.com" autocomplete="off" />
            </div>
            <div class="form-group">
              <label>Kit Architecture</label>
              <select id="obMode" class="form-control">
                <option value="impersonated_sa">Create sa-iam-assessor + Impersonation</option>
                <option value="direct_user">Direct User Read-Only Roles</option>
              </select>
            </div>
          </div>

          <div class="form-group" style="display:__AUTO_RENEW_DISPLAY__;">
            <label style="display:flex; gap:8px; align-items:flex-start; font-weight:500;">
              <input id="obAutoRenew" type="checkbox" style="margin-top:3px;" onchange="refreshInlineSaSetupGuide()" />
              <span>Enable persistent auto-renew (optional). The kit will ALSO grant this platform&rsquo;s runtime Service Account <code>roles/iam.serviceAccountTokenCreator</code> on the customer&rsquo;s assessor SA. The platform then keeps standing read-only access until the customer removes that binding, even if your own access is revoked. Leave unchecked unless the customer explicitly agreed.</span>
            </label>
          </div>

          <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:0.75rem;">
            <button type="button" class="btn btn-secondary" onclick="generateOnboardingKit()">Generate Kit</button>
            <button type="button" class="btn btn-secondary" onclick="downloadOnboardingZip()">Download (.zip)</button>
            <button type="button" class="btn btn-secondary" onclick="copyOnboardingArtifact()">Copy Code</button>
          </div>

          <div class="domain-select" id="obArtifactTabs">
            <button type="button" class="domain-btn active" data-ob="bash_script" onclick="selectOnboardingTab('bash_script')">Cloud Shell (.sh)</button>
            <button type="button" class="domain-btn" data-ob="terraform_hcl" onclick="selectOnboardingTab('terraform_hcl')">Terraform (.tf)</button>
            <button type="button" class="domain-btn" data-ob="guide_markdown" onclick="selectOnboardingTab('guide_markdown')">Guide &amp; Roles</button>
            <button type="button" class="domain-btn" data-ob="offboarding_revoke_snippet" onclick="selectOnboardingTab('offboarding_revoke_snippet')">Offboarding Revoke</button>
          </div>

          <pre id="obCodePreview" class="code-box" style="max-height:195px;">Enter the customer Organization ID &amp; Seed Project ID above and click "Generate Kit" to build a zero-key Cloud Shell or Terraform onboarding package...</pre>
        </div>
      </div>

      <!-- Bottom Card: Live 6-Point GCP Pre-Flight Readiness Verification -->
      <div class="card">
        <div class="card-title">
          <span>3. Live 6-Point GCP Pre-Flight Readiness Verification &amp; Project Discovery</span>
          <span class="tag tag-gcp" id="connSessionSummaryBadge">Session Disconnected — Zero Data Loaded</span>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>GCP Pre-Flight Check</th>
                <th>Required Role</th>
                <th>Latency</th>
                <th>Evidence / Remediation Command</th>
              </tr>
            </thead>
            <tbody id="obChecksTableBody">
              <tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1.25rem;">Connect a target GCP Organization in <strong>Step 1</strong> above to execute the 6 live read-only pre-flight checks and discover active projects.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 1: POSTURE HEALTH DASHBOARD -->
    <!-- ========================================================================= -->
    <div id="tab-dashboard" class="tab-panel">
      <div id="coverageWarningsBanner" style="display:none; background:rgba(245,159,0,0.12); border:1px solid #F59F00; border-radius:8px; padding:0.85rem 1.05rem; margin-bottom:1rem; font-size:0.82rem; color:#FFE066; line-height:1.5;"></div>
      <div class="grid-stats">
        <div class="stat-card" data-kpi-rationale="overall" tabindex="0" aria-describedby="kpiRationalePopover" onclick="showTab('triad')" style="cursor:pointer;">
          <div class="stat-title-row">
            <div class="stat-title">Overall Posture Health</div>
            <span class="kpi-info-cue" aria-hidden="true">&#9432; Formula</span>
          </div>
          <div class="stat-value" id="kpiOverallScore" style="color:var(--warning);">--%</div>
          <div class="stat-desc" id="kpiMaturityTier">Connect an Organization to begin</div>
        </div>
        <div class="stat-card" data-kpi-rationale="compliant" tabindex="0" aria-describedby="kpiRationalePopover" onclick="showTab('triad')" style="cursor:pointer;">
          <div class="stat-title-row">
            <div class="stat-title">Compliant Principals</div>
            <span class="kpi-info-cue" aria-hidden="true">&#9432; Formula</span>
          </div>
          <div class="stat-value" id="kpiCompliantCount" style="color:var(--success);">--</div>
          <div class="stat-desc" id="kpiCompliantSub">Across Internal, External &amp; SAs</div>
        </div>
        <div class="stat-card" data-kpi-rationale="lpi" tabindex="0" aria-describedby="kpiRationalePopover" onclick="showTab('iac')" style="cursor:pointer;">
          <div class="stat-title-row">
            <div class="stat-title">Least-Privilege Index</div>
            <span class="kpi-info-cue" aria-hidden="true">&#9432; Formula</span>
          </div>
          <div class="stat-value" id="kpiExcessPerms" style="color:#8AB4F8;">--%</div>
          <div class="stat-desc" id="kpiExcessSub">Excess permissions analysis</div>
        </div>
        <div class="stat-card" data-kpi-rationale="crithigh" tabindex="0" aria-describedby="kpiRationalePopover" onclick="showTab('triad')" style="cursor:pointer;">
          <div class="stat-title-row">
            <div class="stat-title">Critical &amp; High Gaps</div>
            <span class="kpi-info-cue" aria-hidden="true">&#9432; Formula</span>
          </div>
          <div class="stat-value" id="kpiCritHighCount" style="color:var(--danger);">--</div>
          <div class="stat-desc" id="kpiCritHighSub">Immediate modernization priority</div>
        </div>
      </div>

      <div class="charts-grid">
        <!-- Chart 1: Dynamic SVG Posture Donut -->
        <div class="card" style="margin-bottom:0;">
          <div class="card-title">
            <span>Identity Compliance Distribution</span>
            <span id="donutScopeLabel" style="font-size:0.74rem; color:var(--text-muted); font-weight:500;">No Organization Connected</span>
          </div>
          <div class="donut-wrapper">
            <div class="donut-svg-box">
              <svg viewBox="0 0 36 36" style="width:100%; height:100%; transform:rotate(-90deg);">
                <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#232732" stroke-width="3.8"/>
                <path id="donutArcCompliant" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#2B8A3E" stroke-width="3.8" stroke-dasharray="0, 100"/>
                <path id="donutArcMod" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#F59F00" stroke-width="3.8" stroke-dasharray="0, 100" stroke-dashoffset="0"/>
                <path id="donutArcCrit" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#E03131" stroke-width="3.8" stroke-dasharray="0, 100" stroke-dashoffset="0"/>
              </svg>
              <div class="donut-center-text">
                <div class="donut-pct" id="donutCenterScore" style="color:var(--warning);">--%</div>
                <div class="donut-sub">Posture Score</div>
              </div>
            </div>

            <div class="donut-legend">
              <div class="legend-row" onclick="showTab('triad')">
                <div class="legend-dot" style="background:#2B8A3E;"></div>
                <div><strong id="legendCompliantCount">--</strong> Compliant Principals</div>
              </div>
              <div class="legend-row" onclick="filterFindingsBySeverity('MODERATE')">
                <div class="legend-dot" style="background:#F59F00;"></div>
                <div><strong id="legendMedLowCount">--</strong> Medium / Low Findings</div>
              </div>
              <div class="legend-row" onclick="filterFindingsBySeverity('CRITICAL_HIGH')">
                <div class="legend-dot" style="background:#E03131;"></div>
                <div><strong id="legendCritHighCount">--</strong> Critical / High Gaps</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Chart 2: Domain Maturity Bars -->
        <div class="card" style="margin-bottom:0;">
          <div class="card-title">
            <span>Domain Maturity (IAM Core Pillars)</span>
            <span style="font-size:0.74rem; color:var(--text-muted); font-weight:500;">Click a pillar to inspect</span>
          </div>
          <div class="pillar-chart">
            <div class="pillar-row" onclick="openTriadPillar('INTERNAL_IDENTITIES')">
              <div class="pillar-header">
                <span>1. Internal Workforce &amp; Group RBAC</span>
                <span id="kpiInternalScore" style="color:var(--text-muted);">--%</span>
              </div>
              <div class="pillar-bar-bg"><div class="pillar-bar-fill" id="barInternal" style="width:0%; background:#1A73E8;"></div></div>
            </div>

            <div class="pillar-row" onclick="openTriadPillar('EXTERNAL_IDENTITIES')">
              <div class="pillar-header">
                <span>2. External Identities &amp; Domain Sharing (DRS)</span>
                <span id="kpiExternalScore" style="color:var(--text-muted);">--%</span>
              </div>
              <div class="pillar-bar-bg"><div class="pillar-bar-fill" id="barExternal" style="width:0%; background:#1A73E8;"></div></div>
            </div>

            <div class="pillar-row" onclick="openTriadPillar('SERVICE_ACCOUNTS_WORKLOAD')">
              <div class="pillar-header">
                <span>3. Workload &amp; Service Account Hygiene (WIF)</span>
                <span id="kpiWorkloadScore" style="color:var(--text-muted);">--%</span>
              </div>
              <div class="pillar-bar-bg"><div class="pillar-bar-fill" id="barWorkload" style="width:0%; background:#1A73E8;"></div></div>
            </div>

            <div class="pillar-row" onclick="showTab('graph')">
              <div class="pillar-header">
                <span>4. Impersonation &amp; Escalation Resilience</span>
                <span id="barResilienceVal" style="color:var(--text-muted);">--%</span>
              </div>
              <div class="pillar-bar-bg"><div class="pillar-bar-fill" id="barResilience" style="width:0%; background:#1A73E8;"></div></div>
            </div>

            <div class="pillar-row" onclick="showTab('iac')">
              <div class="pillar-header">
                <span>5. Least-Privilege Optimization Index</span>
                <span id="barLpiVal" style="color:var(--text-muted);">--%</span>
              </div>
              <div class="pillar-bar-bg"><div class="pillar-bar-fill" id="barLpi" style="width:0%; background:#1A73E8;"></div></div>
            </div>
          </div>
        </div>
      </div>

      <!-- Security Framework Benchmarks & Hybrid Agentic Calibration -->
      <div class="card">
        <div class="card-title">
          <span>Security Framework Alignment &amp; Hybrid Agentic Calibration</span>
          <span class="tag tag-gcp" id="frameworkMethodBadge">18 Controls • GCB / NIST / CIS / CISA ZTMM</span>
        </div>
        <div id="agenticCalibrationBanner" style="background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:0.8rem 1rem; margin-bottom:1rem; font-size:0.81rem; color:var(--text-muted); line-height:1.55;">
          Run an ADK scan to evaluate all <strong>18 deterministic IAM controls</strong> (<code>22% Internal + 18% External + 22% Workload + 20% Least-Privilege + 18% Graph Resilience</code>) combined with bounded <code>[-5%, +5%]</code> Google ADK contextual calibration.
        </div>
        <div id="frameworkBenchmarksGrid" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(195px, 1fr)); gap:0.85rem;">
          <div style="color:var(--text-muted); font-size:0.81rem;">Awaiting connected Organization scan to compute Google Cloud Blueprint, NIST SP 800-53r5, NIST CSF 2.0, CIS GCP v3.0, and CISA ZTMM v2.0 alignment...</div>
        </div>
      </div>

      <!-- 18-Control Deterministic & Framework Audit Matrix -->
      <div class="card">
        <div class="card-title">
          <span>18-Control Deterministic &amp; Framework Evaluation Matrix</span>
          <span style="font-size:0.74rem; color:var(--text-muted); font-weight:500;">Exact Numerator / Denominator Math + Authoritative Control Mappings</span>
        </div>
        <div class="domain-select" id="frameworkControlFilters" style="margin-bottom:0.85rem;">
          <button type="button" class="domain-btn active" data-ctrl-dom="ALL" onclick="filterFrameworkControls('ALL')">All 18 Controls</button>
          <button type="button" class="domain-btn" data-ctrl-dom="INTERNAL_IDENTITIES" onclick="filterFrameworkControls('INTERNAL_IDENTITIES')">Internal (22%)</button>
          <button type="button" class="domain-btn" data-ctrl-dom="EXTERNAL_IDENTITIES" onclick="filterFrameworkControls('EXTERNAL_IDENTITIES')">External (18%)</button>
          <button type="button" class="domain-btn" data-ctrl-dom="WORKLOAD_IDENTITIES" onclick="filterFrameworkControls('WORKLOAD_IDENTITIES')">Workload &amp; SAs (22%)</button>
          <button type="button" class="domain-btn" data-ctrl-dom="LEAST_PRIVILEGE" onclick="filterFrameworkControls('LEAST_PRIVILEGE')">Least-Privilege (20%)</button>
          <button type="button" class="domain-btn" data-ctrl-dom="GRAPH_RESILIENCE" onclick="filterFrameworkControls('GRAPH_RESILIENCE')">Graph Resilience (18%)</button>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Control ID</th>
                <th>Control &amp; Security Frameworks</th>
                <th>Exact Ratio (Num / Den)</th>
                <th>Weight</th>
                <th>Score</th>
                <th>Live GCP Telemetry Evidence</th>
              </tr>
            </thead>
            <tbody id="frameworkControlsBody">
              <tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1.25rem;">Connect a target GCP Organization and click <strong>Run ADK Scan</strong> to inspect all 18 mathematical control evaluations.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Clickable Priority Finding Cards -->
      <div class="card">
        <div class="card-title">
          <span>Priority Identity Findings</span>
          <span style="font-size:0.74rem; color:var(--text-muted); font-weight:500;">Click any card to open remediation playbook</span>
        </div>
        <div class="asset-grid" id="dashboardFindingsGrid">
          <div style="color:var(--text-muted); font-size:0.82rem;">No Organization connected yet. Connect your target GCP Organization in <strong>Connect &amp; Onboard Org</strong> and click <strong>Run ADK Scan</strong>.</div>
        </div>
      </div>

      <div class="advisory-note">
        <strong style="color:#F1F5F9;">Consultative Advisory Positioning (Google Cloud Shared Responsibility Model):</strong>
        This platform operates strictly as an IAM Posture Assessment, Modernization, and Least-Privilege Acceleration Engine over live Cloud Asset Inventory, Resource Manager, IAM, Recommender, and bounded Cloud Audit Log samples in an isolated per-user session (no Policy Simulator replay is executed). It does not perform formal regulatory audits or certifications.
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 2: IDENTITY TRIAD & FINDINGS -->
    <!-- ========================================================================= -->
    <div id="tab-triad" class="tab-panel">
      <div class="flow-pipeline">
        <div class="flow-card">
          <div class="flow-step-num">Pillar 1 • Workforce</div>
          <div class="flow-title">Internal Identities (<span id="triadCardIntScore">--%</span>)</div>
          <div class="flow-desc" id="kpiInternalSub">Awaiting connected Organization scan...</div>
        </div>
        <div class="flow-card">
          <div class="flow-step-num">Pillar 2 • Boundary</div>
          <div class="flow-title">External &amp; Partner (<span id="triadCardExtScore">--%</span>)</div>
          <div class="flow-desc" id="kpiExternalSub">Awaiting connected Organization scan...</div>
        </div>
        <div class="flow-card">
          <div class="flow-step-num">Pillar 3 • Non-Human</div>
          <div class="flow-title">Workload &amp; Service Accounts (<span id="triadCardSaScore">--%</span>)</div>
          <div class="flow-desc" id="kpiWorkloadSub">Awaiting connected Organization scan...</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Identity Triad Findings Matrix</span>
          <span id="findingsCountLabel" style="font-size:0.75rem; color:var(--text-muted); font-weight:500;">0 findings</span>
        </div>

        <div class="domain-select" id="triadPillarFilters">
          <button type="button" class="domain-btn active" data-pillar="ALL" onclick="filterTriadTable('ALL')">All Pillars</button>
          <button type="button" class="domain-btn" data-pillar="INTERNAL_IDENTITIES" onclick="filterTriadTable('INTERNAL_IDENTITIES')">1. Internal Workforce</button>
          <button type="button" class="domain-btn" data-pillar="EXTERNAL_IDENTITIES" onclick="filterTriadTable('EXTERNAL_IDENTITIES')">2. External &amp; DRS</button>
          <button type="button" class="domain-btn" data-pillar="SERVICE_ACCOUNTS_WORKLOAD" onclick="filterTriadTable('SERVICE_ACCOUNTS_WORKLOAD')">3. Workload &amp; Service Accounts</button>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Finding ID</th>
                <th>Severity</th>
                <th>Pillar</th>
                <th>Principal &amp; Role</th>
                <th>Evidence Summary</th>
                <th>Recommended Modernization</th>
              </tr>
            </thead>
            <tbody id="findingsTableBody">
              <tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1.5rem;">Connect a target GCP Organization and run an ADK scan to inspect live Cloud Asset Inventory findings.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 2B: ACCOUNTS, SERVICE ACCOUNTS, KEYS, KMS & SECRETS INVENTORY -->
    <!-- ========================================================================= -->
    <div id="tab-inventory" class="tab-panel">
      <div class="grid-stats" style="grid-template-columns:repeat(auto-fit, minmax(215px, 1fr));">
        <div class="stat-card" onclick="selectInvSubTab('accounts')" style="cursor:pointer;">
          <div class="stat-title">Human, Group &amp; Ext Accounts</div>
          <div class="stat-value" id="invKpiAccounts" style="color:#8AB4F8;">--</div>
          <div class="stat-desc" id="invKpiAccountsSub">Users, Security Groups &amp; External</div>
        </div>
        <div class="stat-card" onclick="selectInvSubTab('accounts')" style="cursor:pointer;">
          <div class="stat-title">Standing 24/7 Admins</div>
          <div class="stat-value" id="invKpiStandingAdmins" style="color:var(--warning);">--</div>
          <div class="stat-desc" id="invKpiVaultReachSub">Secret / KMS Accessors: --</div>
        </div>
        <div class="stat-card" onclick="selectInvSubTab('service_accounts')" style="cursor:pointer;">
          <div class="stat-title">Service Accounts</div>
          <div class="stat-value" id="invKpiSas" style="color:var(--text-main);">--</div>
          <div class="stat-desc" id="invKpiSasSub">Custom &amp; Default SAs in scope</div>
        </div>
        <div class="stat-card" onclick="selectInvSubTab('sa_keys')" style="cursor:pointer;">
          <div class="stat-title">SA Cryptographic Keys</div>
          <div class="stat-value" id="invKpiSaKeys" style="color:var(--danger);">--</div>
          <div class="stat-desc" id="invKpiSaKeysSub">User-Managed vs System Keys</div>
        </div>
        <div class="stat-card" onclick="selectInvSubTab('secrets')" style="cursor:pointer;">
          <div class="stat-title">Secret Manager Secrets</div>
          <div class="stat-value" id="invKpiSecrets" style="color:#8CE99A;">--</div>
          <div class="stat-desc" id="invKpiSecretsSub">100% Metadata-Only (Zero Payload Read)</div>
        </div>
        <div class="stat-card" onclick="selectInvSubTab('kms_keys')" style="cursor:pointer;">
          <div class="stat-title">Cloud KMS CryptoKeys</div>
          <div class="stat-value" id="invKpiKms" style="color:#8AB4F8;">--</div>
          <div class="stat-desc" id="invKpiKmsSub">KeyRings, Rotation &amp; SoD Checks</div>
        </div>
        <div class="stat-card" onclick="selectInvSubTab('api_custom')" style="cursor:pointer;">
          <div class="stat-title">Google Cloud API Keys</div>
          <div class="stat-value" id="invKpiApiKeys" style="color:var(--warning);">--</div>
          <div class="stat-desc" id="invKpiApiKeysSub">Restriction &amp; Age Posture</div>
        </div>
        <div class="stat-card" onclick="selectInvSubTab('wif_orgpol')" style="cursor:pointer;">
          <div class="stat-title">Custom Roles &amp; WIF</div>
          <div class="stat-value" id="invKpiCustomWif" style="color:var(--text-main);">--</div>
          <div class="stat-desc" id="invKpiCustomWifSub">Custom Roles, WIF Pools &amp; Org Policies</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title" style="flex-wrap:wrap; gap:10px;">
          <span>Live Accounts, Keys, KMS &amp; Secrets Ledger</span>
          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
            <input id="invSearchInput" type="text" class="filter-pill-input" style="min-width:230px; font-family:'Inter',sans-serif;" placeholder="Filter accounts, SAs, keys, secrets, KMS, roles..." oninput="renderActiveInventoryTable()" />
            <button type="button" class="btn btn-secondary" id="invRefreshBtn" onclick="refreshVaultInventoryOnly()">Refresh Vault Inventory</button>
            <a id="dlInvJsonBtn" href="#" onclick="return guardDownloadLink(event)" class="btn btn-secondary" style="text-decoration:none;">Export JSON</a>
          </div>
        </div>

        <div class="domain-select" id="invSubTabs" style="margin-bottom:0.85rem;">
          <button type="button" class="domain-btn active" data-inv="accounts" onclick="selectInvSubTab('accounts')">1. Accounts &amp; Principals</button>
          <button type="button" class="domain-btn" data-inv="service_accounts" onclick="selectInvSubTab('service_accounts')">2. Service Accounts</button>
          <button type="button" class="domain-btn" data-inv="sa_keys" onclick="selectInvSubTab('sa_keys')">3. SA Keys (JSON &amp; System)</button>
          <button type="button" class="domain-btn" data-inv="secrets" onclick="selectInvSubTab('secrets')">4. Secrets (Metadata)</button>
          <button type="button" class="domain-btn" data-inv="kms_keys" onclick="selectInvSubTab('kms_keys')">5. Cloud KMS CryptoKeys</button>
          <button type="button" class="domain-btn" data-inv="api_custom" onclick="selectInvSubTab('api_custom')">6. API Keys &amp; Custom Roles</button>
          <button type="button" class="domain-btn" data-inv="wif_orgpol" onclick="selectInvSubTab('wif_orgpol')">7. WIF Pools &amp; Org Policies</button>
        </div>

        <div id="invLedgerCountLabel" style="font-size:0.75rem; color:var(--text-muted); margin-bottom:0.6rem;">Connect a target GCP Organization and click <strong>Run ADK Scan</strong> or <strong>Refresh Vault Inventory</strong>.</div>

        <div class="table-container" id="invLedgerContainer">
          <table>
            <thead id="invTableHead">
              <tr><th>Principal</th><th>Type</th><th>Domain</th><th>Privilege Flags</th><th>Granted Roles</th><th>Risk</th></tr>
            </thead>
            <tbody id="invTableBody">
              <tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1.5rem;">No Organization connected yet. Connect your target GCP Organization and run a scan to inspect live Accounts, Keys, KMS &amp; Secrets.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 3: ATTACK PATH TOPOLOGY (NETWORKX) -->
    <!-- ========================================================================= -->
    <div id="tab-graph" class="tab-panel">
      <div class="grid-stats">
        <div class="stat-card">
          <div class="stat-title">Graph Nodes</div>
          <div class="stat-value" id="graphNodesVal" style="color:#8AB4F8;">--</div>
          <div class="stat-desc">Principals, Workloads &amp; Resources</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Privilege Edges</div>
          <div class="stat-value" id="graphEdgesVal" style="color:var(--text-main);">--</div>
          <div class="stat-desc">Directed IAM &amp; Impersonation Grants</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Escalation Paths</div>
          <div class="stat-value" id="graphPathsVal" style="color:var(--danger);">--</div>
          <div class="stat-desc">Multi-hop &amp; High-Blast Chains</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Toxic Combinations</div>
          <div class="stat-value" id="graphToxicVal" style="color:var(--warning);">--</div>
          <div class="stat-desc">Impersonation / Default SA Risks</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>NetworkX IAM Privilege &amp; Escalation Topology</span>
          <span class="tag tag-gcp" id="graphChainsBadge">Awaiting Scan</span>
        </div>
        <div style="background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:18px; display:flex; justify-content:center; align-items:center; min-height:140px;">
          <div id="attackGraphPlaceholder" style="color:var(--text-muted); font-size:0.83rem; text-align:center;">Connect a target GCP Organization and run an ADK scan to render the live NetworkX privilege topology.</div>
          <img id="attackGraphImg" src="" alt="Live NetworkX IAM Attack Path Graph" style="display:none; max-width:100%; max-height:460px; object-fit:contain;"/>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Critical Privilege Escalation &amp; Lateral Movement Chains</span>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Path ID</th>
                <th>Vector &amp; Blast Radius</th>
                <th>Hop Chain</th>
                <th>Mitigation Control</th>
              </tr>
            </thead>
            <tbody id="attackPathsTableBody">
              <tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:1.5rem;">No topology loaded yet. Connect a target Organization and click Run ADK Scan.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 4: LEAST-PRIVILEGE & TERRAFORM REMEDIATION -->
    <!-- ========================================================================= -->
    <div id="tab-iac" class="tab-panel">
      <div class="card">
        <div class="card-title">
          <span>Least-Privilege Role &amp; PAM JIT Recommendations</span>
          <span id="recsCountBadge" class="tag tag-gcp">Awaiting Scan</span>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>ID &amp; Persona</th>
                <th>Principal</th>
                <th>Current Role</th>
                <th>Proposed Role / PAM JIT</th>
                <th>Perm Reduction</th>
              </tr>
            </thead>
            <tbody id="recsTableBody">
              <tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1.5rem;">Connect a target GCP Organization and run an ADK scan to synthesize IAM Recommender &amp; Audit Log findings.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Consultative Terraform Draft (Unvalidated) — Review Before Applying</span>
          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
            <span id="iacBundleBadge" class="mono" style="color:var(--text-muted);">—</span>
            <button type="button" class="btn btn-secondary" onclick="copyCurrentHcl()">Copy HCL</button>
            <a id="dlZip" href="#" onclick="return guardDownloadLink(event)" class="btn">Download Bundle (.zip)</a>
          </div>
        </div>

        <div class="domain-select" id="tfFileTabs">
          <button type="button" class="domain-btn active" data-tf="iam_tf" onclick="selectTfFile('iam_tf')">iam.tf</button>
          <button type="button" class="domain-btn" data-tf="pam_entitlements_tf" onclick="selectTfFile('pam_entitlements_tf')">pam_entitlements.tf</button>
          <button type="button" class="domain-btn" data-tf="org_policies_tf" onclick="selectTfFile('org_policies_tf')">org_policies.tf</button>
          <button type="button" class="domain-btn" data-tf="main_tf" onclick="selectTfFile('main_tf')">main.tf</button>
          <button type="button" class="domain-btn" data-tf="variables_tf" onclick="selectTfFile('variables_tf')">variables.tf</button>
          <button type="button" class="domain-btn" data-tf="manual_steps_md" onclick="selectTfFile('manual_steps_md')">MANUAL_STEPS.md</button>
        </div>

        <pre id="iacCodePreview" class="code-box">Connect a target GCP Organization and run an ADK scan to synthesize Terraform / OpenTofu remediation code...</pre>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 5: ADK COPILOT -->
    <!-- ========================================================================= -->
    <div id="tab-copilot" class="tab-panel">
      <div class="card">
        <div class="card-title">
          <span>Google ADK Multi-Agent Coordinator (iam_coordinator)</span>
          <span class="tag tag-gcp">Vertex AI • global</span>
        </div>
        <p style="color:var(--text-muted); font-size:0.83rem; margin-bottom:1rem;">
          Query live IAM bindings, Organization Policy guardrails, NetworkX attack paths, PAM JIT candidates, and Terraform remediations strictly over your connected target session.
        </p>

        <div style="display:flex; gap:8px; margin-bottom:1rem; flex-wrap:wrap;">
          <input id="agentPrompt" type="text" class="prompt-input" style="flex:1; min-width:260px;"
            value="Analyze the live IAM bindings, Organization Policy posture, NetworkX escalation paths, and PAM JIT / Terraform remediations for this scope." />
          <button type="button" class="btn" id="runBtn" onclick="runAdkChat()" style="height:38px; padding:0 18px;" disabled>Ask ADK Coordinator</button>
        </div>

        <pre id="agentOutput" class="code-box" style="color:var(--text-main);">Connect a target GCP Organization first in "Connect &amp; Onboard Org", then ask iam_coordinator any question or run a full 5-plane posture scan.</pre>
      </div>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 6: OFFICIAL EXECUTIVE REPORT -->
    <!-- ========================================================================= -->
    <div id="tab-report" class="tab-panel">
      <div class="card no-print">
        <div class="card-title">
          <span>Complete Executive IAM, Accounts, Keys &amp; Secrets Deliverable</span>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <a id="dlDocx" href="#" onclick="return guardDownloadLink(event)" class="btn">Download Full Word (.docx)</a>
            <a id="dlPdf" href="#" onclick="return guardDownloadLink(event)" class="btn btn-secondary">Download Full PDF (.pdf)</a>
            <a id="dlInvJsonReport" href="#" onclick="return guardDownloadLink(event)" class="btn btn-secondary">Inventory (.json)</a>
            <button type="button" class="btn btn-secondary" onclick="window.print()">Print / Save A4</button>
          </div>
        </div>
        <p style="color:var(--text-muted); font-size:0.83rem;">
          Complete 7-section executive &amp; technical deliverable (Scorecard, 18-Control Framework Matrix, Identity Triad, Full Accounts/Keys/Secrets/KMS/API-Key/WIF Inventory, NetworkX Attack Graph &amp; Centrality, PAM/Least-Privilege, All 5 Terraform HCL Modules &amp; 3-Wave Roadmap).
        </p>
      </div>

      <div class="gcp-report-wrapper">
        <div class="report-cover-page">
          <div class="gcp-accent-bar">
            <div class="gcp-blue"></div>
            <div class="gcp-red"></div>
            <div class="gcp-yellow"></div>
            <div class="gcp-green"></div>
          </div>

          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.25rem; flex-wrap:wrap; gap:8px;">
            <div class="cover-org">GOOGLE CLOUD SECURITY CONSULTING | COMPLETE EXECUTIVE &amp; VAULT BOOK</div>
            <span class="tag tag-high">CONFIDENTIAL / ADVISORY</span>
          </div>

          <div class="cover-title">IAM Posture, Accounts, Keys, Secrets &amp; Least-Privilege Book</div>
          <div class="cover-subtitle">
            18-Control Framework Assessment (GCB / NIST 800-53r5 / NIST CSF 2.0 / CIS GCP v3.0 / CISA ZTMM v2.0), Credential &amp; Secret Vault Inventory, NetworkX Attack Paths &amp; Advisory Terraform
          </div>

          <div class="report-meta-grid">
            <div class="meta-item">
              <strong>Organization Domain</strong>
              <span id="reportMetaDomain">—</span>
            </div>
            <div class="meta-item">
              <strong>Evaluated Scope</strong>
              <span id="reportMetaScope" class="mono">—</span>
            </div>
            <div class="meta-item">
              <strong>ADK Model (Vertex AI Global)</strong>
              <span id="reportMetaModel" class="mono">__ACTIVE_MODEL__</span>
            </div>
            <div class="meta-item">
              <strong>Generated Timestamp</strong>
              <span id="reportMetaDate">—</span>
            </div>
          </div>
        </div>

        <div class="chapter-h2">1. Executive Summary &amp; CISO Narrative</div>
        <div id="reportExecutiveNarrative" style="font-size:0.86rem; white-space:pre-wrap; color:var(--text-main); line-height:1.7;">
          Connect a target GCP Organization and run an ADK scan to generate the complete 7-section Executive Deliverable.
        </div>

        <div id="reportFullSectionsPreview" style="margin-top:1.5rem;"></div>
      </div>
    </div>

  </main>

  <!-- Slide-Over Finding Inspector Drawer (AISPR Pattern) -->
  <div class="drawer-overlay" id="drawerOverlay" onclick="closeInspectorDrawer()"></div>
  <div class="drawer-panel" id="drawerPanel">
    <div class="drawer-header">
      <div>
        <div class="drawer-title" id="drawerTitle">Finding Details</div>
        <div style="display:flex; gap:6px; margin-top:6px;">
          <span class="tag tag-gcp" id="drawerIdBadge">IAM-001</span>
          <span class="tag tag-high" id="drawerSevBadge">HIGH</span>
        </div>
      </div>
      <button type="button" class="drawer-close" onclick="closeInspectorDrawer()">&times;</button>
    </div>

    <div class="drawer-section">
      <div class="drawer-section-title">Principal &amp; Resource Binding</div>
      <table class="drawer-meta-table">
        <tr><td>Pillar:</td><td id="drawerPillar">—</td></tr>
        <tr><td>Principal:</td><td id="drawerPrincipal" class="mono">—</td></tr>
        <tr><td>IAM Role:</td><td id="drawerRole" class="mono">—</td></tr>
        <tr><td>Resource:</td><td id="drawerResource" class="mono" style="word-break:break-all;">—</td></tr>
        <tr><td>Risk Vector:</td><td id="drawerVector">—</td></tr>
        <tr><td>Remediation Wave:</td><td id="drawerWave">—</td></tr>
        <tr><td>Frameworks:</td><td id="drawerFrameworks" style="font-size:0.76rem; color:#8AB4F8;">—</td></tr>
      </table>
    </div>

    <div class="drawer-section">
      <div class="drawer-section-title">Live Telemetry Evidence</div>
      <p id="drawerEvidence" style="font-size:0.82rem; color:var(--text-muted); line-height:1.55;"></p>
    </div>

    <div class="drawer-section" style="background:var(--surface-variant); padding:1rem; border-radius:6px; border:1px solid var(--border);">
      <div class="drawer-section-title">Recommended Least-Privilege Playbook</div>
      <p id="drawerRemediation" style="font-size:0.82rem; color:var(--text-main); line-height:1.55;"></p>
    </div>
  </div>

  <footer class="footer">
    Agentic IAM Accelerator v2.2 | Google Cloud Security Consulting | Zero-Trust Per-User Encrypted Persistence | Google ADK &amp; Vertex AI (global)
  </footer>

  <!-- Floating Accessible KPI Calculation Rationale Popover -->
  <div id="kpiRationalePopover" class="kpi-rationale-popover" role="tooltip" aria-hidden="true"></div>

  <script>
    let latestBook = null;
    let latestInventory = null;
    let scanHistory = [];
    let currentPillarFilter = 'ALL';
    let currentControlFilter = 'ALL';
    let currentInvSubTab = 'accounts';
    let currentTfKey = 'iam_tf';

    // Standardized Single Recommended Engine (Vertex AI Global)
    const STANDARDIZED_MODEL = __ACTIVE_MODEL_JSON__;
    const DELEGATION_SA_EMAIL = __DELEGATION_SA_JSON__;
    // Auto-renew is emitted only when the deployment enabled it AND the consultant ticked the explicit option
    function autoRenewRequested() {
      return !!DELEGATION_SA_EMAIL && !!document.getElementById('obAutoRenew')?.checked;
    }
    let isAuthenticatedUser = __IS_AUTH_JSON__;

    // Isolated Per-User Persistent Workspace State
    let sessionConnected = false;
    let liveTokenValid = false;
    let persistentDelegation = false;
    let hasSigninOAuthToken = false;
    let activeOrgId = '';
    let activeOrgDomain = '';
    let orgProjects = [];
    let projectScopeMode = 'SELECTED'; // 'ORG_ALL' | 'SELECTED'
    let selectedProjectIds = new Set();
    let _prefSaveTimer = null;

    // Customer Onboarding Kit State
    let latestOnboardingKit = null;
    let currentOnboardingTab = 'bash_script';
    let lastVerifiedOrgData = null;

    function escHtml(s) {
      return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function scoreColor(score) {
      const v = Number(score || 0);
      if (v >= 75) return '#2B8A3E';
      if (v >= 50) return '#F59F00';
      return '#E03131';
    }

    function scoreTextColor(score) {
      const v = Number(score || 0);
      if (v >= 75) return '#8CE99A';
      if (v >= 50) return '#FFD43B';
      return '#FFA8A8';
    }

    function sevTagClass(sev) {
      const s = String(sev || '').toUpperCase();
      if (s === 'CRITICAL' || s === 'HIGH') return 'tag-high';
      if (s === 'MEDIUM') return 'tag-med';
      return 'tag-low';
    }

    function showTab(tabName) {
      document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      const panel = document.getElementById('tab-' + tabName);
      if (panel) panel.classList.add('active');
      const btn = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
      if (btn) btn.classList.add('active');
      try { localStorage.setItem('agentic_iam_active_tab', tabName); } catch (e) {}
      if (tabName === 'inventory' && sessionConnected && !latestInventory) {
        refreshVaultInventoryOnly(false);
      }
    }

    function openTriadPillar(pillar) {
      showTab('triad');
      filterTriadTable(pillar);
    }

    function filterFindingsBySeverity(group) {
      showTab('triad');
      filterTriadTable('ALL', group);
    }

    function computeCanonicalScope() {
      const orgClean = String(activeOrgId || '').trim();
      if (!sessionConnected || !orgClean) {
        return '';
      }
      if (projectScopeMode === 'ORG_ALL') {
        return `organizations/${orgClean}`;
      }
      const chosen = Array.from(selectedProjectIds).sort();
      if (chosen.length === 0) {
        return `organizations/${orgClean}`;
      }
      return `organizations/${orgClean}/projects:${chosen.join(',')}`;
    }

    function currentScope() {
      const computed = computeCanonicalScope();
      const inp = document.getElementById('scopeInput');
      if (inp) inp.value = computed;
      return computed;
    }

    function currentModel() {
      return STANDARDIZED_MODEL;
    }

    function guardDownloadLink(ev) {
      if (!sessionConnected || !currentScope()) {
        if (ev) ev.preventDefault();
        showTab('onboarding');
        showConnFeedback('Connect a target GCP Organization first before downloading session deliverables.', true);
        return false;
      }
      return true;
    }

    function copyGcloudTokenCmd() {
      const cmd = 'gcloud auth print-access-token';
      if (navigator.clipboard) {
        navigator.clipboard.writeText(cmd);
      }
      const btn = document.getElementById('copyTokCmdBtn');
      if (btn) {
        const prev = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => { btn.innerText = prev; }, 1800);
      }
    }

    function updateTokenStatusHint() {
      const el = document.getElementById('connTokenStatus');
      if (!el) return;
      if (persistentDelegation && liveTokenValid) {
        el.innerText = 'Persistent Auto-Renew Active (leave blank to reuse indefinitely)';
        el.style.color = '#8CE99A';
      } else if (hasSigninOAuthToken && liveTokenValid) {
        el.innerText = 'Encrypted OAuth token active in persistent workspace (leave blank to reuse)';
        el.style.color = '#8CE99A';
      } else if (sessionConnected && !liveTokenValid) {
        el.innerText = 'Pinned scan intact — paste fresh token to run a new live scan';
        el.style.color = '#FFD43B';
      } else if (hasSigninOAuthToken) {
        el.innerText = 'OAuth token captured at sign-in (leave blank to reuse)';
        el.style.color = '#8CE99A';
      } else {
        el.innerText = 'Run: gcloud auth print-access-token';
        el.style.color = 'var(--text-subtle)';
      }
    }

    function buildInlineSaGuidePayloads() {
      const rawSa = (document.getElementById('connTargetSa')?.value || '').trim();
      const rawOrg = (document.getElementById('connOrgId')?.value || '').trim().replace(/^organizations\//, '');
      const callerTxt = (document.getElementById('callerBadgeText')?.innerText || '').trim();

      let saName = 'sa-iam-assessor';
      let customSeedProj = '';
      const saMatch = rawSa.match(/^([a-z0-9-]+)@([a-z0-9-]+)\.iam\.gserviceaccount\.com$/i);
      if (saMatch) {
        saName = saMatch[1];
        customSeedProj = saMatch[2];
      }

      const customOrgId = /^\d+$/.test(rawOrg) ? rawOrg : '';

      const seedDetectStep = customSeedProj
        ? `SEED_PROJECT_ID="${customSeedProj}"`
        : 'SEED_PROJECT_ID="${DEVSHELL_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}" && { [ -n "$SEED_PROJECT_ID" ] && [ "$SEED_PROJECT_ID" != "(unset)" ] || SEED_PROJECT_ID=$(gcloud projects list --filter="lifecycleState:ACTIVE" --limit=1 --format="value(projectId)"); } && [ -n "$SEED_PROJECT_ID" ]';

      const authUserStep = (callerTxt && callerTxt.includes('@'))
        ? `AUTHORIZED_USER_EMAIL="${callerTxt}"`
        : 'AUTHORIZED_USER_EMAIL="$(gcloud config get-value account 2>/dev/null)" && [ -n "$AUTHORIZED_USER_EMAIL" ]';

      const orgDetectStep = customOrgId
        ? `ORG_ID="${customOrgId}"`
        : 'ORG_ID=$(gcloud projects get-ancestors "${SEED_PROJECT_ID}" --format="value(type,id)" 2>/dev/null | awk \'$1=="organization"{print $2}\') && { [ -n "$ORG_ID" ] || ORG_ID=$(gcloud organizations list --limit=1 --format="value(ID)"); } && [ -n "$ORG_ID" ]';

      const oneLiner = [
        seedDetectStep,
        authUserStep,
        `SA_NAME="${saName}"`,
        'SA_EMAIL="${SA_NAME}@${SEED_PROJECT_ID}.iam.gserviceaccount.com"',
        'echo "[1/5] Enabling read-only APIs on ${SEED_PROJECT_ID}..."',
        'gcloud services enable cloudasset.googleapis.com cloudresourcemanager.googleapis.com iam.googleapis.com iamcredentials.googleapis.com orgpolicy.googleapis.com recommender.googleapis.com policyanalyzer.googleapis.com policysimulator.googleapis.com logging.googleapis.com --project="${SEED_PROJECT_ID}"',
        orgDetectStep,
        'echo "[2/5] Creating ${SA_EMAIL} (Org: ${ORG_ID})..."',
        '(gcloud iam service-accounts describe "${SA_EMAIL}" --project="${SEED_PROJECT_ID}" >/dev/null 2>&1 || (gcloud iam service-accounts create "${SA_NAME}" --display-name="Agentic IAM Read-Only Assessor" --project="${SEED_PROJECT_ID}" && sleep 5))',
        'echo "[3/5] Granting quota consumer on ${SEED_PROJECT_ID}..."',
        'gcloud projects add-iam-policy-binding "${SEED_PROJECT_ID}" --member="serviceAccount:${SA_EMAIL}" --role="roles/serviceusage.serviceUsageConsumer" --condition=None --quiet >/dev/null',
        (autoRenewRequested()
          ? 'echo "[4/5] Authorizing user:${AUTHORIZED_USER_EMAIL} + persistent auto-renew delegation on ${SA_EMAIL}..."'
          : 'echo "[4/5] Authorizing user:${AUTHORIZED_USER_EMAIL} on ${SA_EMAIL}..."'),
        'gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" --project="${SEED_PROJECT_ID}" --member="user:${AUTHORIZED_USER_EMAIL}" --role="roles/iam.serviceAccountTokenCreator" --condition=None --quiet >/dev/null',
        ...(autoRenewRequested()
          ? [`(gcloud iam service-accounts add-iam-policy-binding "\${SA_EMAIL}" --project="\${SEED_PROJECT_ID}" --member="serviceAccount:${DELEGATION_SA_EMAIL}" --role="roles/iam.serviceAccountTokenCreator" --condition=None --quiet >/dev/null 2>&1 || true)`]
          : []),
        'echo "[5/5] Granting 6 read-only roles on organizations/${ORG_ID}..."',
        'for ROLE in roles/browser roles/cloudasset.viewer roles/iam.securityReviewer roles/orgpolicy.policyViewer roles/recommender.viewer roles/logging.viewer; do gcloud organizations add-iam-policy-binding "${ORG_ID}" --member="serviceAccount:${SA_EMAIL}" --role="${ROLE}" --condition=None --quiet >/dev/null; done',
        'echo "=== READY: Paste in Agentic IAM Console ==="',
        'echo "Service Account : ${SA_EMAIL}"',
        'echo "Organization ID : ${ORG_ID}"'
      ].join(' && ');

      const revokeOneLiner = [
        seedDetectStep,
        orgDetectStep,
        `SA_EMAIL="${saName}@\${SEED_PROJECT_ID}.iam.gserviceaccount.com"`,
        'for ROLE in roles/browser roles/cloudasset.viewer roles/iam.securityReviewer roles/orgpolicy.policyViewer roles/recommender.viewer roles/logging.viewer; do gcloud organizations remove-iam-policy-binding "${ORG_ID}" --member="serviceAccount:${SA_EMAIL}" --role="${ROLE}" --condition=None --quiet >/dev/null 2>&1 || true; done',
        'gcloud iam service-accounts delete "${SA_EMAIL}" --project="${SEED_PROJECT_ID}" --quiet',
        'echo "Revoked and deleted ${SA_EMAIL} from Org ${ORG_ID}."'
      ].join(' && ');

      return { oneLiner, revokeOneLiner };
    }

    function refreshInlineSaSetupGuide() {
      const prev = document.getElementById('saModalPreview');
      const revPrev = document.getElementById('saModalRevokePreview');
      const { oneLiner, revokeOneLiner } = buildInlineSaGuidePayloads();
      if (prev) prev.innerText = oneLiner;
      if (revPrev) revPrev.innerText = revokeOneLiner;
    }

    function openSaSetupModal() {
      refreshInlineSaSetupGuide();
      const modal = document.getElementById('saSetupModal');
      if (modal) modal.style.display = 'flex';
    }

    function closeSaSetupModal() {
      const modal = document.getElementById('saSetupModal');
      if (modal) modal.style.display = 'none';
    }

    function copyInlineSaGuide(kind, btnIdOverride) {
      const { oneLiner, revokeOneLiner } = buildInlineSaGuidePayloads();
      const text = kind === 'revoke' ? revokeOneLiner : oneLiner;
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text);
      }
      const btnId = btnIdOverride || (kind === 'revoke' ? 'modalCopySaRevokeBtn' : 'copySaFullGuideBtn');
      const btn = document.getElementById(btnId);
      if (btn) {
        const orig = btn.innerText;
        btn.innerText = 'Copied 1-Liner!';
        setTimeout(() => { btn.innerText = orig; }, 1800);
      }
    }

    function onConnectionModeChange() {
      const mode = document.getElementById('connMode')?.value || 'impersonated_sa';
      const saGroup = document.getElementById('connSaGroup');
      if (saGroup) {
        saGroup.style.display = mode === 'impersonated_sa' ? 'block' : 'none';
      }
      refreshInlineSaSetupGuide();
    }

    function showConnFeedback(msg, isError) {
      const box = document.getElementById('connFeedbackBox');
      if (!box) return;
      if (!msg) {
        box.style.display = 'none';
        box.innerText = '';
        return;
      }
      box.style.display = 'block';
      box.style.background = isError ? 'rgba(224,49,49,0.14)' : 'rgba(43,138,62,0.15)';
      box.style.border = isError ? '1px solid rgba(224,49,49,0.35)' : '1px solid rgba(43,138,62,0.45)';
      box.style.color = isError ? '#FFA8A8' : '#8CE99A';
      box.innerText = msg;
    }

    function setConnectedControlsEnabled(enabled) {
      sessionConnected = !!enabled;
      const orgSel = document.getElementById('orgSelector');
      const projBtn = document.getElementById('projPickerBtn');
      const assessBtn = document.getElementById('assessBtn');
      const runBtn = document.getElementById('runBtn');
      const discBtn = document.getElementById('disconnectSessionBtn');
      if (orgSel) orgSel.disabled = !enabled;
      if (projBtn) projBtn.disabled = !enabled;
      if (assessBtn) assessBtn.disabled = !enabled;
      if (runBtn) runBtn.disabled = !enabled;
      if (discBtn) discBtn.style.display = enabled ? 'inline-flex' : 'none';
    }

    function resetConsoleToCleanSlate() {
      latestBook = null;
      lastVerifiedOrgData = null;
      scanHistory = [];
      activeOrgId = '';
      activeOrgDomain = '';
      orgProjects = [];
      selectedProjectIds = new Set();
      setConnectedControlsEnabled(false);
      const pinSel = document.getElementById('pinnedScanSelector');
      if (pinSel) { pinSel.style.display = 'none'; pinSel.innerHTML = ''; }

      const orgSel = document.getElementById('orgSelector');
      if (orgSel) orgSel.innerHTML = '<option value="">Not connected — connect an Org below</option>';
      document.getElementById('projPickerLabel').innerText = 'Connect an Organization first';
      document.getElementById('projCanonicalPreview').innerText = 'Not connected';
      document.getElementById('projCheckList').innerHTML = '';
      document.getElementById('scopeInput').value = '';
      document.getElementById('headerScopeBadge').innerText = 'No Organization Connected';
      document.getElementById('assessmentStatusBadge').innerText = 'Clean-Slate (Disconnected)';
      document.getElementById('telTokens').innerText = '—';
      document.getElementById('telToolCalls').innerText = '—';
      document.getElementById('telLatency').innerText = '—';

      document.getElementById('obActivateBtn').style.display = 'none';
      document.getElementById('connSessionSummaryBadge').innerText = 'Session Disconnected — Zero Data Loaded';
      document.getElementById('obChecksTableBody').innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1.25rem;">Connect a target GCP Organization in <strong>Step 1</strong> above to execute the 6 live read-only pre-flight checks and discover active projects.</td></tr>';

      document.getElementById('kpiOverallScore').innerText = '--%';
      document.getElementById('kpiMaturityTier').innerText = 'Connect an Organization to begin';
      document.getElementById('kpiCompliantCount').innerText = '--';
      document.getElementById('kpiExcessPerms').innerText = '--%';
      document.getElementById('kpiCritHighCount').innerText = '--';
      document.getElementById('donutScopeLabel').innerText = 'No Organization Connected';
      document.getElementById('donutCenterScore').innerText = '--%';
      document.getElementById('legendCompliantCount').innerText = '--';
      document.getElementById('legendMedLowCount').innerText = '--';
      document.getElementById('legendCritHighCount').innerText = '--';
      document.getElementById('donutArcCompliant').setAttribute('stroke-dasharray', '0, 100');
      document.getElementById('donutArcMod').setAttribute('stroke-dasharray', '0, 100');
      document.getElementById('donutArcCrit').setAttribute('stroke-dasharray', '0, 100');

      ['kpiInternalScore', 'kpiExternalScore', 'kpiWorkloadScore', 'barResilienceVal', 'barLpiVal'].forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.innerText = '--%'; el.style.color = 'var(--text-muted)'; }
      });
      ['barInternal', 'barExternal', 'barWorkload', 'barResilience', 'barLpi'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.width = '0%';
      });

      document.getElementById('agenticCalibrationBanner').innerHTML = 'Run an ADK scan to evaluate all <strong>18 deterministic IAM controls</strong> (<code>22% Internal + 18% External + 22% Workload + 20% Least-Privilege + 18% Graph Resilience</code>) combined with bounded <code>[-5%, +5%]</code> Google ADK contextual calibration.';
      document.getElementById('frameworkBenchmarksGrid').innerHTML = '<div style="color:var(--text-muted); font-size:0.81rem;">Awaiting connected Organization scan to compute Google Cloud Blueprint, NIST SP 800-53r5, NIST CSF 2.0, CIS GCP v3.0, and CISA ZTMM v2.0 alignment...</div>';
      document.getElementById('frameworkControlsBody').innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1.25rem;">Connect a target GCP Organization and click <strong>Run ADK Scan</strong> to inspect all 18 mathematical control evaluations.</td></tr>';
      document.getElementById('dashboardFindingsGrid').innerHTML = '<div style="color:var(--text-muted); font-size:0.82rem;">No Organization connected yet. Connect your target GCP Organization in <strong>Connect &amp; Onboard Org</strong> and click <strong>Run ADK Scan</strong>.</div>';
      document.getElementById('findingsCountLabel').innerText = '0 findings';
      document.getElementById('findingsTableBody').innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1.5rem;">Connect a target GCP Organization and run an ADK scan to inspect live Cloud Asset Inventory findings.</td></tr>';

      document.getElementById('graphNodesVal').innerText = '--';
      document.getElementById('graphEdgesVal').innerText = '--';
      document.getElementById('graphPathsVal').innerText = '--';
      document.getElementById('graphToxicVal').innerText = '--';
      document.getElementById('graphChainsBadge').innerText = 'Awaiting Scan';
      const gImg = document.getElementById('attackGraphImg');
      const gPh = document.getElementById('attackGraphPlaceholder');
      if (gImg) { gImg.src = ''; gImg.style.display = 'none'; }
      if (gPh) gPh.style.display = 'block';
      document.getElementById('attackPathsTableBody').innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:1.5rem;">No topology loaded yet. Connect a target Organization and click Run ADK Scan.</td></tr>';

      document.getElementById('recsCountBadge').innerText = 'Awaiting Scan';
      document.getElementById('recsTableBody').innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1.5rem;">Connect a target GCP Organization and run an ADK scan to synthesize IAM Recommender &amp; Audit Log findings.</td></tr>';
      document.getElementById('iacBundleBadge').innerText = '—';
      document.getElementById('iacCodePreview').innerText = 'Connect a target GCP Organization and run an ADK scan to synthesize Terraform / OpenTofu remediation code...';

      latestInventory = null;
      ['invKpiAccounts', 'invKpiStandingAdmins', 'invKpiSas', 'invKpiSaKeys', 'invKpiSecrets', 'invKpiKms', 'invKpiApiKeys', 'invKpiCustomWif'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerText = '--';
      });
      document.getElementById('invLedgerCountLabel').innerHTML = 'Connect a target GCP Organization and click <strong>Run ADK Scan</strong> or <strong>Refresh Vault Inventory</strong>.';
      document.getElementById('invTableBody').innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1.5rem;">No Organization connected yet. Connect your target GCP Organization and run a scan to inspect live Accounts, Keys, KMS &amp; Secrets.</td></tr>';

      document.getElementById('agentOutput').innerText = 'Connect a target GCP Organization first in "Connect & Onboard Org", then ask iam_coordinator any question or run a full 5-plane posture scan.';
      document.getElementById('reportMetaDomain').innerText = '—';
      document.getElementById('reportMetaScope').innerText = '—';
      document.getElementById('reportMetaDate').innerText = '—';
      document.getElementById('reportExecutiveNarrative').innerText = 'Connect a target GCP Organization and run an ADK scan to generate the complete 7-section Executive Deliverable.';
      const rfp = document.getElementById('reportFullSectionsPreview');
      if (rfp) rfp.innerHTML = '';

      syncDownloadLinks();
      showTab('onboarding');
    }

    function updateProjectPickerSummary() {
      const scope = currentScope();
      const total = orgProjects.length;
      const chosen = Array.from(selectedProjectIds).sort();
      const labelEl = document.getElementById('projPickerLabel');
      const prevEl = document.getElementById('projCanonicalPreview');
      if (prevEl) prevEl.innerText = scope || 'Not connected';

      if (labelEl) {
        if (!sessionConnected || !scope) {
          labelEl.innerText = 'Connect an Organization first';
        } else if (projectScopeMode === 'ORG_ALL' || chosen.length === 0) {
          labelEl.innerText = total > 0 ? `Entire Organization (${total} active projects)` : 'Entire Organization (Org-Wide)';
        } else if (chosen.length === 1) {
          labelEl.innerText = `1 of ${total || 1} project: ${chosen[0]}`;
        } else if (total > 0 && chosen.length === total) {
          labelEl.innerText = `All ${total} projects selected`;
        } else {
          labelEl.innerText = `${chosen.length} of ${total || chosen.length} projects (${chosen[0]} +${chosen.length - 1})`;
        }
      }

      document.getElementById('modeBtnOrgAll').classList.toggle('active', projectScopeMode === 'ORG_ALL');
      document.getElementById('modeBtnSelected').classList.toggle('active', projectScopeMode !== 'ORG_ALL');
      const selArea = document.getElementById('projSelectionArea');
      if (selArea) selArea.style.opacity = projectScopeMode === 'ORG_ALL' ? '0.55' : '1';

      syncDownloadLinks();
    }

    function syncDownloadLinks() {
      const scope = currentScope();
      const model = currentModel();
      document.getElementById('headerScopeBadge').innerText = scope || 'No Organization Connected';
      if (!sessionConnected || !scope) {
        document.getElementById('dlDocx').href = '#';
        document.getElementById('dlPdf').href = '#';
        document.getElementById('dlZip').href = '#';
        const inv1 = document.getElementById('dlInvJsonBtn');
        const inv2 = document.getElementById('dlInvJsonReport');
        if (inv1) inv1.href = '#';
        if (inv2) inv2.href = '#';
        return;
      }
      const q = `?scope=${encodeURIComponent(scope)}&model=${encodeURIComponent(model)}`;
      document.getElementById('dlDocx').href = `/api/v1/download/docx${q}`;
      document.getElementById('dlPdf').href = `/api/v1/download/pdf${q}`;
      document.getElementById('dlZip').href = `/api/v1/download/terraform-zip${q}`;
      const invUrl = `/api/v1/download/inventory-json${q}`;
      const inv1 = document.getElementById('dlInvJsonBtn');
      const inv2 = document.getElementById('dlInvJsonReport');
      if (inv1) inv1.href = invUrl;
      if (inv2) inv2.href = invUrl;
    }

    function toggleProjPopover(ev) {
      if (!sessionConnected) return;
      if (ev) ev.stopPropagation();
      const pop = document.getElementById('projPickerPopover');
      const btn = document.getElementById('projPickerBtn');
      const isOpen = pop.classList.toggle('open');
      btn.classList.toggle('open', isOpen);
    }

    function closeProjPopover() {
      const pop = document.getElementById('projPickerPopover');
      const btn = document.getElementById('projPickerBtn');
      if (pop) pop.classList.remove('open');
      if (btn) btn.classList.remove('open');
    }

    function persistWorkspaceScopePrefs() {
      if (!sessionConnected) return;
      if (_prefSaveTimer) clearTimeout(_prefSaveTimer);
      _prefSaveTimer = setTimeout(() => {
        fetch('/api/v1/workspace/preferences', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
          body: JSON.stringify({
            selected_scope: currentScope(),
            project_scope_mode: projectScopeMode,
            selected_project_ids: Array.from(selectedProjectIds).sort()
          })
        }).catch(() => {});
      }, 300);
    }

    function applyScopeStringToPicker(scopeStr) {
      const s = String(scopeStr || '').trim();
      if (!s) return;
      const m = s.match(/^organizations\/(\d+)\/projects:(.+)$/i);
      if (m) {
        activeOrgId = m[1];
        projectScopeMode = 'SELECTED';
        selectedProjectIds = new Set(m[2].split(',').map(x => x.trim()).filter(Boolean));
      } else if (/^organizations\/\d+$/i.test(s)) {
        activeOrgId = s.split('/')[1];
        projectScopeMode = 'ORG_ALL';
      }
    }

    function renderPinnedScanSelector(scans, activeScope) {
      scanHistory = Array.isArray(scans) ? scans : [];
      const sel = document.getElementById('pinnedScanSelector');
      if (!sel) return;
      if (!sessionConnected || scanHistory.length === 0) {
        sel.style.display = 'none';
        sel.innerHTML = '';
        return;
      }
      sel.style.display = 'inline-block';
      sel.innerHTML = scanHistory.map(item => {
        const sc = item.scope || '';
        const score = item.overall_posture_score != null ? `${item.overall_posture_score}%` : '--%';
        const ts = (item.generated_at || item.pinned_at_iso || '').slice(0, 16).replace('T', ' ');
        const isSel = sc === activeScope ? 'selected' : '';
        return `<option value="${escHtml(sc)}" ${isSel}>Pinned: ${escHtml(sc)} (${score} • ${escHtml(ts)})</option>`;
      }).join('');
    }

    async function switchToPinnedScan(targetScope) {
      if (!sessionConnected || !targetScope) return;
      applyScopeStringToPicker(targetScope);
      renderProjectCheckboxes();
      updateProjectPickerSummary();
      persistWorkspaceScopePrefs();
      await loadLivePostureBook(false);
    }

    function setProjectScopeMode(mode) {
      projectScopeMode = mode;
      if (mode === 'SELECTED' && selectedProjectIds.size === 0 && orgProjects.length > 0) {
        selectedProjectIds.add(orgProjects[0].project_id);
      }
      renderProjectCheckboxes();
      updateProjectPickerSummary();
      persistWorkspaceScopePrefs();
    }

    function toggleProjectId(pid, checked) {
      projectScopeMode = 'SELECTED';
      if (checked) {
        selectedProjectIds.add(pid);
      } else {
        selectedProjectIds.delete(pid);
      }
      updateProjectPickerSummary();
      persistWorkspaceScopePrefs();
    }

    function selectAllProjects(selectAll) {
      projectScopeMode = 'SELECTED';
      selectedProjectIds.clear();
      if (selectAll) {
        orgProjects.forEach(p => selectedProjectIds.add(p.project_id));
      }
      renderProjectCheckboxes();
      updateProjectPickerSummary();
      persistWorkspaceScopePrefs();
    }

    function renderProjectCheckboxes() {
      const box = document.getElementById('projCheckList');
      if (!box) return;
      if (!box.dataset.listenerBound) {
        box.dataset.listenerBound = '1';
        box.addEventListener('change', (ev) => {
          const cb = ev.target && ev.target.closest ? ev.target.closest('input.proj-checkbox') : null;
          if (cb) {
            toggleProjectId(cb.dataset.projectId || '', cb.checked);
          }
        });
      }
      const q = (document.getElementById('projSearchInput')?.value || '').trim().toLowerCase();
      const filtered = orgProjects.filter(p =>
        !q ||
        p.project_id.toLowerCase().includes(q) ||
        (p.display_name || '').toLowerCase().includes(q)
      );
      if (filtered.length === 0) {
        box.innerHTML = '<div style="padding:10px; font-size:0.76rem; color:var(--text-muted); text-align:center;">No active projects match the current filter.</div>';
        return;
      }
      box.innerHTML = filtered.map(p => {
        const checked = projectScopeMode === 'ORG_ALL' || selectedProjectIds.has(p.project_id) ? 'checked' : '';
        return `<label class="proj-item-row">
          <span class="proj-item-left">
            <input type="checkbox" class="proj-checkbox" data-project-id="${escHtml(p.project_id)}" ${checked} />
            <span class="proj-item-name" title="${escHtml(p.display_name)}">${escHtml(p.display_name)}</span>
          </span>
          <span class="proj-item-id">${escHtml(p.project_id)}</span>
        </label>`;
      }).join('');
    }

    function applyProjectSelectionAndScan() {
      closeProjPopover();
      persistWorkspaceScopePrefs();
      loadLivePostureBook(true);
    }

    function applyOrgHierarchyData(data, targetOrgFallback) {
      if (!data) return;
      activeOrgId = data.organization_id || targetOrgFallback || activeOrgId;
      if (data.organization_display_name) {
        activeOrgDomain = data.organization_display_name;
      }
      orgProjects = data.projects || [];

      const orgSel = document.getElementById('orgSelector');
      const orgs = data.accessible_organizations || [];
      if (orgSel && orgs.length > 0) {
        orgSel.innerHTML = orgs.map(o => {
          const sel = o.organization_id === activeOrgId ? 'selected' : '';
          return `<option value="${escHtml(o.organization_id)}" ${sel}>organizations/${escHtml(o.organization_id)} (${escHtml(o.display_name)})</option>`;
        }).join('');
      } else if (orgSel && activeOrgId) {
        orgSel.innerHTML = `<option value="${escHtml(activeOrgId)}" selected>organizations/${escHtml(activeOrgId)}</option>`;
      }

      const validSet = new Set(orgProjects.map(p => p.project_id));
      const nextSelected = new Set();
      selectedProjectIds.forEach(pid => {
        if (validSet.has(pid)) nextSelected.add(pid);
      });
      if (projectScopeMode !== 'ORG_ALL' && nextSelected.size === 0 && orgProjects.length > 0) {
        nextSelected.add(orgProjects[0].project_id);
      }
      selectedProjectIds = nextSelected;

      renderProjectCheckboxes();
      updateProjectPickerSummary();
    }

    async function loadOrgHierarchy(orgIdOverride, forceRefresh = false) {
      if (!sessionConnected) return;
      const targetOrg = orgIdOverride || document.getElementById('orgSelector')?.value || activeOrgId;
      try {
        const params = new URLSearchParams();
        if (targetOrg) params.set('organization_id', targetOrg);
        if (forceRefresh) params.set('refresh', 'true');
        const qs = params.toString() ? `?${params.toString()}` : '';
        const res = await fetch(`/api/v1/org/hierarchy${qs}`);
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        applyOrgHierarchyData(data, targetOrg);
      } catch (err) {
        const lbl = document.getElementById('projPickerLabel');
        if (lbl) lbl.innerText = 'Error loading Organization projects';
      }
    }

    async function onOrgChange() {
      const chosenOrg = document.getElementById('orgSelector').value;
      selectedProjectIds.clear();
      await loadOrgHierarchy(chosenOrg, true);
      persistWorkspaceScopePrefs();
    }

    function renderReadinessChecksTable(checks) {
      const tbody = document.getElementById('obChecksTableBody');
      if (!tbody) return;
      if (!checks || checks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1.25rem;">No pre-flight probe checks returned.</td></tr>';
        return;
      }
      tbody.innerHTML = checks.map(c => {
        const cls = c.status === 'PASS' ? 'tag-low' : (c.status === 'WARN' ? 'tag-med' : 'tag-high');
        const remHtml = c.remediation
          ? `<div class="mono" style="margin-top:4px; font-size:0.7rem; color:#FFA8A8; word-break:break-all;">Fix: ${escHtml(c.remediation)}</div>`
          : '';
        return `<tr>
          <td><span class="tag ${cls}">${escHtml(c.status)}</span></td>
          <td style="font-weight:600; color:var(--text-main);">${escHtml(c.title)}</td>
          <td class="mono" style="color:#8AB4F8;">${escHtml(c.required_role)}</td>
          <td class="mono">${c.latency_ms} ms (HTTP ${c.http_status})</td>
          <td style="color:var(--text-muted);">${escHtml(c.detail)}${remHtml}</td>
        </tr>`;
      }).join('');
    }

    function updatePersistenceStatusBadges(sess) {
      if (!sess || !sess.connected) return;
      liveTokenValid = !!sess.live_token_valid;
      persistentDelegation = !!sess.persistent_sa_delegation;
      const retDays = Number(sess.workspace_retention_days);
      const backendLbl = sess.workspace_persisted === false
        ? 'Not persisted (session only)'
        : `${sess.persistence_backend === 'GCS_ENCRYPTED_WORKSPACE' ? 'GCS Encrypted' : 'Local Encrypted'}${Number.isFinite(retDays) ? ` • ${retDays}d retention` : ''}`;
      const renewLbl = persistentDelegation
        ? 'Auto-Renew Active'
        : (liveTokenValid ? 'Live Token Active' : 'Pinned Read-Only (Refresh Token to Re-Scan)');
      const summaryEl = document.getElementById('connSessionSummaryBadge');
      if (summaryEl) {
        summaryEl.innerText = `Connected (${sess.effective_identity || sess.connection_mode}) • ${backendLbl} • ${renewLbl}`;
        summaryEl.className = liveTokenValid ? 'tag tag-low' : 'tag tag-med';
      }
      const persistBadge = document.getElementById('connPersistenceBadge');
      if (persistBadge) {
        persistBadge.innerText = persistentDelegation
          ? `Persistent Auto-Renew (${backendLbl})`
          : (liveTokenValid ? `Persistent Workspace (${backendLbl})` : 'Pinned Data Fixed • Token Expired');
        persistBadge.className = liveTokenValid ? 'tag tag-low' : 'tag tag-med';
      }
      const statusBadge = document.getElementById('assessmentStatusBadge');
      if (statusBadge) {
        if (sess.has_pinned_book && sess.pinned_generated_at) {
          const ts = sess.pinned_generated_at.slice(0, 16).replace('T', ' ');
          statusBadge.innerText = liveTokenValid
            ? `Pinned & Live (${ts} UTC)`
            : `Pinned Scan Fixed (${ts} UTC • Refresh Token to Re-Scan)`;
          statusBadge.style.color = liveTokenValid ? '#8CE99A' : '#FFD43B';
        } else {
          statusBadge.innerText = activeOrgId ? `Connected: organizations/${activeOrgId}` : 'Connected';
          statusBadge.style.color = liveTokenValid ? '#8CE99A' : '#FFD43B';
        }
      }
      updateBigQueryStatusUI(sess);
      updateTokenStatusHint();
    }

    function updateBigQueryStatusUI(sess) {
      const badge = document.getElementById('bqExportStatusBadge');
      const tel = document.getElementById('bqTelemetryStatus');
      const bq = sess && sess.bigquery_export_status ? sess.bigquery_export_status : null;
      const tbl = sess && sess.optional_customer_bq_table ? sess.optional_customer_bq_table : '';

      let label = 'BigQuery Export: Ephemeral Session Only (no customer table configured)';
      let color = 'var(--text-subtle)';
      let showTel = false;

      if (bq && bq.status === 'EXPORTED_TO_CUSTOMER_BIGQUERY') {
        label = `BigQuery Export: Exported ${bq.rows_inserted || 0} row(s) to ${bq.customer_table_id || tbl}`;
        color = '#8CE99A';
        showTel = true;
      } else if (bq && bq.status && bq.status !== 'EPHEMERAL_SESSION_ONLY' && bq.status !== 'SKIPPED_PINNED_SNAPSHOT') {
        label = `BigQuery Export: ${bq.status}${bq.customer_table_id ? ' (' + bq.customer_table_id + ')' : ''}`;
        color = '#FFA8A8';
        showTel = true;
      } else if (tbl) {
        label = `BigQuery Export: Configured (${tbl}) — pending next scan/export`;
        color = '#8AB4F8';
        showTel = true;
      }

      if (badge) {
        badge.innerText = label;
        badge.style.color = color;
      }
      if (tel) {
        tel.innerText = label;
        tel.style.color = color;
        tel.style.display = showTel ? 'inline' : 'none';
      }
    }

    async function connectTargetSession() {
      if (!isAuthenticatedUser) {
        document.getElementById('iapAuthGate').style.display = 'flex';
        return;
      }
      const mode = document.getElementById('connMode')?.value || 'impersonated_sa';
      const targetSa = (document.getElementById('connTargetSa')?.value || '').trim();
      const orgId = (document.getElementById('connOrgId')?.value || '').trim();
      const custName = (document.getElementById('connCustomerName')?.value || '').trim();
      const userTok = (document.getElementById('connUserToken')?.value || '').trim();
      const bqTable = (document.getElementById('connBqTable')?.value || '').trim();
      const retentionRaw = parseInt(document.getElementById('connRetentionDays')?.value || '', 10);
      const retentionDays = Number.isFinite(retentionRaw) ? retentionRaw : null;

      const cleanOrgId = orgId.replace(/^organizations\//, '').trim();
      if (cleanOrgId && !/^\d+$/.test(cleanOrgId)) {
        showConnFeedback('Target GCP Organization ID must contain digits only (e.g., 123456789012) or be left blank for auto-discovery.', true);
        return;
      }

      if (mode === 'impersonated_sa' && (!targetSa || !targetSa.endsWith('.iam.gserviceaccount.com'))) {
        showConnFeedback('Enter a valid Service Account email ending in .iam.gserviceaccount.com (e.g., sa-iam-assessor@seed-project.iam.gserviceaccount.com). Use the gcloud commands above to create it.', true);
        return;
      }

      const btn = document.getElementById('connConnectBtn');
      const actBtn = document.getElementById('obActivateBtn');
      const tbody = document.getElementById('obChecksTableBody');
      showConnFeedback('', false);
      btn.disabled = true;
      btn.innerText = mode === 'impersonated_sa' ? 'Impersonating SA & Persisting Workspace...' : 'Connecting & Persisting Workspace...';
      actBtn.style.display = 'none';
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1.25rem;">Validating target credentials and executing 6 live read-only GCP probes...</td></tr>';

      try {
        const res = await fetch('/api/v1/session/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
          body: JSON.stringify({
            connection_mode: mode,
            user_access_token: userTok || null,
            target_sa_email: targetSa,
            organization_id: orgId,
            customer_name: custName,
            optional_customer_bq_table: bqTable,
            workspace_retention_days: retentionDays
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

        const tokInput = document.getElementById('connUserToken');
        if (tokInput) tokInput.value = '';
        hasSigninOAuthToken = true;

        const sess = data.session || {};
        const rd = data.readiness || {};
        lastVerifiedOrgData = rd;
        renderReadinessChecksTable(rd.checks || []);

        activeOrgId = rd.organization_id || sess.organization_id || orgId;
        activeOrgDomain = rd.organization_display_name || sess.organization_domain || '';
        setConnectedControlsEnabled(true);
        updatePersistenceStatusBadges(sess);

        if (data.org_hierarchy) {
          applyOrgHierarchyData(data.org_hierarchy, activeOrgId);
        } else {
          await loadOrgHierarchy(activeOrgId, true);
        }
        persistWorkspaceScopePrefs();

        if (rd.ready_for_scan) {
          const autoMsg = sess.persistent_sa_delegation
            ? ' Persistent Auto-Renew delegation is ACTIVE — your live connection and pinned scans will persist across browser closes and restarts.'
            : ' Connection & pinned scans are persisted in your encrypted workspace across page closes.';
          showConnFeedback(`Connected to organizations/${activeOrgId} (${rd.active_projects_count || 0} active projects discovered).${autoMsg}`, false);
          actBtn.style.display = 'inline-flex';
          actBtn.innerText = `Select Projects & Scan organizations/${activeOrgId} (${rd.active_projects_count || 0} projects) →`;
        } else {
          showConnFeedback('Workspace connected and persisted, but one or more mandatory read-only roles returned FAIL in the readiness table below.', true);
        }
      } catch (err) {
        showConnFeedback(err.message || String(err), true);
        tbody.innerHTML = `<tr><td colspan="5" style="color:#FFA8A8; padding:1.25rem;">Connection / Impersonation failed: ${escHtml(err.message)}</td></tr>`;
      } finally {
        btn.disabled = false;
        btn.innerText = 'Connect, Impersonate & Persist Workspace';
      }
    }

    async function disconnectTargetSession() {
      const ok = window.confirm(
        'Disconnect and permanently wipe your saved Organization connection, encrypted session tokens, and all pinned scan snapshots/reports from your workspace?'
      );
      if (!ok) return;
      try {
        await fetch('/api/v1/session/disconnect', {
          method: 'POST',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
      } catch (e) {}
      hasSigninOAuthToken = false;
      liveTokenValid = false;
      persistentDelegation = false;
      scanHistory = [];
      try { localStorage.removeItem('agentic_iam_active_tab'); } catch (e) {}
      updateTokenStatusHint();
      resetConsoleToCleanSlate();
      showConnFeedback('Saved workspace disconnected and wiped cleanly. Zero connection credentials or pinned scans remain.', false);
    }

    async function logoutAndWipeAll() {
      const wipe = window.confirm('Sign out AND wipe your saved connection & pinned scans? Click Cancel to sign out while keeping your pinned workspace data.');
      try {
        await fetch(`/api/v1/auth/logout?wipe_workspace_data=${wipe ? 'true' : 'false'}`, {
          method: 'POST',
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
      } catch (e) {}
      isAuthenticatedUser = false;
      hasSigninOAuthToken = false;
      liveTokenValid = false;
      persistentDelegation = false;
      updateTokenStatusHint();
      document.getElementById('callerBadgeText').innerText = 'unauthenticated';
      resetConsoleToCleanSlate();
      document.getElementById('iapAuthGate').style.display = 'flex';
    }

    async function checkInitialSessionStatus() {
      if (!isAuthenticatedUser) {
        resetConsoleToCleanSlate();
        return;
      }
      try {
        const res = await fetch('/api/v1/workspace/restore');
        if (!res.ok) {
          resetConsoleToCleanSlate();
          return;
        }
        const ws = await res.json();
        const st = ws.session || {};
        hasSigninOAuthToken = !!ws.has_signin_oauth_token;

        const obEmail = document.getElementById('obUserEmail');
        if (obEmail && !obEmail.value && ws.caller_email && ws.caller_email !== 'unauthenticated') {
          obEmail.value = ws.caller_email;
        }

        if (ws.connected && st.connected) {
          activeOrgId = st.organization_id || '';
          activeOrgDomain = st.organization_domain || '';
          if (st.project_scope_mode) {
            projectScopeMode = st.project_scope_mode;
          }
          if (Array.isArray(st.selected_project_ids) && st.selected_project_ids.length > 0) {
            selectedProjectIds = new Set(st.selected_project_ids);
          }
          if (st.selected_scope) {
            applyScopeStringToPicker(st.selected_scope);
          }

          // Pre-fill Onboarding connection form with persisted workspace settings
          const modeEl = document.getElementById('connMode');
          const saEl = document.getElementById('connTargetSa');
          const orgEl = document.getElementById('connOrgId');
          const custEl = document.getElementById('connCustomerName');
          const bqEl = document.getElementById('connBqTable');
          if (modeEl && st.connection_mode) { modeEl.value = st.connection_mode; onConnectionModeChange(); }
          if (saEl && st.impersonated_sa_email) saEl.value = st.impersonated_sa_email;
          if (orgEl && st.organization_id) orgEl.value = st.organization_id;
          if (custEl && st.customer_name) custEl.value = st.customer_name;
          const retEl = document.getElementById('connRetentionDays');
          if (retEl && st.workspace_retention_days !== undefined && st.workspace_retention_days !== null) {
            retEl.value = String(st.workspace_retention_days);
          }
          if (bqEl && st.optional_customer_bq_table) bqEl.value = st.optional_customer_bq_table;
          refreshInlineSaSetupGuide();

          setConnectedControlsEnabled(true);
          updatePersistenceStatusBadges(st);

          if (ws.readiness) {
            lastVerifiedOrgData = ws.readiness;
            renderReadinessChecksTable(ws.readiness.checks || []);
            const actBtn = document.getElementById('obActivateBtn');
            if (actBtn && ws.readiness.ready_for_scan) {
              actBtn.style.display = 'inline-flex';
              actBtn.innerText = `Select Projects & Scan organizations/${activeOrgId} (${ws.readiness.active_projects_count || 0} projects) →`;
            }
          }

          if (ws.org_hierarchy) {
            applyOrgHierarchyData(ws.org_hierarchy, activeOrgId);
          } else if (st.live_token_valid) {
            await loadOrgHierarchy(activeOrgId, false);
          } else if (activeOrgId) {
            const orgSel = document.getElementById('orgSelector');
            if (orgSel) orgSel.innerHTML = `<option value="${escHtml(activeOrgId)}" selected>organizations/${escHtml(activeOrgId)} (${escHtml(activeOrgDomain || activeOrgId)})</option>`;
            updateProjectPickerSummary();
          }

          // Rehydrate fixed / pinned Posture Book & Accounts/Keys/Secrets Inventory immediately
          if (ws.pinned_book) {
            if (ws.pinned_book.scope) {
              applyScopeStringToPicker(ws.pinned_book.scope);
              renderProjectCheckboxes();
              updateProjectPickerSummary();
            }
            renderPostureBookToUI(ws.pinned_book, true);
          }
          if (ws.pinned_inventory) {
            latestInventory = ws.pinned_inventory;
            renderVaultInventoryUI(ws.pinned_inventory);
          }

          renderPinnedScanSelector(ws.scan_history || [], (ws.pinned_book && ws.pinned_book.scope) || currentScope());

          if (st.token_expired) {
            showConnFeedback(
              'Persisted workspace & pinned scan results restored. Your 1-hour live OAuth token expired — all charts, ledgers, and Word/PDF/Terraform downloads work from the fixed scan; paste a fresh token above only when you want to run a new live GCP scan.',
              false
            );
          } else {
            showConnFeedback(
              `Persistent workspace restored automatically for organizations/${activeOrgId}.${ws.pinned_book ? ' Pinned scan results and Vault Inventory loaded.' : ''}`,
              false
            );
          }

          // Restore last viewed tab (default to dashboard when a pinned scan is already loaded!)
          let savedTab = '';
          try { savedTab = localStorage.getItem('agentic_iam_active_tab') || ''; } catch (e) {}
          const allowedTabs = ['onboarding', 'dashboard', 'triad', 'inventory', 'graph', 'iac', 'copilot', 'report'];
          if (savedTab && allowedTabs.includes(savedTab) && (savedTab !== 'onboarding' || !ws.pinned_book)) {
            showTab(savedTab);
          } else if (ws.pinned_book) {
            showTab('dashboard');
          }
        } else {
          updateTokenStatusHint();
          resetConsoleToCleanSlate();
        }
      } catch (e) {
        resetConsoleToCleanSlate();
      }
    }

    // Customer Onboarding Kit Generator Functions
    function getOnboardingFormPayload() {
      return {
        customer_name: (document.getElementById('obCustomerName')?.value || 'Enterprise Customer').trim() || 'Enterprise Customer',
        organization_id: (document.getElementById('obOrgId')?.value || '').trim(),
        organization_domain: (document.getElementById('obOrgDomain')?.value || '').trim(),
        seed_project_id: (document.getElementById('obSeedProject')?.value || '').trim(),
        onboarding_mode: document.getElementById('obMode')?.value || 'impersonated_sa',
        impersonator_user_email: (document.getElementById('obUserEmail')?.value || '').trim(),
        enable_persistent_auto_renew: autoRenewRequested()
      };
    }

    function selectOnboardingTab(key) {
      currentOnboardingTab = key;
      document.querySelectorAll('#obArtifactTabs .domain-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-ob') === key);
      });
      if (!latestOnboardingKit) return;
      document.getElementById('obCodePreview').innerText = latestOnboardingKit[key] || '';
    }

    function copyOnboardingArtifact() {
      const txt = document.getElementById('obCodePreview')?.innerText || '';
      if (navigator.clipboard && txt) navigator.clipboard.writeText(txt);
    }

    function _formatApiDetail(detail, fallback) {
      if (Array.isArray(detail)) {
        return detail.map(d => `${(d.loc || []).slice(-1)[0] || 'field'}: ${d.msg || 'invalid value'}`).join('; ');
      }
      return detail ? String(detail) : fallback;
    }

    async function generateOnboardingKit() {
      const payload = getOnboardingFormPayload();
      const prev = document.getElementById('obCodePreview');
      if (!payload.organization_id) {
        prev.innerText = 'Enter the Customer GCP Organization ID (numeric) above before generating the onboarding kit.';
        return;
      }
      prev.innerText = 'Generating tailored zero-key read-only onboarding kit...';
      try {
        const res = await fetch('/api/v1/onboarding/kit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(_formatApiDetail(data.detail, `HTTP ${res.status}`));
        latestOnboardingKit = data;
        if (data.target_service_account) {
          const saInp = document.getElementById('connTargetSa');
          if (saInp && !saInp.value) saInp.value = data.target_service_account;
        }
        selectOnboardingTab(currentOnboardingTab);
      } catch (err) {
        prev.innerText = 'Error generating onboarding kit: ' + err.message;
      }
    }

    async function downloadOnboardingZip() {
      const p = getOnboardingFormPayload();
      const prev = document.getElementById('obCodePreview');
      if (!p.organization_id) {
        if (prev) prev.innerText = 'Enter the Customer GCP Organization ID (numeric) above before downloading the .zip kit.';
        return;
      }
      try {
        const res = await fetch('/api/v1/onboarding/download-kit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
          body: JSON.stringify(p)
        });
        if (!res.ok) {
          let errMsg = `HTTP ${res.status}`;
          try {
            const errData = await res.json();
            errMsg = _formatApiDetail(errData.detail, errMsg);
          } catch (_) {}
          throw new Error(errMsg);
        }
        const blob = await res.blob();
        const cd = res.headers.get('Content-Disposition') || '';
        const m = cd.match(/filename="([^"]+)"/);
        const safeOrg = (p.organization_id || '').replace(/[^a-zA-Z0-9]/g, '') || 'customer';
        const fname = m ? m[1] : `agentic_iam_onboarding_${safeOrg}.zip`;
        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = blobUrl;
        link.download = fname;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
      } catch (err) {
        if (prev) prev.innerText = 'Error downloading onboarding kit: ' + err.message;
      }
    }

    async function activateVerifiedOrgInScanner() {
      if (!sessionConnected) return;
      if (lastVerifiedOrgData && lastVerifiedOrgData.organization_id) {
        await loadOrgHierarchy(lastVerifiedOrgData.organization_id);
      }
      showTab('dashboard');
      toggleProjPopover();
    }

    function updateTelemetryBar(tel) {
      if (!tel) return;
      const mv = tel.model_version || tel.requested_model || '—';
      document.getElementById('telModelVersion').innerText = mv;
      document.getElementById('reportMetaModel').innerText = mv;
      const tok = tel.tokens || {};
      document.getElementById('telTokens').innerText = (tok.total_tokens || 0).toLocaleString();
      const calls = tel.tool_calls || [];
      document.getElementById('telToolCalls').innerText = String(calls.length);
      document.getElementById('telLatency').innerText = tel.latency_ms ? `${(tel.latency_ms / 1000).toFixed(1)}s` : '—';
    }

    function setPillarBar(valId, barId, score) {
      const s = Math.max(0, Math.min(100, Number(score || 0)));
      const valEl = document.getElementById(valId);
      const barEl = document.getElementById(barId);
      if (valEl) {
        valEl.innerText = `${s}%`;
        valEl.style.color = scoreTextColor(s);
      }
      if (barEl) {
        barEl.style.width = `${s}%`;
        barEl.style.background = scoreColor(s);
      }
    }

    function renderDonut(compliant, medLow, critHigh, overallScore) {
      const total = Math.max(1, compliant + medLow + critHigh);
      const pComp = (compliant / total) * 100;
      const pMod = (medLow / total) * 100;
      const pCrit = (critHigh / total) * 100;

      const arcComp = document.getElementById('donutArcCompliant');
      const arcMod = document.getElementById('donutArcMod');
      const arcCrit = document.getElementById('donutArcCrit');

      arcComp.setAttribute('stroke-dasharray', `${pComp.toFixed(1)}, 100`);
      arcMod.setAttribute('stroke-dasharray', `${pMod.toFixed(1)}, 100`);
      arcMod.setAttribute('stroke-dashoffset', `-${pComp.toFixed(1)}`);
      arcCrit.setAttribute('stroke-dasharray', `${pCrit.toFixed(1)}, 100`);
      arcCrit.setAttribute('stroke-dashoffset', `-${(pComp + pMod).toFixed(1)}`);

      const center = document.getElementById('donutCenterScore');
      center.innerText = `${overallScore}%`;
      center.style.color = scoreTextColor(overallScore);

      document.getElementById('legendCompliantCount').innerText = compliant;
      document.getElementById('legendMedLowCount').innerText = medLow;
      document.getElementById('legendCritHighCount').innerText = critHigh;
    }

    function openInspectorDrawer(idx) {
      if (!latestBook || !latestBook.triad_matrix || !latestBook.triad_matrix.findings) return;
      const f = latestBook.triad_matrix.findings[idx];
      if (!f) return;
      document.getElementById('drawerTitle').innerText = f.title || f.finding_id;
      document.getElementById('drawerIdBadge').innerText = `${f.finding_id} • ${f.cspr_view_id}`;
      const sevEl = document.getElementById('drawerSevBadge');
      sevEl.innerText = f.severity;
      sevEl.className = 'tag ' + sevTagClass(f.severity);
      document.getElementById('drawerPillar').innerText = f.triad_category;
      document.getElementById('drawerPrincipal').innerText = f.principal;
      document.getElementById('drawerRole').innerText = f.role;
      document.getElementById('drawerResource').innerText = f.resource;
      document.getElementById('drawerVector').innerText = f.risk_vector;
      document.getElementById('drawerWave').innerText = f.remediation_wave;
      document.getElementById('drawerFrameworks').innerText = (f.framework_citations && f.framework_citations.length > 0)
        ? f.framework_citations.join(' • ')
        : 'Google Cloud Blueprint • NIST SP 800-53 • CIS GCP v3.0';
      document.getElementById('drawerEvidence').innerText = f.evidence_summary;
      document.getElementById('drawerRemediation').innerText = f.recommended_modernization;
      document.getElementById('drawerOverlay').classList.add('active');
      document.getElementById('drawerPanel').classList.add('active');
    }

    function closeInspectorDrawer() {
      document.getElementById('drawerOverlay').classList.remove('active');
      document.getElementById('drawerPanel').classList.remove('active');
    }

    function ctrlStatusTagClass(st) {
      const s = String(st || '').toUpperCase();
      if (s === 'PASS') return 'tag-low';
      if (s === 'PARTIAL' || s === 'UNDELEGATED' || s === 'NOT_EVALUATED') return 'tag-med';
      return 'tag-high';
    }

    function renderCoverageWarningsUI(sc) {
      const covEl = document.getElementById('coverageWarningsBanner');
      if (!covEl) return;
      const warnings = (sc && Array.isArray(sc.coverage_warnings)) ? sc.coverage_warnings : [];
      const pct = sc && sc.data_completeness_pct !== undefined ? Number(sc.data_completeness_pct).toFixed(1) : '100.0';
      if (warnings.length === 0) {
        covEl.style.display = 'none';
        covEl.innerHTML = '';
        return;
      }
      covEl.style.display = 'block';
      const itemsHtml = warnings.map(w => `<li style="margin-top:3px;">${escHtml(w)}</li>`).join('');
      covEl.innerHTML = `<div style="font-weight:700; margin-bottom:4px;">Telemetry Coverage Warning (${pct}% Data Completeness)</div><ul style="margin:0 0 0 1.2rem; padding:0;">${itemsHtml}</ul>`;
    }

    function renderFrameworkScorecardUI(sc) {
      renderCoverageWarningsUI(sc);
      const bannerEl = document.getElementById('agenticCalibrationBanner');
      const benchGrid = document.getElementById('frameworkBenchmarksGrid');
      if (bannerEl && sc) {
        const detScore = Number(sc.deterministic_composite_score ?? sc.overall_posture_score ?? 0).toFixed(1);
        const delta = Number(sc.agentic_calibration_delta || 0);
        const deltaStr = (delta >= 0 ? `+${delta.toFixed(1)}%` : `${delta.toFixed(1)}%`);
        const preCap = Number(sc.pre_cap_score ?? (Number(detScore) + delta)).toFixed(1);
        const capDelta = Number(sc.critical_cap_delta || 0);
        const capDeltaStr = capDelta < 0 ? `${capDelta.toFixed(1)}%` : '0.0%';
        const completeness = Number(sc.data_completeness_pct ?? 100.0).toFixed(1);
        const capHtml = sc.critical_exposure_cap_applied
          ? `<div style="margin-top:6px; color:#FFA8A8; font-weight:600;">NIST / CISA Critical Exposure Ceiling Triggered (&le;84%): ${escHtml(sc.critical_exposure_cap_applied)} (Cap Effect: ${capDeltaStr})</div>`
          : '';
        const ratHtml = sc.agentic_calibration_rationale
          ? `<div style="margin-top:6px; color:var(--text-main);"><strong>ADK Specialist Contextual Calibration:</strong> ${escHtml(sc.agentic_calibration_rationale)}</div>`
          : '';
        bannerEl.innerHTML = `<div style="display:flex; flex-wrap:wrap; gap:14px; align-items:center;">
          <span><strong>18-Control Deterministic Baseline:</strong> <span class="mono" style="color:#8AB4F8;">${detScore}%</span></span>
          <span>•</span>
          <span><strong>Bounded ADK Calibration:</strong> <span class="mono" style="color:${delta >= 0 ? '#8CE99A' : '#FFD43B'};">${deltaStr}</span></span>
          <span>•</span>
          <span><strong>Pre-Cap Score:</strong> <span class="mono" style="color:#E2E8F0;">${preCap}%</span></span>
          <span>•</span>
          <span><strong>Cap Effect:</strong> <span class="mono" style="color:${capDelta < 0 ? '#FFA8A8' : 'var(--text-muted)'};">${capDeltaStr}</span></span>
          <span>•</span>
          <span><strong>Data Completeness:</strong> <span class="mono" style="color:${Number(completeness) < 100 ? '#FFD43B' : '#8CE99A'};">${completeness}%</span></span>
          <span>•</span>
          <span><strong>Final Verified Posture Score:</strong> <span class="mono" style="color:${scoreTextColor(sc.overall_posture_score)}; font-weight:700;">${sc.overall_posture_score}% (${escHtml(sc.maturity_tier)})</span></span>
        </div>${capHtml}${ratHtml}`;
      }

      if (benchGrid) {
        const bms = (sc && sc.framework_benchmarks) || [];
        if (bms.length > 0) {
          benchGrid.innerHTML = bms.map(b => `<div style="background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:0.85rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:6px; margin-bottom:6px;">
              <span style="font-size:0.78rem; font-weight:600; color:var(--text-main);">${escHtml(b.framework_name)}</span>
              <span class="mono" style="font-size:0.95rem; font-weight:700; color:${scoreTextColor(b.alignment_score_pct)};">${b.alignment_score_pct}%</span>
            </div>
            <div class="pillar-bar-bg" style="margin-bottom:6px;"><div class="pillar-bar-fill" style="width:${Math.min(100, Math.max(0, b.alignment_score_pct))}%; background:${scoreColor(b.alignment_score_pct)};"></div></div>
            <div style="font-size:0.71rem; color:var(--text-muted);">${b.controls_passed}/${b.controls_evaluated} controls &ge;85% • ${escHtml(b.primary_focus)}</div>
          </div>`).join('');
        }
      }
      filterFrameworkControls(currentControlFilter);
    }

    function filterFrameworkControls(domainFilter) {
      currentControlFilter = domainFilter || 'ALL';
      document.querySelectorAll('#frameworkControlFilters .domain-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-ctrl-dom') === currentControlFilter);
      });
      const tbody = document.getElementById('frameworkControlsBody');
      if (!tbody || !latestBook || !latestBook.scorecard) return;
      const allCtrls = latestBook.scorecard.control_evaluations || [];
      const rows = currentControlFilter === 'ALL'
        ? allCtrls
        : allCtrls.filter(c => c.domain === currentControlFilter);
      if (rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1.25rem;">No controls match the selected domain filter.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(c => {
        const isNotEval = String(c.status || '').toUpperCase() === 'NOT_EVALUATED';
        const scoreDisplay = isNotEval ? 'N/A' : `${c.deterministic_score_pct}%`;
        const scoreStyle = isNotEval ? 'var(--text-muted)' : scoreTextColor(c.deterministic_score_pct);
        return `<tr>
        <td class="mono" style="color:#8AB4F8; font-weight:600;">${escHtml(c.control_id)}<div style="margin-top:4px;"><span class="tag ${ctrlStatusTagClass(c.status)}">${escHtml(c.status)}</span></div></td>
        <td>
          <div style="font-weight:600; color:var(--text-main); margin-bottom:3px;">${escHtml(c.control_title)}</div>
          <div style="font-size:0.71rem; color:#8AB4F8;">${escHtml((c.framework_mappings || []).join(' • '))}</div>
          <div class="mono" style="font-size:0.68rem; color:var(--text-subtle); margin-top:2px;">Formula: ${escHtml(c.formula_expression)}</div>
        </td>
        <td class="mono">${c.numerator} / ${c.denominator}<div style="font-size:0.69rem; color:var(--text-muted);">${escHtml(c.unit_label)}</div></td>
        <td class="mono">${c.domain_weight_pct}%</td>
        <td class="mono" style="font-weight:700; color:${scoreStyle};">${scoreDisplay}</td>
        <td style="color:var(--text-muted); font-size:0.78rem;">${escHtml(c.evidence_summary)}</td>
      </tr>`;
      }).join('');
    }

    function filterTriadTable(pillar, sevGroup) {
      currentPillarFilter = pillar || 'ALL';
      document.querySelectorAll('#triadPillarFilters .domain-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-pillar') === currentPillarFilter);
      });
      if (!latestBook || !latestBook.triad_matrix) return;
      const all = latestBook.triad_matrix.findings || [];
      const filtered = all
        .map((f, idx) => ({ f, idx }))
        .filter(({ f }) => {
          if (currentPillarFilter !== 'ALL' && f.triad_category !== currentPillarFilter) return false;
          if (sevGroup === 'CRITICAL_HIGH') return f.severity === 'CRITICAL' || f.severity === 'HIGH';
          if (sevGroup === 'MODERATE') return f.severity === 'MEDIUM' || f.severity === 'LOW';
          return true;
        });

      document.getElementById('findingsCountLabel').innerText = `${filtered.length} of ${all.length} findings`;
      const tbody = document.getElementById('findingsTableBody');
      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1.5rem;">No findings match the selected filter.</td></tr>';
        return;
      }
      tbody.innerHTML = filtered.map(({ f, idx }) => `<tr onclick="openInspectorDrawer(${idx})" style="cursor:pointer;">
        <td class="mono" style="color:#8AB4F8;">${escHtml(f.finding_id)}<div style="color:var(--text-subtle); font-size:0.7rem;">${escHtml(f.cspr_view_id)}</div></td>
        <td><span class="tag ${sevTagClass(f.severity)}">${escHtml(f.severity)}</span></td>
        <td style="font-size:0.76rem; color:var(--text-muted);">${escHtml(f.triad_category)}<div style="font-size:0.68rem; color:#8AB4F8; margin-top:2px;">${escHtml((f.framework_citations || []).slice(0, 2).join(' • '))}</div></td>
        <td class="mono">${escHtml(f.principal)}<div style="color:#8CE99A; margin-top:2px;">${escHtml(f.role)}</div></td>
        <td style="color:var(--text-muted);">${escHtml(f.evidence_summary)}</td>
        <td>${escHtml(f.recommended_modernization)}</td>
      </tr>`).join('');
    }

    function selectTfFile(key) {
      currentTfKey = key;
      document.querySelectorAll('#tfFileTabs .domain-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-tf') === key);
      });
      if (!latestBook || !latestBook.iac_bundle) return;
      document.getElementById('iacCodePreview').innerText = latestBook.iac_bundle[key] || '# Empty file';
    }

    function copyCurrentHcl() {
      const txt = document.getElementById('iacCodePreview').innerText || '';
      if (navigator.clipboard) navigator.clipboard.writeText(txt);
    }

    function renderPostureBookToUI(book, isPinnedRestore = false) {
      if (!book || !book.scorecard) return;
      latestBook = book;
      const scope = book.scope || currentScope();
      const sc = book.scorecard;
      const tm = book.triad_matrix;
      const ag = book.attack_graph;
      const iac = book.iac_bundle;
      const recs = book.recommendations || [];

      const kpiScoreEl = document.getElementById('kpiOverallScore');
      kpiScoreEl.innerText = `${sc.overall_posture_score}%`;
      kpiScoreEl.style.color = scoreTextColor(sc.overall_posture_score);
      document.getElementById('kpiMaturityTier').innerText = `Tier: ${sc.maturity_tier} • ${sc.total_bindings_analyzed} bindings`;

      const compTotal =
        (tm.internal_identities.compliant_principals || 0) +
        (tm.external_identities.compliant_principals || 0) +
        (tm.workload_service_accounts.compliant_principals || 0);
      const evalTotal =
        (tm.internal_identities.total_principals_evaluated || 0) +
        (tm.external_identities.total_principals_evaluated || 0) +
        (tm.workload_service_accounts.total_principals_evaluated || 0);

      document.getElementById('kpiCompliantCount').innerText = `${compTotal}/${evalTotal}`;
      document.getElementById('kpiCompliantSub').innerText = 'Principals passing baseline checks';

      document.getElementById('kpiExcessPerms').innerText = `${sc.least_privilege_index}%`;
      document.getElementById('kpiExcessSub').innerText = `${(sc.excess_permissions_eliminated || 0).toLocaleString()} excess perms removable`;

      const critHigh = (sc.critical_findings || 0) + (sc.high_findings || 0);
      const medLow = (sc.medium_findings || 0) + (sc.low_findings || 0);
      document.getElementById('kpiCritHighCount').innerText = String(critHigh);
      document.getElementById('kpiCritHighSub').innerText = `${sc.critical_findings} Critical • ${sc.high_findings} High`;

      document.getElementById('donutScopeLabel').innerText = `${book.scope} (${sc.total_bindings_analyzed} bindings)`;
      renderDonut(compTotal, medLow, critHigh, sc.overall_posture_score);

      setPillarBar('kpiInternalScore', 'barInternal', sc.internal_identities_score);
      setPillarBar('kpiExternalScore', 'barExternal', sc.external_identities_score);
      setPillarBar('kpiWorkloadScore', 'barWorkload', sc.workload_identities_score);
      setPillarBar('barResilienceVal', 'barResilience', sc.impersonation_resilience_score);
      setPillarBar('barLpiVal', 'barLpi', sc.least_privilege_index);

      renderFrameworkScorecardUI(sc);

      document.getElementById('triadCardIntScore').innerText = `${sc.internal_identities_score}%`;
      document.getElementById('triadCardExtScore').innerText = `${sc.external_identities_score}%`;
      document.getElementById('triadCardSaScore').innerText = `${sc.workload_identities_score}%`;

      // A domain with no evaluated control shows "N/A" instead of a misleading 0% (scorecard.not_evaluated_domains)
      const notEvaluatedDomains = new Set(sc.not_evaluated_domains || []);
      [
        ['INTERNAL_IDENTITIES', ['kpiInternalScore', 'triadCardIntScore']],
        ['EXTERNAL_IDENTITIES', ['kpiExternalScore', 'triadCardExtScore']],
        ['WORKLOAD_IDENTITIES', ['kpiWorkloadScore', 'triadCardSaScore']],
        ['GRAPH_RESILIENCE', ['barResilienceVal']],
        ['LEAST_PRIVILEGE', ['barLpiVal', 'kpiExcessPerms']]
      ].forEach(([domainKey, elementIds]) => {
        if (!notEvaluatedDomains.has(domainKey)) return;
        elementIds.forEach((elementId) => {
          const el = document.getElementById(elementId);
          if (el) el.innerText = 'N/A';
        });
      });
      document.getElementById('kpiInternalSub').innerText = `${tm.internal_identities.compliant_principals}/${tm.internal_identities.total_principals_evaluated} compliant principals`;
      document.getElementById('kpiExternalSub').innerText = `${tm.external_identities.compliant_principals}/${tm.external_identities.total_principals_evaluated} compliant principals`;
      document.getElementById('kpiWorkloadSub').innerText = `${tm.workload_service_accounts.compliant_principals}/${tm.workload_service_accounts.total_principals_evaluated} compliant principals`;

      // Dashboard Priority Finding Cards
      const findings = tm.findings || [];
      const gridEl = document.getElementById('dashboardFindingsGrid');
      if (findings.length > 0) {
        gridEl.innerHTML = findings.slice(0, 6).map((f, idx) => `<div class="asset-card" onclick="openInspectorDrawer(${idx})">
          <div>
            <div class="asset-card-header">
              <div class="asset-card-title">${escHtml(f.title || f.finding_id)}</div>
              <span class="tag ${sevTagClass(f.severity)}">${escHtml(f.severity)}</span>
            </div>
            <div class="asset-card-meta">${escHtml(f.evidence_summary)}</div>
          </div>
          <div class="asset-card-footer">
            <span>${escHtml(f.principal.split(':').pop())}</span>
            <span style="color:#8AB4F8;">${escHtml(f.role.replace('roles/', ''))}</span>
          </div>
        </div>`).join('');
      } else {
        gridEl.innerHTML = '<div style="color:#8CE99A; font-size:0.84rem;">No critical or high IAM deviations detected in scope.</div>';
      }

      // Triad Table
      filterTriadTable(currentPillarFilter);

      // Attack Graph Tab
      document.getElementById('graphNodesVal').innerText = ag.total_nodes;
      document.getElementById('graphEdgesVal').innerText = ag.total_edges;
      document.getElementById('graphPathsVal').innerText = ag.escalation_paths_count;
      document.getElementById('graphToxicVal').innerText = ag.toxic_combinations_count;
      document.getElementById('graphChainsBadge').innerText = `${ag.escalation_paths_count} Escalation Paths • ${ag.total_nodes} Nodes`;
      const gPh = document.getElementById('attackGraphPlaceholder');
      const gImg = document.getElementById('attackGraphImg');
      if (gPh) gPh.style.display = 'none';
      if (gImg) {
        gImg.style.display = 'block';
        gImg.src = `/api/v1/download/attack-graph-png?scope=${encodeURIComponent(scope)}&theme=dark&t=${Date.now()}`;
      }

      const pathsBody = document.getElementById('attackPathsTableBody');
      if (ag.critical_paths && ag.critical_paths.length > 0) {
        pathsBody.innerHTML = ag.critical_paths.map(p => `<tr>
          <td class="mono" style="color:#8AB4F8;">${escHtml(p.path_id)}</td>
          <td><span class="tag tag-high">${escHtml(p.toxic_combination_type)}</span><div style="font-size:0.74rem; color:var(--text-muted); margin-top:4px;">Blast Radius: ${p.blast_radius_score}/10</div></td>
          <td class="mono" style="color:var(--text-main);">${escHtml((p.hop_sequence || []).join(' -> '))}</td>
          <td style="color:var(--text-muted);">${escHtml(p.mitigation_control)}</td>
        </tr>`).join('');
      } else {
        pathsBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#8CE99A; padding:1.25rem;">No multi-hop escalation chains detected.</td></tr>';
      }

      // Least-Privilege & Terraform Tab
      document.getElementById('recsCountBadge').innerText = `${recs.length} Recommendations`;
      const recsBody = document.getElementById('recsTableBody');
      if (recs.length > 0) {
        recsBody.innerHTML = recs.map(r => `<tr>
          <td><strong style="color:#8AB4F8;" class="mono">${escHtml(r.recommendation_id)}</strong><div style="font-size:0.73rem; color:var(--text-muted);">${escHtml(r.persona_classification)}</div></td>
          <td class="mono">${escHtml(r.principal)}</td>
          <td class="mono" style="color:#FFA8A8;">${escHtml(r.current_role)}</td>
          <td class="mono" style="color:#8CE99A;">${escHtml(r.proposed_role_or_entitlement)}</td>
          <td><span class="tag tag-low">-${r.permission_reduction_pct}%</span></td>
        </tr>`).join('');
      } else {
        recsBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1.25rem;">No overprivileged bindings flagged in scope.</td></tr>';
      }

      const iacWin = (iac.audit_sample_window_start || iac.audit_sample_window_end)
        ? `${(iac.audit_sample_window_start || '').slice(0, 10)} a ${(iac.audit_sample_window_end || '').slice(0, 10)}`
        : 'janela indisponível';
      document.getElementById('iacBundleBadge').innerText = `${iac.bundle_id} (${(iac.policy_simulations || []).length} estimativas • ${iac.audit_sample_size || 0} eventos na amostra, ${iacWin} — não validado)`;
      selectTfFile(currentTfKey);

      if (book.asset_inventory) {
        latestInventory = book.asset_inventory;
        renderVaultInventoryUI(book.asset_inventory);
      } else if (!isPinnedRestore) {
        refreshVaultInventoryOnly(false);
      }

      // Copilot & Full Executive Report Tabs
      const narrative = book.executive_narrative_markdown || '';
      document.getElementById('agentOutput').innerText = narrative;
      document.getElementById('reportExecutiveNarrative').innerText = narrative;
      document.getElementById('reportMetaDomain').innerText = activeOrgDomain || `organizations/${activeOrgId}`;
      document.getElementById('reportMetaScope').innerText = book.scope;
      document.getElementById('reportMetaDate').innerText = (book.generated_at || '').slice(0, 19).replace('T', ' ') + ' UTC';
      renderFullExecutiveReportPreview(book);

      updateTelemetryBar(book.telemetry);
      syncDownloadLinks();
    }

    function handleServerSessionMissing(statusCode, detail) {
      if (statusCode === 412 || statusCode === 401) {
        sessionConnected = false;
        showTab('onboarding');
        showConnFeedback(
          detail || 'Your server-side GCP inspection session no longer exists on the server (expired or cleared after a container restart). Please reconnect your target GCP Organization in Step 1.',
          true
        );
        return true;
      }
      return false;
    }

    async function loadLivePostureBook(forceRefresh) {
      if (!sessionConnected || !currentScope()) {
        showTab('onboarding');
        showConnFeedback('Connect a target GCP Organization first before running an ADK scan.', true);
        return;
      }
      const btn = document.getElementById('assessBtn');
      const statusBadge = document.getElementById('assessmentStatusBadge');
      const scope = currentScope();
      const model = currentModel();
      syncDownloadLinks();

      const activeNav = document.querySelector('.nav-item.active');
      if (activeNav && activeNav.getAttribute('data-tab') === 'onboarding') {
        showTab('dashboard');
      }

      btn.disabled = true;
      btn.innerText = forceRefresh ? 'Running ADK...' : 'Loading Pinned...';
      statusBadge.innerText = forceRefresh ? `Evaluating ${scope}...` : `Restoring pinned ${scope}...`;

      try {
        async function _safeParseJson(res) {
          const text = await res.text();
          if (!text) return {};
          try {
            return JSON.parse(text);
          } catch (_) {
            return { detail: `HTTP ${res.status}: ${text.slice(0, 180)}` };
          }
        }

        async function _runBackgroundScanViaPost(doRefresh) {
          const startedAtMs = Date.now();
          const startRes = await fetch('/api/v1/scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
            body: JSON.stringify({ scope, model, refresh: !!doRefresh })
          });
          const startData = await _safeParseJson(startRes);
          if (!startRes.ok) {
            if (handleServerSessionMissing(startRes.status, startData.detail)) return null;
            throw new Error(startData.detail || `HTTP ${startRes.status}`);
          }
          const scanId = startData.scan_id;
          while (true) {
            await new Promise(r => setTimeout(r, 1500));
            const elapsedSec = Math.max(1, Math.round((Date.now() - startedAtMs) / 1000));
            statusBadge.innerText = `Evaluating ${scope}... (${elapsedSec}s)`;
            const pollRes = await fetch(`/api/v1/scans/${encodeURIComponent(scanId)}`);
            const pollData = await _safeParseJson(pollRes);
            if (!pollRes.ok) {
              if (handleServerSessionMissing(pollRes.status, pollData.detail)) return null;
              throw new Error(pollData.detail || `HTTP ${pollRes.status}`);
            }
            if (pollData.status === 'completed' && pollData.book) {
              return pollData.book;
            }
            if (pollData.status === 'failed' || pollData.status === 'cancelled') {
              if (handleServerSessionMissing(pollData.http_status, pollData.error)) return null;
              throw new Error(pollData.error || `Scan ${pollData.status}`);
            }
          }
        }

        let book = null;
        if (forceRefresh) {
          book = await _runBackgroundScanViaPost(true);
          if (!book) return;
        } else {
          const url = `/api/v1/book?scope=${encodeURIComponent(scope)}&model=${encodeURIComponent(model)}`;
          const res = await fetch(url);
          if (res.status === 404) {
            book = await _runBackgroundScanViaPost(false);
            if (!book) return;
          } else {
            book = await res.json();
            if (!res.ok) {
              if (handleServerSessionMissing(res.status, book.detail)) return;
              throw new Error(book.detail || `HTTP ${res.status}`);
            }
          }
        }

        renderPostureBookToUI(book, !forceRefresh);
        const ts = (book.generated_at || '').slice(0, 16).replace('T', ' ');
        statusBadge.innerText = `Pinned & Synced (${ts} UTC)`;
        statusBadge.style.color = '#8CE99A';

        // Refresh pinned snapshot dropdown with latest saved scan index
        try {
          const wsRes = await fetch('/api/v1/workspace/restore');
          if (wsRes.ok) {
            const wsData = await wsRes.json();
            renderPinnedScanSelector(wsData.scan_history || [], book.scope || scope);
            if (wsData.session) updatePersistenceStatusBadges(wsData.session);
          }
        } catch (e) {}
      } catch (err) {
        statusBadge.innerText = 'ADK Error';
        statusBadge.style.color = '#FFA8A8';
        document.getElementById('agentOutput').innerText = `Google ADK / Vertex AI Error: ${err.message}`;
        if (String(err.message || '').toLowerCase().includes('token') || String(err.message || '').toLowerCase().includes('expired')) {
          showConnFeedback(err.message, true);
        }
      } finally {
        btn.disabled = !sessionConnected;
        btn.innerText = 'Run ADK Scan';
      }
    }

    async function refreshVaultInventoryOnly(forceRefresh = true) {
      if (!sessionConnected || !currentScope()) {
        showTab('onboarding');
        showConnFeedback('Connect a target GCP Organization first before inspecting Accounts, Keys & Secrets.', true);
        return;
      }
      const btn = document.getElementById('invRefreshBtn');
      const scope = currentScope();
      syncDownloadLinks();
      if (btn) { btn.disabled = true; btn.innerText = 'Collecting...'; }
      try {
        const res = await fetch(`/api/v1/inventory?scope=${encodeURIComponent(scope)}&refresh=${forceRefresh ? 'true' : 'false'}`, {
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const inv = await res.json();
        if (!res.ok) {
          if (handleServerSessionMissing(res.status, inv.detail)) return;
          throw new Error(inv.detail || `HTTP ${res.status}`);
        }
        latestInventory = inv;
        if (latestBook) {
          latestBook.asset_inventory = inv;
          renderFullExecutiveReportPreview(latestBook);
        }
        renderVaultInventoryUI(inv);
      } catch (err) {
        document.getElementById('invLedgerCountLabel').innerText = `Inventory Error: ${err.message}`;
      } finally {
        if (btn) { btn.disabled = false; btn.innerText = 'Refresh Vault Inventory'; }
      }
    }

    function renderVaultInventoryUI(inv) {
      if (!inv || !inv.kpis) return;
      const k = inv.kpis;
      document.getElementById('invKpiAccounts').innerText = String(k.human_and_group_accounts_total);
      document.getElementById('invKpiAccountsSub').innerText = `${k.internal_users_count} Users • ${k.security_groups_count} Groups • ${k.external_and_public_principals_count} Ext`;

      document.getElementById('invKpiStandingAdmins').innerText = String(k.standing_admin_accounts_count);
      document.getElementById('invKpiVaultReachSub').innerText = `Secret / KMS Accessors: ${k.principals_with_secret_or_kms_access}`;

      document.getElementById('invKpiSas').innerText = String(k.service_accounts_total);
      document.getElementById('invKpiSasSub').innerText = `${k.default_sas_with_roles_count} Active Default SAs • ${k.disabled_sas_count} Disabled`;

      document.getElementById('invKpiSaKeys').innerText = `${k.user_managed_sa_keys_total} / ${(inv.sa_keys || []).length}`;
      document.getElementById('invKpiSaKeysSub').innerText = `${k.user_managed_sa_keys_total} User (${k.sa_keys_over_90d_count} >90d) • ${k.system_managed_sa_keys_total} System`;

      document.getElementById('invKpiSecrets').innerText = String(k.secrets_total_count);
      document.getElementById('invKpiSecretsSub').innerText = `${k.secrets_unrotated_count} Unrotated • ${k.secrets_without_cmek_count} Non-CMEK`;

      document.getElementById('invKpiKms').innerText = String(k.kms_cryptokeys_total);
      document.getElementById('invKpiKmsSub').innerText = `${k.kms_keyrings_count} KeyRings • ${k.kms_keys_missing_90d_rotation_count} Unrotated • ${k.kms_sod_conflicts_count} SoD`;

      document.getElementById('invKpiApiKeys').innerText = String(k.api_keys_total_count);
      document.getElementById('invKpiApiKeysSub').innerText = `${k.unrestricted_api_keys_count} Unrestricted • ${k.api_keys_over_90d_count} >90d`;

      document.getElementById('invKpiCustomWif').innerText = `${k.custom_roles_total_count} / ${k.wif_pools_count}`;
      document.getElementById('invKpiCustomWifSub').innerText = `${k.custom_roles_with_escalation_perms_count} Esc Roles • ${k.org_policies_enforced_count}/${k.org_policies_evaluated_count} OrgPol`;

      renderActiveInventoryTable();
    }

    function selectInvSubTab(subKey) {
      currentInvSubTab = subKey || 'accounts';
      document.querySelectorAll('#invSubTabs .domain-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-inv') === currentInvSubTab);
      });
      renderActiveInventoryTable();
    }

    function renderActiveInventoryTable() {
      const thead = document.getElementById('invTableHead');
      const tbody = document.getElementById('invTableBody');
      const countLbl = document.getElementById('invLedgerCountLabel');
      if (!thead || !tbody || !latestInventory) return;
      const q = (document.getElementById('invSearchInput')?.value || '').trim().toLowerCase();
      const matchQ = (obj) => !q || JSON.stringify(obj).toLowerCase().includes(q);

      if (currentInvSubTab === 'accounts') {
        const rows = (latestInventory.accounts || []).filter(matchQ);
        const invWin = (latestInventory.audit_sample_window_start || latestInventory.audit_sample_window_end)
          ? `${(latestInventory.audit_sample_window_start || '').slice(0, 10)} a ${(latestInventory.audit_sample_window_end || '').slice(0, 10)}`
          : 'janela indisponível';
        countLbl.innerText = `Showing ${rows.length} of ${(latestInventory.accounts || []).length} Human, Group, Domain & External Principals • ${latestInventory.audit_sample_size || 0} eventos na amostra (${invWin})`;
        thead.innerHTML = '<tr><th>Principal &amp; Type</th><th>Domain</th><th>Bindings &amp; Projects</th><th>Vault &amp; Admin Flags</th><th>Granted IAM Roles</th><th>Risk</th></tr>';
        tbody.innerHTML = rows.length ? rows.map(a => `<tr>
          <td><div class="mono" style="color:var(--text-main); font-weight:600;">${escHtml(a.principal)}</div><div style="font-size:0.72rem; color:#8AB4F8;">${escHtml(a.principal_type)}</div></td>
          <td class="mono">${escHtml(a.domain)}${a.is_external ? ' <span class="tag tag-high" style="margin-left:4px;">EXT</span>' : ''}</td>
          <td style="font-size:0.77rem;"><strong>${a.bindings_count}</strong> bindings<div class="mono" style="color:var(--text-muted); font-size:0.71rem;">${escHtml((a.projects || []).slice(0, 4).join(', '))}${(a.projects || []).length > 4 ? ` +${a.projects.length - 4}` : ''}</div></td>
          <td style="font-size:0.73rem;">
            ${a.is_standing_admin ? '<span class="tag tag-high">24/7 Admin</span> ' : ''}
            ${a.can_access_secrets ? '<span class="tag tag-med">Secrets</span> ' : ''}
            ${a.can_use_or_admin_kms ? '<span class="tag tag-gcp">KMS</span> ' : ''}
            ${a.can_impersonate_sa ? '<span class="tag tag-high">Impersonate</span> ' : ''}
            <span style="color:var(--text-muted);">Eventos na amostra: ${a.audit_events_30d} (${escHtml(invWin)})</span>
          </td>
          <td class="mono" style="font-size:0.73rem; color:#8CE99A;">${escHtml((a.roles || []).join(', '))}</td>
          <td><span class="tag ${sevTagClass(a.risk_level)}">${escHtml(a.risk_level)}</span></td>
        </tr>`).join('') : '<tr><td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">No matching accounts in scope.</td></tr>';
      } else if (currentInvSubTab === 'service_accounts') {
        const rows = (latestInventory.service_accounts || []).filter(matchQ);
        countLbl.innerText = `Showing ${rows.length} of ${(latestInventory.service_accounts || []).length} Customer & Default Service Accounts`;
        thead.innerHTML = '<tr><th>Service Account</th><th>Project &amp; State</th><th>Keys (User / System)</th><th>Attached Workloads &amp; Vault</th><th>Granted Roles</th><th>Risk</th></tr>';
        tbody.innerHTML = rows.length ? rows.map(s => `<tr>
          <td><div class="mono" style="color:#8AB4F8; font-weight:600;">${escHtml(s.email)}</div><div style="font-size:0.72rem; color:var(--text-muted);">${escHtml(s.sa_subtype)}</div></td>
          <td class="mono">${escHtml(s.project_id)}<div style="font-size:0.7rem; color:${s.disabled ? '#FFA8A8' : '#8CE99A'};">${s.disabled ? 'DISABLED' : 'ENABLED'}</div></td>
          <td class="mono">User: <strong>${s.user_managed_keys_count}</strong> (max ${s.oldest_user_key_age_days}d)<div style="font-size:0.71rem; color:var(--text-muted);">System: ${s.system_managed_keys_count}</div></td>
          <td style="font-size:0.75rem;">${escHtml((s.attached_workloads || []).join(', ') || 'No VM/CloudRun attached')}${s.can_access_secrets_or_kms ? '<div><span class="tag tag-med" style="margin-top:3px;">Secret/KMS Reach</span></div>' : ''}</td>
          <td class="mono" style="font-size:0.73rem; color:#8CE99A;">${escHtml((s.granted_roles || []).join(', ') || 'None')}</td>
          <td><span class="tag ${sevTagClass(s.risk_level)}">${escHtml(s.risk_level)}</span></td>
        </tr>`).join('') : '<tr><td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">No matching Service Accounts in scope.</td></tr>';
      } else if (currentInvSubTab === 'sa_keys') {
        const rows = (latestInventory.sa_keys || []).filter(matchQ);
        countLbl.innerText = `Showing ${rows.length} of ${(latestInventory.sa_keys || []).length} Service Account Keys (USER_MANAGED & SYSTEM_MANAGED)`;
        thead.innerHTML = '<tr><th>Key ID</th><th>Service Account &amp; Project</th><th>Key Type &amp; Origin</th><th>Algorithm</th><th>Created &rarr; Expires (Age)</th><th>Risk</th></tr>';
        tbody.innerHTML = rows.length ? rows.map(k => `<tr>
          <td class="mono" style="color:#8AB4F8;">${escHtml(k.key_id)}</td>
          <td class="mono">${escHtml(k.sa_email)}<div style="font-size:0.71rem; color:var(--text-muted);">Project: ${escHtml(k.project_id)}</div></td>
          <td><span class="tag ${k.key_type === 'USER_MANAGED' ? 'tag-high' : 'tag-low'}">${escHtml(k.key_type)}</span><div class="mono" style="font-size:0.7rem; color:var(--text-muted); margin-top:2px;">${escHtml(k.key_origin)}</div></td>
          <td class="mono">${escHtml(k.key_algorithm)}</td>
          <td class="mono" style="font-size:0.74rem;">${escHtml(k.valid_after_time)} &rarr; ${escHtml(k.valid_before_time)}<div style="color:${k.age_days > 90 && k.key_type === 'USER_MANAGED' ? '#FFA8A8' : 'var(--text-muted)'};">Age: ${k.age_days} days</div></td>
          <td><span class="tag ${sevTagClass(k.risk_level)}">${escHtml(k.risk_level)}</span></td>
        </tr>`).join('') : '<tr><td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">No matching Service Account keys in scope.</td></tr>';
      } else if (currentInvSubTab === 'secrets') {
        const rows = (latestInventory.secrets || []).filter(matchQ);
        countLbl.innerText = `Showing ${rows.length} of ${(latestInventory.secrets || []).length} Secret Manager Secrets (100% Metadata-Only — Zero Secret Payload Access)`;
        thead.innerHTML = '<tr><th>Secret Name &amp; Project</th><th>Replication &amp; Versions</th><th>Encryption</th><th>Rotation &amp; Expiry</th><th>IAM Principals with Secret Access</th><th>Risk</th></tr>';
        tbody.innerHTML = rows.length ? rows.map(s => {
          const accList = s.accessor_principals || [];
          const accTotal = Math.max(Number(s.accessor_principals_total || 0), accList.length);
          const accShown = accList.slice(0, 8);
          const accSuffix = accTotal > accShown.length ? ` (+${accTotal - accShown.length} more)` : '';
          return `<tr>
          <td><div class="mono" style="color:#8CE99A; font-weight:600;">${escHtml(s.secret_name)}</div><div class="mono" style="font-size:0.71rem; color:var(--text-muted);">Project: ${escHtml(s.project_id)} • ${escHtml(s.created_at || '—')}</div></td>
          <td class="mono" style="font-size:0.75rem;">${escHtml(s.replication_policy)}<div style="color:var(--text-muted);">Enabled Versions: ${s.active_versions_count}</div></td>
          <td><span class="tag ${s.encryption_type === 'CMEK' ? 'tag-low' : 'tag-med'}">${escHtml(s.encryption_type)}</span>${s.kms_key_name ? `<div class="mono" style="font-size:0.68rem; color:var(--text-muted); margin-top:2px;">${escHtml(s.kms_key_name)}</div>` : ''}</td>
          <td style="font-size:0.75rem;">${s.rotation_configured ? `<span class="tag tag-low">Rotated (${s.rotation_period_days || '?'}d)</span>` : '<span class="tag tag-med">Unrotated</span>'}${s.expire_or_ttl ? `<div class="mono" style="font-size:0.7rem; color:var(--text-muted);">TTL/Exp: ${escHtml(s.expire_or_ttl)}</div>` : ''}</td>
          <td style="font-size:0.73rem;"><div style="color:var(--text-main); font-weight:600;">${accTotal} principals (${s.broad_primitive_accessors_count} Owner/Editor)</div><div class="mono" style="color:var(--text-muted); font-size:0.7rem;">${escHtml(accShown.join(', ') + accSuffix)}</div></td>
          <td><span class="tag ${sevTagClass(s.risk_level)}">${escHtml(s.risk_level)}</span></td>
        </tr>`;
        }).join('') : '<tr><td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">No Secret Manager secrets discovered in scope.</td></tr>';
      } else if (currentInvSubTab === 'kms_keys') {
        const rows = (latestInventory.kms_keys || []).filter(matchQ);
        countLbl.innerText = `Showing ${rows.length} of ${(latestInventory.kms_keys || []).length} Cloud KMS CryptoKeys`;
        thead.innerHTML = '<tr><th>CryptoKey &amp; KeyRing</th><th>Project &amp; Location</th><th>Purpose, Protection &amp; Algorithm</th><th>Rotation (&le;90d SLA)</th><th>KMS Admin + Decrypter SoD Conflicts</th><th>Risk</th></tr>';
        tbody.innerHTML = rows.length ? rows.map(k => `<tr>
          <td><div class="mono" style="color:#8AB4F8; font-weight:600;">${escHtml(k.crypto_key_name)}</div><div class="mono" style="font-size:0.71rem; color:var(--text-muted);">KeyRing: ${escHtml(k.key_ring)}</div></td>
          <td class="mono">${escHtml(k.project_id)}<div style="font-size:0.71rem; color:var(--text-muted);">${escHtml(k.location)}</div></td>
          <td style="font-size:0.75rem;"><strong>${escHtml(k.purpose)}</strong><div class="mono" style="font-size:0.71rem; color:#8CE99A;">${escHtml(k.protection_level)} • ${escHtml(k.algorithm)}</div></td>
          <td class="mono" style="font-size:0.75rem;">${k.rotation_period_days ? `${k.rotation_period_days}d` : (k.purpose !== 'ENCRYPT_DECRYPT' ? 'Asymmetric (Manual)' : '<span style="color:#FFA8A8;">UNROTATED</span>')}</td>
          <td class="mono" style="font-size:0.72rem; color:${(k.sod_conflict_principals || []).length ? '#FFA8A8' : '#8CE99A'};">${escHtml((k.sod_conflict_principals || []).join(', ') || 'Clean SoD')}</td>
          <td><span class="tag ${sevTagClass(k.risk_level)}">${escHtml(k.risk_level)}</span></td>
        </tr>`).join('') : '<tr><td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">No Cloud KMS CryptoKeys discovered in scope.</td></tr>';
      } else if (currentInvSubTab === 'api_custom') {
        const akRows = (latestInventory.api_keys || []).filter(matchQ);
        const crRows = (latestInventory.custom_roles || []).filter(matchQ);
        countLbl.innerText = `Showing ${akRows.length} Google Cloud API Keys & ${crRows.length} Custom IAM Roles`;
        thead.innerHTML = '<tr><th>Category</th><th>Name / Identifier</th><th>Project / Scope</th><th>Posture / Stage</th><th>Restrictions or Escalation Permissions</th><th>Risk</th></tr>';
        const akHtml = akRows.map(a => `<tr>
          <td><span class="tag tag-gcp">API KEY</span></td>
          <td><div style="font-weight:600;">${escHtml(a.display_name)}</div><div class="mono" style="font-size:0.7rem; color:var(--text-muted);">UID: ${escHtml(a.key_uid)}</div></td>
          <td class="mono">${escHtml(a.project_id)}<div style="font-size:0.7rem; color:var(--text-muted);">${escHtml(a.created_at)} (${a.age_days}d)</div></td>
          <td class="mono">${escHtml(a.restriction_mode)}</td>
          <td class="mono" style="font-size:0.72rem;">${escHtml((a.restricted_services || []).join(', ') || 'UNRESTRICTED (All APIs Allowed)')}</td>
          <td><span class="tag ${sevTagClass(a.risk_level)}">${escHtml(a.risk_level)}</span></td>
        </tr>`);
        const crHtml = crRows.map(c => `<tr>
          <td><span class="tag tag-med">CUSTOM ROLE</span></td>
          <td><div style="font-weight:600;">${escHtml(c.title)}</div><div class="mono" style="font-size:0.7rem; color:#8AB4F8;">${escHtml(c.role_name)}</div></td>
          <td class="mono">${escHtml(c.scope_level)}: ${escHtml(c.project_or_org)}</td>
          <td class="mono">${escHtml(c.stage)} • ${c.included_permissions_count} perms (${c.assigned_bindings_count} bound)</td>
          <td class="mono" style="font-size:0.72rem; color:${(c.escalation_permissions || []).length ? '#FFA8A8' : '#8CE99A'};">${escHtml((c.escalation_permissions || []).join(', ') || 'No escalation permissions')}</td>
          <td><span class="tag ${sevTagClass(c.risk_level)}">${escHtml(c.risk_level)}</span></td>
        </tr>`);
        const combined = akHtml.concat(crHtml);
        tbody.innerHTML = combined.length ? combined.join('') : '<tr><td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">No API Keys or Custom Roles discovered in scope.</td></tr>';
      } else {
        const wRows = (latestInventory.wif_providers || []).filter(matchQ);
        const oRows = (latestInventory.org_policies || []).filter(matchQ);
        countLbl.innerText = `Showing ${wRows.length} Workload Identity Federation Entries & ${oRows.length} Effective Organization Policies`;
        thead.innerHTML = '<tr><th>Asset Class</th><th>Identifier / Constraint</th><th>Scope &amp; State</th><th>Issuer / Evaluation</th><th>Guardrail / CEL Condition</th><th>Posture</th></tr>';
        const wHtml = wRows.map(w => `<tr>
          <td><span class="tag tag-gcp">WIF POOL</span></td>
          <td class="mono" style="color:#8AB4F8;">${escHtml(w.pool_name)} / ${escHtml(w.provider_name)}</td>
          <td class="mono">${escHtml(w.project_id)} (${escHtml(w.state)})</td>
          <td class="mono" style="font-size:0.73rem;">${escHtml(w.issuer_uri)}</td>
          <td class="mono" style="font-size:0.72rem;">${w.has_attribute_condition ? escHtml(w.attribute_condition) : '<span style="color:#FFA8A8;">MISSING ATTRIBUTE CONDITION</span>'}</td>
          <td><span class="tag ${sevTagClass(w.risk_level)}">${escHtml(w.risk_level)}</span></td>
        </tr>`);
        const oHtml = oRows.map(o => {
          const opLabel = o.enforced === true ? 'ENFORCED' : (o.enforced === false ? 'NOT ENFORCED' : 'NOT EVALUATED');
          const opTag = o.enforced === true ? 'tag-low' : (o.enforced === false ? 'tag-high' : 'tag-med');
          return `<tr>
          <td><span class="tag tag-low">ORG POLICY</span></td>
          <td class="mono" style="font-weight:600;">${escHtml(o.constraint)}</td>
          <td class="mono">${escHtml(o.evaluated_on)}</td>
          <td class="mono">${escHtml(o.status)}</td>
          <td class="mono">enforced = ${String(o.enforced)}</td>
          <td><span class="tag ${opTag}">${opLabel}</span></td>
        </tr>`;
        });
        const combined = wHtml.concat(oHtml);
        tbody.innerHTML = combined.length ? combined.join('') : '<tr><td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">No WIF Pools or Org Policies returned.</td></tr>';
      }
    }

    function renderFullExecutiveReportPreview(book) {
      const el = document.getElementById('reportFullSectionsPreview');
      if (!el || !book) return;
      const sc = book.scorecard || {};
      const inv = book.asset_inventory || latestInventory;
      const k = (inv && inv.kpis) || {};
      const bms = sc.framework_benchmarks || [];
      const findings = (book.triad_matrix && book.triad_matrix.findings) || [];
      const paths = (book.attack_graph && book.attack_graph.critical_paths) || [];
      const recs = book.recommendations || [];

      const bmHtml = bms.map(b => `<tr>
        <td><strong>${escHtml(b.framework_name)}</strong></td>
        <td class="mono"><strong>${b.alignment_score_pct}%</strong></td>
        <td class="mono">${b.controls_passed} / ${b.controls_evaluated}</td>
        <td style="color:var(--text-muted);">${escHtml(b.primary_focus)}</td>
      </tr>`).join('');

      const vaultHtml = inv ? `<div class="chapter-h2" style="margin-top:1.5rem;">3. Accounts, Service Accounts, Keys, KMS &amp; Secrets Summary</div>
        <div class="table-container"><table>
          <thead><tr><th>Credential / Vault Domain</th><th>Live Count</th><th>Risk &amp; Governance Breakdown</th></tr></thead>
          <tbody>
            <tr><td><strong>Human, Group &amp; External Accounts</strong></td><td class="mono">${k.human_and_group_accounts_total}</td><td>${k.internal_users_count} Internal Users • ${k.security_groups_count} Groups • ${k.external_and_public_principals_count} External (${k.standing_admin_accounts_count} Standing 24/7 Admins)</td></tr>
            <tr><td><strong>Customer &amp; Default Service Accounts</strong></td><td class="mono">${k.service_accounts_total}</td><td>${k.default_sas_with_roles_count} Default SAs with active roles • ${k.disabled_sas_count} Disabled • ${k.principals_with_secret_or_kms_access} Principals with Secret/KMS reach</td></tr>
            <tr><td><strong>Service Account Cryptographic Keys</strong></td><td class="mono">${k.user_managed_sa_keys_total} User / ${k.system_managed_sa_keys_total} System</td><td>${k.sa_keys_over_90d_count} static keys &gt;90 days • ${k.user_uploaded_sa_keys_count} user-uploaded keys</td></tr>
            <tr><td><strong>Secret Manager Secrets (Metadata-Only)</strong></td><td class="mono">${k.secrets_total_count} (${k.secret_versions_enabled_count} versions)</td><td>${k.secrets_unrotated_count} without rotation policy • ${k.secrets_without_cmek_count} without CMEK</td></tr>
            <tr><td><strong>Cloud KMS KeyRings &amp; CryptoKeys</strong></td><td class="mono">${k.kms_cryptokeys_total} Keys / ${k.kms_keyrings_count} Rings</td><td>${k.kms_keys_missing_90d_rotation_count} missing &le;90d rotation • ${k.kms_hsm_keys_count} HSM • ${k.kms_sod_conflicts_count} KMS Admin+Decrypter SoD conflicts</td></tr>
            <tr><td><strong>API Keys, Custom Roles &amp; WIF</strong></td><td class="mono">${k.api_keys_total_count} API Keys / ${k.custom_roles_total_count} Roles</td><td>${k.unrestricted_api_keys_count} unrestricted API keys • ${k.custom_roles_with_escalation_perms_count} Custom Roles with escalation perms • ${k.wif_pools_count} WIF Pools (${k.org_policies_enforced_count}/${k.org_policies_evaluated_count} Org Policies enforced)</td></tr>
          </tbody>
        </table></div>` : '';

      const iac = book.iac_bundle || {};
      const sims = iac.policy_simulations || [];
      const iacWin = (iac.audit_sample_window_start || iac.audit_sample_window_end)
        ? `${(iac.audit_sample_window_start || '').slice(0, 10)} a ${(iac.audit_sample_window_end || '').slice(0, 10)}`
        : 'janela indisponível';
      const iacSampleCount = Number(iac.audit_sample_size || 0);

      el.innerHTML = `
        <div class="chapter-h2" style="margin-top:1.5rem;">2. Posture Scorecard &amp; 5 Security Framework Benchmarks (${sc.overall_posture_score}% — ${escHtml(sc.maturity_tier)})</div>
        <div class="table-container"><table>
          <thead><tr><th>Security Framework Benchmark</th><th>Alignment %</th><th>Controls &ge;85%</th><th>Primary Focus</th></tr></thead>
          <tbody>${bmHtml}</tbody>
        </table></div>
        ${vaultHtml}
        <div class="chapter-h2" style="margin-top:1.5rem;">4. Identity Triad Findings (${findings.length}) &amp; Attack Paths (${paths.length})</div>
        <div class="table-container"><table>
          <thead><tr><th>ID</th><th>Severity</th><th>Principal &amp; Role</th><th>Recommended Modernization</th></tr></thead>
          <tbody>${findings.map(f => `<tr><td class="mono">${escHtml(f.finding_id)}</td><td><span class="tag ${sevTagClass(f.severity)}">${escHtml(f.severity)}</span></td><td class="mono">${escHtml(f.principal)} (${escHtml(f.role)})</td><td>${escHtml(f.recommended_modernization)}</td></tr>`).join('') || '<tr><td colspan="4">No findings in scope.</td></tr>'}</tbody>
        </table></div>
        <div class="chapter-h2" style="margin-top:1.5rem;">5. Least-Privilege Right-Sizing &amp; PAM JIT Entitlements (${recs.length})</div>
        <div class="table-container"><table>
          <thead><tr><th>ID &amp; Persona</th><th>Principal</th><th>Current Role &rarr; Proposed</th><th>Surface Reduction</th></tr></thead>
          <tbody>${recs.map(r => `<tr><td class="mono">${escHtml(r.recommendation_id)} (${escHtml(r.persona_classification)})</td><td class="mono">${escHtml(r.principal)}</td><td class="mono">${escHtml(r.current_role)} &rarr; ${escHtml(r.proposed_role_or_entitlement)}</td><td><span class="tag tag-low">-${r.permission_reduction_pct}%</span></td></tr>`).join('') || '<tr><td colspan="4">No recommendations in scope.</td></tr>'}</tbody>
        </table></div>
        <div class="chapter-h2" style="margin-top:1.5rem;">6. Estimativa de impacto e bundle Terraform consultivo (não validado)</div>
        <p style="font-size:0.78rem; color:var(--text-muted); margin-bottom:0.5rem;">Bundle consultivo sem validação por Policy Simulator replay • <strong>${iacSampleCount} eventos na amostra</strong> (janela: ${escHtml(iacWin)}).</p>
        <div class="table-container"><table>
          <thead><tr><th>Estimate ID</th><th>Principal</th><th>Eventos na amostra</th><th>Verdict</th></tr></thead>
          <tbody>${sims.map(s => `<tr><td class="mono">${escHtml(s.simulation_id)}</td><td class="mono">${escHtml(s.principal)}</td><td class="mono">${Number(s.sample_events_observed || 0)} eventos na amostra (${escHtml(iacWin)})</td><td><span class="tag tag-med">${escHtml(s.simulator_verdict)}</span></td></tr>`).join('') || '<tr><td colspan="4">No impact estimates in scope.</td></tr>'}</tbody>
        </table></div>
        <p style="margin-top:1rem; font-size:0.8rem; color:var(--text-muted);">Download the <strong>Full Word (.docx)</strong> or <strong>Full PDF (.pdf)</strong> above for all 7 complete sections, including every individual Account, Service Account, SA Key, Secret Manager entry, KMS CryptoKey, API Key, Custom Role, WIF Pool, Choke-Point Centrality table, and all 5 advisory Terraform HCL modules.</p>
      `;
    }

    // =========================================================================
    // ACCESSIBLE KPI CALCULATION RATIONALE POPOVER (HOVER + KEYBOARD FOCUS)
    // =========================================================================
    let _kpiHideTimer = null;
    let _activeKpiAnchor = null;

    function _kpiRow(label, value, valueColor) {
      const style = valueColor ? ` style="color:${valueColor};"` : '';
      return `<div class="kpi-pop-row"><span class="kpi-pop-row-k">${escHtml(label)}</span><span class="kpi-pop-row-v"${style}>${escHtml(value)}</span></div>`;
    }

    function buildKpiRationaleHtml(kpiKey, book) {
      const sc = book && book.scorecard ? book.scorecard : null;
      const tm = book && book.triad_matrix ? book.triad_matrix : null;
      const recs = (book && Array.isArray(book.recommendations)) ? book.recommendations : [];
      const notEval = new Set((sc && sc.not_evaluated_domains) || []);

      if (kpiKey === 'overall') {
        if (!sc) {
          return `<div class="kpi-pop-hdr"><span class="kpi-pop-title">Overall Posture Health</span><span class="kpi-pop-badge">Formula</span></div>
            <div class="kpi-pop-label">Methodology</div>
            <div class="kpi-pop-formula">Final = clamp(22% Internal + 18% External + 22% Workload + 20% Least-Privilege + 18% Resilience + ADK_Delta[-5,+5] + Cap_Effect, 0, 100)</div>
            <div class="kpi-pop-note">Connect a GCP Organization and run an ADK scan to see live weighted contributions per pillar, bounded ADK calibration, and ceiling gate checks.</div>`;
        }
        const pillars = [
          { key: 'INTERNAL_IDENTITIES', name: '1. Internal Workforce & Group RBAC', baseW: 22, score: Number(sc.internal_identities_score || 0) },
          { key: 'EXTERNAL_IDENTITIES', name: '2. External Identities & DRS', baseW: 18, score: Number(sc.external_identities_score || 0) },
          { key: 'WORKLOAD_IDENTITIES', name: '3. Workload & SA Hygiene (WIF)', baseW: 22, score: Number(sc.workload_identities_score || 0) },
          { key: 'LEAST_PRIVILEGE', name: '4. Least-Privilege Index', baseW: 20, score: Number(sc.least_privilege_index || 0) },
          { key: 'GRAPH_RESILIENCE', name: '5. Impersonation & Escalation Resilience', baseW: 18, score: Number(sc.impersonation_resilience_score || 0) }
        ];
        const activeWeightSum = pillars.reduce((acc, p) => acc + (notEval.has(p.key) ? 0 : p.baseW), 0) || 100;
        const pillarRows = pillars.map(p => {
          if (notEval.has(p.key)) {
            return _kpiRow(`${p.name} (excluded)`, 'N/A (weight renormalized)', 'var(--text-muted)');
          }
          const effW = (p.baseW / activeWeightSum) * 100;
          const contrib = (p.score * (p.baseW / activeWeightSum));
          const wLabel = Math.abs(effW - p.baseW) > 0.05 ? `${effW.toFixed(1)}% renorm` : `${p.baseW}%`;
          return _kpiRow(`${p.name} (${wLabel})`, `${p.score.toFixed(1)}% -> +${contrib.toFixed(2)} pts`, scoreTextColor(p.score));
        }).join('');

        const detBase = Number(sc.deterministic_composite_score ?? sc.overall_posture_score ?? 0);
        const adkDelta = Number(sc.agentic_calibration_delta || 0);
        const preCap = Number(sc.pre_cap_score ?? (detBase + adkDelta));
        const capDelta = Number(sc.critical_cap_delta || 0);
        const completeness = Number(sc.data_completeness_pct ?? 100);
        const deltaStr = adkDelta >= 0 ? `+${adkDelta.toFixed(1)}%` : `${adkDelta.toFixed(1)}%`;
        const capStr = capDelta < 0 ? `${capDelta.toFixed(1)}% (<=84% ceiling)` : '0.0% (not triggered)';
        const capNote = sc.critical_exposure_cap_applied
          ? `Critical Exposure Ceiling triggered: ${sc.critical_exposure_cap_applied}.`
          : 'Tiers: Optimized (>=85%, 100% completeness), Managed (70-84.9%, or max tier when completeness <100%), Developing (50-69.9%), Initial (<50%). The <=84% ceiling triggers only on public bindings or >90d static SA keys without disableServiceAccountKeyCreation when Pre-Cap > 84%.';

        return `<div class="kpi-pop-hdr"><span class="kpi-pop-title">Overall Posture Health</span><span class="kpi-pop-badge" style="color:${scoreTextColor(sc.overall_posture_score)};">${Number(sc.overall_posture_score).toFixed(1)}% • ${escHtml(sc.maturity_tier)}</span></div>
          <div class="kpi-pop-label">Formula</div>
          <div class="kpi-pop-formula">Final = 18-Control Weighted Baseline (${detBase.toFixed(1)}%) + ADK Calibration (${deltaStr}) + Cap (${capDelta.toFixed(1)}%)</div>
          <div class="kpi-pop-label">Live Pillar Contributions (Weighted)</div>
          <div class="kpi-pop-rows">${pillarRows}</div>
          <div class="kpi-pop-label">Calibration, Ceiling &amp; Scope</div>
          <div class="kpi-pop-rows">
            ${_kpiRow('18-Control Deterministic Baseline', `${detBase.toFixed(1)}%`, '#8AB4F8')}
            ${_kpiRow('Bounded ADK Calibration ([-5%, +5%])', deltaStr, adkDelta >= 0 ? '#8CE99A' : '#FFD43B')}
            ${_kpiRow('Pre-Cap Composite Score', `${preCap.toFixed(1)}%`)}
            ${_kpiRow('Critical Exposure Gate (<=84% cap)', capStr, capDelta < 0 ? '#FFA8A8' : 'var(--text-muted)')}
            ${_kpiRow('Bindings Analyzed / Completeness', `${Number(sc.total_bindings_analyzed || 0).toLocaleString()} bindings • ${completeness.toFixed(1)}%`, completeness < 100 ? '#FFD43B' : '#8CE99A')}
          </div>
          <div class="kpi-pop-note">${escHtml(capNote)}</div>`;
      }

      if (kpiKey === 'compliant') {
        if (!tm) {
          return `<div class="kpi-pop-hdr"><span class="kpi-pop-title">Compliant Principals</span><span class="kpi-pop-badge">Formula</span></div>
            <div class="kpi-pop-label">Methodology</div>
            <div class="kpi-pop-formula">(Internal_Compliant + External_Compliant + Workload_Compliant) / Total_Principals_Evaluated</div>
            <div class="kpi-pop-note">Counts every individual human, group, external identity, and Service Account passing all deterministic baseline hygiene rules across the 3 Identity Triad pillars.</div>`;
        }
        const intM = tm.internal_identities || {};
        const extM = tm.external_identities || {};
        const wklM = tm.workload_service_accounts || {};
        const iC = Number(intM.compliant_principals || 0), iT = Number(intM.total_principals_evaluated || 0);
        const eC = Number(extM.compliant_principals || 0), eT = Number(extM.total_principals_evaluated || 0);
        const wC = Number(wklM.compliant_principals || 0), wT = Number(wklM.total_principals_evaluated || 0);
        const cSum = iC + eC + wC;
        const tSum = iT + eT + wT;
        const failSum = Math.max(0, tSum - cSum);
        const passPct = tSum > 0 ? ((cSum / tSum) * 100).toFixed(1) : '0.0';

        return `<div class="kpi-pop-hdr"><span class="kpi-pop-title">Compliant Principals</span><span class="kpi-pop-badge" style="color:#8CE99A;">${cSum}/${tSum} (${passPct}%)</span></div>
          <div class="kpi-pop-label">Formula</div>
          <div class="kpi-pop-formula">(${iC} Internal + ${eC} External + ${wC} Workload) / (${iT} + ${eT} + ${wT}) = ${cSum}/${tSum}</div>
          <div class="kpi-pop-label">Live Pillar Breakdown</div>
          <div class="kpi-pop-rows">
            ${_kpiRow('Internal Workforce (Users & Groups)', `${iC}/${iT} passing (${Math.max(0, iT - iC)} failing)`, iC === iT ? '#8CE99A' : '#FFD43B')}
            ${_kpiRow('External & Partner Identities', `${eC}/${eT} passing (${Math.max(0, eT - eC)} failing)`, eC === eT ? '#8CE99A' : '#FFD43B')}
            ${_kpiRow('Workload & Service Accounts', `${wC}/${wT} passing (${Math.max(0, wT - wC)} failing)`, wC === wT ? '#8CE99A' : '#FFD43B')}
            ${_kpiRow('Non-Compliant Principals Total', `${failSum} failing >=1 baseline check`, failSum > 0 ? '#FFA8A8' : '#8CE99A')}
          </div>
          <div class="kpi-pop-label">Baseline Pass Criteria</div>
          <ul class="kpi-pop-list">
            <li><strong>Internal:</strong> Group-based or JIT-conditioned/single-SA grants; no unconditioned standing Owner/Editor/OrgAdmin/SecurityAdmin; no hierarchy-wide SA impersonation.</li>
            <li><strong>External:</strong> Not allUsers/allAuthenticatedUsers, not consumer Gmail, and zero primitive/admin/impersonation roles.</li>
            <li><strong>Workload SAs:</strong> Verified key status (not UNKNOWN), 0 user-managed keys, no active bindings on Default SAs, and zero primitive roles.</li>
          </ul>
          <div class="kpi-pop-note">A principal can fail baseline hygiene (e.g. a direct non-group user grant or active Default SA binding) without generating a separate Critical/High finding—so failing principals (${failSum}) can exceed Critical &amp; High Gaps.</div>`;
      }

      if (kpiKey === 'lpi') {
        if (!sc) {
          return `<div class="kpi-pop-hdr"><span class="kpi-pop-title">Least-Privilege Index</span><span class="kpi-pop-badge">Formula</span></div>
            <div class="kpi-pop-label">Methodology</div>
            <div class="kpi-pop-formula">LPI = 40% IAM-LPI-01 + 35% IAM-LPI-02 + 25% IAM-LPI-03 (+ ADK Delta[-5,+5])</div>
            <div class="kpi-pop-note">Measures non-primitive role adoption, permission tightness versus observed Cloud Audit Log activity, and IAM Recommender right-sizing backlog.</div>`;
        }
        const ctrls = (sc.control_evaluations || []).filter(c => c.domain === 'LEAST_PRIVILEGE');
        const ctrlById = {};
        ctrls.forEach(c => { ctrlById[c.control_id] = c; });
        const lpiDefs = [
          { id: 'IAM-LPI-01', label: 'Non-Primitive Role Adoption (40%)', w: 40 },
          { id: 'IAM-LPI-02', label: 'Grant Tightness vs. Audit Logs (35%)', w: 35 },
          { id: 'IAM-LPI-03', label: 'Recommender & >=1k-Perm Backlog (25%)', w: 25 }
        ];
        let detNum = 0, detW = 0;
        const ctrlRows = lpiDefs.map(d => {
          const c = ctrlById[d.id];
          if (!c) return _kpiRow(`${d.id} — ${d.label}`, 'Pending');
          if (String(c.status || '').toUpperCase() === 'NOT_EVALUATED') {
            return _kpiRow(`${d.id} (${d.w}% excluded)`, 'NOT_EVALUATED', 'var(--text-muted)');
          }
          const pct = Number(c.deterministic_score_pct || 0);
          detNum += pct * d.w;
          detW += d.w;
          return _kpiRow(`${d.id} — ${d.label}`, `${c.numerator}/${c.denominator} = ${pct.toFixed(1)}%`, scoreTextColor(pct));
        }).join('');
        const detLpi = detW > 0 ? (detNum / detW) : Number(sc.least_privilege_index || 0);
        const finalLpi = Number(sc.least_privilege_index || 0);
        const lpiDelta = finalLpi - detLpi;
        const lpiDeltaStr = Math.abs(lpiDelta) >= 0.05 ? `${lpiDelta >= 0 ? '+' : ''}${lpiDelta.toFixed(1)}%` : '0.0%';
        const excessPerms = Number(sc.excess_permissions_eliminated || 0);
        const overprivCnt = Number(sc.overprivileged_bindings_count || 0);

        return `<div class="kpi-pop-hdr"><span class="kpi-pop-title">Least-Privilege Index</span><span class="kpi-pop-badge" style="color:${scoreTextColor(finalLpi)};">${finalLpi}%</span></div>
          <div class="kpi-pop-label">Formula</div>
          <div class="kpi-pop-formula">LPI = 0.40 * LPI-01 + 0.35 * LPI-02 + 0.25 * LPI-03 (+ bounded ADK delta)</div>
          <div class="kpi-pop-label">Live Control Breakdown</div>
          <div class="kpi-pop-rows">
            ${ctrlRows}
            ${_kpiRow('Deterministic LPI / ADK Calibration', `${detLpi.toFixed(1)}% (${lpiDeltaStr}) -> ${finalLpi.toFixed(1)}%`, '#8AB4F8')}
          </div>
          <div class="kpi-pop-label">Excess Permissions Removable</div>
          <div class="kpi-pop-rows">
            ${_kpiRow('Removable Permissions (Sum across Recs)', `${excessPerms.toLocaleString()} perms across ${recs.length} rec(s)`, '#8CE99A')}
            ${_kpiRow('Overprivileged Bindings Flagged', `${overprivCnt} binding(s)`, overprivCnt > 0 ? '#FFD43B' : '#8CE99A')}
          </div>
          <div class="kpi-pop-note">IAM-LPI-02 scores each binding via <code>1 - min(1, max(0, granted - max(exercised, 40)) / 2500)</code> (with a 75% waste discount when an upper-bounded temporal CEL JIT condition exists). Removable permissions equal the sum of <code>granted_perms - proposed_role_perms</code> across right-sizing recommendations.</div>`;
      }

      // Default: crithigh (Critical & High Gaps)
      if (!sc || !tm) {
        return `<div class="kpi-pop-hdr"><span class="kpi-pop-title">Critical &amp; High Gaps</span><span class="kpi-pop-badge">Formula</span></div>
          <div class="kpi-pop-label">Methodology</div>
          <div class="kpi-pop-formula">Critical_High_Gaps = Critical_Findings + High_Findings (Telemetry-Grounded)</div>
          <div class="kpi-pop-note">Counts strictly telemetry-grounded Critical and High findings verified against live CAI bindings and resources before scoring.</div>`;
      }
      const crit = Number(sc.critical_findings || 0);
      const high = Number(sc.high_findings || 0);
      const med = Number(sc.medium_findings || 0);
      const low = Number(sc.low_findings || 0);
      const totalF = crit + high + med + low;
      const intM = tm.internal_identities || {};
      const extM = tm.external_identities || {};
      const wklM = tm.workload_service_accounts || {};
      const findings = Array.isArray(tm.findings) ? tm.findings : [];
      const topCritHigh = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 4);
      const dropped = Number((book.telemetry && book.telemetry.ungrounded_findings_dropped) || 0);
      const topListHtml = topCritHigh.length > 0
        ? `<div class="kpi-pop-label">Counted Critical &amp; High Findings</div><ul class="kpi-pop-list">${topCritHigh.map(f => `<li><strong>[${escHtml(f.severity)}]</strong> ${escHtml(f.title || f.finding_id)} <span class="mono" style="color:#8AB4F8;">(${escHtml(String(f.principal || '').split(':').pop())})</span></li>`).join('')}${crit + high > topCritHigh.length ? `<li>+${(crit + high) - topCritHigh.length} additional Critical/High finding(s) in Triad Matrix</li>` : ''}</ul>`
        : '';
      const groundNote = dropped > 0
        ? `Every finding is deterministically verified against live CAI bindings/resources (${dropped} unverified LLM finding(s) were automatically dropped before counting).`
        : 'Every finding is deterministically verified against live CAI bindings/resources (principal, role, and resource) before counting.';

      return `<div class="kpi-pop-hdr"><span class="kpi-pop-title">Critical &amp; High Gaps</span><span class="kpi-pop-badge" style="color:${(crit + high) > 0 ? '#FFA8A8' : '#8CE99A'};">${crit + high} (${crit}C / ${high}H)</span></div>
        <div class="kpi-pop-label">Formula</div>
        <div class="kpi-pop-formula">Critical (${crit}) + High (${high}) = ${crit + high} priority gaps (out of ${totalF} grounded findings)</div>
        <div class="kpi-pop-label">Severity &amp; Pillar Distribution</div>
        <div class="kpi-pop-rows">
          ${_kpiRow('Critical / High', `${crit} Critical • ${high} High`, (crit + high) > 0 ? '#FFA8A8' : '#8CE99A')}
          ${_kpiRow('Medium / Low', `${med} Medium • ${low} Low`, 'var(--text-muted)')}
          ${_kpiRow('Internal Workforce Pillar', `${Number(intM.critical_findings_count || 0)}C • ${Number(intM.high_findings_count || 0)}H`)}
          ${_kpiRow('External & Partner Pillar', `${Number(extM.critical_findings_count || 0)}C • ${Number(extM.high_findings_count || 0)}H`)}
          ${_kpiRow('Workload & Service Accounts Pillar', `${Number(wklM.critical_findings_count || 0)}C • ${Number(wklM.high_findings_count || 0)}H`)}
        </div>
        ${topListHtml}
        <div class="kpi-pop-note">${escHtml(groundNote)}</div>`;
    }

    function positionKpiRationalePopover(anchorEl) {
      const pop = document.getElementById('kpiRationalePopover');
      if (!pop || !anchorEl) return;
      const rect = anchorEl.getBoundingClientRect();
      const pad = 12;
      const popRect = pop.getBoundingClientRect();
      const popW = popRect.width || 420;
      const popH = popRect.height || 260;

      let left = rect.left + (rect.width / 2) - (popW / 2);
      left = Math.max(pad, Math.min(left, window.innerWidth - popW - pad));

      let top = rect.bottom + 10;
      if (top + popH > window.innerHeight - pad && rect.top - popH - 10 >= pad) {
        top = rect.top - popH - 10;
      } else if (top + popH > window.innerHeight - pad) {
        top = Math.max(pad, window.innerHeight - popH - pad);
      }

      pop.style.left = `${Math.round(left)}px`;
      pop.style.top = `${Math.round(top)}px`;
    }

    function showKpiRationalePopover(anchorEl) {
      const pop = document.getElementById('kpiRationalePopover');
      if (!pop || !anchorEl) return;
      const key = anchorEl.getAttribute('data-kpi-rationale');
      if (!key) return;
      if (_kpiHideTimer) { clearTimeout(_kpiHideTimer); _kpiHideTimer = null; }
      _activeKpiAnchor = anchorEl;
      pop.innerHTML = buildKpiRationaleHtml(key, latestBook);
      pop.setAttribute('aria-hidden', 'false');
      pop.classList.add('visible');
      positionKpiRationalePopover(anchorEl);
    }

    function scheduleHideKpiRationalePopover(delayMs = 140) {
      if (_kpiHideTimer) clearTimeout(_kpiHideTimer);
      _kpiHideTimer = setTimeout(() => {
        const pop = document.getElementById('kpiRationalePopover');
        if (!pop) return;
        pop.classList.remove('visible');
        pop.setAttribute('aria-hidden', 'true');
        _activeKpiAnchor = null;
      }, delayMs);
    }

    function initKpiRationalePopovers() {
      const pop = document.getElementById('kpiRationalePopover');
      if (!pop) return;
      document.querySelectorAll('.stat-card[data-kpi-rationale]').forEach(card => {
        card.addEventListener('mouseenter', () => showKpiRationalePopover(card));
        card.addEventListener('mouseleave', () => scheduleHideKpiRationalePopover(140));
        card.addEventListener('focus', () => showKpiRationalePopover(card));
        card.addEventListener('blur', () => scheduleHideKpiRationalePopover(100));
        card.addEventListener('click', () => scheduleHideKpiRationalePopover(0));
      });
      pop.addEventListener('mouseenter', () => {
        if (_kpiHideTimer) { clearTimeout(_kpiHideTimer); _kpiHideTimer = null; }
      });
      pop.addEventListener('mouseleave', () => scheduleHideKpiRationalePopover(120));
      window.addEventListener('keydown', (ev) => {
        if (ev.key === 'Escape') scheduleHideKpiRationalePopover(0);
      });
      window.addEventListener('scroll', () => {
        if (_activeKpiAnchor) positionKpiRationalePopover(_activeKpiAnchor);
      }, { passive: true });
      window.addEventListener('resize', () => {
        if (_activeKpiAnchor) positionKpiRationalePopover(_activeKpiAnchor);
      });
    }

    async function runAdkChat() {
      if (!sessionConnected || !currentScope()) {
        showTab('onboarding');
        showConnFeedback('Connect a target GCP Organization first before querying the ADK Coordinator.', true);
        return;
      }
      const btn = document.getElementById('runBtn');
      const out = document.getElementById('agentOutput');
      const prompt = document.getElementById('agentPrompt').value;
      const scope = currentScope();
      const model = currentModel();
      btn.disabled = true;
      btn.innerText = 'Running...';
      out.innerText = `Executing Google ADK iam_coordinator (${model}, location=global) on ${scope}...`;
      try {
        const res = await fetch('/api/v1/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
          body: JSON.stringify({ prompt: prompt, scope: scope, model: model })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        updateTelemetryBar(data.telemetry);
        out.innerText = `[Model: ${data.model_version} | Location: ${data.location} | Tokens: ${data.tokens.total_tokens} | Tool Calls: ${data.tool_calls.length}]\n\n` + data.response;
      } catch (err) {
        out.innerText = 'Google ADK Execution Error: ' + err.message;
      } finally {
        btn.disabled = !sessionConnected;
        btn.innerText = 'Ask ADK Coordinator';
      }
    }

    function openOAuthBridgePopup() {
      const w = 500, h = 620;
      const left = Math.max(0, Math.round((window.screen.width - w) / 2));
      const top = Math.max(0, Math.round((window.screen.height - h) / 2));
      const bridgeUrl = `${window.location.origin}/api/v1/auth/bridge`;
      window.open(bridgeUrl, 'iam_google_signin_bridge', `width=${w},height=${h},left=${left},top=${top},resizable=yes,scrollbars=yes`);
    }

    async function submitGoogleCredential(payload) {
      const errEl = document.getElementById('authErrorMsg');
      errEl.style.display = 'none';
      try {
        const res = await fetch('/api/v1/auth/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Authentication failed');
        isAuthenticatedUser = true;
        hasSigninOAuthToken = !!data.has_user_access_token;
        updateTokenStatusHint();
        document.getElementById('callerBadgeText').innerText = data.email;
        refreshInlineSaSetupGuide();
        const obEmail = document.getElementById('obUserEmail');
        if (obEmail && !obEmail.value) obEmail.value = data.email;
        const cliInp = document.getElementById('cliTokenInput');
        if (cliInp) cliInp.value = '';
        document.getElementById('iapAuthGate').style.display = 'none';
        await checkInitialSessionStatus();
      } catch (err) {
        errEl.innerText = err.message || String(err);
        errEl.style.display = 'block';
      }
    }

    function verifyCliAccessToken() {
      const tok = document.getElementById('cliTokenInput').value.trim();
      if (!tok) return;
      submitGoogleCredential({ access_token: tok });
    }

    window.addEventListener('click', () => {
      closeProjPopover();
    });

    window.addEventListener('message', (ev) => {
      if (ev.origin !== window.location.origin) return;
      if (ev.data && ev.data.type === 'AGENTIC_GOOGLE_AUTH') {
        submitGoogleCredential(ev.data);
      }
    });

    window.addEventListener('DOMContentLoaded', async () => {
      initKpiRationalePopovers();
      onConnectionModeChange();
      await checkInitialSessionStatus();
    });
  </script>
</body>
</html>"""

    caller_email_clean = caller["email"] if is_authenticated else ""
    has_js_oauth_client = bool(configured_oauth_client_id())

    html_doc = (
        template.replace("__AUTH_DISPLAY__", "none" if is_authenticated else "flex")
        .replace("__JS_OAUTH_DISPLAY__", "inline-flex" if has_js_oauth_client else "none")
        .replace("__IS_AUTH_JSON__", json.dumps(bool(is_authenticated)))
        .replace("__CALLER_EMAIL__", html.escape(caller["email"]))
        .replace("__CALLER_EMAIL_CLEAN__", html.escape(caller_email_clean))
        .replace("__ACTIVE_MODEL__", html.escape(settings.vertex_model_id))
        .replace("__ACTIVE_MODEL_JSON__", json.dumps(settings.vertex_model_id))
        .replace("__DELEGATION_SA_JSON__", json.dumps(configured_delegation_sa_email()))
        .replace("__AUTO_RENEW_DISPLAY__", "block" if persistent_delegation_enabled() else "none")
        .replace("__RETENTION_OPTIONS_HTML__", _retention_options_html())
        .replace("__FAVICON_DATA_URI__", _FAVICON_DATA_URI or "/favicon.png?v=3")
    )
    return HTMLResponse(content=html_doc)
