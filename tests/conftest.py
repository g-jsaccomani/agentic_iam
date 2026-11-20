"""Shared offline test fixtures for Agentic IAM Accelerator (`tests/conftest.py`).

Guarantees that the entire test suite runs 100% offline with zero real GCP/Vertex AI
credentials and zero outbound network requests:
- `offline_test_environment` (autouse): isolates workspace/session storage in `tmp_path`,
  strips real GCP credential environment variables, and blocks `google.auth.default`.
- `block_outbound_httpx` (autouse): fails any test that attempts an unmocked outbound
  HTTP request via `httpx` (sync or async), while preserving in-process ASGI/Mock transports.
- `fake_session`: builds a synthetic `InspectionSession` and binds it via
  `bind_inspection_session_context`.
- `fake_gcp`: replaces `backend.tools.cai_collector.gcp_rest_request` (and its bound
  imports across tool modules) with an in-memory `(method, url) -> (status, payload)` router.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Pattern, Sequence, Tuple, Union

import google.auth
import httpx
import pytest

# Ensure the repository root is always importable under `pytest -q`
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

def _offline_env_default(name: str, value: str) -> None:
    """Applies an offline default when the variable is missing OR empty.

    CI exports some of these variables as empty strings on purpose (zero credentials), and
    `os.environ.setdefault` would keep the empty value.
    """
    if not (os.environ.get(name) or "").strip():
        os.environ[name] = value


# Safe offline defaults before any `backend.*` module executes import-time setup
_offline_env_default("GOOGLE_GENAI_USE_VERTEXAI", "TRUE")
_offline_env_default("GOOGLE_CLOUD_PROJECT", "test-offline-project")
_offline_env_default("IAM_SESSION_SECRET", "test-offline-session-secret")
_offline_env_default(
    "AGENTIC_IAM_LOCAL_STORE_DIR",
    str(Path(tempfile.gettempdir()) / "agentic_iam_pytest_workspaces"),
)


class OfflineNetworkError(RuntimeError):
    """Raised whenever a test attempts an unmocked outbound network call via `httpx`."""


class OfflineCredentialError(RuntimeError):
    """Raised whenever a test attempts to load real GCP Application Default Credentials."""


def _blocked_google_auth_default(*args: Any, **kwargs: Any) -> Any:
    raise OfflineCredentialError(
        "Blocked google.auth.default() in offline test suite. "
        "Tests must run without real GCP/Vertex AI credentials."
    )


# Prevent backend.config.install_gcloud_adc_fallback from installing a gcloud subprocess hook on import
_blocked_google_auth_default._agentic_iam_patched = True  # type: ignore[attr-defined]
google.auth.default = _blocked_google_auth_default  # type: ignore[assignment]


@dataclass
class _FakeGcpRoute:
    method: str
    matcher: Union[str, Pattern[str]]
    handler: Callable[..., Tuple[int, Dict[str, Any]]]

    def matches(self, method: str, url: str) -> bool:
        if self.method != "*" and self.method != method.upper():
            return False
        if isinstance(self.matcher, re.Pattern):
            return self.matcher.search(url) is not None
        return url == self.matcher


class FakeGcpRouter:
    """In-memory router replacing `backend.tools.cai_collector.gcp_rest_request`."""

    def __init__(self) -> None:
        self._routes: List[_FakeGcpRoute] = []
        self._default_response: Optional[Tuple[int, Dict[str, Any]]] = None
        self.calls: List[Dict[str, Any]] = []

    def add(
        self,
        method: str,
        url: Union[str, Pattern[str]],
        status: int = 200,
        data: Optional[Dict[str, Any]] = None,
        *,
        handler: Optional[Callable[..., Tuple[int, Dict[str, Any]]]] = None,
    ) -> "FakeGcpRouter":
        """Registers an exact URL or regex route for `(method, url)`."""
        if handler is None:
            payload = dict(data) if data is not None else {}

            def _static_handler(
                _method: str,
                _url: str,
                _params: Optional[Dict[str, Any]],
                _json_body: Optional[Dict[str, Any]],
            ) -> Tuple[int, Dict[str, Any]]:
                return status, dict(payload)

            resolved_handler = _static_handler
        else:
            resolved_handler = handler

        self._routes.append(
            _FakeGcpRoute(
                method=method.upper(),
                matcher=url,
                handler=resolved_handler,
            )
        )
        return self

    def add_sequence(
        self,
        method: str,
        url: Union[str, Pattern[str]],
        responses: Sequence[Tuple[int, Dict[str, Any]]],
    ) -> "FakeGcpRouter":
        """Registers a sequence of `(status, payload)` responses for repeated calls (e.g., pagination)."""
        queue = list(responses)
        if not queue:
            raise ValueError("responses sequence must contain at least one (status, payload) entry.")

        def _seq_handler(
            _method: str,
            _url: str,
            _params: Optional[Dict[str, Any]],
            _json_body: Optional[Dict[str, Any]],
        ) -> Tuple[int, Dict[str, Any]]:
            status_code, payload = queue.pop(0) if len(queue) > 1 else queue[0]
            return status_code, dict(payload)

        return self.add(method, url, handler=_seq_handler)

    def set_default(self, status: int, data: Optional[Dict[str, Any]] = None) -> "FakeGcpRouter":
        """Configures a fallback `(status, payload)` for unmatched requests."""
        self._default_response = (status, dict(data) if data is not None else {})
        return self

    def __call__(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: float = 20.0,
        quota_project: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        method_upper = method.upper()
        self.calls.append(
            {
                "method": method_upper,
                "url": url,
                "params": dict(params) if params is not None else None,
                "json_body": dict(json_body) if json_body is not None else None,
                "timeout": timeout,
                "quota_project": quota_project,
            }
        )
        for route in reversed(self._routes):
            if route.matches(method_upper, url):
                return route.handler(method_upper, url, params, json_body)
        if self._default_response is not None:
            status_code, payload = self._default_response
            return status_code, dict(payload)
        raise AssertionError(
            f"Unregistered fake_gcp request: {method_upper} {url} "
            f"(params={params!r}, json_body={json_body!r})"
        )


@pytest.fixture(autouse=True)
def offline_test_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Keeps every test isolated from workstation credentials, GCS buckets, and local export dirs."""
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("WORKSPACE_STATE_BUCKET", raising=False)
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "TRUE")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-offline-project")
    monkeypatch.setenv("IAM_SESSION_SECRET", "test-offline-session-secret")
    monkeypatch.setenv("AGENTIC_IAM_LOCAL_STORE_DIR", str(tmp_path / "workspaces"))

    monkeypatch.setattr(google.auth, "default", _blocked_google_auth_default)

    if "backend.workspace_store" in sys.modules:
        ws_mod = sys.modules["backend.workspace_store"]
        monkeypatch.setattr(ws_mod, "_LOCAL_STORE_ROOT", tmp_path / "workspaces")
        monkeypatch.setattr(ws_mod, "_MASTER_KEY_CACHE", None)

    if "backend.session_vault" in sys.modules:
        sv_mod = sys.modules["backend.session_vault"]
        monkeypatch.setattr(sv_mod, "_SESSION_ROOT_DIR", tmp_path / "sessions")

    if "backend.identity_guard" in sys.modules:
        ig_mod = sys.modules["backend.identity_guard"]
        ig_mod.clear_auth_caches_for_tests()


@pytest.fixture(autouse=True)
def block_outbound_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fails any test where `httpx` tries to send an outbound network request.

    Patches `HTTPTransport.handle_request` and `AsyncHTTPTransport.handle_async_request` so
    both top-level `httpx.get(...)` calls and pre-initialized `httpx.Client()` instances fail
    immediately, while in-process ASGI/Mock transports (such as FastAPI `TestClient`) continue
    to work offline.
    """

    def _blocked_sync(self: httpx.HTTPTransport, request: httpx.Request) -> httpx.Response:
        raise OfflineNetworkError(
            f"Outbound network request blocked in offline test: {request.method} {request.url}. "
            "Mock the call with `fake_gcp` or an in-memory `httpx.MockTransport`."
        )

    async def _blocked_async(
        self: httpx.AsyncHTTPTransport,
        request: httpx.Request,
    ) -> httpx.Response:
        raise OfflineNetworkError(
            f"Outbound async network request blocked in offline test: {request.method} {request.url}. "
            "Mock the call with `fake_gcp` or an in-memory `httpx.MockTransport`."
        )

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _blocked_sync)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _blocked_async)


@pytest.fixture
def fake_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[Any]:
    """Creates a synthetic `InspectionSession` and binds it via `bind_inspection_session_context`."""
    from backend import session_vault

    monkeypatch.setattr(session_vault, "_SESSION_ROOT_DIR", tmp_path / "sessions")
    sess = session_vault.InspectionSession(
        session_id="test-session-001",
        owner_email="tester@example.com",
        connection_mode="impersonated_sa",
        base_user_access_token="fake-user-oauth-token",
        impersonated_sa_email="sa-iam-assessor@test-offline-project.iam.gserviceaccount.com",
        effective_access_token="fake-sa-access-token",
        token_expires_at=time.time() + 3600.0,
        organization_id="123456789012",
        organization_domain="example.com",
        customer_name="Example Corp",
        selected_scope="organizations/123456789012",
    )
    try:
        with session_vault.bind_inspection_session_context(sess):
            yield sess
    finally:
        for hook in list(session_vault._CACHE_PURGE_HOOKS):
            try:
                hook(sess.session_id)
            except Exception:
                pass


@pytest.fixture
def fake_gcp(monkeypatch: pytest.MonkeyPatch) -> FakeGcpRouter:
    """Replaces `backend.tools.cai_collector.gcp_rest_request` with an in-memory router."""
    import importlib

    from backend.tools import cai_collector

    original_fn = cai_collector.gcp_rest_request
    router = FakeGcpRouter()

    # Import sibling tool modules before patching so `monkeypatch` restores every bound reference
    sibling_modules = (
        "backend.tools.recommender_tool",
        "backend.tools.directory_collector",
        "backend.tools.asset_key_secret_inventory",
        "backend.tools.onboarding_manager",
    )
    for mod_name in sibling_modules:
        importlib.import_module(mod_name)

    monkeypatch.setattr(cai_collector, "gcp_rest_request", router)

    for mod_name, mod in list(sys.modules.items()):
        if (
            mod is not None
            and mod_name.startswith("backend.")
            and getattr(mod, "gcp_rest_request", None) is original_fn
        ):
            monkeypatch.setattr(mod, "gcp_rest_request", router)

    return router
