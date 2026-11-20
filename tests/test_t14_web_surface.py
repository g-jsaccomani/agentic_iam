"""T14 — Web Surface Hardening (Headers, /health, K_SERVICE docs lock, Non-ASCII cookies, CSRF/GET-safety, Path Stripping, Rate Limiting, Opaque Errors)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend import identity_guard as guard_mod
from backend import main as main_mod
from backend import session_vault as vault_mod
from backend.identity_guard import IAM_SESSION_COOKIE, IamConsultantIdentity, mint_consultant_cookie


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    main_mod.reset_rate_limiter_for_tests()
    yield
    main_mod.reset_rate_limiter_for_tests()


def _client_with_session(fake_session, email: str = "tester@example.com") -> TestClient:
    ident = IamConsultantIdentity(
        email=email,
        display_name="T14 Tester",
        domain=email.split("@")[-1],
        subject="sub-t14",
        auth_channel="verified_google_cookie",
    )
    cookie = mint_consultant_cookie(ident)
    # Mirror into workspace_sid matching verified cookie
    ws_sid = guard_mod._deterministic_session_id(email, "sub-t14")
    fake_session.session_id = ws_sid
    fake_session.owner_email = email
    vault_mod._SESSION_VAULT[ws_sid] = fake_session
    client = TestClient(main_mod.app)
    client.cookies.set(IAM_SESSION_COOKIE, cookie)
    return client


def test_html_responses_include_all_security_headers_and_safe_esc_html() -> None:
    client = TestClient(main_mod.app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("referrer-policy") == "no-referrer"
    assert "max-age=" in (resp.headers.get("strict-transport-security") or "")
    assert "frame-ancestors 'none'" in (resp.headers.get("content-security-policy") or "")
    assert "default-src 'self'" in (resp.headers.get("content-security-policy-report-only") or "")

    # Verify escHtml escapes single & double quotes and checkbox uses data-project-id listener
    html = resp.text
    assert "&quot;" in html
    assert "&#39;" in html
    assert 'data-project-id="' in html
    assert "onchange=\"toggleProjectId(" not in html


def test_health_returns_only_status_without_session_id_or_email(fake_session) -> None:
    client = _client_with_session(fake_session)
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"status": "ok"}
    raw = resp.text.lower()
    assert "session_id" not in raw
    assert "tester@example.com" not in raw
    assert "caller" not in raw


def test_k_service_disables_openapi_docs_and_strips_localhost_cors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("K_SERVICE", "agentic-iam-prod")
    client = TestClient(main_mod.app)
    for docs_path in ("/api/docs", "/api/redoc", "/openapi.json"):
        r = client.get(docs_path)
        assert r.status_code == 404, f"{docs_path} must return 404 on Cloud Run"

    r_cors = client.get("/health", headers={"Origin": "http://localhost:8080"})
    assert r_cors.status_code == 200
    assert "localhost" not in (r_cors.headers.get("access-control-allow-origin") or "")


@pytest.mark.asyncio
async def test_non_ascii_cookie_returns_401_not_500() -> None:
    # Direct unit test on cookie verifier
    assert guard_mod.verify_consultant_cookie("caf\u00e9.deadbeef") is None
    assert guard_mod.verify_consultant_cookie("\u65e5\u672c\u8a9e.deadbeef") is None

    # Raw ASGI request carrying non-ASCII bytes in Cookie header (as sent by raw TCP/curl clients)
    responses = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/v1/session/status",
        "raw_path": b"/api/v1/session/status",
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"cookie", f"{IAM_SESSION_COOKIE}=".encode("ascii") + b"caf\xc3\xa9.deadbeef"),
        ],
    }

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        responses.append(message)

    await main_mod.app(scope, _receive, _send)
    start_msg = next(m for m in responses if m["type"] == "http.response.start")
    assert start_msg["status"] == 401


def test_get_book_refresh_true_never_triggers_scan_and_post_requires_csrf_header(
    fake_session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = {"n": 0}

    async def _fail_if_called(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("GET /api/v1/book?refresh=true MUST NEVER run a scan!")

    monkeypatch.setattr(main_mod, "run_posture_book_assessment", _fail_if_called)
    client = _client_with_session(fake_session)

    # GET ?refresh=true must be rejected with 405 and never invoke run_posture_book_assessment
    r_get_refresh = client.get("/api/v1/book", params={"scope": "organizations/123456789012", "refresh": "true"})
    assert r_get_refresh.status_code == 405
    assert called["n"] == 0

    # GET without persisted book also never triggers a live scan (returns 404)
    r_get_cold = client.get("/api/v1/book", params={"scope": "organizations/123456789012"})
    assert r_get_cold.status_code == 404
    assert called["n"] == 0

    # POST without X-Requested-With must be rejected with 403
    r_post_no_csrf = client.post("/api/v1/scans", json={"scope": "organizations/123456789012", "refresh": True})
    assert r_post_no_csrf.status_code == 403
    assert called["n"] == 0


def test_403_domain_rejection_does_not_list_allowed_domains(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOWED_IAP_DOMAINS", "secret-corp.example,internal-bank.example")
    with pytest.raises(main_mod.HTTPException) as exc_info:
        guard_mod._check_email_authorized("outsider@random.org")
    assert exc_info.value.status_code == 403
    detail = str(exc_info.value.detail)
    assert "secret-corp.example" not in detail
    assert "internal-bank.example" not in detail


def test_rate_limiter_returns_429_when_exceeded_and_errors_hide_internal_details(
    fake_session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_RATE_LIMIT_CHAT_PER_MINUTE", "2")

    async def _ok_chat(*args, **kwargs):
        return {
            "response": "ok",
            "model_version": "gemini-3.1-pro-preview-customtools",
            "location": "global",
            "tokens": {"total_tokens": 10},
            "tool_calls": [],
            "telemetry": {},
        }

    monkeypatch.setattr(main_mod, "run_coordinator_chat", _ok_chat)
    client = _client_with_session(fake_session)
    hdrs = {"X-Requested-With": "XMLHttpRequest"}
    payload = {"prompt": "hello", "scope": "organizations/123456789012"}

    assert client.post("/api/v1/chat", json=payload, headers=hdrs).status_code == 200
    assert client.post("/api/v1/chat", json=payload, headers=hdrs).status_code == 200
    r3 = client.post("/api/v1/chat", json=payload, headers=hdrs)
    assert r3.status_code == 429
    assert r3.headers.get("retry-after")

    # Reset limit and verify opaque 502 error with correlation_id (hides raw internal secret text)
    main_mod.reset_rate_limiter_for_tests()

    async def _boom_chat(*args, **kwargs):
        raise RuntimeError("INTERNAL_SECRET_DB_PASSWORD_LEAK")

    monkeypatch.setattr(main_mod, "run_coordinator_chat", _boom_chat)
    r_err = client.post("/api/v1/chat", json=payload, headers=hdrs)
    assert r_err.status_code == 502
    assert "INTERNAL_SECRET_DB_PASSWORD_LEAK" not in r_err.text
    assert "correlation_id=" in r_err.json()["detail"]
    assert r_err.headers.get("x-correlation-id")


def test_strip_server_paths_removes_all_local_filesystem_keys() -> None:
    sample = {
        "scope": "organizations/123456789012",
        "deliverable_paths": {"executive_docx_report": "/tmp/secret/report.docx"},
        "manifest_json": "/tmp/secret/manifest.json",
        "deliverables_manifest_json": "/tmp/secret/dmanifest.json",
        "session_jsonl_path": "/tmp/secret/findings.jsonl",
        "iac_bundle": {
            "bundle_id": "iac-1",
            "bundle_zip_path": "/tmp/secret/bundle.zip",
            "main_tf": "terraform {}",
        },
        "deliverables": {
            "executive_docx_report": "/tmp/secret/report.docx",
            "terraform_directory": "/tmp/secret/tf",
        },
    }
    cleaned = main_mod._strip_server_paths(sample)
    raw = str(cleaned)
    assert "/tmp/secret/" not in raw
    assert "deliverable_paths" not in cleaned
    assert "manifest_json" not in cleaned
    assert "deliverables_manifest_json" not in cleaned
    assert "session_jsonl_path" not in cleaned
    assert "bundle_zip_path" not in cleaned["iac_bundle"]
    assert "terraform_directory" not in cleaned["deliverables"]
    assert cleaned["deliverables"]["executive_docx_report"] is True
