"""Offline unit & API tests for T04 — Authentication Hardening (H1, H2, M1).

Covers all 7 requirements and all 5 acceptance criteria:
1. OIDC ID token: requires `audience=IAM_OAUTH_CLIENT_ID`; rejected when unset; no unverified tokeninfo fallback.
2. OAuth2 access token: requires `azp`/`aud` in allowlist (`IAM_OAUTH_CLIENT_ID` + `IAM_ALLOWED_TOKEN_AZP`).
3. OAuth bridge popup (`/api/v1/auth/bridge`): ignores `origin`/`target_origin` query params; `TARGET_ORIGIN`
   is strictly the service's own origin (`IAM_PUBLIC_ORIGIN` or derived from request); `localhost` blocked on Cloud Run.
4. Cloud Run IAP: exact `aud` comparison (no prefix fallback); ignored + warning logged on Cloud Run without
   `IAM_IAP_AUDIENCE`; IAP public keys cached for 1 hour (with rotation refresh).
5. Precedence: valid IAP identity overrides cookie when emails differ, discarding old cookie and minting a new `sid`.
6. Revocation: TTL-backed revoked `sid` registry checked in `verify_consultant_cookie`; populated on logout & disconnect.
7. Event-loop offloading (`asyncio.to_thread`) and <= 60s SHA-256 hash-keyed Bearer verification cache.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import threading
import time
from typing import Any, Dict, Tuple

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from google.auth import jwt as google_jwt
from google.auth.crypt import es256

from backend import identity_guard as ig
from backend import main as main_mod
from backend.identity_guard import (
    IAM_SESSION_COOKIE,
    IAP_CERTS_CACHE_TTL_SECONDS,
    IAP_CERTS_URL,
    IAP_ISSUER,
    IamConsultantIdentity,
    mint_consultant_cookie,
    verify_consultant_cookie,
)


def _generate_es256_keypair(kid: str = "iap-test-kid-1") -> Tuple[es256.ES256Signer, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    signer = es256.ES256Signer.from_string(priv_pem, key_id=kid)
    return signer, pub_pem


def _mint_iap_jwt(
    signer: es256.ES256Signer,
    *,
    kid: str = "iap-test-kid-1",
    email: str = "user_b@example.com",
    sub: str = "accounts.google.com:user-b-sub",
    aud: str = "/projects/123456789012/locations/us-central1/services/agentic-iam-accelerator",
    iss: str = IAP_ISSUER,
    ttl_seconds: int = 600,
) -> str:
    now = int(time.time())
    payload = {
        "iss": iss,
        "aud": aud,
        "email": email,
        "sub": sub,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return google_jwt.encode(signer, payload, header={"alg": "ES256", "kid": kid}).decode("ascii")


def _decode_cookie_payload_unverified(ticket: str) -> Dict[str, Any]:
    body_b64 = ticket.rsplit(".", 1)[0]
    pad = "=" * ((4 - len(body_b64) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode((body_b64 + pad).encode("ascii")).decode("utf-8"))


def _extract_set_cookie_value(response: httpx.Response, cookie_name: str = IAM_SESSION_COOKIE) -> str:
    for hdr in response.headers.get_list("set-cookie"):
        if hdr.startswith(f"{cookie_name}="):
            return hdr.split("=", 1)[1].split(";", 1)[0]
    return ""


# ==============================================================================
# 1. OIDC ID Token Audience Enforcement
# ==============================================================================


def test_id_token_rejected_when_oauth_client_id_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without IAM_OAUTH_CLIENT_ID configured, ID tokens must return 401 without calling tokeninfo."""
    monkeypatch.delenv("IAM_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)

    verify_called = False

    def _fail_if_called(*args: Any, **kwargs: Any) -> Any:
        nonlocal verify_called
        verify_called = True
        raise AssertionError("Should not invoke verify_oauth2_token or httpx when IAM_OAUTH_CLIENT_ID is empty")

    monkeypatch.setattr(ig.google_id_token, "verify_oauth2_token", _fail_if_called)
    monkeypatch.setattr(ig.httpx, "get", _fail_if_called)

    client = TestClient(main_mod.app)
    resp = client.post("/api/v1/auth/verify", json={"id_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"})
    assert resp.status_code == 401
    assert not verify_called


def test_id_token_with_wrong_audience_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    """Acceptance Criterion 1: ID token with aud != IAM_OAUTH_CLIENT_ID returns 401 (no tokeninfo fallback)."""
    monkeypatch.setenv("IAM_OAUTH_CLIENT_ID", "expected-client.apps.googleusercontent.com")
    seen_audiences: list[Any] = []
    tokeninfo_called = False

    def _mock_verify(tok: str, req: Any, audience: Any = None) -> Dict[str, Any]:
        seen_audiences.append(audience)
        if audience != "wrong-client.apps.googleusercontent.com":
            raise ValueError("Token has wrong audience wrong-client.apps.googleusercontent.com")
        return {}

    def _fail_tokeninfo(*args: Any, **kwargs: Any) -> Any:
        nonlocal tokeninfo_called
        tokeninfo_called = True
        raise AssertionError("Must NOT fall back to tokeninfo for ID tokens")

    monkeypatch.setattr(ig.google_id_token, "verify_oauth2_token", _mock_verify)
    monkeypatch.setattr(ig.httpx, "get", _fail_tokeninfo)

    client = TestClient(main_mod.app)
    resp = client.post("/api/v1/auth/verify", json={"id_token": "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ3cm9uZyJ9.sig"})
    assert resp.status_code == 401
    assert seen_audiences == ["expected-client.apps.googleusercontent.com"]
    assert not tokeninfo_called


def test_id_token_with_mismatched_aud_claim_defense_in_depth_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    """Defense-in-depth: even if verify_oauth2_token returns claims with mismatched aud, reject with 401."""
    monkeypatch.setenv("IAM_OAUTH_CLIENT_ID", "expected-client.apps.googleusercontent.com")
    monkeypatch.setattr(
        ig.google_id_token,
        "verify_oauth2_token",
        lambda tok, req, audience=None: {
            "aud": "other-client.apps.googleusercontent.com",
            "email": "alice@example.com",
            "email_verified": True,
            "sub": "sub-alice",
            "exp": int(time.time()) + 600,
        },
    )
    client = TestClient(main_mod.app)
    resp = client.post("/api/v1/auth/verify", json={"id_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.sig"})
    assert resp.status_code == 401


def test_id_token_with_matching_audience_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Valid ID token matching IAM_OAUTH_CLIENT_ID succeeds and sets HttpOnly cookie."""
    cid = "expected-client.apps.googleusercontent.com"
    monkeypatch.setenv("IAM_OAUTH_CLIENT_ID", cid)
    monkeypatch.setattr(
        ig.google_id_token,
        "verify_oauth2_token",
        lambda tok, req, audience=None: {
            "aud": cid,
            "email": "alice@example.com",
            "email_verified": True,
            "name": "Alice Security",
            "sub": "sub-alice",
            "exp": int(time.time()) + 600,
        },
    )
    client = TestClient(main_mod.app)
    resp = client.post("/api/v1/auth/verify", json={"id_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.sig"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "alice@example.com"
    assert _extract_set_cookie_value(resp)


# ==============================================================================
# 2. OAuth2 Access Token azp / aud Allowlist Enforcement
# ==============================================================================


def _mock_tokeninfo_and_userinfo(
    monkeypatch: pytest.MonkeyPatch,
    tokeninfo_payload: Dict[str, Any],
    *,
    status_code: int = 200,
    call_counter: list[str] | None = None,
) -> None:
    def _fake_get(url: str, **kwargs: Any) -> httpx.Response:
        if call_counter is not None:
            call_counter.append(url)
        if url == ig.GOOGLE_TOKENINFO_URI:
            return httpx.Response(status_code=status_code, json=tokeninfo_payload)
        if url == ig.GOOGLE_USERINFO_URI:
            return httpx.Response(status_code=200, json={"name": "Alice Cloud"})
        raise AssertionError(f"Unexpected httpx.get URL: {url}")

    monkeypatch.setattr(ig.httpx, "get", _fake_get)


def test_access_token_with_disallowed_azp_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    """Acceptance Criterion 2: Access token with azp outside allowlist results in 401."""
    monkeypatch.setenv("IAM_OAUTH_CLIENT_ID", "app-client.apps.googleusercontent.com")
    monkeypatch.setenv("IAM_ALLOWED_TOKEN_AZP", "32555940559.apps.googleusercontent.com")
    _mock_tokeninfo_and_userinfo(
        monkeypatch,
        {
            "azp": "untrusted-third-party.apps.googleusercontent.com",
            "aud": "untrusted-third-party.apps.googleusercontent.com",
            "email": "alice@example.com",
            "email_verified": "true",
            "sub": "111",
            "expires_in": "3500",
        },
    )

    client = TestClient(main_mod.app)
    resp = client.post("/api/v1/auth/verify", json={"access_token": "ya29.a0evilclienttoken"})
    assert resp.status_code == 401

    # Also rejected on Authorization: Bearer
    resp_bearer = client.get(
        "/api/v1/session/status",
        headers={"Authorization": "Bearer ya29.a0evilclienttoken"},
    )
    assert resp_bearer.status_code == 401


def test_access_token_rejected_when_allowlist_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail-closed: access tokens are rejected when neither IAM_OAUTH_CLIENT_ID nor IAM_ALLOWED_TOKEN_AZP is set."""
    monkeypatch.delenv("IAM_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("IAM_ALLOWED_TOKEN_AZP", raising=False)

    client = TestClient(main_mod.app)
    resp = client.post("/api/v1/auth/verify", json={"access_token": "ya29.a0somegcloudtoken"})
    assert resp.status_code == 401


def test_access_token_with_allowed_gcloud_azp_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Access token whose azp is in IAM_ALLOWED_TOKEN_AZP is accepted."""
    monkeypatch.delenv("IAM_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.setenv(
        "IAM_ALLOWED_TOKEN_AZP",
        "32555940559.apps.googleusercontent.com,999999999999-testclient0000000000000000000000.apps.googleusercontent.com",
    )
    _mock_tokeninfo_and_userinfo(
        monkeypatch,
        {
            "azp": "32555940559.apps.googleusercontent.com",
            "aud": "32555940559.apps.googleusercontent.com",
            "email": "admin@example.com",
            "email_verified": "true",
            "sub": "999",
            "expires_in": "3500",
        },
    )

    client = TestClient(main_mod.app)
    resp = client.post("/api/v1/auth/verify", json={"access_token": "ya29.a0validgcloudtoken"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "admin@example.com"


# ==============================================================================
# 3. OAuth Bridge Popup TARGET_ORIGIN Hardening
# ==============================================================================


def _extract_target_origin_from_bridge_html(html_text: str) -> str:
    m = re.search(r"const TARGET_ORIGIN = (.*?);", html_text)
    assert m is not None, "TARGET_ORIGIN assignment missing from bridge HTML"
    return json.loads(m.group(1))


def test_oauth_bridge_ignores_evil_origin_query_param(monkeypatch: pytest.MonkeyPatch) -> None:
    """Acceptance Criterion 3: GET /api/v1/auth/bridge?origin=https://evil.example renders service's own origin."""
    monkeypatch.delenv("IAM_PUBLIC_ORIGIN", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)

    client = TestClient(main_mod.app, base_url="https://iam-accel.example.com")
    resp = client.get("/api/v1/auth/bridge?origin=https://evil.example&target_origin=https://evil.example")
    assert resp.status_code == 200
    target = _extract_target_origin_from_bridge_html(resp.text)
    assert target == "https://iam-accel.example.com"
    assert "evil.example" not in resp.text


def test_oauth_bridge_uses_iam_public_origin_env_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit IAM_PUBLIC_ORIGIN takes precedence over request host and query params."""
    monkeypatch.setenv("IAM_PUBLIC_ORIGIN", "https://agentic-iam-accelerator-123456789012.us-central1.run.app/")
    monkeypatch.setenv("K_SERVICE", "agentic-iam-accelerator")

    client = TestClient(main_mod.app, base_url="https://other-host.example.com")
    resp = client.get("/api/v1/auth/bridge?origin=https://evil.example")
    assert resp.status_code == 200
    assert (
        _extract_target_origin_from_bridge_html(resp.text)
        == "https://agentic-iam-accelerator-123456789012.us-central1.run.app"
    )


def test_oauth_bridge_blocks_localhost_on_cloud_run_but_allows_locally(monkeypatch: pytest.MonkeyPatch) -> None:
    """localhost is allowed outside Cloud Run, and blocked when K_SERVICE is set."""
    monkeypatch.delenv("IAM_PUBLIC_ORIGIN", raising=False)

    # Local workstation: localhost allowed
    monkeypatch.delenv("K_SERVICE", raising=False)
    local_client = TestClient(main_mod.app, base_url="http://localhost:8080")
    resp_local = local_client.get("/api/v1/auth/bridge?origin=https://evil.example")
    assert resp_local.status_code == 200
    assert _extract_target_origin_from_bridge_html(resp_local.text) == "http://localhost:8080"

    # Cloud Run: localhost rejected (empty TARGET_ORIGIN)
    monkeypatch.setenv("K_SERVICE", "agentic-iam-accelerator")
    cr_client = TestClient(main_mod.app, base_url="http://localhost:8080")
    resp_cr = cr_client.get("/api/v1/auth/bridge?origin=http://localhost:8080")
    assert resp_cr.status_code == 200
    assert _extract_target_origin_from_bridge_html(resp_cr.text) == ""

    # Cloud Run with IAM_PUBLIC_ORIGIN=http://localhost:8080 also rejected
    monkeypatch.setenv("IAM_PUBLIC_ORIGIN", "http://localhost:8080")
    resp_cr_env = cr_client.get("/api/v1/auth/bridge")
    assert resp_cr_env.status_code == 200
    assert _extract_target_origin_from_bridge_html(resp_cr_env.text) == ""


# ==============================================================================
# 4. Cloud Run IAP Exact Audience, Missing-Audience Warning, and 1h Key Cache
# ==============================================================================


def test_iap_exact_audience_required_prefix_fallback_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    """IAP JWT with same project prefix but different service name must be rejected."""
    signer, pub_pem = _generate_es256_keypair(kid="kid-1")
    expected_aud = "/projects/123456789012/locations/us-central1/services/agentic-iam-accelerator"
    other_service_aud = "/projects/123456789012/locations/us-central1/services/other-service"

    monkeypatch.setenv("IAM_IAP_AUDIENCE", expected_aud)
    monkeypatch.setattr(
        ig.httpx,
        "get",
        lambda url, **kwargs: httpx.Response(status_code=200, json={"kid-1": pub_pem}),
    )

    # Exact match succeeds
    good_jwt = _mint_iap_jwt(signer, kid="kid-1", email="alice@example.com", aud=expected_aud)
    ident = ig.verify_iap_jwt_token(good_jwt)
    assert ident is not None
    assert ident.email == "alice@example.com"

    # Same /projects/123456789012/ prefix, different service -> MUST be rejected
    prefix_spoof_jwt = _mint_iap_jwt(signer, kid="kid-1", email="alice@example.com", aud=other_service_aud)
    assert ig.verify_iap_jwt_token(prefix_spoof_jwt) is None


def test_iap_on_cloud_run_without_audience_ignores_header_and_logs_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """On Cloud Run without IAM_IAP_AUDIENCE, X-Goog-IAP-JWT-Assertion is ignored and a warning is logged."""
    signer, _ = _generate_es256_keypair(kid="kid-1")
    monkeypatch.setenv("K_SERVICE", "agentic-iam-accelerator")
    monkeypatch.delenv("IAM_IAP_AUDIENCE", raising=False)
    monkeypatch.delenv("GOOGLE_IAP_AUDIENCE", raising=False)

    jwt_tok = _mint_iap_jwt(signer, kid="kid-1", email="alice@example.com")
    client = TestClient(main_mod.app)
    with caplog.at_level(logging.WARNING, logger="backend.identity_guard"):
        resp = client.get("/api/v1/session/status", headers={"X-Goog-IAP-JWT-Assertion": jwt_tok})

    assert resp.status_code == 401
    assert any("IAM_IAP_AUDIENCE" in rec.message for rec in caplog.records)


def test_iap_public_keys_cached_for_one_hour_and_refreshed_on_expiry_or_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IAP public keys are fetched once and cached for 3600s, refreshing after TTL expiry."""
    signer1, pub_pem1 = _generate_es256_keypair(kid="kid-1")
    signer2, pub_pem2 = _generate_es256_keypair(kid="kid-2")
    expected_aud = "/projects/123456789012/locations/us-central1/services/agentic-iam-accelerator"
    monkeypatch.setenv("IAM_IAP_AUDIENCE", expected_aud)

    fake_now = [1000.0]
    fetch_count = [0]
    current_keys: Dict[str, str] = {"kid-1": pub_pem1}

    monkeypatch.setattr(ig.time, "monotonic", lambda: fake_now[0])

    def _mock_certs_get(url: str, **kwargs: Any) -> httpx.Response:
        assert url == IAP_CERTS_URL
        fetch_count[0] += 1
        return httpx.Response(status_code=200, json=dict(current_keys))

    monkeypatch.setattr(ig.httpx, "get", _mock_certs_get)

    jwt1 = _mint_iap_jwt(signer1, kid="kid-1", email="alice@example.com", aud=expected_aud)
    assert ig.verify_iap_jwt_token(jwt1) is not None
    assert fetch_count[0] == 1

    # 30 minutes later: still served from cache
    fake_now[0] += 1800.0
    assert ig.verify_iap_jwt_token(jwt1) is not None
    assert fetch_count[0] == 1

    # Key rotation (new kid-2 after cooldown): refreshes once
    current_keys["kid-2"] = pub_pem2
    jwt2 = _mint_iap_jwt(signer2, kid="kid-2", email="bob@example.com", aud=expected_aud)
    ident2 = ig.verify_iap_jwt_token(jwt2)
    assert ident2 is not None and ident2.email == "bob@example.com"
    assert fetch_count[0] == 2

    # After 1 hour TTL expiry: fetches again
    fake_now[0] += IAP_CERTS_CACHE_TTL_SECONDS + 1.0
    assert ig.verify_iap_jwt_token(jwt2) is not None
    assert fetch_count[0] == 3


# ==============================================================================
# 5. Precedence: IAP Overrides Mismatched Cookie & Mints Fresh sid
# ==============================================================================


def test_iap_user_b_overrides_cookie_user_a_and_mints_new_sid(monkeypatch: pytest.MonkeyPatch) -> None:
    """Acceptance Criterion 4: Cookie of user A + IAP JWT of user B results in identity B and new sid."""
    signer, pub_pem = _generate_es256_keypair(kid="kid-prec")
    expected_aud = "/projects/123456789012/locations/us-central1/services/agentic-iam-accelerator"
    monkeypatch.setenv("IAM_IAP_AUDIENCE", expected_aud)
    monkeypatch.setattr(
        ig.httpx,
        "get",
        lambda url, **kwargs: httpx.Response(status_code=200, json={"kid-prec": pub_pem}),
    )

    ident_a = IamConsultantIdentity(
        email="user_a@example.com",
        display_name="User A",
        domain="example.com",
        subject="sub-a",
        auth_channel="verified_google_cookie",
    )
    cookie_a = mint_consultant_cookie(ident_a)
    payload_a = _decode_cookie_payload_unverified(cookie_a)

    iap_jwt_b = _mint_iap_jwt(
        signer,
        kid="kid-prec",
        email="user_b@example.com",
        sub="accounts.google.com:sub-b",
        aud=expected_aud,
    )

    client = TestClient(main_mod.app)
    client.cookies.set(IAM_SESSION_COOKIE, cookie_a)
    resp = client.get(
        "/api/v1/session/status",
        headers={
            "X-Goog-IAP-JWT-Assertion": iap_jwt_b,
            "X-Goog-Authenticated-User-Email": "accounts.google.com:user_b@example.com",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["caller_email"] == "user_b@example.com"

    # Middleware must emit a brand-new cookie for user B with a new `sid` and user B's workspace `ws`
    new_cookie = _extract_set_cookie_value(resp)
    assert new_cookie, "Expected middleware to set a new session cookie for IAP User B"
    assert new_cookie != cookie_a
    payload_b = _decode_cookie_payload_unverified(new_cookie)
    assert payload_b["em"] == "user_b@example.com"
    assert payload_b["sid"] != payload_a["sid"]
    assert payload_b["ws"] != payload_a["ws"]


def test_iap_same_user_preserves_valid_cookie_without_remint(monkeypatch: pytest.MonkeyPatch) -> None:
    """When IAP email matches a valid non-revoked cookie, cookie is kept without re-minting."""
    signer, pub_pem = _generate_es256_keypair(kid="kid-same")
    expected_aud = "/projects/123456789012/locations/us-central1/services/agentic-iam-accelerator"
    monkeypatch.setenv("IAM_IAP_AUDIENCE", expected_aud)
    monkeypatch.setattr(
        ig.httpx,
        "get",
        lambda url, **kwargs: httpx.Response(status_code=200, json={"kid-same": pub_pem}),
    )

    ident_a = IamConsultantIdentity(
        email="user_a@example.com",
        display_name="User A",
        domain="example.com",
        subject="sub-a",
        auth_channel="cloud_run_iap",
    )
    cookie_a = mint_consultant_cookie(ident_a)
    iap_jwt_a = _mint_iap_jwt(signer, kid="kid-same", email="user_a@example.com", aud=expected_aud)

    client = TestClient(main_mod.app)
    client.cookies.set(IAM_SESSION_COOKIE, cookie_a)
    resp = client.get("/api/v1/session/status", headers={"X-Goog-IAP-JWT-Assertion": iap_jwt_a})
    assert resp.status_code == 200
    assert resp.json()["caller_email"] == "user_a@example.com"
    assert _extract_set_cookie_value(resp) == ""


# ==============================================================================
# 6. Cookie Revocation on Logout & Disconnect
# ==============================================================================


def test_logout_revokes_cookie_sid_and_old_cookie_receives_401() -> None:
    """Acceptance Criterion 5: After logout, replaying the old cookie on /api/v1/session/status returns 401."""
    ident = IamConsultantIdentity(
        email="logout_user@example.com",
        display_name="Logout User",
        domain="example.com",
        subject="sub-logout",
        auth_channel="verified_google_cookie",
    )
    old_cookie = mint_consultant_cookie(ident)

    # Works before logout
    client = TestClient(main_mod.app)
    client.cookies.set(IAM_SESSION_COOKIE, old_cookie)
    assert client.get("/api/v1/session/status").status_code == 200

    # Logout revokes old cookie sid
    logout_resp = client.post("/api/v1/auth/logout", headers={"X-Requested-With": "XMLHttpRequest"})
    assert logout_resp.status_code == 200

    # Replay the exact old cookie on a fresh client -> MUST return 401
    replay_client = TestClient(main_mod.app)
    replay_client.cookies.set(IAM_SESSION_COOKIE, old_cookie)
    replay_resp = replay_client.get("/api/v1/session/status")
    assert replay_resp.status_code == 401
    assert verify_consultant_cookie(old_cookie) is None

    # A newly minted cookie for the SAME user still works cleanly (new sid)
    new_cookie = mint_consultant_cookie(ident)
    fresh_client = TestClient(main_mod.app)
    fresh_client.cookies.set(IAM_SESSION_COOKIE, new_cookie)
    assert fresh_client.get("/api/v1/session/status").status_code == 200


def test_disconnect_also_revokes_cookie_sid() -> None:
    """POST /api/v1/session/disconnect revokes the caller's cookie sid so replaying it returns 401."""
    ident = IamConsultantIdentity(
        email="disc_user@example.com",
        display_name="Disconnect User",
        domain="example.com",
        subject="sub-disc",
        auth_channel="verified_google_cookie",
    )
    old_cookie = mint_consultant_cookie(ident)

    client = TestClient(main_mod.app)
    client.cookies.set(IAM_SESSION_COOKIE, old_cookie)
    assert client.get("/api/v1/session/status").status_code == 200

    disc_resp = client.post("/api/v1/session/disconnect", headers={"X-Requested-With": "XMLHttpRequest"})
    assert disc_resp.status_code == 200
    assert disc_resp.json()["wiped"] is True

    replay_client = TestClient(main_mod.app)
    replay_client.cookies.set(IAM_SESSION_COOKIE, old_cookie)
    assert replay_client.get("/api/v1/session/status").status_code == 401


def test_revoked_sid_expires_after_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Revoked sid entries automatically expire after their expiration timestamp."""
    fake_epoch = [1_800_000_000.0]
    monkeypatch.setattr(ig.time, "time", lambda: fake_epoch[0])

    ig.revoke_session_id("ephemeral-sid-1", expires_at=fake_epoch[0] + 30.0)
    assert ig.is_session_revoked("ephemeral-sid-1") is True

    fake_epoch[0] += 31.0
    assert ig.is_session_revoked("ephemeral-sid-1") is False


# ==============================================================================
# 7. Event-Loop Offloading (asyncio.to_thread) & 60s Bearer Verification Cache
# ==============================================================================


def test_bearer_verification_cached_60s_by_token_hash_and_offloaded_from_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bearer token verification runs off the event loop, caches <=60s keyed by SHA-256 hash, and skips caching failures."""
    monkeypatch.setenv("IAM_ALLOWED_TOKEN_AZP", "32555940559.apps.googleusercontent.com")
    fake_mono = [5000.0]
    monkeypatch.setattr(ig.time, "monotonic", lambda: fake_mono[0])

    calls: list[str] = []
    worker_threads: list[int] = []
    main_thread_id = threading.get_ident()

    def _fake_get(url: str, **kwargs: Any) -> httpx.Response:
        calls.append(url)
        worker_threads.append(threading.get_ident())
        if url == ig.GOOGLE_TOKENINFO_URI:
            tok = (kwargs.get("params") or {}).get("access_token", "")
            if tok == "ya29.a0validcachedtoken":
                return httpx.Response(
                    status_code=200,
                    json={
                        "azp": "32555940559.apps.googleusercontent.com",
                        "aud": "32555940559.apps.googleusercontent.com",
                        "email": "cli_user@example.com",
                        "email_verified": "true",
                        "sub": "sub-cli",
                        "expires_in": "3500",
                    },
                )
            return httpx.Response(status_code=400, json={"error_description": "Invalid Value"})
        if url == ig.GOOGLE_USERINFO_URI:
            return httpx.Response(status_code=200, json={"name": "CLI User"})
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(ig.httpx, "get", _fake_get)

    raw_tok = "ya29.a0validcachedtoken"
    expected_hash = hashlib.sha256(raw_tok.encode("utf-8")).hexdigest()

    client = TestClient(main_mod.app)
    r1 = client.get("/api/v1/session/status", headers={"Authorization": f"Bearer {raw_tok}"})
    assert r1.status_code == 200
    assert r1.json()["caller_email"] == "cli_user@example.com"
    assert calls.count(ig.GOOGLE_TOKENINFO_URI) == 1
    # Executed inside asyncio.to_thread worker thread, not the TestClient/event-loop thread
    assert any(tid != main_thread_id for tid in worker_threads)
    # Cache stores SHA-256 hash, NEVER the raw bearer token
    assert expected_hash in ig._BEARER_VERIFY_CACHE
    assert raw_tok not in ig._BEARER_VERIFY_CACHE

    # Second call 30s later hits cache (zero new tokeninfo HTTP calls)
    fake_mono[0] += 30.0
    r2 = client.get("/api/v1/session/status", headers={"Authorization": f"Bearer {raw_tok}"})
    assert r2.status_code == 200
    assert calls.count(ig.GOOGLE_TOKENINFO_URI) == 1

    # After 60s TTL, cache expires and tokeninfo is queried again
    fake_mono[0] += 31.0
    r3 = client.get("/api/v1/session/status", headers={"Authorization": f"Bearer {raw_tok}"})
    assert r3.status_code == 200
    assert calls.count(ig.GOOGLE_TOKENINFO_URI) == 2

    # Failed Bearer verifications are NEVER cached
    bad_tok = "ya29.a0badtoken"
    bad_hash = hashlib.sha256(bad_tok.encode("utf-8")).hexdigest()
    rb1 = client.get("/api/v1/session/status", headers={"Authorization": f"Bearer {bad_tok}"})
    assert rb1.status_code == 401
    assert bad_hash not in ig._BEARER_VERIFY_CACHE
