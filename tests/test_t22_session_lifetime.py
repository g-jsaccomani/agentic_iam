"""Tests for T22 — 8-hour browser session and a logout that survives a restart (N5)."""

from __future__ import annotations

import time

import pytest

from backend import identity_guard as ig
from backend import main as main_mod
from backend import workspace_store as ws
from tests.round2_helpers import ORG_A, XRW, authed_client, connect_direct, identity, reset_state

EMAIL = "t22@example.com"


@pytest.fixture(autouse=True)
def _clean_state():
    reset_state()
    yield
    reset_state()


def _simulate_restart() -> None:
    """A restart or redeploy empties every in-memory revocation structure."""
    ig.clear_auth_caches_for_tests()
    assert ig._REVOKED_SIDS == {}
    assert ig._PERSISTED_REVOKED_CACHE == {}


def test_default_cookie_lifetime_is_eight_hours_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_SESSION_TTL_SECONDS", raising=False)
    assert ig._configured_session_ttl_seconds() == 28800
    monkeypatch.setenv("IAM_SESSION_TTL_SECONDS", "60")
    assert ig._configured_session_ttl_seconds() == 300
    monkeypatch.setenv("IAM_SESSION_TTL_SECONDS", "999999999")
    assert ig._configured_session_ttl_seconds() == 30 * 24 * 3600
    monkeypatch.setenv("IAM_SESSION_TTL_SECONDS", "not-a-number")
    assert ig._configured_session_ttl_seconds() == 28800
    assert main_mod.IAM_SESSION_TTL_SECONDS == ig.IAM_SESSION_TTL_SECONDS <= 30 * 24 * 3600


def test_logout_survives_a_restart() -> None:
    cookie = ig.mint_consultant_cookie(identity(EMAIL))
    assert ig.verify_consultant_cookie(cookie) is not None

    assert ig.revoke_consultant_cookie(cookie)
    assert ig.verify_consultant_cookie(cookie) is None

    _simulate_restart()
    assert ig.verify_consultant_cookie(cookie) is None, "a cookie copied before logout must stay rejected"

    # a fresh sign-in of the same user is unaffected
    assert ig.verify_consultant_cookie(ig.mint_consultant_cookie(identity(EMAIL))) is not None


def test_revocation_is_sealed_and_outlives_disconnect_and_wipe() -> None:
    wid = ws.derive_workspace_id(EMAIL)
    connect_direct(EMAIL, ORG_A)
    cookie = ig.mint_consultant_cookie(identity(EMAIL))
    sid = ig.revoke_consultant_cookie(cookie)
    path = ws._LOCAL_STORE_ROOT / wid / "security" / "revoked_sids.json"
    assert path.exists()
    assert sid.encode() not in path.read_bytes()

    ws.wipe_workspace(wid)
    _simulate_restart()
    assert ig.verify_consultant_cookie(cookie) is None


def test_cookie_older_than_its_lifetime_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    cookie = ig.mint_consultant_cookie(identity(EMAIL))
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + ig.IAM_SESSION_TTL_SECONDS - 60)
    assert ig.verify_consultant_cookie(cookie) is not None
    monkeypatch.setattr(time, "time", lambda: real_time() + ig.IAM_SESSION_TTL_SECONDS + 5)
    assert ig.verify_consultant_cookie(cookie) is None


def test_http_logout_then_replay_after_restart_is_unauthenticated() -> None:
    connect_direct(EMAIL, ORG_A)
    client = authed_client(EMAIL)
    stolen = client.cookies.get(ig.IAM_SESSION_COOKIE)
    assert client.get("/api/v1/workspace/restore").json()["authenticated"] is True

    assert client.post("/api/v1/auth/logout", headers=XRW).status_code == 200
    _simulate_restart()

    from fastapi.testclient import TestClient

    replay = TestClient(main_mod.app)
    replay.cookies.set(ig.IAM_SESSION_COOKIE, stolen)
    assert replay.get("/api/v1/workspace/restore").status_code == 401
