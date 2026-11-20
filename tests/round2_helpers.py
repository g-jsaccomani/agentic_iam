"""Shared helpers for the round-2 remediation tests (T18–T22). Fully offline."""

from __future__ import annotations

import time
from typing import Any, List, Tuple

import pytest
from fastapi.testclient import TestClient

from backend import identity_guard as ig
from backend import main as main_mod
from backend import session_vault as sv
from backend import workspace_store as ws

SA_A = "sa-iam-assessor@customer-a-seed.iam.gserviceaccount.com"
SA_B = "sa-iam-assessor@customer-b-seed.iam.gserviceaccount.com"
ORG_A = "111111111111"
ORG_B = "222222222222"
SCOPE_A = f"organizations/{ORG_A}"
SCOPE_B = f"organizations/{ORG_B}"
XRW = {"X-Requested-With": "XMLHttpRequest"}


def reset_state() -> None:
    """Clears every in-memory structure that a real restart would clear."""
    with sv._VAULT_LOCK:
        sv._SESSION_VAULT.clear()
        sv._HYDRATE_MISS_UNTIL.clear()
    with ws._STORE_LOCK:
        ws._RETENTION_BY_WS.clear()
    ws._LAST_OBJECT_SWEEP_AT = 0.0
    ig.clear_auth_caches_for_tests()
    main_mod.reset_rate_limiter_for_tests()


def forget_sessions_in_memory() -> None:
    """Drops only the RAM session vault so the next lookup must hydrate from the store."""
    with sv._VAULT_LOCK:
        sv._SESSION_VAULT.clear()
        sv._HYDRATE_MISS_UNTIL.clear()


def identity(email: str) -> ig.IamConsultantIdentity:
    return ig.IamConsultantIdentity(
        email=email,
        display_name="Round2 Tester",
        domain=email.split("@", 1)[1],
        subject=f"sub-{email}",
        auth_channel="verified_google_cookie",
    )


def authed_client(email: str) -> TestClient:
    client = TestClient(main_mod.app)
    client.cookies.set(ig.IAM_SESSION_COOKIE, ig.mint_consultant_cookie(identity(email)))
    return client


def connect_direct(email: str, org_id: str = ORG_A, **kwargs: Any) -> sv.InspectionSession:
    return sv.store_inspection_session(
        session_id=ws.derive_workspace_id(email),
        owner_email=email,
        user_access_token="offline-direct-token",
        connection_mode="direct_user",
        organization_id=org_id,
        token_expires_at=time.time() + 3600.0,
        **kwargs,
    )


def connect_sa(email: str, sa_email: str, org_id: str = "", token: str = "ya29.user", **kwargs: Any) -> sv.InspectionSession:
    return sv.store_inspection_session(
        session_id=ws.derive_workspace_id(email),
        owner_email=email,
        user_access_token=token,
        connection_mode="impersonated_sa",
        target_sa_email=sa_email,
        organization_id=org_id,
        **kwargs,
    )


def stub_token_minting(monkeypatch: pytest.MonkeyPatch, *, runtime_ok: bool = True) -> List[Tuple[str, str]]:
    """Replaces both token mints with offline fakes and returns the call log `[(kind, target_sa)]`."""
    calls: List[Tuple[str, str]] = []

    def fake_user_mint(user_access_token: str, target_sa_email: str, caller_email: str = "", lifetime_seconds: int = 3600):
        calls.append(("user", target_sa_email))
        return "ya29.user-minted", time.time() + 3000.0

    def fake_runtime_mint(target_sa_email: str, lifetime_seconds: int = 3600):
        calls.append(("runtime", target_sa_email))
        if not runtime_ok:
            raise PermissionError("customer did not grant the platform runtime SA")
        return "ya29.runtime-minted", time.time() + 3000.0

    monkeypatch.setattr(sv, "mint_impersonated_sa_token", fake_user_mint)
    monkeypatch.setattr(sv, "mint_delegated_sa_token_via_runtime_sa", fake_runtime_mint)
    return calls


def book_dict(scope: str, marker: str) -> dict:
    return {"scope": scope, "generated_at": "2026-01-01T00:00:00Z", "scorecard": {}, "marker": marker}
