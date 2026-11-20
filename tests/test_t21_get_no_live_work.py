"""Tests for T21 — a GET request never runs live collection or an agent (N4)."""

from __future__ import annotations

from typing import Any, List

import pytest

from backend import main as main_mod
from backend import workspace_store as ws
from backend.models.findings import AccountsKeysSecretsInventory
from tests.round2_helpers import ORG_A, SCOPE_A, XRW, authed_client, connect_direct, reset_state

EMAIL = "t21@example.com"
AGENT_GETS = [
    "/api/v1/scorecard",
    "/api/v1/triad",
    "/api/v1/attack-graph",
    "/api/v1/recommendations",
    "/api/v1/iac-bundle",
]


@pytest.fixture(autouse=True)
def _clean_state():
    reset_state()
    yield
    reset_state()


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch):
    """Authenticated, connected client where any agent run or live collection is recorded as a failure."""
    connect_direct(EMAIL, ORG_A)
    live: List[str] = []

    async def _agent(*_a: Any, **_k: Any) -> Any:
        live.append("agent")
        raise AssertionError("an agent must never run on GET")

    def _collector(*_a: Any, **_k: Any) -> Any:
        live.append("collector")
        raise AssertionError("live collection must not run")

    for name in (
        "run_scorecard_assessment",
        "run_triad_assessment",
        "run_attack_path_assessment",
        "run_recommender_assessment",
        "run_iac_assessment",
        "run_posture_book_assessment",
        "generate_all_executive_deliverables_async",
    ):
        monkeypatch.setattr(main_mod, name, _agent)
    monkeypatch.setattr(main_mod, "build_accounts_keys_secrets_inventory", _collector)
    monkeypatch.setattr(main_mod, "compute_iam_framework_baseline", _collector)
    return authed_client(EMAIL), live


@pytest.mark.parametrize("path", AGENT_GETS + ["/api/v1/download/docx", "/api/v1/download/attack-graph-png"])
def test_refresh_through_get_is_refused(env, path: str) -> None:
    client, live = env
    resp = client.get(path, params={"scope": SCOPE_A, "refresh": "true"})
    assert resp.status_code == 405
    assert resp.headers.get("allow") == "POST"
    assert live == []


@pytest.mark.parametrize("path", AGENT_GETS + ["/api/v1/download/pdf", "/api/v1/download/attack-graph-png"])
def test_get_without_a_pinned_book_answers_409_without_any_live_work(env, path: str) -> None:
    client, live = env
    resp = client.get(path, params={"scope": SCOPE_A})
    assert resp.status_code == 409
    assert "Run a scan first" in resp.json()["detail"]
    assert live == []


def test_get_serves_sections_of_the_pinned_book(env) -> None:
    client, live = env
    ws.save_pinned_book(
        ws.derive_workspace_id(EMAIL),
        EMAIL,
        SCOPE_A,
        {
            "scope": SCOPE_A,
            "generated_at": "2026-01-01T00:00:00Z",
            "scorecard": {"overall_posture_score": 77.0, "least_privilege_index": 61.0},
            "triad_matrix": {"marker": "PINNED_TRIAD"},
            "attack_graph": {"marker": "PINNED_GRAPH"},
            "recommendations": [{"marker": "PINNED_REC"}],
            "iac_bundle": {"marker": "PINNED_IAC"},
        },
    )
    assert client.get("/api/v1/scorecard", params={"scope": SCOPE_A}).json()["overall_posture_score"] == 77.0
    assert client.get("/api/v1/triad", params={"scope": SCOPE_A}).json()["marker"] == "PINNED_TRIAD"
    assert client.get("/api/v1/attack-graph", params={"scope": SCOPE_A}).json()["marker"] == "PINNED_GRAPH"
    recs = client.get("/api/v1/recommendations", params={"scope": SCOPE_A}).json()
    assert recs["count"] == 1 and recs["least_privilege_index"] == 61.0
    assert client.get("/api/v1/iac-bundle", params={"scope": SCOPE_A}).json()["marker"] == "PINNED_IAC"
    assert live == []


def test_live_inventory_collection_needs_the_custom_header(env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, live = env
    wid = ws.derive_workspace_id(EMAIL)

    # no pinned inventory + plain GET (what a cross-site link can send): refused before any collection
    plain = client.get("/api/v1/inventory", params={"scope": SCOPE_A})
    assert plain.status_code == 403
    assert live == []

    # pinned inventory is served to a plain GET
    ws.save_pinned_inventory(wid, EMAIL, SCOPE_A, {"scope": SCOPE_A, "marker": "PINNED_INVENTORY"})
    assert client.get("/api/v1/inventory", params={"scope": SCOPE_A}).json()["marker"] == "PINNED_INVENTORY"
    assert client.get("/api/v1/inventory", params={"scope": SCOPE_A, "refresh": "true"}).status_code == 403
    assert live == []

    # the dashboard sends the header: live collection runs
    collected: List[str] = []

    def _fake_collect(scope: str, refresh: bool = False) -> AccountsKeysSecretsInventory:
        collected.append(scope)
        return AccountsKeysSecretsInventory(scope=scope, accounts=[])

    monkeypatch.setattr(main_mod, "build_accounts_keys_secrets_inventory", _fake_collect)
    fresh = client.get("/api/v1/inventory", params={"scope": SCOPE_A, "refresh": "true"}, headers=XRW)
    assert fresh.status_code == 200
    assert collected == [SCOPE_A]


def test_framework_scorecard_needs_the_custom_header(env) -> None:
    client, live = env
    assert client.get("/api/v1/framework-scorecard", params={"scope": SCOPE_A}).status_code == 403
    assert live == []


def test_pinned_inventory_download_is_served_without_collection(env) -> None:
    client, live = env
    ws.save_pinned_inventory(
        ws.derive_workspace_id(EMAIL), EMAIL, SCOPE_A, AccountsKeysSecretsInventory(scope=SCOPE_A, accounts=[]).model_dump()
    )
    resp = client.get("/api/v1/download/inventory-json", params={"scope": SCOPE_A})
    assert resp.status_code == 200
    assert resp.json()["scope"] == SCOPE_A
    assert live == []
