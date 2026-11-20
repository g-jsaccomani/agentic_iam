"""Tests for T08 — Async execution, timeouts, single-refresh, bounded 2,080-node graph, and background scans."""

from __future__ import annotations

import asyncio
import contextvars
import json
import time
from pathlib import Path
from typing import Any, Dict, List

import httpx
import networkx as nx
import pytest

from backend import main
from backend.agents import coordinator, telemetry
from backend.models.findings import (
    AttackPathAgentOutput,
    CoordinatorAgentOutput,
    IaCAgentOutput,
    IaCPlan,
    RecommenderAgentOutput,
    TriadAgentOutput,
    TriadPillarSynthesis,
)
from backend.tools import cai_collector, graph_engine, posture_scoring_engine


@pytest.mark.asyncio
async def test_health_responds_under_200ms_during_2s_blocking_scan(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    """Acceptance criterion: /health responds in < 200ms while a 2s scan is executing."""

    def slow_blocking_bindings(scope: str, force_refresh: bool = False) -> List[Dict[str, Any]]:
        time.sleep(1.5)
        return []

    async def slow_book(*args: Any, **kwargs: Any) -> Any:
        # Simulate heavy sync CPU/IO offloaded properly via asyncio.to_thread
        await asyncio.to_thread(slow_blocking_bindings, "organizations/123456789012", True)
        raise ValueError("done")

    monkeypatch.setattr(main, "run_posture_book_assessment", slow_book)
    cookie_val = _cookie_for_session(fake_session)

    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        cookies={main.IAM_SESSION_COOKIE: cookie_val},
    ) as client:
        scan_task = asyncio.create_task(
            client.post(
                "/api/v1/book?scope=organizations/123456789012&refresh=true",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
        )
        await asyncio.sleep(0.15)
        t0 = time.monotonic()
        health_resp = await client.get("/health")
        elapsed_ms = (time.monotonic() - t0) * 1000.0
        await scan_task

    assert health_resp.status_code == 200
    assert elapsed_ms < 200.0, f"/health took {elapsed_ms:.1f}ms during concurrent scan!"


def _cookie_for_session(fake_session: Any) -> str:
    from backend import identity_guard, session_vault

    cookie_val = main.mint_consultant_cookie(
        main.IamConsultantIdentity(
            email=fake_session.owner_email,
            display_name="Tester",
            domain="example.com",
            subject="sub-001",
            auth_channel="session_cookie",
            session_id=fake_session.session_id,
        )
    )
    verified = identity_guard.verify_consultant_cookie(cookie_val)
    assert verified is not None
    fake_session.session_id = verified.session_id
    session_vault._SESSION_VAULT[verified.session_id] = fake_session
    return cookie_val


def test_synthetic_2080_node_graph_finishes_under_15s(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    """Acceptance criterion: Synthetic 2,080-node PoC graph completes well under 15 seconds."""
    graph_engine._GRAPH_OBJ_CACHE.clear()

    # Construct 2,080 nodes: 1,000 users, 500 SAs, 500 workloads, 80 project resources
    bindings: List[Dict[str, Any]] = []
    resources: List[Dict[str, Any]] = []
    for p in range(80):
        pid = f"proj-{p:03d}"
        for u in range(12):
            idx = p * 12 + u
            if idx < 1000:
                bindings.append(
                    {
                        "principal": f"user:u{idx}@example.com",
                        "principal_type": "user",
                        "role": "roles/iam.serviceAccountTokenCreator" if u == 0 else "roles/viewer",
                        "resource": f"//cloudresourcemanager.googleapis.com/projects/{pid}",
                        "project_id": pid,
                        "is_google_service_agent": False,
                    }
                )
    for s in range(500):
        pid = f"proj-{s % 80:03d}"
        sa_email = f"sa-{s:03d}@{pid}.iam.gserviceaccount.com"
        resources.append(
            {
                "asset_type": "iam.googleapis.com/ServiceAccount",
                "name": f"//iam.googleapis.com/projects/{pid}/serviceAccounts/{sa_email}",
                "project_id": pid,
                "additional_attributes": {"email": sa_email},
            }
        )
        if s < 160:
            bindings.append(
                {
                    "principal": f"serviceAccount:{sa_email}",
                    "principal_type": "service_account",
                    "role": "roles/editor",
                    "resource": f"//cloudresourcemanager.googleapis.com/projects/{pid}",
                    "project_id": pid,
                    "is_google_service_agent": False,
                }
            )
    for w in range(500):
        pid = f"proj-{w % 80:03d}"
        sa_email = f"sa-{w:03d}@{pid}.iam.gserviceaccount.com"
        resources.append(
            {
                "asset_type": "compute.googleapis.com/Instance",
                "name": f"//compute.googleapis.com/projects/{pid}/zones/us-central1-a/instances/vm-{w:03d}",
                "project_id": pid,
                "display_name": f"vm-{w:03d}",
                "additional_attributes": {"serviceAccountEmail": sa_email},
            }
        )

    monkeypatch.setattr(graph_engine, "collect_live_iam_bindings", lambda scope, force_refresh=False: bindings)
    monkeypatch.setattr(graph_engine, "collect_live_resources", lambda scope, force_refresh=False: resources)

    t0 = time.monotonic()
    G, summary = graph_engine.build_iam_privilege_graph("organizations/123456789012", force_refresh=True)
    paths = graph_engine.extract_raw_topological_paths(G, max_paths=30, time_budget_seconds=5.0)
    elapsed = time.monotonic() - t0

    assert G.number_of_nodes() >= 2000, f"Expected >=2000 nodes, got {G.number_of_nodes()}"
    assert elapsed < 15.0, f"2,080-node graph took {elapsed:.2f}s (limit 15s)!"

    # Verify analyze_iam_attack_paths returns summarized subset + full totals
    payload = json.loads(graph_engine.analyze_iam_attack_paths("organizations/123456789012"))
    assert payload["total_nodes"] == G.number_of_nodes()
    assert len(payload["nodes"]) <= 60
    assert len(payload["edges"]) <= 100
    assert payload["nodes_truncated"] is True


@pytest.mark.asyncio
async def test_hanging_agent_triggers_timeout_and_returns_http_504(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    """Acceptance criterion: Hanging agent raises AgentExecutionTimeoutError and maps to HTTP 504."""

    class HangingRunner:
        def __init__(self, **kwargs: Any) -> None:
            pass

        async def run_async(self, **kwargs: Any):
            await asyncio.sleep(5.0)
            yield  # pragma: no cover

    monkeypatch.setattr(telemetry, "Runner", HangingRunner)
    monkeypatch.setenv("IAM_AGENT_TIMEOUT_SECONDS", "0.15")

    fake_agent = type("FakeAgent", (), {"name": "hanging_agent"})()
    t0 = time.monotonic()
    with pytest.raises(telemetry.AgentExecutionTimeoutError, match="exceeded"):
        await telemetry.execute_adk_agent(fake_agent, "hello")
    assert (time.monotonic() - t0) < 1.0

    # Verify API route returns HTTP 504 on timeout
    async def timeout_book(*args: Any, **kwargs: Any) -> Any:
        raise telemetry.AgentExecutionTimeoutError("ADK agent exceeded 0.2s timeout")

    monkeypatch.setattr(main, "run_posture_book_assessment", timeout_book)
    cookie_val = _cookie_for_session(fake_session)

    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        cookies={main.IAM_SESSION_COOKIE: cookie_val},
    ) as client:
        resp = await client.post(
            "/api/v1/book?scope=organizations/123456789012&refresh=true",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
    assert resp.status_code == 504
    assert "timeout" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_scan_with_refresh_true_collects_bindings_only_once(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any, tmp_path: Path
) -> None:
    """Acceptance criterion: A full scan with refresh=True invokes raw bindings collection ONLY ONCE."""
    cai_collector._BINDINGS_CACHE.clear()
    cai_collector._RESOURCES_CACHE.clear()
    cai_collector._ORG_POLICIES_CACHE.clear()
    cai_collector._ACTIVE_ORG_PROJECTS_CACHE.clear()
    cai_collector._SA_KEYS_CACHE.clear()
    cai_collector._COVERAGE_CACHE.clear()
    posture_scoring_engine._SCORING_BASELINE_CACHE.clear()
    graph_engine._GRAPH_OBJ_CACHE.clear()
    coordinator._TRIAD_CACHE.clear()
    coordinator._GRAPH_CACHE.clear()
    coordinator._REC_CACHE.clear()
    coordinator._IAC_CACHE.clear()
    coordinator._BOOK_CACHE.clear()

    search_policies_calls = {"count": 0}

    def fake_rest(method: str, url: str, **kwargs: Any):
        if ":searchAllIamPolicies" in url:
            search_policies_calls["count"] += 1
            return 200, {
                "results": [
                    {
                        "resource": "//cloudresourcemanager.googleapis.com/projects/alpha-proj",
                        "project": "projects/101",
                        "policy": {
                            "bindings": [
                                {"role": "roles/viewer", "members": ["group:eng@example.com"]}
                            ]
                        },
                    }
                ]
            }
        if ":searchAllResources" in url:
            return 200, {"results": []}
        if "cloudresourcemanager.googleapis.com/v3/projects:search" in url:
            return 200, {"projects": [{"projectId": "alpha-proj", "name": "projects/101", "state": "ACTIVE"}]}
        if "orgpolicy.googleapis.com" in url:
            return 200, {"spec": {"rules": [{"enforce": True}]}, "rules": [{"enforce": True}]}
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr("backend.tools.recommender_tool.gcp_rest_request", fake_rest)
    monkeypatch.setattr("backend.tools.asset_key_secret_inventory.gcp_rest_request", fake_rest)

    # Stub ADK agent creation & execution so zero Vertex traffic occurs
    monkeypatch.setattr(coordinator, "create_triad_analyzer_agent", lambda **kw: type("A", (), {"name": "triad_analyzer"})())
    monkeypatch.setattr(coordinator, "create_attack_path_agent", lambda **kw: type("A", (), {"name": "attack_path_agent"})())
    monkeypatch.setattr(coordinator, "create_recommender_agent", lambda **kw: type("A", (), {"name": "recommender_agent"})())
    monkeypatch.setattr(coordinator, "create_iac_generator_agent", lambda **kw: type("A", (), {"name": "iac_generator"})())
    monkeypatch.setattr(coordinator, "create_coordinator_agent", lambda **kw: type("A", (), {"name": "iam_coordinator"})())

    async def fake_exec(agent: Any, prompt: str, **kw: Any) -> str:
        n = getattr(agent, "name", "")
        if n == "triad_analyzer":
            return TriadAgentOutput(
                internal_identities=TriadPillarSynthesis(posture_score=90.0, total_principals_evaluated=1, compliant_principals=1),
                external_identities=TriadPillarSynthesis(posture_score=100.0, total_principals_evaluated=0, compliant_principals=0),
                workload_service_accounts=TriadPillarSynthesis(posture_score=100.0, total_principals_evaluated=0, compliant_principals=0),
                findings=[],
            ).model_dump_json()
        if n == "attack_path_agent":
            return AttackPathAgentOutput(toxic_combinations_count=0, impersonation_resilience_score=95.0).model_dump_json()
        if n == "recommender_agent":
            return RecommenderAgentOutput(least_privilege_index=95.0, recommendations=[]).model_dump_json()
        if n == "iac_generator":
            return IaCAgentOutput(bundle_id="IAC-ONCE", plan=IaCPlan()).model_dump_json()
        return CoordinatorAgentOutput(
            overall_posture_score=92.0,
            maturity_tier="Managed",
            least_privilege_index=95.0,
            impersonation_resilience_score=95.0,
            executive_narrative_markdown="Executive summary.",
        ).model_dump_json()

    monkeypatch.setattr(coordinator, "execute_adk_agent", fake_exec)

    book = await coordinator.run_posture_book_assessment("organizations/123456789012", force_refresh=True)
    assert book.scope == "organizations/123456789012"
    assert search_policies_calls["count"] == 1, f"Expected 1 bindings collection call, got {search_policies_calls['count']}"


def test_render_attack_graph_png_oo_matplotlib_and_dollar_signs_no_mathtext(tmp_path: Path) -> None:
    """Verifies OO matplotlib rendering without pyplot and safe dollar-sign labels (T08 #3 & T17 #6)."""
    import inspect

    src = inspect.getsource(graph_engine)
    assert "matplotlib.pyplot" not in src
    assert "plt." not in src

    from backend.models.findings import AttackPathEdge, AttackPathGraphSummary, AttackPathNode, RiskSeverity

    summary = AttackPathGraphSummary(
        scope="organizations/123456789012",
        total_nodes=2,
        total_edges=1,
        escalation_paths_count=1,
        toxic_combinations_count=0,
        max_chain_depth=1,
        nodes=[
            AttackPathNode(
                node_id="user:cost$100@example.com",
                label="cost$100_user$test",
                node_type="user",
                risk_level=RiskSeverity.HIGH,
            ),
            AttackPathNode(
                node_id="projects/alpha-proj",
                label="proj$alpha",
                node_type="resource",
                risk_level=RiskSeverity.MEDIUM,
            ),
        ],
        edges=[
            AttackPathEdge(
                source="user:cost$100@example.com",
                target="projects/alpha-proj",
                relationship="roles/custom$role",
                permission_vector="resourcemanager.projects.get",
                is_escalation_edge=True,
            )
        ],
    )
    out_png = tmp_path / "graph_dollar.png"
    res = graph_engine.render_attack_graph_png(out_png, "organizations/123456789012", graph_summary=summary)
    assert res.exists() and res.stat().st_size > 1000


@pytest.mark.asyncio
async def test_run_async_from_sync_propagates_contextvars() -> None:
    cv: contextvars.ContextVar[str] = contextvars.ContextVar("t08_test_cv", default="unset")
    tok = cv.set("propagated-value")
    try:
        async def read_cv() -> str:
            return cv.get()

        val = telemetry.run_async_from_sync(read_cv())
        assert val == "propagated-value"
    finally:
        cv.reset(tok)


@pytest.mark.asyncio
async def test_background_scans_post_and_poll_with_owner_isolation(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    """T08 Part B: POST /api/v1/scans returns 202 scan_id; GET /api/v1/scans/{id} polls to completed & enforces owner isolation."""
    main._BACKGROUND_SCANS.clear()

    from backend.models.findings import (
        AttackPathGraphSummary,
        IaCRemediationBundle,
        IdentityTriadCategory,
        IdentityTriadMatrix,
        IdentityTriadMetrics,
        PostureAccelerationBook,
        PostureScorecard,
    )

    def _tm(cat: IdentityTriadCategory, name: str) -> IdentityTriadMetrics:
        return IdentityTriadMetrics(
            category=cat,
            display_name=name,
            posture_score=90.0,
            total_principals_evaluated=1,
            compliant_principals=1,
            critical_findings_count=0,
            high_findings_count=0,
            medium_findings_count=0,
        )

    fake_book = PostureAccelerationBook(
        scope="organizations/123456789012",
        organization_domain="example.com",
        scorecard=PostureScorecard(
            scope="organizations/123456789012",
            organization_domain="example.com",
            overall_posture_score=91.0,
            maturity_tier="Managed",
            internal_identities_score=90.0,
            external_identities_score=95.0,
            workload_identities_score=90.0,
            least_privilege_index=90.0,
            impersonation_resilience_score=90.0,
            total_bindings_analyzed=5,
            overprivileged_bindings_count=0,
            excess_permissions_eliminated=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
        ),
        triad_matrix=IdentityTriadMatrix(
            scope="organizations/123456789012",
            internal_identities=_tm(IdentityTriadCategory.INTERNAL, "Internal"),
            external_identities=_tm(IdentityTriadCategory.EXTERNAL, "External"),
            workload_service_accounts=_tm(IdentityTriadCategory.WORKLOAD_SA, "Workload"),
            findings=[],
        ),
        attack_graph=AttackPathGraphSummary(
            scope="organizations/123456789012",
            total_nodes=1,
            total_edges=0,
            escalation_paths_count=0,
            toxic_combinations_count=0,
            max_chain_depth=0,
        ),
        recommendations=[],
        iac_bundle=IaCRemediationBundle(
            bundle_id="BG-1",
            scope="organizations/123456789012",
            main_tf="# draft",
            iam_tf="# draft",
            pam_entitlements_tf="# draft",
            org_policies_tf="# draft",
            variables_tf="# draft",
        ),
        executive_narrative_markdown="Done.",
    )

    async def fast_book(*args: Any, **kwargs: Any) -> PostureAccelerationBook:
        await asyncio.sleep(0.05)
        return fake_book

    monkeypatch.setattr(main, "run_posture_book_assessment", fast_book)
    monkeypatch.setattr(main, "_persist_book_and_base_artifacts", lambda b, d: None)
    owner_cookie = _cookie_for_session(fake_session)
    other_cookie = main.mint_consultant_cookie(
        main.IamConsultantIdentity(
            email="other@example.com",
            display_name="Other",
            domain="example.com",
            subject="sub-002",
            auth_channel="session_cookie",
            session_id="other-session-id",
        )
    )

    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        cookies={main.IAM_SESSION_COOKIE: owner_cookie},
    ) as client:
        r_start = await client.post(
            "/api/v1/scans",
            headers={"X-Requested-With": "XMLHttpRequest"},
            json={"scope": "organizations/123456789012", "refresh": True},
        )
        assert r_start.status_code == 202
        scan_id = r_start.json()["scan_id"]

        for _ in range(25):
            r_poll = await client.get(f"/api/v1/scans/{scan_id}")
            assert r_poll.status_code == 200
            if r_poll.json()["status"] == "completed":
                break
            await asyncio.sleep(0.03)
        assert r_poll.json()["status"] == "completed"
        assert r_poll.json()["book"]["scorecard"]["overall_posture_score"] == 91.0

    # Different user cannot inspect another user's scan
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        cookies={main.IAM_SESSION_COOKIE: other_cookie},
    ) as other_client:
        r_other = await other_client.get(f"/api/v1/scans/{scan_id}")
        assert r_other.status_code in (404, 412)
