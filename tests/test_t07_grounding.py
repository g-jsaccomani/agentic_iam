"""Tests for T07 — Deterministic Python grounding of LLM outputs (findings, attack paths, recommendations)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

import networkx as nx
import pytest

from backend.agents import coordinator, grounding
from backend.agents.telemetry import merge_adk_telemetries
from backend.models.findings import (
    AdkExecutionTelemetry,
    AttackPathAgentOutput,
    AttackPathFinding,
    GcpIamPostureFinding,
    IdentityTriadCategory,
    LeastPrivilegeRecommendation,
    RecommenderAgentOutput,
    RiskSeverity,
    TriadAgentOutput,
    TriadPillarSynthesis,
)


def _sample_bindings() -> List[Dict[str, Any]]:
    return [
        {
            "principal": "user:alice@example.com",
            "principal_type": "user",
            "role": "roles/owner",
            "resource": "//cloudresourcemanager.googleapis.com/projects/alpha-proj",
            "project_id": "alpha-proj",
            "is_google_service_agent": False,
        },
        {
            "principal": "serviceAccount:runner@alpha-proj.iam.gserviceaccount.com",
            "principal_type": "service_account",
            "role": "roles/editor",
            "resource": "//cloudresourcemanager.googleapis.com/projects/alpha-proj",
            "project_id": "alpha-proj",
            "is_google_service_agent": False,
        },
    ]


def _make_finding(
    *,
    finding_id: str = "DUP-1",
    principal: str = "user:alice@example.com",
    role: str = "roles/owner",
    resource: str = "//cloudresourcemanager.googleapis.com/projects/alpha-proj",
    severity: RiskSeverity = RiskSeverity.CRITICAL,
    category: IdentityTriadCategory = IdentityTriadCategory.INTERNAL,
) -> GcpIamPostureFinding:
    return GcpIamPostureFinding(
        finding_id=finding_id,
        scope="organizations/123456789012",
        project_id="alpha-proj",
        triad_category=category,
        severity=severity,
        title=f"Finding for {principal}",
        principal=principal,
        role=role,
        resource=resource,
        risk_vector="Standing Privilege",
        evidence_summary="Observed in live bindings",
        recommended_modernization="Replace with least-privilege role",
    )


def test_finding_with_invented_principal_role_or_out_of_scope_resource_is_dropped() -> None:
    bindings = _sample_bindings()
    findings = [
        _make_finding(finding_id="X-1", principal="user:alice@example.com", role="roles/owner", severity=RiskSeverity.CRITICAL),
        _make_finding(finding_id="X-1", principal="serviceAccount:runner@alpha-proj.iam.gserviceaccount.com", role="roles/editor", severity=RiskSeverity.HIGH, category=IdentityTriadCategory.WORKLOAD_SA),
        # Invented principal
        _make_finding(finding_id="X-3", principal="user:ghost@evil.com", role="roles/owner", severity=RiskSeverity.CRITICAL),
        # Existing principal, invented role
        _make_finding(finding_id="X-4", principal="user:alice@example.com", role="roles/resourcemanager.organizationAdmin", severity=RiskSeverity.CRITICAL),
        # Out-of-scope org resource
        _make_finding(finding_id="X-5", principal="user:alice@example.com", role="roles/owner", resource="//cloudresourcemanager.googleapis.com/organizations/999999999999", severity=RiskSeverity.CRITICAL),
    ]

    grounded, dropped = grounding.ground_triad_findings(
        findings,
        bindings=bindings,
        resources=[],
        target_scope="organizations/123456789012",
    )

    assert dropped == 3
    assert len(grounded) == 2
    # Deterministic unique renumbering
    assert [f.finding_id for f in grounded] == ["IAM-001", "IAM-002"]
    assert grounded[0].principal == "user:alice@example.com"
    assert grounded[1].principal == "serviceAccount:runner@alpha-proj.iam.gserviceaccount.com"


def test_attack_path_with_nonexistent_edge_is_dropped_and_counts_computed_in_python() -> None:
    G = nx.DiGraph()
    G.add_node("user:alice@example.com", node_type="user")
    G.add_node("serviceAccount:runner@alpha-proj.iam.gserviceaccount.com", node_type="service_account")
    G.add_node("projects/alpha-proj", node_type="resource")
    G.add_edge(
        "user:alice@example.com",
        "serviceAccount:runner@alpha-proj.iam.gserviceaccount.com",
        is_escalation_edge=True,
        relationship="roles/iam.serviceAccountTokenCreator",
    )
    G.add_edge(
        "serviceAccount:runner@alpha-proj.iam.gserviceaccount.com",
        "projects/alpha-proj",
        is_escalation_edge=True,
        relationship="roles/owner",
    )

    valid_path = AttackPathFinding(
        path_id="LLM-99",
        title="Valid Impersonation Chain",
        severity=RiskSeverity.CRITICAL,
        entry_principal="user:alice@example.com",
        target_crown_jewel="projects/alpha-proj",
        hop_sequence=[
            "user:alice@example.com",
            "serviceAccount:runner@alpha-proj.iam.gserviceaccount.com",
            "projects/alpha-proj",
        ],
        permissions_exploited=["iam.serviceAccounts.getAccessToken"],
        toxic_combination_type="SA_IMPERSONATION_CHAIN",
        blast_radius_score=9.0,
        mitigation_control="Remove TokenCreator",
    )
    hallucinated_path = AttackPathFinding(
        path_id="LLM-100",
        title="Fake Path with Nonexistent Edge",
        severity=RiskSeverity.CRITICAL,
        entry_principal="user:alice@example.com",
        target_crown_jewel="projects/alpha-proj",
        hop_sequence=[
            "user:alice@example.com",
            "projects/alpha-proj",  # direct edge does NOT exist in G!
        ],
        permissions_exploited=["resourcemanager.projects.setIamPolicy"],
        toxic_combination_type="PRIMITIVE_STANDING_PRIVILEGE",
        blast_radius_score=10.0,
        mitigation_control="None",
    )

    grounded, dropped, esc_cnt, toxic_cnt = grounding.ground_attack_paths(
        [valid_path, hallucinated_path],
        graph=G,
        base_escalation_paths_count=1,
    )

    assert dropped == 1
    assert len(grounded) == 1
    assert grounded[0].path_id == "AP-001"
    assert esc_cnt >= 1
    assert toxic_cnt >= 1


def test_recommendation_permission_counts_and_audit_usage_overwritten_from_live_apis() -> None:
    bindings = _sample_bindings()
    recs = [
        LeastPrivilegeRecommendation(
            recommendation_id="LLM-R1",
            principal="user:alice@example.com",
            resource="//cloudresourcemanager.googleapis.com/projects/alpha-proj",
            current_role="roles/owner",
            recommended_action="DOWNGRADE_PREDEFINED_ROLE",
            proposed_role_or_entitlement="roles/viewer",
            permissions_granted_count=99999,  # hallucinated!
            permissions_exercised_90d=55555,  # hallucinated!
            excess_permissions_removed=44444,
            permission_reduction_pct=44.44,
            persona_classification="Platform Admin",
        ),
        # Ungrounded principal + role pair -> dropped
        LeastPrivilegeRecommendation(
            recommendation_id="LLM-R2",
            principal="user:invented@example.com",
            resource="//cloudresourcemanager.googleapis.com/projects/alpha-proj",
            current_role="roles/owner",
            recommended_action="REVOKE_UNUSED_BINDING",
            proposed_role_or_entitlement="REVOKE",
            permissions_granted_count=5000,
            permissions_exercised_90d=0,
            excess_permissions_removed=5000,
            permission_reduction_pct=100.0,
            persona_classification="Platform Admin",
        ),
    ]

    def fake_role_meta(role: str) -> Dict[str, Any]:
        if role == "roles/owner":
            return {"role": role, "included_permissions_count": 4200, "http_status": 200}
        return {"role": role, "included_permissions_count": 0, "http_status": 404}

    audit_usage = {
        "alice@example.com": {"distinct_permissions_exercised_count": 12},
    }

    grounded, dropped = grounding.ground_recommendations(
        recs,
        bindings=bindings,
        role_metadata_fn=fake_role_meta,
        audit_usage_by_principal=audit_usage,
        target_scope="organizations/123456789012",
    )

    assert dropped == 1
    assert len(grounded) == 1
    r = grounded[0]
    assert r.recommendation_id == "REC-001"
    assert r.permissions_granted_count == 4200
    assert r.permissions_exercised_90d == 12
    assert r.excess_permissions_removed == 4188
    assert r.permission_reduction_pct == round((4188 / 4200) * 100.0, 2)


@pytest.mark.asyncio
async def test_coordinator_triad_drops_hallucinated_finding_updates_counts_and_exposes_telemetry(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    coordinator._TRIAD_CACHE.clear()
    bindings = _sample_bindings()

    monkeypatch.setattr(coordinator, "collect_live_iam_bindings", lambda scope, force_refresh=False: bindings)
    monkeypatch.setattr(coordinator, "collect_live_resources", lambda scope, force_refresh=False: [])
    monkeypatch.setattr(
        coordinator,
        "compute_iam_framework_baseline",
        lambda scope, force_refresh=False: {
            "deterministic_domain_scores": {
                "INTERNAL_IDENTITIES": 70.0,
                "EXTERNAL_IDENTITIES": 90.0,
                "WORKLOAD_IDENTITIES": 80.0,
                "LEAST_PRIVILEGE": 75.0,
                "GRAPH_RESILIENCE": 85.0,
            },
            "principal_compliance_counts": {
                "internal": {"total_principals_evaluated": 1, "compliant_principals": 0},
                "external": {"total_principals_evaluated": 0, "compliant_principals": 0},
                "workload": {"total_principals_evaluated": 1, "compliant_principals": 0},
            },
        },
    )
    monkeypatch.setattr(coordinator, "create_triad_analyzer_agent", lambda **kwargs: object())

    fake_llm_output = TriadAgentOutput(
        internal_identities=TriadPillarSynthesis(posture_score=70.0, total_principals_evaluated=1, compliant_principals=0),
        external_identities=TriadPillarSynthesis(posture_score=90.0, total_principals_evaluated=0, compliant_principals=0),
        workload_service_accounts=TriadPillarSynthesis(posture_score=80.0, total_principals_evaluated=1, compliant_principals=0),
        findings=[
            _make_finding(principal="user:alice@example.com", role="roles/owner", severity=RiskSeverity.HIGH),
            _make_finding(principal="user:hallucinated@example.com", role="roles/owner", severity=RiskSeverity.CRITICAL),
        ],
    )

    async def fake_exec(agent: Any, prompt: str, **kwargs: Any) -> str:
        return fake_llm_output.model_dump_json()

    monkeypatch.setattr(coordinator, "execute_adk_agent", fake_exec)

    matrix, tel = await coordinator.run_triad_assessment("organizations/123456789012", force_refresh=True)
    assert len(matrix.findings) == 1
    assert matrix.findings[0].principal == "user:alice@example.com"
    assert matrix.findings[0].finding_id == "IAM-001"
    # Critical hallucinated finding was dropped BEFORE pillar severity counts were computed!
    assert matrix.internal_identities.critical_findings_count == 0
    assert matrix.internal_identities.high_findings_count == 1
    assert tel.ungrounded_findings_dropped == 1
    assert tel.ungrounded_items_dropped_by_agent == {"triad_analyzer": 1}

    # Verify merge_adk_telemetries aggregates dropped counts across agents
    other_tel = AdkExecutionTelemetry(
        requested_model="gemini-3.1-pro-preview-customtools",
        model_version="gemini-3.1-pro-preview-customtools",
        ungrounded_findings_dropped=2,
        ungrounded_items_dropped_by_agent={"attack_path_agent": 2},
    )
    merged = merge_adk_telemetries("gemini-3.1-pro-preview-customtools", [tel, other_tel], wall_latency_ms=120.0)
    assert merged.ungrounded_findings_dropped == 3
    assert merged.ungrounded_items_dropped_by_agent == {"triad_analyzer": 1, "attack_path_agent": 2}
