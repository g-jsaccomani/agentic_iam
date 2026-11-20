"""Tests for T03 — Remove unverified Policy Simulator & 30d/90d audit replay claims."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import docx
import pytest

from backend import report_generator, tools
from backend.models.findings import (
    AccountPrincipalRecord,
    AccountsKeysSecretsInventory,
    AccountsKeysSecretsSummaryKPIs,
    AttackPathGraphSummary,
    IaCAgentOutput,
    IaCRemediationBundle,
    IdentityTriadCategory,
    IdentityTriadMatrix,
    IdentityTriadMetrics,
    LeastPrivilegeRecommendation,
    PolicySimulationValidation,
    PostureAccelerationBook,
    PostureScorecard,
)
from backend.tools import recommender_tool


def _make_audit_entry(ts: str, email: str, perm: str = "storage.buckets.list") -> Dict[str, Any]:
    return {
        "timestamp": ts,
        "protoPayload": {
            "authenticationInfo": {"principalEmail": email},
            "methodName": "storage.buckets.list",
            "serviceName": "storage.googleapis.com",
            "resourceName": "projects/proj-a",
            "authorizationInfo": [{"permission": perm, "granted": True}],
        },
    }


def test_tool_renamed_and_exported_cleanly() -> None:
    assert hasattr(recommender_tool, "collect_change_impact_evidence")
    assert not hasattr(recommender_tool, "validate_remediation_with_policy_simulator")
    assert "collect_change_impact_evidence" in tools.__all__
    assert "validate_remediation_with_policy_simulator" not in tools.__all__


def test_audit_log_pagination_cap_window_and_project_ratio(monkeypatch: pytest.MonkeyPatch) -> None:
    recommender_tool._AUDIT_USAGE_CACHE.clear()
    calls: List[Dict[str, Any]] = []

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        body = kwargs.get("json_body") or {}
        calls.append(body)
        if not body.get("pageToken"):
            return 200, {
                "entries": [
                    _make_audit_entry("2026-11-15T12:00:00Z", "alice@example.com"),
                    _make_audit_entry("2026-11-10T08:30:00Z", "alice@example.com"),
                ],
                "nextPageToken": "tok-page-2",
            }
        return 200, {
            "entries": [
                _make_audit_entry("2026-11-01T06:00:00Z", "bob@example.com"),
                _make_audit_entry("2026-10-20T04:00:00Z", "bob@example.com"),
            ],
            "nextPageToken": "tok-page-3",
        }

    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "active_cache_namespace", lambda: "test-ns-cap")

    projects = [f"proj-{i}" for i in range(12)]
    res = recommender_tool._collect_cloud_audit_usage_by_principal(
        projects,
        days_back=90,
        max_entries=3,
        time_budget_seconds=10.0,
        page_size=2,
    )

    assert len(calls) == 2
    assert calls[1]["pageToken"] == "tok-page-2"
    assert res["is_sample"] is True
    assert res["truncated_by_cap"] is True
    assert res["sample_size"] == 3
    assert res["window_start"] == "2026-11-01T06:00:00+00:00"
    assert res["window_end"] == "2026-11-15T12:00:00+00:00"
    assert res["window"]["start"] == "2026-11-01T06:00:00+00:00"
    assert res["window"]["end"] == "2026-11-15T12:00:00+00:00"
    assert res["projects_queried_count"] == 10
    assert res["total_projects_in_scope"] == 12
    assert res["projects_queried_over_total"] == "10/12"
    assert res["principal_usage"]["alice@example.com"]["audit_events_count"] == 2
    assert res["principal_usage"]["bob@example.com"]["audit_events_count"] == 1


def test_audit_log_exhaustive_sample_false_when_all_pages_and_projects_read(monkeypatch: pytest.MonkeyPatch) -> None:
    recommender_tool._AUDIT_USAGE_CACHE.clear()

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        body = kwargs.get("json_body") or {}
        if not body.get("pageToken"):
            return 200, {
                "entries": [_make_audit_entry("2026-11-14T10:00:00Z", "alice@example.com")],
                "nextPageToken": "p2",
            }
        return 200, {
            "entries": [_make_audit_entry("2026-11-12T09:00:00Z", "alice@example.com")],
        }

    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "active_cache_namespace", lambda: "test-ns-full")

    res = recommender_tool._collect_cloud_audit_usage_by_principal(
        ["proj-1", "proj-2"],
        days_back=30,
        max_entries=100,
        time_budget_seconds=10.0,
    )
    assert res["is_sample"] is False
    assert res["sample_size"] == 2
    assert res["pages_fetched"] == 2
    assert res["projects_queried_over_total"] == "2/2"
    assert res["window_start"] == "2026-11-12T09:00:00+00:00"
    assert res["window_end"] == "2026-11-14T10:00:00+00:00"


def test_audit_log_respects_time_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    recommender_tool._AUDIT_USAGE_CACHE.clear()
    monotonic_values = iter([100.0, 100.0, 100.05, 100.25, 100.3, 100.4])

    monkeypatch.setattr(recommender_tool.time, "monotonic", lambda: next(monotonic_values, 101.0))
    monkeypatch.setattr(recommender_tool, "active_cache_namespace", lambda: "test-ns-budget")

    call_count = 0

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        nonlocal call_count
        call_count += 1
        return 200, {
            "entries": [_make_audit_entry("2026-11-14T10:00:00Z", "alice@example.com")],
            "nextPageToken": f"next-{call_count}",
        }

    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)

    res = recommender_tool._collect_cloud_audit_usage_by_principal(
        ["proj-1"],
        days_back=30,
        max_entries=500,
        time_budget_seconds=0.1,
    )
    assert call_count == 1
    assert res["truncated_by_time_budget"] is True
    assert res["is_sample"] is True
    assert res["sample_size"] == 1


def test_collect_change_impact_evidence_payload_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    recommender_tool._AUDIT_USAGE_CACHE.clear()
    monkeypatch.setattr(recommender_tool, "DEFAULT_AUDIT_LOG_MAX_ENTRIES", 2)
    monkeypatch.setattr(recommender_tool, "discover_accessible_projects_in_scope", lambda scope: ["proj-a", "proj-b"])
    monkeypatch.setattr(recommender_tool, "collect_live_org_policies", lambda scope: [])
    monkeypatch.setattr(recommender_tool, "active_cache_namespace", lambda: "test-ns-tool")

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        if "policysimulator" in url:
            return 200, {"replays": []}
        return 200, {
            "entries": [
                _make_audit_entry("2026-11-02T01:00:00Z", "admin@example.com"),
                _make_audit_entry("2026-11-18T23:00:00Z", "admin@example.com"),
            ],
            "nextPageToken": "more-logs",
        }

    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)

    raw = recommender_tool.collect_change_impact_evidence("organizations/123456789012")
    payload = json.loads(raw)

    assert payload["is_sample"] is True
    assert payload["sample_size"] == 2
    assert payload["simulation_executed"] is False
    assert payload["policy_simulator_api"]["replay_executed"] is False
    assert payload["window"]["start"] == "2026-11-02T01:00:00+00:00"
    assert payload["window"]["end"] == "2026-11-18T23:00:00+00:00"
    assert payload["projects_queried_over_total"] == "2/2"
    assert "cloud_audit_log_sample" in payload
    assert "cloud_audit_replay_baseline_90d" not in payload


def test_verdict_vocabulary_and_python_grounded_sample_counts(tmp_path: Path) -> None:
    # Even if an LLM supplies legacy verdict text and invented replay counts, Python enforces clean vocabulary & real counts.
    legacy_verdict = "SAFE_" + "TO_APPLY"
    sim_from_llm = PolicySimulationValidation(
        simulation_id="SIM-01",
        target_resource="projects/proj-a",
        principal="user:alice@example.com",
        proposed_change_summary="Replace Editor with Custom Role",
        access_replay_90d_calls_tested=23482,  # Hallucinated LLM count
        excess_risk_eliminated_pct=94.5,
        simulator_verdict=legacy_verdict,
    )
    assert sim_from_llm.simulator_verdict == "REVIEW_REQUIRED"

    sim_break = PolicySimulationValidation(
        simulation_id="SIM-02",
        target_resource="projects/proj-a",
        principal="user:bob@example.com",
        proposed_change_summary="Revoke KMS Decrypter",
        access_replay_90d_calls_tested=99999,
        excess_risk_eliminated_pct=50.0,
        simulator_verdict="BREAKAGE_RISK",
    )
    assert sim_break.simulator_verdict == "LIKELY_BREAKING"

    sim_ok = PolicySimulationValidation(
        simulation_id="SIM-03",
        target_resource="organizations/123456789012",
        principal="organizations/123456789012",
        proposed_change_summary="Enforce disableServiceAccountKeyCreation",
        access_replay_90d_calls_tested=77777,
        excess_risk_eliminated_pct=80.0,
        simulator_verdict="NO_CONFLICT_IN_SAMPLE",
    )
    assert sim_ok.simulator_verdict == "NO_CONFLICT_IN_SAMPLE"

    iac_out = IaCAgentOutput(
        bundle_id="IAC-T03",
        main_tf='terraform { required_version = ">= 1.6" }',
        variables_tf='variable "org_id" { default = "123456789012" }',
        iam_tf="# iam",
        pam_entitlements_tf="# pam",
        org_policies_tf="# org policies",
        policy_simulations=[sim_from_llm, sim_break, sim_ok],
    )
    audit_sample = {
        "is_sample": True,
        "sample_size": 42,
        "window_start": "2026-10-01T00:00:00+00:00",
        "window_end": "2026-11-15T23:59:59+00:00",
        "projects_queried_count": 2,
        "total_projects_in_scope": 3,
        "principal_usage": {
            "alice@example.com": {"audit_events_count": 7},
        },
    }

    bundle = recommender_tool.package_terraform_remediation_files(
        iac_out,
        scope="organizations/123456789012",
        output_dir=tmp_path,
        audit_sample=audit_sample,
    )

    assert bundle.audit_sample_size == 42
    assert bundle.audit_sample_is_sample is True
    assert bundle.audit_sample_window_start == "2026-10-01T00:00:00+00:00"
    assert bundle.audit_sample_window_end == "2026-11-15T23:59:59+00:00"
    assert bundle.audit_projects_queried == 2
    assert bundle.audit_total_projects_in_scope == 3

    by_id = {s.simulation_id: s for s in bundle.policy_simulations}
    assert by_id["SIM-01"].sample_events_observed == 7
    assert by_id["SIM-01"].access_replay_90d_calls_tested == 7
    assert by_id["SIM-02"].sample_events_observed == 0  # unseen principal, never LLM's 99999
    assert by_id["SIM-03"].sample_events_observed == 42  # scope-wide uses Python sample_size


def _build_minimal_book() -> PostureAccelerationBook:
    pillar = IdentityTriadMetrics(
        category=IdentityTriadCategory.INTERNAL,
        display_name="Internal Workforce",
        posture_score=75.0,
        total_principals_evaluated=1,
        compliant_principals=1,
        critical_findings_count=0,
        high_findings_count=0,
        medium_findings_count=0,
    )
    triad = IdentityTriadMatrix(
        scope="organizations/123456789012",
        internal_identities=pillar,
        external_identities=pillar.model_copy(
            update={"category": IdentityTriadCategory.EXTERNAL, "display_name": "External"}
        ),
        workload_service_accounts=pillar.model_copy(
            update={"category": IdentityTriadCategory.WORKLOAD_SA, "display_name": "Workloads"}
        ),
    )
    scorecard = PostureScorecard(
        scope="organizations/123456789012",
        organization_domain="example.com",
        overall_posture_score=75.0,
        internal_identities_score=75.0,
        external_identities_score=75.0,
        workload_identities_score=75.0,
        least_privilege_index=75.0,
        impersonation_resilience_score=75.0,
        maturity_tier="Managed",
        total_bindings_analyzed=10,
        overprivileged_bindings_count=1,
        excess_permissions_eliminated=500,
        critical_findings=0,
        high_findings=1,
        medium_findings=0,
        low_findings=0,
    )
    inv = AccountsKeysSecretsInventory(
        scope="organizations/123456789012",
        kpis=AccountsKeysSecretsSummaryKPIs(human_and_group_accounts_total=1),
        accounts=[
            AccountPrincipalRecord(
                principal="user:alice@example.com",
                principal_type="USER",
                domain="example.com",
                bindings_count=1,
                roles=["roles/editor"],
                projects=["proj-a"],
                audit_events_30d=7,
                risk_level="HIGH",
            )
        ],
        audit_sample_is_sample=True,
        audit_sample_size=42,
        audit_sample_window_start="2026-10-01T00:00:00+00:00",
        audit_sample_window_end="2026-11-15T23:59:59+00:00",
        audit_projects_queried=2,
        audit_total_projects_in_scope=3,
    )
    iac = IaCRemediationBundle(
        bundle_id="IAC-T03",
        scope="organizations/123456789012",
        main_tf='terraform { required_version = ">= 1.6" }',
        variables_tf='variable "org_id" { default = "123456789012" }',
        iam_tf="# iam",
        pam_entitlements_tf="# pam",
        org_policies_tf="# org policies",
        policy_simulations=[
            PolicySimulationValidation(
                simulation_id="SIM-01",
                target_resource="projects/proj-a",
                principal="user:alice@example.com",
                proposed_change_summary="Replace Editor with Custom Role",
                sample_events_observed=7,
                sample_window_start="2026-10-01T00:00:00+00:00",
                sample_window_end="2026-11-15T23:59:59+00:00",
                is_sample=True,
                excess_risk_eliminated_pct=94.5,
                simulator_verdict="NO_CONFLICT_IN_SAMPLE",
            )
        ],
        audit_sample_is_sample=True,
        audit_sample_size=42,
        audit_sample_window_start="2026-10-01T00:00:00+00:00",
        audit_sample_window_end="2026-11-15T23:59:59+00:00",
        audit_projects_queried=2,
        audit_total_projects_in_scope=3,
    )
    return PostureAccelerationBook(
        scope="organizations/123456789012",
        organization_domain="example.com",
        scorecard=scorecard,
        triad_matrix=triad,
        attack_graph=AttackPathGraphSummary(
            scope="organizations/123456789012",
            total_nodes=3,
            total_edges=2,
            escalation_paths_count=0,
            toxic_combinations_count=0,
            max_chain_depth=1,
        ),
        recommendations=[
            LeastPrivilegeRecommendation(
                recommendation_id="REC-01",
                principal="user:alice@example.com",
                resource="projects/proj-a",
                current_role="roles/editor",
                recommended_action="MIGRATE_TO_PAM_JIT",
                proposed_role_or_entitlement="PAM 1h JIT",
                permissions_granted_count=5000,
                permissions_exercised_90d=7,
                excess_permissions_removed=4993,
                permission_reduction_pct=99.86,
                persona_classification="Platform Admin",
                pam_jit_eligible=True,
            )
        ],
        iac_bundle=iac,
        asset_inventory=inv,
        executive_narrative_markdown="Executive posture summary for test scope.",
    )


def _extract_pdf_stream_text(pdf_bytes: bytes) -> str:
    import base64
    import re
    import zlib

    chunks: List[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\n?endstream", pdf_bytes, flags=re.DOTALL):
        raw_stream = match.group(1).strip()
        data = raw_stream
        if data.endswith(b"~>"):
            try:
                data = base64.a85decode(data, adobe=True)
            except Exception:
                pass
        try:
            decoded = zlib.decompress(data).decode("latin-1", errors="ignore")
        except Exception:
            decoded = data.decode("latin-1", errors="ignore")
        chunks.append(decoded)
    return "\n".join(chunks)


def test_report_generator_uses_new_section_6_title_and_removes_unverified_claims(tmp_path: Path) -> None:
    book = _build_minimal_book()
    docx_path = tmp_path / "report.docx"
    pdf_path = tmp_path / "report.pdf"
    fake_png = tmp_path / "missing_graph.png"

    report_generator.build_executive_docx_report(book, fake_png, docx_path)
    report_generator.build_executive_pdf_report(book, fake_png, pdf_path)

    assert docx_path.exists() and docx_path.stat().st_size > 0
    assert pdf_path.exists() and pdf_path.stat().st_size > 0

    parsed_doc = docx.Document(str(docx_path))
    all_parts: List[str] = [p.text for p in parsed_doc.paragraphs]
    for tbl in parsed_doc.tables:
        for row in tbl.rows:
            for cell in row.cells:
                all_parts.append(cell.text)
    full_docx_text = "\n".join(all_parts)

    assert "Estimativa de impacto e bundle Terraform consultivo (não validado)" in full_docx_text
    assert "verified against" not in full_docx_text.lower()
    assert "Policy Simulator Verification" not in full_docx_text
    assert ("SAFE_" + "TO_APPLY") not in full_docx_text
    assert "Audit30d" not in full_docx_text
    assert "NO_CONFLICT_IN_SAMPLE" in full_docx_text
    assert "42 eventos na amostra" in full_docx_text
    assert "2026-10-01 a 2026-11-15" in full_docx_text

    # Also verify decompressed PDF content streams
    pdf_text = _extract_pdf_stream_text(pdf_path.read_bytes())
    assert "Estimativa de impacto e bundle Terraform consultivo" in pdf_text
    assert "verified against" not in pdf_text.lower()
    assert "Policy Simulator Verification" not in pdf_text
    assert ("SAFE_" + "TO_APPLY") not in pdf_text
    assert "Audit30d" not in pdf_text
    assert "42 eventos na amostra" in pdf_text
