"""Tests for T05 — Complete collection, pagination, retries, and explicit coverage."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import docx
import pytest

from backend import report_generator
from backend.models.findings import (
    AttackPathGraphSummary,
    IaCAgentOutput,
    IaCRemediationBundle,
    IdentityTriadCategory,
    IdentityTriadMatrix,
    IdentityTriadMetrics,
    PostureAccelerationBook,
)
from backend.tools import (
    asset_key_secret_inventory,
    cai_collector,
    posture_scoring_engine,
    recommender_tool,
)


def _clear_collector_caches() -> None:
    cai_collector._BINDINGS_CACHE.clear()
    cai_collector._RESOURCES_CACHE.clear()
    cai_collector._ORG_POLICIES_CACHE.clear()
    cai_collector._ACTIVE_ORG_PROJECTS_CACHE.clear()
    cai_collector._COVERAGE_CACHE.clear()
    cai_collector._SA_KEYS_CACHE.clear()
    posture_scoring_engine._SCORING_BASELINE_CACHE.clear()
    recommender_tool._ROLE_META_CACHE.clear()
    recommender_tool._AUDIT_USAGE_CACHE.clear()


def test_seven_pages_of_iam_policies_collected_with_complete_coverage(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_collector_caches()

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        params = kwargs.get("params") or {}
        if ":searchAllIamPolicies" in url:
            tok = str(params.get("pageToken") or "")
            page_idx = int(tok[1:]) if tok.startswith("p") else 1
            next_tok = f"p{page_idx + 1}" if page_idx < 7 else ""
            body: Dict[str, Any] = {
                "results": [
                    {
                        "resource": f"//cloudresourcemanager.googleapis.com/projects/proj-{page_idx:02d}",
                        "project": f"projects/{page_idx}",
                        "policy": {
                            "bindings": [
                                {
                                    "role": "roles/viewer",
                                    "members": [f"user:alice{page_idx}@example.com"],
                                }
                            ]
                        },
                    }
                ]
            }
            if next_tok:
                body["nextPageToken"] = next_tok
            return 200, body
        if "cloudresourcemanager.googleapis.com/v3/projects:search" in url:
            return 200, {
                "projects": [
                    {"projectId": f"proj-{i:02d}", "name": f"projects/{i}", "state": "ACTIVE"}
                    for i in range(1, 8)
                ]
            }
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)

    bindings = cai_collector.collect_live_iam_bindings("organizations/123456789012", force_refresh=True)
    assert len(bindings) == 7
    cov = cai_collector.get_scan_coverage_map("organizations/123456789012")
    policy_statuses = [v for k, v in cov.items() if k.startswith("iam_bindings")]
    assert len(policy_statuses) == 1
    st = policy_statuses[0]
    assert st.complete is True
    assert st.pages_fetched == 7
    assert st.items_collected == 7
    assert st.http_status == 200


def test_paginator_retries_on_429_and_503(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = {"count": 0}

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return 429, {"error": "rate limit"}
        if attempts["count"] == 2:
            return 503, {"error": "service unavailable"}
        return 200, {"results": [{"id": "ok-1"}]}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)

    items, status = cai_collector.gcp_paginated_request(
        "GET",
        "https://cloudasset.googleapis.com/v1/organizations/123456789012:searchAllIamPolicies",
        results_key="results",
        collector="test_retry",
        scope="organizations/123456789012",
        max_retries=3,
        sleep_fn=lambda _: None,
    )
    assert attempts["count"] == 3
    assert items == [{"id": "ok-1"}]
    assert status.complete is True
    assert status.http_status == 200


def test_search_all_resources_403_marks_wkl_not_evaluated_and_emits_warning(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_collector_caches()

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        if ":searchAllIamPolicies" in url:
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
            return 403, {"error": {"message": "Permission denied on searchAllResources"}}
        if "cloudresourcemanager.googleapis.com/v3/projects:search" in url:
            return 200, {
                "projects": [
                    {"projectId": "alpha-proj", "name": "projects/101", "state": "ACTIVE"}
                ]
            }
        if "orgpolicy.googleapis.com" in url:
            return 200, {"spec": {"rules": [{"enforce": True}]}}
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)

    baseline = posture_scoring_engine.compute_iam_framework_baseline(
        "organizations/123456789012", force_refresh=True
    )
    controls_by_id = {c["control_id"]: c for c in baseline["control_evaluations"]}

    assert controls_by_id["IAM-WKL-01"]["status"] == "NOT_EVALUATED"
    assert controls_by_id["IAM-WKL-03"]["status"] == "NOT_EVALUATED"
    assert controls_by_id["IAM-WKL-04"]["status"] == "NOT_EVALUATED"
    assert baseline["coverage_warnings"], "Expected coverage warnings on 403 searchAllResources"
    assert any("403" in w or "cai_resources" in w for w in baseline["coverage_warnings"])
    assert baseline["data_completeness_pct"] < 100.0
    assert baseline["deterministic_composite_score"] < 100.0


def test_200_service_accounts_with_old_key_on_150th_triggers_critical_ceiling(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_collector_caches()
    old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=150)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    sa_resources = [
        {
            "assetType": "iam.googleapis.com/ServiceAccount",
            "name": f"//iam.googleapis.com/projects/alpha-proj/serviceAccounts/sa-{i:03d}@alpha-proj.iam.gserviceaccount.com",
            "project": "projects/101",
            "displayName": f"SA {i:03d}",
        }
        for i in range(200)
    ]

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        if ":searchAllIamPolicies" in url:
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
            return 200, {"results": sa_resources}
        if "/keys" in url and "iam.googleapis.com/v1/" in url:
            if "sa-149%40" in url or "sa-149@" in url:
                return 200, {
                    "keys": [
                        {
                            "name": "projects/alpha-proj/serviceAccounts/sa-149@alpha-proj.iam.gserviceaccount.com/keys/old-key-1",
                            "keyType": "USER_MANAGED",
                            "keyAlgorithm": "KEY_ALG_RSA_2048",
                            "validAfterTime": old_ts,
                        }
                    ]
                }
            return 200, {"keys": []}
        if "cloudresourcemanager.googleapis.com/v3/projects:search" in url:
            return 200, {
                "projects": [
                    {"projectId": "alpha-proj", "name": "projects/101", "state": "ACTIVE"}
                ]
            }
        if "orgpolicy.googleapis.com" in url:
            if "disableServiceAccountKeyCreation" in url:
                return 200, {"spec": {"rules": [{"enforce": False}]}}
            return 200, {"spec": {"rules": [{"enforce": True}]}}
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(asset_key_secret_inventory, "gcp_rest_request", fake_rest)

    # 1) Unified SA key collector finds the key on the 150th SA (index 149)
    sa_unified = cai_collector.collect_unified_service_account_keys(
        "organizations/123456789012", force_refresh=True
    )
    assert len(sa_unified["by_sa"]) == 200
    assert sa_unified["user_managed_keys_total"] == 1
    assert any(k["age_days"] > 90 for k in sa_unified["all_keys"])

    # 2) Scoring engine triggers critical exposure ceiling (<=84.0%)
    baseline = posture_scoring_engine.compute_iam_framework_baseline(
        "organizations/123456789012", force_refresh=False
    )
    assert baseline["critical_exposure_gate"]["triggered"] is True
    assert baseline["critical_exposure_gate"]["ceiling_score_pct"] == 84.0
    assert any("90 days" in r for r in baseline["critical_exposure_gate"]["reasons"])
    assert baseline["deterministic_maturity_tier"] in {"Managed", "Developing", "Initial"}

    # 3) Inventory and scorecard report the EXACT same user_managed_keys count
    inv_bundle = asset_key_secret_inventory.build_accounts_keys_secrets_inventory(
        "organizations/123456789012",
        force_refresh=False,
    )
    assert inv_bundle.kpis.user_managed_sa_keys_total == baseline["total_user_managed_keys"] == 1


def test_sa_key_cap_emits_evaluated_x_of_y_warning_and_caps_tier_at_managed(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_collector_caches()
    sa_resources = [
        {
            "assetType": "iam.googleapis.com/ServiceAccount",
            "name": f"//iam.googleapis.com/projects/alpha-proj/serviceAccounts/sa-{i:02d}@alpha-proj.iam.gserviceaccount.com",
            "project": "projects/101",
            "displayName": f"SA {i:02d}",
        }
        for i in range(25)
    ]

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        if ":searchAllIamPolicies" in url:
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
            return 200, {"results": sa_resources}
        if "/keys" in url:
            return 200, {"keys": []}
        if "cloudresourcemanager.googleapis.com/v3/projects:search" in url:
            return 200, {
                "projects": [
                    {"projectId": "alpha-proj", "name": "projects/101", "state": "ACTIVE"}
                ]
            }
        if "orgpolicy.googleapis.com" in url:
            return 200, {"spec": {"rules": [{"enforce": True}]}}
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)
    monkeypatch.setenv("IAM_MAX_SA_KEY_CHECKS", "10")

    baseline = posture_scoring_engine.compute_iam_framework_baseline(
        "organizations/123456789012", force_refresh=True
    )
    assert any("10" in w and "25" in w for w in baseline["coverage_warnings"]), baseline["coverage_warnings"]
    assert baseline["deterministic_maturity_tier"] in {"Managed", "Developing", "Initial"}
    assert baseline["deterministic_maturity_tier"] != "Optimized"


def test_failed_sa_key_lookup_marks_unknown_not_keyless(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_collector_caches()
    sa_resources = [
        {
            "asset_type": "iam.googleapis.com/ServiceAccount",
            "name": "//iam.googleapis.com/projects/alpha-proj/serviceAccounts/sa-ok@alpha-proj.iam.gserviceaccount.com",
            "project_id": "alpha-proj",
            "additional_attributes": {"email": "sa-ok@alpha-proj.iam.gserviceaccount.com"},
        },
        {
            "asset_type": "iam.googleapis.com/ServiceAccount",
            "name": "//iam.googleapis.com/projects/alpha-proj/serviceAccounts/sa-denied@alpha-proj.iam.gserviceaccount.com",
            "project_id": "alpha-proj",
            "additional_attributes": {"email": "sa-denied@alpha-proj.iam.gserviceaccount.com"},
        },
    ]

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        if "sa-denied" in url:
            return 403, {"error": "forbidden"}
        if "sa-ok" in url:
            return 200, {"keys": []}
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)

    unified = cai_collector.collect_unified_service_account_keys(
        "organizations/123456789012", bindings=[], resources=sa_resources, force_refresh=True
    )
    by_sa = unified["by_sa"]
    assert by_sa["sa-ok@alpha-proj.iam.gserviceaccount.com"]["key_inspection_status"] == "LIVE_IAM_API_VERIFIED"
    assert by_sa["sa-denied@alpha-proj.iam.gserviceaccount.com"]["key_inspection_status"] == "UNKNOWN"
    cov = cai_collector.get_scan_coverage_map("organizations/123456789012")
    assert cov["sa_keys"].complete is False


def test_predefined_roles_never_dropped_by_alphabetical_order(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_collector_caches()

    # 30 custom roles starting with "organizations/123456789012/roles/aaa_..." sort BEFORE "roles/owner"
    bindings = [
        {
            "role": f"organizations/123456789012/roles/aaa_custom_{i:03d}",
            "members": [f"user:u{i}@example.com"],
        }
        for i in range(30)
    ]
    bindings.append({"role": "roles/owner", "members": ["user:boss@example.com"]})
    queried_roles: List[str] = []

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        if ":searchAllIamPolicies" in url:
            return 200, {
                "results": [
                    {
                        "resource": "//cloudresourcemanager.googleapis.com/projects/alpha-proj",
                        "project": "projects/101",
                        "policy": {"bindings": bindings},
                    }
                ]
            }
        if "iam.googleapis.com/v1/" in url and "/roles/" in url:
            role_part = url.split("iam.googleapis.com/v1/", 1)[1]
            queried_roles.append(role_part)
            return 200, {"name": role_part, "includedPermissions": ["resourcemanager.projects.get"]}
        if "cloudresourcemanager.googleapis.com/v3/projects:search" in url:
            return 200, {"projects": [{"projectId": "alpha-proj", "name": "projects/101", "state": "ACTIVE"}]}
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)
    monkeypatch.setenv("IAM_MAX_CUSTOM_ROLE_METADATA", "5")

    recommender_tool.fetch_iam_role_recommendations("organizations/123456789012")
    assert "roles/owner" in queried_roles, f"roles/owner was dropped! queried={queried_roles}"


def test_docx_and_pdf_render_coverage_warnings_banner(tmp_path: Path) -> None:
    sc = posture_scoring_engine.synthesize_final_framework_scorecard(
        baseline={
            "scope": "organizations/123456789012",
            "organization_domain": "example.com",
            "control_evaluations": [],
            "framework_benchmarks": [],
            "deterministic_domain_scores": {
                "INTERNAL_IDENTITIES": 80.0,
                "EXTERNAL_IDENTITIES": 90.0,
                "WORKLOAD_IDENTITIES": 0.0,
                "LEAST_PRIVILEGE": 85.0,
                "GRAPH_RESILIENCE": 85.0,
            },
            "deterministic_composite_score": 85.0,
            "deterministic_maturity_tier": "Managed",
            "critical_exposure_gate": {"triggered": False, "ceiling_score_pct": 100.0, "reasons": []},
            "coverage": {
                "coverage_warnings": ["cai_resources: HTTP 403 Forbidden (incomplete)"],
                "data_completeness_pct": 66.7,
                "bindings_incomplete": False,
                "sa_keys_incomplete": True,
            },
            "coverage_warnings": ["cai_resources: HTTP 403 Forbidden (incomplete)"],
            "data_completeness_pct": 66.7,
        },
        total_bindings_analyzed=10,
        overprivileged_bindings_count=1,
        excess_permissions_eliminated=100,
        critical_findings=0,
        high_findings=1,
        medium_findings=0,
        low_findings=0,
    )
    def _tm(cat: IdentityTriadCategory, name: str) -> IdentityTriadMetrics:
        return IdentityTriadMetrics(
            category=cat,
            display_name=name,
            posture_score=85.0,
            total_principals_evaluated=5,
            compliant_principals=4,
            critical_findings_count=0,
            high_findings_count=1,
            medium_findings_count=0,
        )

    book = PostureAccelerationBook(
        scope="organizations/123456789012",
        organization_domain="example.com",
        scorecard=sc,
        triad_matrix=IdentityTriadMatrix(
            scope="organizations/123456789012",
            organization_domain="example.com",
            internal_identities=_tm(IdentityTriadCategory.INTERNAL, "Internal"),
            external_identities=_tm(IdentityTriadCategory.EXTERNAL, "External"),
            workload_service_accounts=_tm(IdentityTriadCategory.WORKLOAD_SA, "Workload"),
            findings=[],
        ),
        attack_graph=AttackPathGraphSummary(
            scope="organizations/123456789012",
            total_nodes=2,
            total_edges=1,
            toxic_combinations_count=0,
            escalation_paths_count=0,
            max_chain_depth=0,
            impersonation_resilience_score=95.0,
        ),
        recommendations=[],
        iac_bundle=IaCRemediationBundle(
            scope="organizations/123456789012",
            bundle_id="test-cov",
            target_findings_addressed=[],
            main_tf="# draft",
            iam_tf="# draft",
            variables_tf="# draft",
            org_policies_tf="# draft",
            pam_entitlements_tf="# draft",
            custom_roles_tf="# draft",
        ),
        executive_narrative_markdown="Executive overview.",
    )
    docx_path = tmp_path / "cov.docx"
    pdf_path = tmp_path / "cov.pdf"
    report_generator.build_executive_docx_report(book, graph_png_path=None, output_path=docx_path)
    report_generator.build_executive_pdf_report(book, graph_png_path=None, output_path=pdf_path)

    doc = docx.Document(str(docx_path))
    all_text = "\n".join(
        cell.text for tbl in doc.tables for row in tbl.rows for cell in row.cells
    )
    assert "TELEMETRY COVERAGE WARNING" in all_text
    assert "HTTP 403 Forbidden" in all_text
    assert pdf_path.exists() and pdf_path.stat().st_size > 1000
