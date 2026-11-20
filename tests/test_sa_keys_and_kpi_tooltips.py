"""Regression tests for SA key collection coverage accuracy and KPI hover rationale popovers."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

import pytest
from fastapi.testclient import TestClient

from backend import main as main_mod
from backend.tools import cai_collector, posture_scoring_engine, recommender_tool


def _clear_caches() -> None:
    cai_collector._BINDINGS_CACHE.clear()
    cai_collector._RESOURCES_CACHE.clear()
    cai_collector._ORG_POLICIES_CACHE.clear()
    cai_collector._ACTIVE_ORG_PROJECTS_CACHE.clear()
    cai_collector._ORG_PROJECT_META_CACHE.clear()
    cai_collector._SA_KEYS_CACHE.clear()
    cai_collector._COVERAGE_CACHE.clear()
    posture_scoring_engine._SCORING_BASELINE_CACHE.clear()
    recommender_tool._ROLE_META_CACHE.clear()
    recommender_tool._AUDIT_USAGE_CACHE.clear()


def test_google_service_agent_patterns_cover_common_platform_robots_but_keep_defaults() -> None:
    google_agents = [
        "serviceAccount:service-123456@gs-project-accounts.iam.gserviceaccount.com",
        "serviceAccount:service-123456@gcf-admin-robot.iam.gserviceaccount.com",
        "serviceAccount:service-123456@dataflow-service-producer-prod.iam.gserviceaccount.com",
        "serviceAccount:service-123456@gcp-gae-service.iam.gserviceaccount.com",
        "serviceAccount:service-123456@firebase-rules.system.gserviceaccount.com",
        "serviceAccount:service-123456@gae-api-prod.google.com.iam.gserviceaccount.com",
        "serviceAccount:service-123456@bigquery-encryption.iam.gserviceaccount.com",
    ]
    for p in google_agents:
        assert cai_collector.is_google_managed_service_agent(p) is True, f"Expected Google agent: {p}"

    customer_or_default = [
        "serviceAccount:100200300-compute@developer.gserviceaccount.com",
        "serviceAccount:proj-alpha@appspot.gserviceaccount.com",
        "serviceAccount:100200300@cloudbuild.gserviceaccount.com",
        "serviceAccount:app-runner@proj-alpha.iam.gserviceaccount.com",
    ]
    for p in customer_or_default:
        assert cai_collector.is_google_managed_service_agent(p) is False, f"Should NOT be excluded: {p}"


def test_sa_keys_skips_cloudbuild_and_external_sas_and_resolves_org_level_default_sas(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_caches()
    scope = "organizations/123456789012"
    queried_urls: List[str] = []

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        params = kwargs.get("params") or {}
        if ":searchAllResources" in url:
            atypes = str(params.get("assetTypes") or "")
            if "cloudresourcemanager.googleapis.com/Project" in atypes:
                return 200, {
                    "results": [
                        {
                            "name": "//cloudresourcemanager.googleapis.com/projects/proj-alpha",
                            "project": "projects/100200300",
                            "state": "ACTIVE",
                        }
                    ]
                }
            return 200, {
                "results": [
                    {
                        "name": "//iam.googleapis.com/projects/proj-alpha/serviceAccounts/app@proj-alpha.iam.gserviceaccount.com",
                        "assetType": "iam.googleapis.com/ServiceAccount",
                        "project": "projects/100200300",
                        "additionalAttributes": {"email": "app@proj-alpha.iam.gserviceaccount.com"},
                    }
                ]
            }
        if ":searchAllIamPolicies" in url:
            return 200, {
                "results": [
                    {
                        "resource": "//cloudresourcemanager.googleapis.com/organizations/123456789012",
                        "policy": {
                            "bindings": [
                                {
                                    "role": "roles/editor",
                                    "members": [
                                        # Google-managed service agent -> excluded from key checks
                                        "serviceAccount:service-100200300@gs-project-accounts.iam.gserviceaccount.com",
                                        # Cloud Build legacy SA -> Google-hosted, cannot hold user keys
                                        "serviceAccount:100200300@cloudbuild.gserviceaccount.com",
                                        # External partner SA -> foreign org project, uninspectable
                                        "serviceAccount:vendor@foreign-partner-proj.iam.gserviceaccount.com",
                                        # Org-level default AppEngine SA -> must resolve to proj-alpha (not organizations/...)
                                        "serviceAccount:proj-alpha@appspot.gserviceaccount.com",
                                        # Org-level default Compute SA -> must resolve to 100200300 (not organizations/...)
                                        "serviceAccount:100200300-compute@developer.gserviceaccount.com",
                                        # Stale deleted SA in binding only -> returns 404
                                        "serviceAccount:deleted-sa@proj-alpha.iam.gserviceaccount.com",
                                    ],
                                }
                            ]
                        },
                    }
                ]
            }
        if "iam.googleapis.com/v1/" in url and "/keys" in url:
            queried_urls.append(url)
            assert "organizations" not in url, f"Org path must never be placed in IAM projects/ segment: {url}"
            if "deleted-sa" in url:
                return 404, {"error": {"status": "NOT_FOUND", "message": "Service account does not exist."}}
            # Simulate Compute SA returning 404 on numeric project, then 200 on wildcard `projects/-`
            if "100200300-compute" in url and "/projects/100200300/" in url:
                return 404, {"error": {"status": "NOT_FOUND", "message": "Not found on number"}}
            return 200, {"keys": []}
        if "orgpolicy.googleapis.com" in url:
            return 200, {"spec": {"rules": [{"enforce": True}]}}
        if "entries:list" in url:
            return 200, {"entries": []}
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)

    unified = cai_collector.collect_unified_service_account_keys(scope, force_refresh=True)
    by_sa = unified["by_sa"]

    # Never queried Google service agents, Cloud Build, or external partner SAs
    assert not any("gs-project-accounts" in u for u in queried_urls)
    assert not any("cloudbuild.gserviceaccount.com" in u for u in queried_urls)
    assert not any("foreign-partner-proj" in u for u in queried_urls)

    # Default Compute SA retried via projects/- after 404 and succeeded
    assert any("/projects/-/serviceAccounts/100200300-compute" in u for u in queried_urls)
    assert by_sa["100200300-compute@developer.gserviceaccount.com"]["key_inspection_status"] == "LIVE_IAM_API_VERIFIED"
    assert by_sa["proj-alpha@appspot.gserviceaccount.com"]["key_inspection_status"] == "LIVE_IAM_API_VERIFIED"
    assert by_sa["100200300@cloudbuild.gserviceaccount.com"]["key_inspection_status"] == "NOT_APPLICABLE_GOOGLE_HOSTED"
    assert by_sa["vendor@foreign-partner-proj.iam.gserviceaccount.com"]["key_inspection_status"] == "EXTERNAL_OUT_OF_SCOPE"
    assert by_sa["deleted-sa@proj-alpha.iam.gserviceaccount.com"]["key_inspection_status"] == "NOT_FOUND_OR_ORPHANED"

    # Collector coverage is 100% complete — zero false-positive HTTP_ERROR warnings!
    cov = cai_collector.summarize_scan_coverage(scope)
    assert cov["sa_keys_incomplete"] is False
    assert cov["data_completeness_pct"] == 100.0
    assert cov["coverage_warnings"] == []

    # Scoring: Cloud Build SA with roles/editor is STILL audited in IAM-WKL-03, and external SA is NOT double-counted in Domain 3
    baseline = posture_scoring_engine.compute_iam_framework_baseline(scope, force_refresh=True)
    assert baseline["data_completeness_pct"] == 100.0
    p_counts = baseline["principal_compliance_counts"]
    assert p_counts["external"]["total_principals_evaluated"] == 1  # vendor@foreign-partner-proj
    # Workload SAs: app, cloudbuild, appspot, compute, deleted-sa = 5 (external SA excluded from Domain 3!)
    assert p_counts["workload"]["total_principals_evaluated"] == 5
    # Only app@proj-alpha (no roles, verified keyless) is compliant; defaults with roles & orphaned are non-compliant
    assert p_counts["workload"]["compliant_principals"] == 1


def test_real_cai_sa_http_403_still_fails_closed_with_actionable_error_reason(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_caches()
    scope = "organizations/123456789012"
    sa_resources = [
        {
            "asset_type": "iam.googleapis.com/ServiceAccount",
            "name": "//iam.googleapis.com/projects/alpha-proj/serviceAccounts/ok@alpha-proj.iam.gserviceaccount.com",
            "project_id": "alpha-proj",
            "additional_attributes": {"email": "ok@alpha-proj.iam.gserviceaccount.com"},
        },
        {
            "asset_type": "iam.googleapis.com/ServiceAccount",
            "name": "//iam.googleapis.com/projects/alpha-proj/serviceAccounts/denied@alpha-proj.iam.gserviceaccount.com",
            "project_id": "alpha-proj",
            "additional_attributes": {"email": "denied@alpha-proj.iam.gserviceaccount.com"},
        },
    ]

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        if "denied" in url:
            return 403, {"error": {"status": "PERMISSION_DENIED", "message": "Missing iam.serviceAccountKeys.list"}}
        return 200, {"keys": []}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)

    unified = cai_collector.collect_unified_service_account_keys(
        scope, bindings=[], resources=sa_resources, force_refresh=True
    )
    assert unified["by_sa"]["denied@alpha-proj.iam.gserviceaccount.com"]["key_inspection_status"] == "UNKNOWN"
    cov = cai_collector.summarize_scan_coverage(scope)
    assert cov["sa_keys_incomplete"] is True
    assert cov["coverage_warnings"]
    assert any("HTTP_403" in w and "PERMISSION_DENIED" in w for w in cov["coverage_warnings"]), cov["coverage_warnings"]


def test_dashboard_html_renders_kpi_hover_rationale_popovers_and_85_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("K_SERVICE", raising=False)
    client = TestClient(main_mod.app)
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.text

    # All 4 KPI cards carry accessible rationale popover attributes and Formula cues
    for key in ("overall", "compliant", "lpi", "crithigh"):
        assert f'data-kpi-rationale="{key}"' in body
    assert 'id="kpiRationalePopover"' in body
    assert 'role="tooltip"' in body
    assert "function buildKpiRationaleHtml(" in body
    assert "function showKpiRationalePopover(" in body
    assert "function initKpiRationalePopovers(" in body
    assert "initKpiRationalePopovers();" in body

    # Rationale covers all 4 metrics' real calculation inputs
    assert "18-Control Weighted Baseline" in body
    assert "Baseline Pass Criteria" in body
    assert "IAM-LPI-01" in body and "IAM-LPI-02" in body and "IAM-LPI-03" in body
    assert "Counted Critical &amp; High Findings" in body

    # Report preview threshold aligns with unified 85% benchmark threshold
    assert "Controls &ge;85%" in body
    assert "Controls &ge;80%" not in body
