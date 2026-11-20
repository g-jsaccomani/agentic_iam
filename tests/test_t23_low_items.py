"""Tests for T23 — LOW-severity items: secret-material read guard, JIT `||` bypass, PAM duration bound,
not-evaluated domains, `resources_incomplete` tier cap, and payload-cap totals."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import docx
import pytest

from backend import report_generator as rg
from backend.models.findings import (
    AttackPathGraphSummary,
    CreatePamEntitlementAction,
    IaCAgentOutput,
    IaCPlan,
    IaCRemediationBundle,
    IdentityTriadCategory,
    IdentityTriadMatrix,
    IdentityTriadMetrics,
    PostureAccelerationBook,
    PostureScorecard,
)
from backend.tools import cai_collector, iac_renderer, posture_scoring_engine, recommender_tool
from backend.validators import assert_read_only_gcp_request

SCOPE = "organizations/123456789012"
ALL_DOMAINS = list(posture_scoring_engine.DOMAIN_COMPOSITE_WEIGHTS.keys())
NA_LABEL = "N/A (not evaluated)"


def _clear_caches() -> None:
    cai_collector._BINDINGS_CACHE.clear()
    cai_collector._RESOURCES_CACHE.clear()
    cai_collector._ORG_POLICIES_CACHE.clear()
    cai_collector._ACTIVE_ORG_PROJECTS_CACHE.clear()
    cai_collector._COVERAGE_CACHE.clear()
    cai_collector._SA_KEYS_CACHE.clear()
    posture_scoring_engine._SCORING_BASELINE_CACHE.clear()
    recommender_tool._ROLE_META_CACHE.clear()
    recommender_tool._AUDIT_USAGE_CACHE.clear()


def _make_fake_rest(*, resources_status: int = 200, policies_status: int = 200) -> Any:
    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        if ":searchAllIamPolicies" in url:
            if policies_status != 200:
                return policies_status, {"error": {"message": "Permission denied on searchAllIamPolicies"}}
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
            if resources_status != 200:
                return resources_status, {"error": {"message": "Permission denied on searchAllResources"}}
            return 200, {"results": []}
        if "cloudresourcemanager.googleapis.com/v3/projects:search" in url:
            return 200, {"projects": [{"projectId": "alpha-proj", "name": "projects/101", "state": "ACTIVE"}]}
        if "orgpolicy.googleapis.com" in url:
            return 200, {"spec": {"rules": [{"enforce": True}]}}
        return 200, {}

    return fake_rest


def _synthetic_baseline(
    *,
    domain_score: float = 96.0,
    coverage: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    baseline: Dict[str, Any] = {
        "scope": SCOPE,
        "organization_domain": "example.com",
        "control_evaluations": [],
        "framework_benchmarks": [],
        "deterministic_domain_scores": {dom: domain_score for dom in ALL_DOMAINS},
        "deterministic_composite_score": domain_score,
        "deterministic_maturity_tier": "Managed",
        "critical_exposure_gate": {"triggered": False, "ceiling_score_pct": 100.0, "reasons": []},
        "coverage": coverage
        or {
            "coverage_warnings": [],
            "data_completeness_pct": 100.0,
            "bindings_incomplete": False,
            "resources_incomplete": False,
            "sa_keys_incomplete": False,
        },
        "coverage_warnings": [],
        "data_completeness_pct": 100.0,
    }
    baseline.update(extra or {})
    return baseline


def _synthesize(baseline: Dict[str, Any]) -> PostureScorecard:
    return posture_scoring_engine.synthesize_final_framework_scorecard(
        baseline=baseline,
        total_bindings_analyzed=10,
        overprivileged_bindings_count=0,
        excess_permissions_eliminated=0,
        critical_findings=0,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
    )


# ---------------------------------------------------------------------------
# Item 1 — read-only guard must block secret material reads
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,url",
    [
        ("GET", "https://secretmanager.googleapis.com/v1/projects/x/secrets/s/versions/latest:access"),
        ("GET", "https://secretmanager.googleapis.com/v1/projects/x/secrets/s/versions/3:access?alt=json"),
        ("GET", "https://secretmanager.googleapis.com/v1/projects/x/secrets/s/versions/latest%3Aaccess"),
        ("POST", "https://secretmanager.googleapis.com/v1/projects/x/secrets/s/versions/latest:access"),
        ("GET", "https://apikeys.googleapis.com/v2/projects/x/locations/global/keys/k/keyString"),
        ("GET", "https://apikeys.googleapis.com/v2/projects/x/locations/global/keys/k/keyString/"),
        ("GET", "https://apikeys.googleapis.com/v2/projects/x/locations/global/keys/k%2FkeyString"),
    ],
)
def test_read_only_guard_blocks_secret_material_reads(method: str, url: str) -> None:
    with pytest.raises(PermissionError):
        assert_read_only_gcp_request(method, url)


@pytest.mark.parametrize(
    "method,url",
    [
        ("GET", "https://secretmanager.googleapis.com/v1/projects/x/secrets"),
        ("GET", "https://secretmanager.googleapis.com/v1/projects/x/secrets/s"),
        ("GET", "https://secretmanager.googleapis.com/v1/projects/x/secrets/s/versions"),
        ("GET", "https://secretmanager.googleapis.com/v1/projects/x/secrets/s/versions/latest"),
        ("POST", "https://secretmanager.googleapis.com/v1/projects/x/secrets/s:getIamPolicy"),
        ("GET", "https://apikeys.googleapis.com/v2/projects/x/locations/global/keys"),
        ("GET", "https://apikeys.googleapis.com/v2/projects/x/locations/global/keys/k"),
        ("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/x:getIamPolicy"),
    ],
)
def test_read_only_guard_still_allows_metadata_reads(method: str, url: str) -> None:
    assert_read_only_gcp_request(method, url)


@pytest.mark.parametrize(
    "url",
    [
        "https://secretmanager.googleapis.com/v1/projects/x/secrets/s/versions/latest:access",
        "https://apikeys.googleapis.com/v2/projects/x/locations/global/keys/k/keyString",
    ],
)
def test_gcp_rest_request_refuses_secret_material_before_token_or_network(url: str) -> None:
    # No session and no fake router: the error must come from the guard itself, before any token or HTTP use
    with pytest.raises(PermissionError, match="^Blocked (Secret Manager|API Keys)"):
        cai_collector.gcp_rest_request("GET", url)


# ---------------------------------------------------------------------------
# Item 2 — a CEL condition containing `||` is never a temporal JIT condition
# ---------------------------------------------------------------------------


def test_temporal_jit_condition_rejects_logical_or() -> None:
    jit = posture_scoring_engine._has_temporal_jit_condition
    assert jit('true || request.time < timestamp("2030-01-01T00:00:00Z")') is False
    assert jit('request.time < timestamp("2030-01-01T00:00:00Z") || true') is False
    assert jit('request.time < timestamp("2030-01-01T00:00:00Z")||resource.name.startsWith("x")') is False
    # Conditions without `||` keep their behaviour: an upper time bound is required
    assert jit('request.time < timestamp("2030-01-01T00:00:00Z")') is True
    assert jit('resource.name.startsWith("x") && request.time < timestamp("2030-01-01T00:00:00Z")') is True
    assert jit('request.time > timestamp("2020-01-01T00:00:00Z")') is False


# ---------------------------------------------------------------------------
# Item 3 — PAM entitlement max_request_duration upper/lower bound
# ---------------------------------------------------------------------------


def _pam_action(entitlement_id: str, duration: str) -> CreatePamEntitlementAction:
    return CreatePamEntitlementAction(
        entitlement_id=entitlement_id,
        parent_scope="projects/alpha-proj",
        eligible_principals=["group:platform-ops@example.com"],
        granted_role="roles/compute.viewer",
        max_request_duration=duration,
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
        }
    ]


def test_pam_entitlement_duration_999999s_is_rejected_and_absent_from_hcl(tmp_path: Path) -> None:
    plan = IaCPlan(
        create_pam_entitlements=[
            _pam_action("too-long-jit", "999999s"),
            _pam_action("one-hour-jit", "3600s"),
        ]
    )

    with pytest.raises(ValueError, match="max_request_duration '999999s'"):
        iac_renderer.validate_iac_plan(plan, bindings=_sample_bindings(), target_scope=SCOPE, strict=True)

    cleaned, rejected = iac_renderer.validate_iac_plan(
        plan, bindings=_sample_bindings(), target_scope=SCOPE, strict=False
    )
    assert [p.entitlement_id for p in cleaned.create_pam_entitlements] == ["one-hour-jit"]
    assert len(rejected) == 1
    assert "create_pam_entitlements[0]" in rejected[0] and "999999s" in rejected[0]

    bundle = recommender_tool.package_terraform_remediation_files(
        IaCAgentOutput(bundle_id="IAC-T23-PAM", plan=plan),
        scope=SCOPE,
        output_dir=tmp_path,
        bindings=_sample_bindings(),
        strict=False,
    )
    assert any("999999s" in reason for reason in bundle.rejected_plan_actions)
    all_hcl = "\n".join(
        [bundle.main_tf, bundle.variables_tf, bundle.iam_tf, bundle.pam_entitlements_tf, bundle.org_policies_tf]
    )
    assert "999999s" not in all_hcl
    assert "too-long-jit" not in all_hcl
    assert '"one-hour-jit"' in bundle.pam_entitlements_tf
    assert 'max_request_duration = "3600s"' in bundle.pam_entitlements_tf


def test_pam_entitlement_duration_boundaries() -> None:
    lo = iac_renderer.MIN_PAM_REQUEST_DURATION_SECONDS
    hi = iac_renderer.MAX_PAM_REQUEST_DURATION_SECONDS
    assert lo == 1800
    assert hi < 999999

    def _accepted(duration: str) -> bool:
        cleaned, rejected = iac_renderer.validate_iac_plan(
            IaCPlan(create_pam_entitlements=[_pam_action("bound-jit", duration)]),
            bindings=_sample_bindings(),
            target_scope=SCOPE,
            strict=False,
        )
        return bool(cleaned.create_pam_entitlements) and not rejected

    assert _accepted("3600s") is True
    assert _accepted(f"{lo}s") is True
    assert _accepted(f"{hi}s") is True
    assert _accepted(f"{lo - 1}s") is False
    assert _accepted(f"{hi + 1}s") is False


# ---------------------------------------------------------------------------
# Item 4 — not-evaluated domains are listed and rendered as N/A
# ---------------------------------------------------------------------------


def test_scorecard_lists_not_evaluated_domains_when_only_internal_is_evaluated() -> None:
    other_four = [d for d in ALL_DOMAINS if d != "INTERNAL_IDENTITIES"]
    scores = {dom: (88.0 if dom == "INTERNAL_IDENTITIES" else 0.0) for dom in ALL_DOMAINS}
    base_extra = {
        "deterministic_domain_scores": scores,
        "deterministic_composite_score": 88.0,
        "evaluated_domain_weights": {"INTERNAL_IDENTITIES": 0.22},
    }

    # Baseline carries the explicit key (current `compute_iam_framework_baseline` output shape)
    sc_explicit = _synthesize(_synthetic_baseline(extra={**base_extra, "not_evaluated_domains": list(other_four)}))
    assert sc_explicit.not_evaluated_domains == other_four

    # Older baseline without the key: derived from `evaluated_domain_weights`
    sc_derived = _synthesize(_synthetic_baseline(extra=base_extra))
    assert sc_derived.not_evaluated_domains == other_four

    # Existing score fields stay numeric and the composite only uses the evaluated domain
    assert sc_derived.internal_identities_score == 88.0
    assert sc_derived.external_identities_score == 0.0
    assert isinstance(sc_derived.impersonation_resilience_score, float)
    assert sc_derived.overall_posture_score == 88.0


def test_scorecard_not_evaluated_domains_defaults_to_empty_without_baseline_keys() -> None:
    sc = _synthesize(_synthetic_baseline())
    assert sc.not_evaluated_domains == []
    assert PostureScorecard.model_fields["not_evaluated_domains"].default_factory is list


@pytest.mark.parametrize(
    "resources_status,policies_status,expected_not_evaluated",
    [
        (200, 200, []),
        (403, 200, []),
        # No IAM bindings telemetry at all: every Least-Privilege and Graph control is NOT_EVALUATED
        (200, 403, ["LEAST_PRIVILEGE", "GRAPH_RESILIENCE"]),
    ],
)
def test_baseline_reports_not_evaluated_domains(
    monkeypatch: pytest.MonkeyPatch,
    fake_session: Any,
    resources_status: int,
    policies_status: int,
    expected_not_evaluated: List[str],
) -> None:
    _clear_caches()
    fake_rest = _make_fake_rest(resources_status=resources_status, policies_status=policies_status)
    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)

    baseline = posture_scoring_engine.compute_iam_framework_baseline(SCOPE, force_refresh=True)
    assert baseline["not_evaluated_domains"] == expected_not_evaluated

    # Independent derivation: a domain is not evaluated iff every one of its controls is NOT_EVALUATED
    statuses_by_domain: Dict[str, List[str]] = {}
    for ctrl in baseline["control_evaluations"]:
        statuses_by_domain.setdefault(ctrl["domain"], []).append(ctrl["status"])
    assert baseline["not_evaluated_domains"] == [
        dom for dom in ALL_DOMAINS if all(s == "NOT_EVALUATED" for s in statuses_by_domain[dom])
    ]
    assert set(baseline["not_evaluated_domains"]).isdisjoint(baseline["evaluated_domain_weights"])
    for dom in baseline["not_evaluated_domains"]:
        assert baseline["deterministic_domain_scores"][dom] == 0.0

    sc = _synthesize(baseline)
    assert sc.not_evaluated_domains == expected_not_evaluated


def _book_with_scorecard(sc: PostureScorecard) -> PostureAccelerationBook:
    def _tm(cat: IdentityTriadCategory, name: str) -> IdentityTriadMetrics:
        return IdentityTriadMetrics(
            category=cat,
            display_name=name,
            posture_score=0.0 if cat != IdentityTriadCategory.INTERNAL else 88.0,
            total_principals_evaluated=5,
            compliant_principals=4,
            critical_findings_count=0,
            high_findings_count=0,
            medium_findings_count=0,
        )

    return PostureAccelerationBook(
        scope=SCOPE,
        organization_domain="example.com",
        scorecard=sc,
        triad_matrix=IdentityTriadMatrix(
            scope=SCOPE,
            organization_domain="example.com",
            internal_identities=_tm(IdentityTriadCategory.INTERNAL, "Internal"),
            external_identities=_tm(IdentityTriadCategory.EXTERNAL, "External"),
            workload_service_accounts=_tm(IdentityTriadCategory.WORKLOAD_SA, "Workload"),
            findings=[],
        ),
        attack_graph=AttackPathGraphSummary(
            scope=SCOPE,
            total_nodes=0,
            total_edges=0,
            toxic_combinations_count=0,
            escalation_paths_count=0,
            max_chain_depth=0,
        ),
        recommendations=[],
        iac_bundle=IaCRemediationBundle(
            scope=SCOPE,
            bundle_id="test-t23",
            main_tf="# draft",
            iam_tf="# draft",
            variables_tf="# draft",
            org_policies_tf="# draft",
            pam_entitlements_tf="# draft",
        ),
        executive_narrative_markdown="Executive overview.",
    )


def _pdf_story_texts(flowable: Any) -> List[str]:
    """Recursively collects plain text from ReportLab flowables (Paragraphs, Tables, containers)."""
    if isinstance(flowable, (list, tuple)):
        out: List[str] = []
        for item in flowable:
            out.extend(_pdf_story_texts(item))
        return out
    if isinstance(flowable, str):
        return [flowable]
    if hasattr(flowable, "_cellvalues"):
        return _pdf_story_texts(flowable._cellvalues)
    if hasattr(flowable, "_content"):
        return _pdf_story_texts(flowable._content)
    if hasattr(flowable, "getPlainText"):
        return [flowable.getPlainText()]
    return []


def test_docx_and_pdf_render_na_for_not_evaluated_domains(tmp_path: Path) -> None:
    scores = {dom: (88.0 if dom == "INTERNAL_IDENTITIES" else 0.0) for dom in ALL_DOMAINS}
    sc = _synthesize(
        _synthetic_baseline(
            extra={
                "deterministic_domain_scores": scores,
                "deterministic_composite_score": 88.0,
                "evaluated_domain_weights": {"INTERNAL_IDENTITIES": 0.22},
            }
        )
    )
    book = _book_with_scorecard(sc)

    vm = rg.report_view_model(book)
    sec1_rows = [s for s in vm["sections"] if s["key"] == "sec_1"][0]["tables"][0]["rows"]
    score_by_dimension = {row[0]: row[1] for row in sec1_rows}
    assert score_by_dimension["Internal Workforce Identities (22%)"] == "88.0%"
    for label in (
        "External & Partner Boundaries (18%)",
        "Workload & Service Accounts (22%)",
        "Least-Privilege Optimization Index (20%)",
        "Attack-Graph & Impersonation Resilience (18%)",
    ):
        assert score_by_dimension[label] == NA_LABEL

    sec2_rows = [s for s in vm["sections"] if s["key"] == "sec_2"][0]["tables"][0]["rows"]
    assert {row[0]: row[1] for row in sec2_rows} == {
        "Internal": "88.0%",
        "External": NA_LABEL,
        "Workload": NA_LABEL,
    }

    docx_path = tmp_path / "na.docx"
    pdf_path = tmp_path / "na.pdf"
    rg.build_executive_docx_report(book, graph_png_path=None, output_path=docx_path)
    rg.build_executive_pdf_report(book, graph_png_path=None, output_path=pdf_path)

    doc = docx.Document(str(docx_path))
    docx_cells = [cell.text for tbl in doc.tables for row in tbl.rows for cell in row.cells]
    # 4 not-evaluated domains in the Section 1 scorecard + 2 not-evaluated pillars in the Section 2 triad table
    assert sum(1 for txt in docx_cells if txt.strip() == NA_LABEL) == 6
    assert "88.0%" in [txt.strip() for txt in docx_cells]

    assert pdf_path.read_bytes().startswith(b"%PDF-")
    pdf_texts = [t.strip() for t in _pdf_story_texts(rg._build_pdf_story(vm, None))]
    assert pdf_texts.count(NA_LABEL) == 6
    assert "88.0%" in pdf_texts


def test_reports_keep_numeric_scores_when_all_domains_are_evaluated() -> None:
    book = _book_with_scorecard(_synthesize(_synthetic_baseline(domain_score=80.0)))
    vm = rg.report_view_model(book)
    all_cells = [
        cell
        for section in vm["sections"]
        for table in section["tables"]
        for row in table["rows"]
        for cell in row
    ]
    assert NA_LABEL not in all_cells
    sec1_rows = [s for s in vm["sections"] if s["key"] == "sec_1"][0]["tables"][0]["rows"]
    assert {row[0]: row[1] for row in sec1_rows}["Least-Privilege Optimization Index (20%)"] == "80.0%"


# ---------------------------------------------------------------------------
# Item 5 — `resources_incomplete` caps the maturity tier at 'Managed'
# ---------------------------------------------------------------------------


def test_scorecard_tier_capped_at_managed_when_resources_incomplete() -> None:
    complete = _synthesize(_synthetic_baseline(domain_score=96.0))
    assert complete.overall_posture_score == 96.0
    assert complete.maturity_tier == "Zero-Trust Accelerated"

    incomplete = _synthesize(
        _synthetic_baseline(
            domain_score=96.0,
            coverage={
                "coverage_warnings": ["cai_resources [organizations/123456789012]: API error HTTP 403."],
                "data_completeness_pct": 66.7,
                "bindings_incomplete": False,
                "resources_incomplete": True,
                "sa_keys_incomplete": False,
            },
        )
    )
    assert incomplete.overall_posture_score == 96.0
    assert incomplete.maturity_tier == "Managed"


@pytest.mark.parametrize("resources_incomplete,expected_tier", [(True, "Managed"), (False, "Zero-Trust Accelerated")])
def test_baseline_tier_capped_at_managed_when_only_resources_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    fake_session: Any,
    resources_incomplete: bool,
    expected_tier: str,
) -> None:
    _clear_caches()
    fake_rest = _make_fake_rest()
    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)

    # Isolate the `resources_incomplete` flag: bindings and SA keys are reported complete
    real_summarize = cai_collector.summarize_scan_coverage

    def _coverage_with_only_resources_flag(scope: str = "") -> Dict[str, Any]:
        cov = dict(real_summarize(scope))
        cov.update(
            bindings_incomplete=False,
            resources_incomplete=resources_incomplete,
            sa_keys_incomplete=False,
        )
        return cov

    monkeypatch.setattr(cai_collector, "summarize_scan_coverage", _coverage_with_only_resources_flag)

    # Force a 99% score into the tier classifier so the coverage cap is the only thing that can lower the tier
    real_classify = posture_scoring_engine.classify_maturity_tier

    def _classify_as_if_score_99(score_pct: float, *, max_tier: Optional[str] = None) -> str:
        return real_classify(99.0, max_tier=max_tier)

    monkeypatch.setattr(posture_scoring_engine, "classify_maturity_tier", _classify_as_if_score_99)

    baseline = posture_scoring_engine.compute_iam_framework_baseline(SCOPE, force_refresh=True)
    assert baseline["coverage"]["resources_incomplete"] is resources_incomplete
    assert baseline["deterministic_maturity_tier"] == expected_tier


def test_resources_403_baseline_and_scorecard_never_exceed_managed(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_caches()
    fake_rest = _make_fake_rest(resources_status=403)
    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)

    baseline = posture_scoring_engine.compute_iam_framework_baseline(SCOPE, force_refresh=True)
    assert baseline["coverage"]["resources_incomplete"] is True
    assert baseline["deterministic_maturity_tier"] != "Zero-Trust Accelerated"

    # Even if every domain scored 97%, the real coverage block from a 403 scan keeps the tier at 'Managed'
    boosted = dict(baseline)
    boosted["deterministic_domain_scores"] = {dom: 97.0 for dom in ALL_DOMAINS}
    boosted["deterministic_composite_score"] = 97.0
    boosted["evaluated_domain_weights"] = dict(posture_scoring_engine.DOMAIN_COMPOSITE_WEIGHTS)
    boosted["not_evaluated_domains"] = []
    boosted["critical_exposure_gate"] = {"triggered": False, "ceiling_score_pct": 100.0, "reasons": []}
    sc = _synthesize(boosted)
    assert sc.overall_posture_score >= 95.0
    assert sc.maturity_tier == "Managed"


# ---------------------------------------------------------------------------
# Item 6 — payload-size caps carry the total population count
# ---------------------------------------------------------------------------


def test_iac_environment_payload_reports_total_service_accounts(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    sa_resources = [
        {
            "asset_type": "iam.googleapis.com/ServiceAccount",
            "name": f"//iam.googleapis.com/projects/alpha-proj/serviceAccounts/sa-{i:02d}@alpha-proj.iam.gserviceaccount.com",
            "project_id": "alpha-proj",
        }
        for i in range(45)
    ]
    monkeypatch.setattr(recommender_tool, "collect_live_iam_bindings", lambda scope: _sample_bindings())
    monkeypatch.setattr(recommender_tool, "collect_live_org_policies", lambda scope: {})
    monkeypatch.setattr(recommender_tool, "discover_accessible_projects_in_scope", lambda scope: ["alpha-proj"])
    monkeypatch.setattr(recommender_tool, "collect_live_resources", lambda scope: sa_resources)

    env = json.loads(recommender_tool.inspect_iac_target_environment(SCOPE))
    assert len(env["service_accounts"]) == 40
    assert env["service_accounts_total"] == 45
    assert env["service_accounts_listed_over_total"] == "40/45"


def test_sa_inventory_payload_reports_total_workloads(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    workloads = [
        {
            "asset_type": "compute.googleapis.com/Instance",
            "name": f"//compute.googleapis.com/projects/alpha-proj/zones/us-central1-a/instances/vm-{i:02d}",
            "project_id": "alpha-proj",
            "location": "us-central1-a",
        }
        for i in range(65)
    ]
    monkeypatch.setattr(cai_collector, "collect_live_iam_bindings", lambda scope, **kw: [])
    monkeypatch.setattr(cai_collector, "collect_live_resources", lambda scope, **kw: workloads)
    monkeypatch.setattr(
        cai_collector,
        "collect_unified_service_account_keys",
        lambda scope, **kw: {"by_sa": {}, "user_managed_keys_total": 0, "status": {}, "unknown_sa_count": 0},
    )

    inv = json.loads(cai_collector.collect_cai_service_account_inventory(SCOPE))
    assert len(inv["active_compute_and_cloud_run_workloads"]) == 60
    assert inv["active_compute_and_cloud_run_workloads_total"] == 65
    assert inv["active_compute_and_cloud_run_workloads_listed_over_total"] == "60/65"
