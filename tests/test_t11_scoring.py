"""Tests for T11 — Posture scoring math, cap separation, NaN/clamp handling, JIT regex, and weights."""

from __future__ import annotations

import math
from typing import Any, Dict, Tuple

import pytest

from backend.models.findings import (
    AttackPathAgentOutput,
    RecommenderAgentOutput,
    TriadPillarSynthesis,
)
from backend.tools import cai_collector, posture_scoring_engine, recommender_tool


def _clear_caches() -> None:
    cai_collector._BINDINGS_CACHE.clear()
    cai_collector._RESOURCES_CACHE.clear()
    cai_collector._ORG_POLICIES_CACHE.clear()
    cai_collector._ACTIVE_ORG_PROJECTS_CACHE.clear()
    cai_collector._COVERAGE_CACHE.clear()
    cai_collector._SA_KEYS_CACHE.clear()
    posture_scoring_engine._SCORING_BASELINE_CACHE.clear()


def test_poc_baseline_92_3_with_cap_separates_calibration_and_cap_delta() -> None:
    """PoC acceptance case: baseline 92.3 with critical exposure cap (<=84.0) ->
    agentic_calibration_delta=0.0, pre_cap_score=92.3, critical_cap_delta=-8.3, final=84.0.
    """
    baseline = {
        "scope": "organizations/123456789012",
        "organization_domain": "example.com",
        "control_evaluations": [],
        "framework_benchmarks": [],
        "deterministic_domain_scores": {
            "INTERNAL_IDENTITIES": 92.3,
            "EXTERNAL_IDENTITIES": 92.3,
            "WORKLOAD_IDENTITIES": 92.3,
            "LEAST_PRIVILEGE": 92.3,
            "GRAPH_RESILIENCE": 92.3,
        },
        "deterministic_composite_score": 92.3,
        "deterministic_maturity_tier": "Managed",
        "critical_exposure_gate": {
            "triggered": True,
            "ceiling_score_pct": 84.0,
            "reasons": ["1 static SA key(s) >90 days without disableServiceAccountKeyCreation"],
        },
        "coverage": {
            "coverage_warnings": [],
            "data_completeness_pct": 100.0,
            "bindings_incomplete": False,
            "sa_keys_incomplete": False,
        },
        "coverage_warnings": [],
        "data_completeness_pct": 100.0,
    }
    sc = posture_scoring_engine.synthesize_final_framework_scorecard(
        baseline=baseline,
        total_bindings_analyzed=100,
        overprivileged_bindings_count=2,
        excess_permissions_eliminated=500,
        critical_findings=1,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
    )
    assert sc.deterministic_composite_score == 92.3
    assert sc.agentic_calibration_delta == 0.0
    assert sc.pre_cap_score == 92.3
    assert sc.critical_cap_delta == -8.3
    assert sc.overall_posture_score == 84.0
    assert sc.maturity_tier == "Managed"


def test_clamp_non_finite_values_become_zero() -> None:
    assert posture_scoring_engine._clamp(float("nan")) == 0.0
    assert posture_scoring_engine._clamp(float("inf")) == 0.0
    assert posture_scoring_engine._clamp(float("-inf")) == 0.0
    assert posture_scoring_engine._clamp(120.0) == 100.0
    assert posture_scoring_engine._clamp(-5.0) == 0.0


def test_agent_output_schemas_clamp_out_of_range_and_nan_deltas_without_raising() -> None:
    base_kwargs = dict(posture_score=80.0, total_principals_evaluated=10, compliant_principals=8)
    p1 = TriadPillarSynthesis(**base_kwargs, agentic_calibration_delta=7.5)
    assert p1.agentic_calibration_delta == 5.0
    p2 = TriadPillarSynthesis(**base_kwargs, agentic_calibration_delta=-12.0)
    assert p2.agentic_calibration_delta == -5.0
    p3 = TriadPillarSynthesis(**base_kwargs, agentic_calibration_delta=float("nan"))
    assert p3.agentic_calibration_delta == 0.0

    a1 = AttackPathAgentOutput(
        toxic_combinations_count=0,
        impersonation_resilience_score=90.0,
        agentic_calibration_delta=9.2,
    )
    assert a1.agentic_calibration_delta == 5.0
    a2 = AttackPathAgentOutput(
        toxic_combinations_count=0,
        impersonation_resilience_score=90.0,
        agentic_calibration_delta=float("inf"),
    )
    assert a2.agentic_calibration_delta == 0.0

    r1 = RecommenderAgentOutput(least_privilege_index=85.0, agentic_calibration_delta=-8.8)
    assert r1.agentic_calibration_delta == -5.0
    r2 = RecommenderAgentOutput(least_privilege_index=85.0, agentic_calibration_delta=float("-inf"))
    assert r2.agentic_calibration_delta == 0.0


def test_temporal_jit_condition_requires_upper_bound() -> None:
    # Lower-bound-only condition MUST NOT count as JIT!
    assert (
        posture_scoring_engine._has_temporal_jit_condition(
            'request.time > timestamp("2020-01-01T00:00:00Z")'
        )
        is False
    )
    assert (
        posture_scoring_engine._has_temporal_jit_condition(
            'request.time >= timestamp("2020-01-01T00:00:00Z")'
        )
        is False
    )
    # Upper-bound conditions DO count as JIT!
    assert (
        posture_scoring_engine._has_temporal_jit_condition(
            'request.time < timestamp("2026-12-31T23:59:59Z")'
        )
        is True
    )
    assert (
        posture_scoring_engine._has_temporal_jit_condition(
            'request.time <= timestamp("2026-12-31T23:59:59Z")'
        )
        is True
    )
    assert posture_scoring_engine._has_temporal_jit_condition(None) is False


def test_int_04_without_directory_api_is_partial_never_pass(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    _clear_caches()

    def fake_rest(method: str, url: str, **kwargs: Any) -> Tuple[int, Dict[str, Any]]:
        if ":searchAllIamPolicies" in url:
            return 200, {
                "results": [
                    {
                        "resource": "//cloudresourcemanager.googleapis.com/projects/alpha-proj",
                        "project": "projects/101",
                        "policy": {
                            "bindings": [
                                {"role": "roles/viewer", "members": ["user:alice@example.com"]}
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
        if "admin.googleapis.com" in url:
            return 403, {"error": "Domain-wide delegation not configured"}
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)

    baseline = posture_scoring_engine.compute_iam_framework_baseline(
        "organizations/123456789012", force_refresh=True
    )
    controls = {c["control_id"]: c for c in baseline["control_evaluations"]}
    int04 = controls["IAM-INT-04"]
    assert int04["status"] in {"PARTIAL", "UNDELEGATED"}
    assert int04["status"] != "PASS"
    assert int04["deterministic_score_pct"] <= 30.0
    assert "Directory" in int04["evidence_summary"] or "MFA" in int04["evidence_summary"]


def test_weights_sum_to_100_per_domain_and_composite_and_unified_threshold(
    monkeypatch: pytest.MonkeyPatch, fake_session: Any
) -> None:
    # Composite domain weights sum to 1.0 (100%)
    assert math.isclose(sum(posture_scoring_engine.DOMAIN_COMPOSITE_WEIGHTS.values()), 1.0, rel_tol=1e-9)
    assert posture_scoring_engine.PASS_THRESHOLD_PCT == 85.0

    _clear_caches()

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
            return 200, {"results": []}
        if "cloudresourcemanager.googleapis.com/v3/projects:search" in url:
            return 200, {"projects": [{"projectId": "alpha-proj", "name": "projects/101", "state": "ACTIVE"}]}
        if "orgpolicy.googleapis.com" in url:
            return 200, {"spec": {"rules": [{"enforce": True}]}}
        return 200, {}

    monkeypatch.setattr(cai_collector, "gcp_rest_request", fake_rest)
    monkeypatch.setattr(recommender_tool, "gcp_rest_request", fake_rest)

    baseline = posture_scoring_engine.compute_iam_framework_baseline(
        "organizations/123456789012", force_refresh=True
    )
    assert baseline["methodology_version"] == "GCB-NIST-CIS-ZTMM-v2.1"
    by_domain: Dict[str, float] = {}
    for c in baseline["control_evaluations"]:
        by_domain[c["domain"]] = by_domain.get(c["domain"], 0.0) + float(c["domain_weight_pct"])
    assert len(baseline["control_evaluations"]) == 18
    for dom, total_w in by_domain.items():
        assert math.isclose(total_w, 100.0, rel_tol=1e-6), f"Domain {dom} weights sum to {total_w}"
    # Verify LPI-03 numerator <= denominator on identical population
    lpi03 = next(c for c in baseline["control_evaluations"] if c["control_id"] == "IAM-LPI-03")
    assert 0 <= lpi03["numerator"] <= lpi03["denominator"]
