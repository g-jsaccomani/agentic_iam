"""Framework-Grounded Deterministic + Agentic IAM Posture Scoring Engine (`posture_scoring_engine.py`).

Implements a transparent, CISO-auditable two-layer scoring architecture grounded in five
authoritative cloud identity security frameworks (framed strictly as Consultative IAM Posture
Assessment & Modernization under the Google Cloud Shared Responsibility Model):
  1. Google Cloud Security Foundations Blueprint & Architecture Framework (`GCB-IAM-01..06`)
  2. NIST SP 800-53 Rev. 5 (`AC-2, AC-3, AC-4, AC-5, AC-6, IA-2(1), IA-5, SC-7, CA-7`)
  3. NIST Cybersecurity Framework (CSF) 2.0 (`PR.AA-01, PR.AA-03, PR.AA-05, DE.CM-03`)
  4. CIS Google Cloud Platform Foundation Benchmark v3.0 (`CIS 1.1, 1.3, 1.4, 1.5, 1.6, 1.7, 1.15, 4.4, 5.1`)
  5. CISA Zero Trust Maturity Model (ZTMM) v2.0 — Identity Pillar (`Traditional -> Initial -> Advanced -> Optimal`)

Mathematical Architecture:
- Layer 1 (Deterministic Control Engine — 95% Anchor): Evaluates 16 explicit controls across 5 domains
  using 100% live GCP telemetry, where every control exposes an exact `numerator / denominator` ratio
  and domain weight (`22% Internal + 18% External + 22% Workload + 20% Least-Privilege + 18% Graph = 100%`).
- Layer 2 (Bounded Agentic Contextual Calibration — ±5.0 pts max per domain): Google ADK specialist
  agents inspect contextual nuances (CEL JIT condition semantics, custom role permission toxicity,
  single-SA impersonation scoping, cross-binding toxic combinations) and apply an evidence-justified
  delta strictly bounded to `[-5.0, +5.0]` points.
- Layer 3 (NIST / CISA Critical Exposure Ceiling): Prevents false `Zero-Trust Accelerated (>= 85%)`
  classification when unmitigated anonymous public IAM access (`allUsers`/`allAuthenticatedUsers`) or
  aged (`> 90d`) static Service Account keys remain active without preventive Org Policy enforcement.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from backend.models.findings import (
    FrameworkBenchmarkScore,
    FrameworkControlEvaluation,
    PostureScorecard,
)
from backend.session_vault import register_cache_purge_hook
from backend.tools.cai_collector import (
    active_cache_namespace,
    active_organization_domain,
    collect_cai_service_account_inventory,
    collect_live_iam_bindings,
    collect_live_org_policies,
    normalize_gcp_scope,
)
from backend.tools.directory_collector import collect_cloud_identity_posture
from backend.tools.graph_engine import build_iam_privilege_graph
from backend.tools.recommender_tool import fetch_iam_role_recommendations

logger = logging.getLogger(__name__)

_SCORING_BASELINE_CACHE: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}
_SCORING_CACHE_TTL_SECONDS = 120.0

DOMAIN_COMPOSITE_WEIGHTS: Dict[str, float] = {
    "INTERNAL_IDENTITIES": 0.22,
    "EXTERNAL_IDENTITIES": 0.18,
    "WORKLOAD_IDENTITIES": 0.22,
    "LEAST_PRIVILEGE": 0.20,
    "GRAPH_RESILIENCE": 0.18,
}

PRIMITIVE_ROLES: Set[str] = {"roles/owner", "roles/editor"}
STANDING_HIGH_ADMIN_ROLES: Set[str] = {
    "roles/owner",
    "roles/editor",
    "roles/resourcemanager.organizationAdmin",
    "roles/iam.securityAdmin",
}
BROAD_IMPERSONATION_OR_KEY_ROLES: Set[str] = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountKeyAdmin",
}


def _purge_scoring_cache(session_id: str) -> None:
    prefix = f"{session_id}:"
    for k in [key for key in list(_SCORING_BASELINE_CACHE.keys()) if key[0].startswith(prefix)]:
        _SCORING_BASELINE_CACHE.pop(k, None)


register_cache_purge_hook(_purge_scoring_cache)


PASS_THRESHOLD_PCT = 85.0
PARTIAL_THRESHOLD_PCT = 50.0


def _clamp(val: Any, lo: float = 0.0, hi: float = 100.0) -> float:
    import math

    try:
        fval = float(val)
    except (TypeError, ValueError):
        fval = 0.0
    if not math.isfinite(fval):
        fval = 0.0
    return max(lo, min(hi, fval))


def _has_temporal_jit_condition(condition_expr: Optional[str]) -> bool:
    """Returns True ONLY if a CEL expression enforces an upper time bound (`request.time <` or `<=` + `timestamp(...)`).

    Any expression containing a logical OR (`||`) is rejected: an OR branch can make the time bound
    irrelevant (e.g. `true || request.time < timestamp(...)` is always true).
    """
    import re

    if not condition_expr:
        return False
    if "||" in condition_expr:
        return False
    lowered = condition_expr.lower()
    if "request.time" not in lowered or "timestamp(" not in lowered:
        return False
    if re.search(r"request\.time\s*<=?\s*timestamp\s*\(", lowered):
        return True
    if re.search(r"timestamp\s*\([^)]*\)\s*>=?\s*request\.time", lowered):
        return True
    return False


def _status_from_score(score_pct: float) -> str:
    if score_pct >= PASS_THRESHOLD_PCT:
        return "PASS"
    if score_pct >= PARTIAL_THRESHOLD_PCT:
        return "PARTIAL"
    return "FAIL"


def classify_maturity_tier(score_pct: float, *, max_tier: Optional[str] = None) -> str:
    """Maps 0-100% posture score to CISA ZTMM v2.0 / NIST CSF 2.0 aligned maturity tiers."""
    tier_order = ("Foundational", "Developing", "Managed", "Zero-Trust Accelerated")
    if score_pct >= 85.0:
        tier = "Zero-Trust Accelerated"
    elif score_pct >= 70.0:
        tier = "Managed"
    elif score_pct >= 50.0:
        tier = "Developing"
    else:
        tier = "Foundational"
    if max_tier in tier_order:
        if tier_order.index(tier) > tier_order.index(max_tier):
            return max_tier
    return tier


def _make_control(
    *,
    control_id: str,
    domain: str,
    control_title: str,
    framework_mappings: List[str],
    formula_expression: str,
    numerator: float,
    denominator: float,
    unit_label: str,
    domain_weight_pct: float,
    evidence_summary: str,
    override_status: Optional[str] = None,
    not_evaluated: bool = False,
) -> FrameworkControlEvaluation:
    if not_evaluated or override_status == "NOT_EVALUATED":
        return FrameworkControlEvaluation(
            control_id=control_id,
            domain=domain,
            control_title=control_title,
            framework_mappings=framework_mappings,
            formula_expression=formula_expression,
            numerator=0.0,
            denominator=0.0,
            unit_label=unit_label,
            deterministic_score_pct=0.0,
            domain_weight_pct=domain_weight_pct,
            status="NOT_EVALUATED",
            evidence_summary=evidence_summary,
        )
    safe_den = denominator if denominator > 0 else 1.0
    raw_pct = _clamp((numerator / safe_den) * 100.0, 0.0, 100.0)
    score_pct = round(raw_pct, 2)
    return FrameworkControlEvaluation(
        control_id=control_id,
        domain=domain,
        control_title=control_title,
        framework_mappings=framework_mappings,
        formula_expression=formula_expression,
        numerator=round(numerator, 2),
        denominator=round(safe_den, 2),
        unit_label=unit_label,
        deterministic_score_pct=score_pct,
        domain_weight_pct=domain_weight_pct,
        status=override_status or _status_from_score(score_pct),
        evidence_summary=evidence_summary,
    )


def _compute_framework_benchmarks(controls: List[FrameworkControlEvaluation]) -> List[FrameworkBenchmarkScore]:
    """Aggregates evaluated controls (excluding NOT_EVALUATED) into 5 authoritative security benchmark scores."""
    specs = [
        (
            "GCB",
            "Google Cloud Security Blueprint",
            "GCB-",
            "Group RBAC, Zero Standing Primitives, DRS, Keyless WIF & Continuous Right-Sizing",
        ),
        (
            "NIST_800_53",
            "NIST SP 800-53 Rev. 5",
            "NIST SP 800-53",
            "AC-2 Account Mgmt, AC-3/AC-6 Least Privilege, AC-5 SoD, IA-2/IA-5 AuthN & CA-7 Monitoring",
        ),
        (
            "NIST_CSF_2",
            "NIST CSF 2.0 (PR.AA / DE.CM)",
            "NIST CSF 2.0",
            "Identity Management, Authentication, Access Control & Continuous Activity Verification",
        ),
        (
            "CIS_GCP_3",
            "CIS Google Cloud Benchmark v3.0",
            "CIS GCP v3.0",
            "Corporate Identities, 2SV/OS Login, Zero User SA Keys (>90d), Default SA & Public Access Prevention",
        ),
        (
            "CISA_ZTMM_2",
            "CISA Zero Trust Maturity v2.0",
            "CISA ZTMM",
            "Identity Pillar Progression: Phishing-Resistant Auth, JIT Privilege & Lateral Movement Containment",
        ),
    ]
    out: List[FrameworkBenchmarkScore] = []
    for fid, fname, prefix, focus in specs:
        matched = [
            c
            for c in controls
            if c.status != "NOT_EVALUATED" and any(m.startswith(prefix) for m in c.framework_mappings)
        ]
        if not matched:
            out.append(
                FrameworkBenchmarkScore(
                    framework_id=fid,
                    framework_name=fname,
                    alignment_score_pct=0.0,
                    controls_passed=0,
                    controls_evaluated=0,
                    primary_focus=focus,
                )
            )
            continue
        avg_pct = round(sum(c.deterministic_score_pct for c in matched) / len(matched), 1)
        passed = sum(1 for c in matched if c.deterministic_score_pct >= PASS_THRESHOLD_PCT)
        out.append(
            FrameworkBenchmarkScore(
                framework_id=fid,
                framework_name=fname,
                alignment_score_pct=avg_pct,
                controls_passed=passed,
                controls_evaluated=len(matched),
                primary_focus=focus,
            )
        )
    return out


def compute_iam_framework_baseline(scope: str = "", force_refresh: bool = False) -> Dict[str, Any]:
    """Computes the 100% deterministic 18-control IAM scorecard baseline with explicit coverage awareness."""
    from backend.tools.cai_collector import assert_scope_allowed, discover_accessible_projects_in_scope, summarize_scan_coverage

    target_scope = assert_scope_allowed(scope).canonical_scope
    cache_key = (active_cache_namespace(), target_scope)
    now = time.monotonic()
    if not force_refresh and cache_key in _SCORING_BASELINE_CACHE:
        ts, cached = _SCORING_BASELINE_CACHE[cache_key]
        if (now - ts) < _SCORING_CACHE_TTL_SECONDS:
            return cached

    bindings = collect_live_iam_bindings(target_scope, force_refresh=force_refresh)
    org_policies = collect_live_org_policies(target_scope)
    sa_inv = json.loads(collect_cai_service_account_inventory(target_scope))
    dir_inv = json.loads(collect_cloud_identity_posture(target_scope))
    rec_inv = json.loads(fetch_iam_role_recommendations(target_scope))
    G, graph_summary = build_iam_privilege_graph(target_scope)
    projects_in_scope = discover_accessible_projects_in_scope(target_scope)
    coverage = summarize_scan_coverage(target_scope)

    bindings_incomplete = bool(coverage.get("bindings_incomplete"))
    resources_incomplete = bool(coverage.get("resources_incomplete"))
    sa_keys_incomplete = bool(coverage.get("sa_keys_incomplete"))
    cov_collectors = coverage.get("collectors") or {}
    resources_failed_http = any(
        (k == "cai_resources" or k.startswith("cai_resources:")) and not v.get("complete") and v.get("cutoff_reason") == "HTTP_ERROR"
        for k, v in cov_collectors.items()
    )

    cust_bindings = [b for b in bindings if not b.get("is_google_service_agent")]
    org_domain = active_organization_domain() or dir_inv.get("primary_organization_domain") or target_scope

    def _pol_status(constraint: str) -> Tuple[bool, bool]:
        entry = org_policies.get(constraint) or {}
        if entry.get("status") == "LIVE_EVALUATED":
            return True, bool(entry.get("enforced") is True)
        return False, False

    # -------------------------------------------------------------------------
    # DOMAIN 1: INTERNAL WORKFORCE IDENTITIES (Weight = 22%)
    # -------------------------------------------------------------------------
    int_user_bindings = [
        b for b in cust_bindings if b.get("principal_type") == "user" and not b.get("is_external")
    ]
    int_group_bindings = [
        b for b in cust_bindings if b.get("principal_type") == "group" and not b.get("is_external")
    ]
    internal_users: Set[str] = {b["principal"] for b in int_user_bindings}
    internal_groups: Set[str] = {b["principal"] for b in int_group_bindings}
    internal_principals: Set[str] = internal_users | internal_groups

    # IAM-INT-01: Group-Based RBAC Ratio (35%)
    human_group_total = len(int_user_bindings) + len(int_group_bindings)
    if human_group_total > 0:
        c_int_01_num, c_int_01_den, c_int_01_ne = float(len(int_group_bindings)), float(human_group_total), False
        c_int_01_ev = (
            f"{len(int_group_bindings)} group: bindings vs. {len(int_user_bindings)} direct user: bindings "
            f"across {len(internal_principals)} internal workforce principals."
        )
    elif bindings_incomplete:
        c_int_01_num, c_int_01_den, c_int_01_ne = 0.0, 0.0, True
        c_int_01_ev = "Not evaluated: IAM policy collection was incomplete."
    else:
        c_int_01_num, c_int_01_den, c_int_01_ne = 1.0, 1.0, False
        c_int_01_ev = "0 items in scope (complete coverage verified): no internal user or group bindings found."

    c_int_01 = _make_control(
        control_id="IAM-INT-01",
        domain="INTERNAL_IDENTITIES",
        control_title="Group-Based RBAC Governance (Group vs. Direct User Grants)",
        framework_mappings=[
            "GCB-IAM-01 (Group-Based Access)",
            "NIST SP 800-53 AC-2 (Account Management)",
            "NIST CSF 2.0 PR.AA-01",
            "CISA ZTMM v2.0 Identity Governance",
        ],
        formula_expression="group_bindings / (internal_direct_user_bindings + group_bindings)",
        numerator=c_int_01_num,
        denominator=c_int_01_den,
        unit_label="group bindings / workforce bindings",
        domain_weight_pct=35.0,
        evidence_summary=c_int_01_ev,
        not_evaluated=c_int_01_ne,
    )

    # IAM-INT-02: Zero Unconditioned Standing Primitive / OrgAdmin Roles on Workforce (35%)
    standing_prim_principals: Set[str] = set()
    for b in int_user_bindings + int_group_bindings:
        if b["role"] in STANDING_HIGH_ADMIN_ROLES and not _has_temporal_jit_condition(b.get("condition")):
            standing_prim_principals.add(b["principal"])

    if internal_principals:
        c_int_02_num = float(len(internal_principals - standing_prim_principals))
        c_int_02_den = float(len(internal_principals))
        c_int_02_ne = False
        c_int_02_ev = (
            f"{len(standing_prim_principals)} of {len(internal_principals)} internal workforce principals hold "
            f"unconditioned Owner/Editor/OrgAdmin/SecurityAdmin roles without upper-bounded temporal CEL expiry."
        )
    elif bindings_incomplete:
        c_int_02_num, c_int_02_den, c_int_02_ne = 0.0, 0.0, True
        c_int_02_ev = "Not evaluated: IAM policy collection was incomplete."
    else:
        c_int_02_num, c_int_02_den, c_int_02_ne = 1.0, 1.0, False
        c_int_02_ev = "0 items in scope (complete coverage verified): no internal workforce principals found."

    c_int_02 = _make_control(
        control_id="IAM-INT-02",
        domain="INTERNAL_IDENTITIES",
        control_title="Elimination of Unconditioned Standing Primitive & Org-Admin Roles",
        framework_mappings=[
            "GCB-IAM-02 (PAM JIT Over Standing Admin)",
            "NIST SP 800-53 AC-6(2), AC-6(5) (Privileged Accounts)",
            "CIS GCP v3.0 1.5",
            "CISA ZTMM v2.0 Just-In-Time Access",
        ],
        formula_expression="(internal_principals - unconditioned_standing_admin_principals) / internal_principals",
        numerator=c_int_02_num,
        denominator=c_int_02_den,
        unit_label="JIT-safe principals / internal principals",
        domain_weight_pct=35.0,
        evidence_summary=c_int_02_ev,
        not_evaluated=c_int_02_ne,
    )

    # IAM-INT-03: Separation of Duties on Hierarchy-Wide SA Impersonation / Key Admin (15%)
    broad_impersonators: Set[str] = set()
    for b in int_user_bindings:
        res = b.get("resource", "")
        is_hierarchy_wide = "/serviceAccounts/" not in res
        if (
            is_hierarchy_wide
            and b["role"] in BROAD_IMPERSONATION_OR_KEY_ROLES
            and not _has_temporal_jit_condition(b.get("condition"))
        ):
            broad_impersonators.add(b["principal"])

    if internal_users:
        c_int_03_num = float(len(internal_users - broad_impersonators))
        c_int_03_den = float(len(internal_users))
        c_int_03_ne = False
        c_int_03_ev = (
            f"{len(broad_impersonators)} of {len(internal_users)} internal users hold unconditioned "
            f"TokenCreator/SAUser/KeyAdmin at Project/Folder/Org level (single-SA resource scoping is compliant)."
        )
    elif bindings_incomplete:
        c_int_03_num, c_int_03_den, c_int_03_ne = 0.0, 0.0, True
        c_int_03_ev = "Not evaluated: IAM policy collection was incomplete."
    else:
        c_int_03_num, c_int_03_den, c_int_03_ne = 1.0, 1.0, False
        c_int_03_ev = "0 items in scope (complete coverage verified): no direct internal user bindings found."

    c_int_03 = _make_control(
        control_id="IAM-INT-03",
        domain="INTERNAL_IDENTITIES",
        control_title="Separation of Duties on Project/Org-Wide SA Impersonation & Key Admin",
        framework_mappings=[
            "CIS GCP v3.0 1.6 (Separation of Duties)",
            "NIST SP 800-53 AC-5 (Separation of Duties)",
            "NIST CSF 2.0 PR.AA-05",
        ],
        formula_expression="(internal_users - broad_impersonation_users) / internal_users",
        numerator=c_int_03_num,
        denominator=c_int_03_den,
        unit_label="SoD-compliant users / internal users",
        domain_weight_pct=15.0,
        evidence_summary=c_int_03_ev,
        not_evaluated=c_int_03_ne,
    )

    # IAM-INT-04: Workforce Strong Auth (Workspace 2SV + Compute OS Login) (15%)
    os_login_eval, os_login_enforced = _pol_status("constraints/compute.requireOsLogin")
    ws_dir = dir_inv.get("workspace_directory_api") or {}
    if ws_dir.get("reachable"):
        dir_total = max(int(ws_dir.get("directory_users_returned") or 0), 1)
        dir_2sv = int(ws_dir.get("mfa_2sv_enrolled_count") or 0)
        mfa_ratio = dir_2sv / dir_total
        combined_auth = 0.70 * mfa_ratio + 0.30 * (1.0 if os_login_enforced else 0.0)
        c_int_04_num = round(combined_auth * 100.0, 2)
        c_int_04_den = 100.0
        c_int_04_status = None
        c_int_04_ne = False
        c_int_04_ev = (
            f"Directory 2SV enrolled: {dir_2sv}/{dir_total} ({round(mfa_ratio * 100, 1)}%); "
            f"constraints/compute.requireOsLogin enforced={os_login_enforced}."
        )
    elif os_login_eval:
        c_int_04_num = 30.0 if os_login_enforced else 0.0
        c_int_04_den = 100.0
        c_int_04_status = "PARTIAL" if os_login_enforced else "UNDELEGATED"
        c_int_04_ne = False
        c_int_04_ev = (
            f"Partial telemetry only: Workspace Directory 2SV/MFA API not delegated "
            f"(HTTP {ws_dir.get('http_status', 'N/A')}) — MFA cannot be marked PASS. "
            f"constraints/compute.requireOsLogin enforced={os_login_enforced} (30% sub-weight)."
        )
    else:
        c_int_04_num, c_int_04_den, c_int_04_status, c_int_04_ne = 0.0, 0.0, "NOT_EVALUATED", True
        c_int_04_ev = (
            f"Not evaluated: both Workspace Directory API (HTTP {ws_dir.get('http_status', 'N/A')}) "
            f"and compute.requireOsLogin org policy were unavailable."
        )

    c_int_04 = _make_control(
        control_id="IAM-INT-04",
        domain="INTERNAL_IDENTITIES",
        control_title="Strong Workforce Authentication (2SV/MFA & Compute OS Login)",
        framework_mappings=[
            "NIST SP 800-53 IA-2(1) (Multi-Factor Auth)",
            "NIST CSF 2.0 PR.AA-03",
            "CIS GCP v3.0 1.3, 4.4 (OS Login)",
            "CISA ZTMM v2.0 Phishing-Resistant Auth",
        ],
        formula_expression="0.70 * directory_2sv_ratio + 0.30 * compute_require_os_login (PARTIAL when Directory API unavailable)",
        numerator=c_int_04_num,
        denominator=c_int_04_den,
        unit_label="auth enforcement units / 100",
        domain_weight_pct=15.0,
        evidence_summary=c_int_04_ev,
        override_status=c_int_04_status,
        not_evaluated=c_int_04_ne,
    )

    compliant_internal_set: Set[str] = set()
    roles_by_int_principal: Dict[str, List[Dict[str, Any]]] = {}
    for b in int_user_bindings + int_group_bindings:
        roles_by_int_principal.setdefault(b["principal"], []).append(b)

    for p in internal_principals:
        if p in standing_prim_principals or p in broad_impersonators:
            continue
        if p.startswith("group:"):
            compliant_internal_set.add(p)
        else:
            p_bindings = roles_by_int_principal.get(p, [])
            if p_bindings and all(
                _has_temporal_jit_condition(x.get("condition"))
                or ("/serviceAccounts/" in x.get("resource", "") and x["role"] == "roles/iam.serviceAccountTokenCreator")
                for x in p_bindings
            ):
                compliant_internal_set.add(p)

    # -------------------------------------------------------------------------
    # DOMAIN 2: EXTERNAL & PARTNER BOUNDARIES (Weight = 18%)
    # -------------------------------------------------------------------------
    public_bindings = [b for b in cust_bindings if b.get("principal_type") == "public"]
    ext_non_public_bindings = [
        b for b in cust_bindings if b.get("is_external") and b.get("principal_type") != "public"
    ]
    external_principals: Set[str] = {
        b["principal"] for b in cust_bindings if b.get("is_external") or b.get("principal_type") == "public"
    }

    # IAM-EXT-01: Zero Anonymous / Public IAM Exposure (35%)
    c_ext_01_num = max(0.0, 2.0 - float(len(public_bindings)))
    c_ext_01_ev = (
        f"{len(public_bindings)} anonymous/public IAM bindings (allUsers / allAuthenticatedUsers) detected in scope."
        if public_bindings
        else "0 items in scope (complete coverage verified): no allUsers or allAuthenticatedUsers bindings found."
    )
    c_ext_01 = _make_control(
        control_id="IAM-EXT-01",
        domain="EXTERNAL_IDENTITIES",
        control_title="Zero Anonymous or Public IAM Bindings (allUsers / allAuthenticatedUsers)",
        framework_mappings=[
            "GCB-IAM-03 (Zero Public Exposure)",
            "CIS GCP v3.0 1.15, 5.1",
            "NIST SP 800-53 AC-3 (Access Enforcement)",
            "NIST CSF 2.0 PR.AA-05",
        ],
        formula_expression="max(0, 2 - public_iam_bindings_count) / 2",
        numerator=c_ext_01_num,
        denominator=2.0,
        unit_label="zero-public gates passed / 2",
        domain_weight_pct=35.0,
        evidence_summary=c_ext_01_ev,
        not_evaluated=(bindings_incomplete and len(public_bindings) == 0),
    )

    # IAM-EXT-02: Domain Restricted Sharing (25%)
    drs_eval, drs_enforced = _pol_status("constraints/iam.allowedPolicyMemberDomains")
    c_ext_02 = _make_control(
        control_id="IAM-EXT-02",
        domain="EXTERNAL_IDENTITIES",
        control_title="Domain Restricted Sharing Enforcement (iam.allowedPolicyMemberDomains)",
        framework_mappings=[
            "GCB-IAM-03 (Domain Restricted Sharing)",
            "NIST SP 800-53 AC-3(7), AC-20 (External Systems)",
            "CISA ZTMM v2.0 Cross-Tenant Boundary",
        ],
        formula_expression="1 / 1 if allowedPolicyMemberDomains enforced else 0 / 1",
        numerator=1.0 if drs_enforced else 0.0,
        denominator=1.0,
        unit_label="org policy enforced / 1",
        domain_weight_pct=25.0,
        evidence_summary=(
            f"Effective policy constraints/iam.allowedPolicyMemberDomains enforced={drs_enforced}."
            if drs_eval
            else "Not evaluated: Organization Policy API unavailable for constraints/iam.allowedPolicyMemberDomains."
        ),
        not_evaluated=not drs_eval,
    )

    # IAM-EXT-03: Storage Public Access Prevention (15%)
    pap_eval, pap_enforced = _pol_status("constraints/storage.publicAccessPrevention")
    c_ext_03 = _make_control(
        control_id="IAM-EXT-03",
        domain="EXTERNAL_IDENTITIES",
        control_title="Cloud Storage Public Access Prevention (storage.publicAccessPrevention)",
        framework_mappings=[
            "GCB-IAM-03 (Data Perimeter)",
            "CIS GCP v3.0 5.1",
            "NIST SP 800-53 SC-7 (Boundary Protection)",
        ],
        formula_expression="1 / 1 if storage.publicAccessPrevention enforced else 0 / 1",
        numerator=1.0 if pap_enforced else 0.0,
        denominator=1.0,
        unit_label="org policy enforced / 1",
        domain_weight_pct=15.0,
        evidence_summary=(
            f"Effective policy constraints/storage.publicAccessPrevention enforced={pap_enforced}."
            if pap_eval
            else "Not evaluated: Organization Policy API unavailable for constraints/storage.publicAccessPrevention."
        ),
        not_evaluated=not pap_eval,
    )

    # IAM-EXT-04: External & Consumer Identity Least-Privilege Hygiene (25%)
    ext_by_principal: Dict[str, List[Dict[str, Any]]] = {}
    for b in public_bindings + ext_non_public_bindings:
        ext_by_principal.setdefault(b["principal"], []).append(b)

    compliant_external_set: Set[str] = set()
    ext_credit_sum = 0.0
    if not external_principals:
        if bindings_incomplete:
            c_ext_04_num, c_ext_04_den, c_ext_04_ne = 0.0, 0.0, True
            c_ext_04_ev = "Not evaluated: IAM policy collection was incomplete."
        else:
            c_ext_04_num, c_ext_04_den, c_ext_04_ne = 1.0, 1.0, False
            c_ext_04_ev = f"0 items in scope (complete coverage verified): no external/public principals outside '{org_domain}'."
    else:
        c_ext_04_ne = False
        for ep, eb_list in ext_by_principal.items():
            lower_ep = ep.lower()
            is_public_or_consumer = (
                ep in ("allUsers", "allAuthenticatedUsers")
                or lower_ep.endswith(("@gmail.com", "@googlemail.com"))
            )
            has_admin_or_prim = any(
                x["role"] in (PRIMITIVE_ROLES | STANDING_HIGH_ADMIN_ROLES | BROAD_IMPERSONATION_OR_KEY_ROLES)
                or "admin" in x["role"].lower()
                for x in eb_list
            )
            all_jit = all(_has_temporal_jit_condition(x.get("condition")) for x in eb_list)
            if not is_public_or_consumer and not has_admin_or_prim:
                if all_jit:
                    ext_credit_sum += 1.0
                    compliant_external_set.add(ep)
                else:
                    ext_credit_sum += 0.6
                    compliant_external_set.add(ep)
        c_ext_04_num = round(ext_credit_sum, 2)
        c_ext_04_den = float(len(external_principals))
        c_ext_04_ev = (
            f"{len(external_principals)} external/public principals evaluated across primary domain '{org_domain}'; "
            f"{len(compliant_external_set)} strictly scoped corporate partner principals."
        )

    c_ext_04 = _make_control(
        control_id="IAM-EXT-04",
        domain="EXTERNAL_IDENTITIES",
        control_title="External Partner & Consumer Account Governance (No Unmanaged Gmail / Admin)",
        framework_mappings=[
            "CIS GCP v3.0 1.1 (Corporate Credentials Only)",
            "NIST SP 800-53 AC-20 (External Information Systems)",
            "NIST CSF 2.0 PR.AA-01",
        ],
        formula_expression="governed_external_partner_units / total_external_or_public_principals",
        numerator=c_ext_04_num,
        denominator=c_ext_04_den,
        unit_label="governed external units / external principals",
        domain_weight_pct=25.0,
        evidence_summary=c_ext_04_ev,
        not_evaluated=c_ext_04_ne,
    )

    # -------------------------------------------------------------------------
    # DOMAIN 3: WORKLOAD & SERVICE ACCOUNTS (Weight = 22%)
    # -------------------------------------------------------------------------
    all_sas_raw: List[Dict[str, Any]] = sa_inv.get("service_accounts") or []
    sa_records: Dict[str, Dict[str, Any]] = {}
    for s in all_sas_raw:
        if s.get("is_google_managed_service_agent"):
            continue
        em = str(s.get("email") or "").strip().lower()
        if em:
            sa_records[em] = {
                "email": em,
                "is_default": bool(s.get("is_default_service_account")),
                "key_status": str(s.get("key_inspection_status") or "UNKNOWN"),
                "user_keys": int(s.get("user_managed_keys_count") or 0),
                "oldest_key_days": int(s.get("oldest_user_managed_key_age_days") or 0),
                "roles": set(s.get("granted_roles") or []),
            }
    for b in cust_bindings:
        if b.get("principal_type") == "service_account" and not b.get("is_google_service_agent"):
            em = b["principal"].split(":", 1)[-1].strip().lower()
            rec = sa_records.setdefault(
                em,
                {
                    "email": em,
                    "is_default": bool(b.get("is_default_sa")),
                    "key_status": "UNKNOWN",
                    "user_keys": 0,
                    "oldest_key_days": 0,
                    "roles": set(),
                },
            )
            rec["roles"].add(b["role"])

    total_sas = len(sa_records)
    verified_key_sas = [r for r in sa_records.values() if r["key_status"] != "UNKNOWN"]
    unknown_key_sas = [r for r in sa_records.values() if r["key_status"] == "UNKNOWN"]
    sas_keys_over_90d = sum(1 for r in sa_records.values() if r["oldest_key_days"] > 90)
    total_user_managed_keys = int(sa_inv.get("total_user_managed_keys") or sum(r["user_keys"] for r in sa_records.values()))
    wif_pools_count = int(sa_inv.get("workload_identity_pools_count") or 0)

    # IAM-WKL-01: Keyless Service Accounts & 90-Day Rotation Hygiene (30%)
    if resources_failed_http:
        c_wkl_01_num, c_wkl_01_den, c_wkl_01_ne = 0.0, 0.0, True
        c_wkl_01_ev = "Not evaluated: CAI searchAllResources failed (HTTP error); Service Account population unknown."
    elif total_sas == 0:
        if resources_incomplete or bindings_incomplete:
            c_wkl_01_num, c_wkl_01_den, c_wkl_01_ne = 0.0, 0.0, True
            c_wkl_01_ev = "Not evaluated: incomplete CAI resource or IAM binding collection."
        else:
            c_wkl_01_num, c_wkl_01_den, c_wkl_01_ne = 1.0, 1.0, False
            c_wkl_01_ev = "0 items in scope (complete coverage verified): no customer or default Service Accounts found."
    elif not verified_key_sas:
        c_wkl_01_num, c_wkl_01_den, c_wkl_01_ne = 0.0, 0.0, True
        c_wkl_01_ev = (
            f"Not evaluated: key inspection status UNKNOWN for all {total_sas} Service Accounts "
            f"(IAM key API queries failed or capped)."
        )
    else:
        c_wkl_01_ne = False
        key_credits = 0.0
        for r in verified_key_sas:
            if r["user_keys"] == 0:
                key_credits += 1.0
            elif r["oldest_key_days"] <= 90:
                key_credits += 0.25
        c_wkl_01_num = round(key_credits, 2)
        c_wkl_01_den = float(len(verified_key_sas))
        unk_note = f"; {len(unknown_key_sas)} SA(s) excluded with UNKNOWN key status" if unknown_key_sas else ""
        c_wkl_01_ev = (
            f"{sum(1 for r in verified_key_sas if r['user_keys'] == 0)}/{len(verified_key_sas)} verified SAs have zero "
            f"user-managed keys ({total_user_managed_keys} user-managed keys total; {sas_keys_over_90d} SAs >90d{unk_note})."
        )

    c_wkl_01 = _make_control(
        control_id="IAM-WKL-01",
        domain="WORKLOAD_IDENTITIES",
        control_title="Zero User-Managed Static SA Keys & 90-Day Key Hygiene",
        framework_mappings=[
            "GCB-IAM-04 (Keyless Workloads)",
            "CIS GCP v3.0 1.4, 1.7 (No User SA Keys / 90d Rotation)",
            "NIST SP 800-53 IA-5 (Authenticator Management)",
            "CISA ZTMM v2.0 Short-Lived Credentials",
        ],
        formula_expression="keyless_or_rotated_verified_sa_units / verified_customer_and_default_sas",
        numerator=c_wkl_01_num,
        denominator=c_wkl_01_den,
        unit_label="keyless SA units / verified SAs",
        domain_weight_pct=30.0,
        evidence_summary=c_wkl_01_ev,
        not_evaluated=c_wkl_01_ne,
    )

    # IAM-WKL-02: Preventive SA Key Creation & Upload Guardrails (25%)
    nkc_eval, no_key_create = _pol_status("constraints/iam.disableServiceAccountKeyCreation")
    nku_eval, no_key_upload = _pol_status("constraints/iam.disableServiceAccountKeyUpload")
    wkl_02_den = float(int(nkc_eval) + int(nku_eval))
    wkl_02_num = float((int(no_key_create) if nkc_eval else 0) + (int(no_key_upload) if nku_eval else 0))
    c_wkl_02 = _make_control(
        control_id="IAM-WKL-02",
        domain="WORKLOAD_IDENTITIES",
        control_title="Preventive SA Key Guardrails (disableServiceAccountKeyCreation & Upload)",
        framework_mappings=[
            "GCB-IAM-04 (Preventive Key Guardrails)",
            "NIST SP 800-53 IA-5, CM-6",
            "NIST CSF 2.0 PR.AA-03",
        ],
        formula_expression="(disableKeyCreation_enforced + disableKeyUpload_enforced) / evaluated_key_policies",
        numerator=wkl_02_num,
        denominator=wkl_02_den if wkl_02_den > 0 else 2.0,
        unit_label="key org policies enforced",
        domain_weight_pct=25.0,
        evidence_summary=(
            f"disableServiceAccountKeyCreation={no_key_create if nkc_eval else 'UNAVAILABLE'}, "
            f"disableServiceAccountKeyUpload={no_key_upload if nku_eval else 'UNAVAILABLE'}."
            if wkl_02_den > 0
            else "Not evaluated: Organization Policy API unavailable for SA key creation/upload constraints."
        ),
        not_evaluated=(wkl_02_den == 0),
    )

    # IAM-WKL-03: Default Compute & AppEngine SA De-Privileging (25%)
    nad_eval, no_auto_default_grants = _pol_status("constraints/iam.automaticIamGrantsForDefaultServiceAccounts")
    default_sas = [r for r in sa_records.values() if r["is_default"]]
    clean_default_sas = sum(1 for r in default_sas if len(r["roles"]) == 0)
    if resources_failed_http:
        c_wkl_03_num, c_wkl_03_den, c_wkl_03_ne = 0.0, 0.0, True
        c_wkl_03_ev = "Not evaluated: CAI searchAllResources failed (HTTP error); default SA inventory unavailable."
    else:
        c_wkl_03_ne = False
        pol_part = (1.0 if no_auto_default_grants else 0.0) if nad_eval else 0.0
        pol_den = 1.0 if nad_eval else 0.0
        c_wkl_03_num = pol_part + float(clean_default_sas)
        c_wkl_03_den = pol_den + float(len(default_sas))
        if c_wkl_03_den == 0:
            c_wkl_03_num, c_wkl_03_den = 1.0, 1.0
            c_wkl_03_ev = "0 items in scope (complete coverage verified): no default SAs found."
        else:
            c_wkl_03_ev = (
                f"automaticIamGrantsForDefaultServiceAccounts={no_auto_default_grants if nad_eval else 'UNAVAILABLE'}; "
                f"{len(default_sas) - clean_default_sas} of {len(default_sas)} Default SAs hold active IAM role bindings."
            )

    c_wkl_03 = _make_control(
        control_id="IAM-WKL-03",
        domain="WORKLOAD_IDENTITIES",
        control_title="Default Compute & AppEngine SA De-Privileging",
        framework_mappings=[
            "GCB-IAM-05 (Dedicated Per-Workload SAs)",
            "CIS GCP v3.0 1.5",
            "NIST SP 800-53 AC-6 (Least Privilege)",
        ],
        formula_expression="(automaticIamGrants_disabled + unprivileged_default_sas) / (evaluated_policy + default_sas_count)",
        numerator=c_wkl_03_num,
        denominator=c_wkl_03_den,
        unit_label="de-privileged units / total default SA checks",
        domain_weight_pct=25.0,
        evidence_summary=c_wkl_03_ev,
        not_evaluated=c_wkl_03_ne,
    )

    # IAM-WKL-04: Custom Workload SA Least-Privilege & WIF Adoption (20%)
    custom_sas = [r for r in sa_records.values() if not r["is_default"]]
    if resources_failed_http:
        c_wkl_04_num, c_wkl_04_den, c_wkl_04_ne = 0.0, 0.0, True
        c_wkl_04_ev = "Not evaluated: CAI searchAllResources failed (HTTP error); custom SA and WIF inventory unavailable."
    elif custom_sas:
        c_wkl_04_ne = False
        scoped_custom_sas = sum(
            1
            for r in custom_sas
            if not (r["roles"] & (PRIMITIVE_ROLES | {"roles/resourcemanager.organizationAdmin", "roles/iam.securityAdmin"}))
        )
        c_wkl_04_num = float(scoped_custom_sas)
        c_wkl_04_den = float(len(custom_sas))
        c_wkl_04_ev = (
            f"{scoped_custom_sas}/{len(custom_sas)} custom Service Accounts free of Owner/Editor/OrgAdmin; "
            f"{wif_pools_count} Workload Identity Federation pools discovered."
        )
    elif resources_incomplete:
        c_wkl_04_num, c_wkl_04_den, c_wkl_04_ne = 0.0, 0.0, True
        c_wkl_04_ev = "Not evaluated: CAI resource inventory was incomplete."
    else:
        c_wkl_04_ne = False
        c_wkl_04_num = 1.0 if clean_default_sas == len(default_sas) else 0.5
        c_wkl_04_den = 1.0
        c_wkl_04_ev = f"0 items in scope (complete coverage verified): 0 custom SAs; {wif_pools_count} WIF pools."

    c_wkl_04 = _make_control(
        control_id="IAM-WKL-04",
        domain="WORKLOAD_IDENTITIES",
        control_title="Dedicated Custom SA Least-Privilege & Workload Identity Federation",
        framework_mappings=[
            "GCB-IAM-04, GCB-IAM-05",
            "CIS GCP v3.0 1.5 (No Admin/Primitive Roles on SA)",
            "NIST CSF 2.0 PR.AA-05",
        ],
        formula_expression="non_primitive_custom_sas / total_custom_sas",
        numerator=c_wkl_04_num,
        denominator=c_wkl_04_den,
        unit_label="scoped custom SAs / custom SAs",
        domain_weight_pct=20.0,
        evidence_summary=c_wkl_04_ev,
        not_evaluated=c_wkl_04_ne,
    )

    compliant_workload_count = sum(
        1
        for r in sa_records.values()
        if r["key_status"] != "UNKNOWN"
        and r["user_keys"] == 0
        and not (r["is_default"] and len(r["roles"]) > 0)
        and not (r["roles"] & PRIMITIVE_ROLES)
    )

    # -------------------------------------------------------------------------
    # DOMAIN 4: LEAST-PRIVILEGE & RIGHT-SIZING INDEX (Weight = 20%)
    # -------------------------------------------------------------------------
    primitive_or_conv_bindings = [
        b
        for b in cust_bindings
        if b["role"] in PRIMITIVE_ROLES or b["principal"].startswith(("projectOwner:", "projectEditor:"))
    ]
    if cust_bindings:
        c_lpi_01_num = float(len(cust_bindings) - len(primitive_or_conv_bindings))
        c_lpi_01_den = float(len(cust_bindings))
        c_lpi_01_ne = False
        c_lpi_01_ev = (
            f"{len(cust_bindings) - len(primitive_or_conv_bindings)}/{len(cust_bindings)} customer IAM bindings "
            f"avoid legacy Owner/Editor and projectOwner/projectEditor grants."
        )
    elif bindings_incomplete:
        c_lpi_01_num, c_lpi_01_den, c_lpi_01_ne = 0.0, 0.0, True
        c_lpi_01_ev = "Not evaluated: IAM policy collection was incomplete."
    else:
        c_lpi_01_num, c_lpi_01_den, c_lpi_01_ne = 1.0, 1.0, False
        c_lpi_01_ev = "0 items in scope (complete coverage verified): no customer IAM bindings found."

    c_lpi_01 = _make_control(
        control_id="IAM-LPI-01",
        domain="LEAST_PRIVILEGE",
        control_title="Non-Primitive Role Adoption Across All Customer Bindings",
        framework_mappings=[
            "NIST SP 800-53 AC-6(5) (Privileged Accounts)",
            "GCB-IAM-02 (Predefined & Custom Roles Over Primitives)",
            "CIS GCP v3.0 1.5",
        ],
        formula_expression="(customer_bindings - primitive_or_convenience_bindings) / customer_bindings",
        numerator=c_lpi_01_num,
        denominator=c_lpi_01_den,
        unit_label="scoped bindings / customer bindings",
        domain_weight_pct=40.0,
        evidence_summary=c_lpi_01_ev,
        not_evaluated=c_lpi_01_ne,
    )

    # IAM-LPI-02: Permission Grant Tightness vs. Observed Cloud Audit Usage (35%)
    exposure_rows: List[Dict[str, Any]] = rec_inv.get("live_binding_permission_exposure") or []
    high_waste_count = 0
    total_unused_perms = 0
    if exposure_rows:
        eff_sum = 0.0
        for row in exposure_rows:
            g_cnt = int(row.get("granted_permissions_count") or 0)
            u_cnt = int(row.get("observed_permissions_exercised_in_audit_logs") or 0)
            has_jit = _has_temporal_jit_condition(row.get("condition"))
            excess_over_floor = max(0, g_cnt - max(u_cnt, 40))
            total_unused_perms += max(0, g_cnt - u_cnt)
            waste_ratio = min(1.0, excess_over_floor / 2500.0)
            if has_jit:
                waste_ratio *= 0.25
            eff_sum += 1.0 - waste_ratio
            if g_cnt >= 1000 and u_cnt <= 10 and not has_jit:
                high_waste_count += 1
        c_lpi_02_num = round(eff_sum, 2)
        c_lpi_02_den = float(len(exposure_rows))
        c_lpi_02_ne = False
    elif bindings_incomplete:
        c_lpi_02_num, c_lpi_02_den, c_lpi_02_ne = 0.0, 0.0, True
    else:
        c_lpi_02_num, c_lpi_02_den, c_lpi_02_ne = 1.0, 1.0, False

    audit_sample_meta = rec_inv.get("cloud_audit_log_usage") or {}
    audit_sample_size = int(audit_sample_meta.get("sample_size") or audit_sample_meta.get("total_audit_log_entries_sampled") or 0)
    audit_win_start = str(audit_sample_meta.get("window_start") or "")[:10]
    audit_win_end = str(audit_sample_meta.get("window_end") or "")[:10]
    audit_win_desc = f"{audit_win_start}..{audit_win_end}" if (audit_win_start and audit_win_end) else "observed window"

    c_lpi_02 = _make_control(
        control_id="IAM-LPI-02",
        domain="LEAST_PRIVILEGE",
        control_title="Permission Surface Tightness vs. Observed Cloud Audit Log Activity",
        framework_mappings=[
            "NIST SP 800-53 AC-6 (Least Privilege)",
            "NIST CSF 2.0 PR.AA-05",
            "GCB-IAM-06 (Permission Right-Sizing)",
        ],
        formula_expression="sum(1 - min(1, max(0, granted_perms - max(exercised_perms, 40)) / 2500)) / evaluated_bindings",
        numerator=c_lpi_02_num,
        denominator=c_lpi_02_den,
        unit_label="tightness-weighted bindings / evaluated bindings",
        domain_weight_pct=35.0,
        evidence_summary=(
            f"Evaluated {len(exposure_rows)} bindings against live IAM Roles API permission counts and "
            f"{audit_sample_size:,} sampled audit events ({audit_win_desc}; "
            f"{total_unused_perms:,} unexercised permissions across evaluated bindings)."
            if exposure_rows
            else (
                "Not evaluated: IAM policy collection was incomplete."
                if c_lpi_02_ne
                else "0 items in scope (complete coverage verified): no bindings to evaluate for permission waste."
            )
        ),
        not_evaluated=c_lpi_02_ne,
    )

    # IAM-LPI-03: IAM Recommender & Over-Privilege Backlog Containment (25%)
    rec_api = rec_inv.get("recommender_api") or {}
    active_ml_recs = int(rec_api.get("active_recommender_items_count") or 0)
    lpi_03_population = len(exposure_rows)
    if lpi_03_population > 0:
        overpriv_backlog = min(lpi_03_population, max(active_ml_recs, high_waste_count))
        c_lpi_03_num = float(lpi_03_population - overpriv_backlog)
        c_lpi_03_den = float(lpi_03_population)
        c_lpi_03_ne = False
        c_lpi_03_ev = (
            f"{active_ml_recs} active google.iam.policy.Recommender items and {high_waste_count} unconditioned "
            f">=1,000-permission bindings pending right-sizing across {lpi_03_population} evaluated bindings."
        )
    elif bindings_incomplete:
        c_lpi_03_num, c_lpi_03_den, c_lpi_03_ne = 0.0, 0.0, True
        c_lpi_03_ev = "Not evaluated: IAM policy collection was incomplete."
    else:
        c_lpi_03_num, c_lpi_03_den, c_lpi_03_ne = 1.0, 1.0, False
        c_lpi_03_ev = "0 items in scope (complete coverage verified): 0 right-sizing backlog items."

    c_lpi_03 = _make_control(
        control_id="IAM-LPI-03",
        domain="LEAST_PRIVILEGE",
        control_title="IAM Recommender & Broad-Admin Right-Sizing Backlog",
        framework_mappings=[
            "GCB-IAM-06 (IAM Recommender Automation)",
            "NIST SP 800-53 CA-7 (Continuous Monitoring), AC-6(1)",
            "NIST CSF 2.0 DE.CM-03",
        ],
        formula_expression="(evaluated_bindings - min(evaluated_bindings, max(active_recommender_items, unconditioned_1000perm_bindings))) / evaluated_bindings",
        numerator=c_lpi_03_num,
        denominator=c_lpi_03_den,
        unit_label="right-sized bindings / evaluated bindings",
        domain_weight_pct=25.0,
        evidence_summary=c_lpi_03_ev,
        not_evaluated=c_lpi_03_ne,
    )

    # -------------------------------------------------------------------------
    # DOMAIN 5: ATTACK-GRAPH & IMPERSONATION RESILIENCE (Weight = 18%)
    # -------------------------------------------------------------------------
    total_edges = G.number_of_edges()
    esc_edges = sum(1 for _, _, d in G.edges(data=True) if d.get("is_escalation_edge"))
    if total_edges > 0:
        c_grp_01_num = float(max(0, total_edges - esc_edges))
        c_grp_01_den = float(total_edges)
        c_grp_01_ne = False
        c_grp_01_ev = (
            f"{total_edges - esc_edges}/{total_edges} edges in the live NetworkX IAM graph are non-escalation "
            f"({esc_edges} edges carry escalation, impersonation, or external vectors)."
        )
    elif bindings_incomplete:
        c_grp_01_num, c_grp_01_den, c_grp_01_ne = 0.0, 0.0, True
        c_grp_01_ev = "Not evaluated: IAM policy collection was incomplete."
    else:
        c_grp_01_num, c_grp_01_den, c_grp_01_ne = 1.0, 1.0, False
        c_grp_01_ev = "0 items in scope (complete coverage verified): no attack graph edges discovered."

    c_grp_01 = _make_control(
        control_id="IAM-GRP-01",
        domain="GRAPH_RESILIENCE",
        control_title="Escalation-Free Directed IAM Graph Edge Ratio",
        framework_mappings=[
            "NIST SP 800-53 AC-6(10) (Prevent Privilege Escalation)",
            "CISA ZTMM v2.0 Lateral Movement Containment",
            "GCB-IAM-02",
        ],
        formula_expression="(total_graph_edges - escalation_capable_edges) / total_graph_edges",
        numerator=c_grp_01_num,
        denominator=c_grp_01_den,
        unit_label="non-escalation edges / total graph edges",
        domain_weight_pct=35.0,
        evidence_summary=c_grp_01_ev,
        not_evaluated=c_grp_01_ne,
    )

    # IAM-GRP-02: Size-Normalized Multi-Hop Escalation Containment (per 100 entry principals) (35%)
    from backend.tools.graph_engine import extract_raw_topological_paths

    entry_nodes = [
        nid for nid in G.nodes if G.nodes[nid].get("node_type") in ("user", "external_user", "group", "workload")
    ]
    bounded_paths = extract_raw_topological_paths(G, max_paths=50)
    multihop_esc_paths = sum(
        1
        for p in bounded_paths
        if int(p.get("hop_count") or 0) >= 2 and bool(p.get("has_escalation_edge", True))
    )
    entry_scale = max(len(entry_nodes) / 100.0, 1.0)
    paths_per_100_entries = round(multihop_esc_paths / entry_scale, 3)

    c_grp_02_num = 1.0
    c_grp_02_den = round(1.0 + 0.15 * paths_per_100_entries, 3)
    c_grp_02 = _make_control(
        control_id="IAM-GRP-02",
        domain="GRAPH_RESILIENCE",
        control_title="Multi-Hop SA Impersonation & Lateral Escalation Containment",
        framework_mappings=[
            "CISA ZTMM v2.0 Segmentation & Lateral Containment",
            "CIS GCP v3.0 1.6 (SA Impersonation SoD)",
            "NIST SP 800-53 AC-4 (Information Flow Enforcement)",
        ],
        formula_expression="1.0 / (1.0 + 0.15 * (multihop_escalation_paths / max(entry_principals / 100, 1)))",
        numerator=c_grp_02_num,
        denominator=c_grp_02_den,
        unit_label="normalized containment factor",
        domain_weight_pct=35.0,
        evidence_summary=(
            f"{multihop_esc_paths} multi-hop (>=2 hops) escalation paths ({paths_per_100_entries:.2f} per 100 entry principals; "
            f"{len(entry_nodes)} entry principals across {G.number_of_nodes()} graph nodes, max depth={graph_summary.max_chain_depth})."
        ),
        not_evaluated=(bindings_incomplete and total_edges == 0),
    )

    # IAM-GRP-03: Choke-Point Centrality & Size-Normalized Convenience ACL Isolation (30%)
    max_btw = 0.0
    if graph_summary.high_centrality_principals:
        max_btw = max(float(x.get("betweenness_centrality") or 0.0) for x in graph_summary.high_centrality_principals)
    conv_acl_nodes = sum(1 for nid in G.nodes if str(nid).startswith(("projectOwner:", "projectEditor:")))
    proj_scale = max(len(projects_in_scope), 1)
    conv_acl_per_project = conv_acl_nodes / proj_scale
    topo_penalty = min(1.0, 0.60 * max_btw + 0.20 * conv_acl_per_project)
    c_grp_03_num = round(10.0 * (1.0 - topo_penalty), 2)
    c_grp_03 = _make_control(
        control_id="IAM-GRP-03",
        domain="GRAPH_RESILIENCE",
        control_title="Blast-Radius Choke-Point Centrality & Convenience ACL Elimination",
        framework_mappings=[
            "NIST SP 800-53 AC-4, SC-7",
            "GCB-IAM-05 (Blast-Radius Isolation)",
            "CISA ZTMM v2.0",
        ],
        formula_expression="10 * (1 - min(1, 0.60 * max_betweenness + 0.20 * (convenience_acl_nodes / max(projects, 1)))) / 10",
        numerator=c_grp_03_num,
        denominator=10.0,
        unit_label="topology isolation units / 10",
        domain_weight_pct=30.0,
        evidence_summary=(
            f"Max NetworkX betweenness centrality={max_btw:.4f}; {conv_acl_nodes} legacy projectOwner:/projectEditor: "
            f"convenience ACL nodes across {proj_scale} project(s) ({conv_acl_per_project:.2f}/project)."
        ),
        not_evaluated=(bindings_incomplete and total_edges == 0),
    )

    controls: List[FrameworkControlEvaluation] = [
        c_int_01,
        c_int_02,
        c_int_03,
        c_int_04,
        c_ext_01,
        c_ext_02,
        c_ext_03,
        c_ext_04,
        c_wkl_01,
        c_wkl_02,
        c_wkl_03,
        c_wkl_04,
        c_lpi_01,
        c_lpi_02,
        c_lpi_03,
        c_grp_01,
        c_grp_02,
        c_grp_03,
    ]

    # Weight renormalization: NOT_EVALUATED controls are excluded and weights renormalized to 100%
    def _domain_det_score(dom: str) -> Tuple[Optional[float], int]:
        dom_ctrls = [c for c in controls if c.domain == dom and c.status != "NOT_EVALUATED"]
        if not dom_ctrls:
            return None, 0
        total_w = sum(c.domain_weight_pct for c in dom_ctrls)
        if total_w <= 0:
            return None, 0
        score = sum(c.deterministic_score_pct * (c.domain_weight_pct / total_w) for c in dom_ctrls)
        return round(score, 1), len(dom_ctrls)

    domain_scores: Dict[str, float] = {}
    evaluated_domain_weights: Dict[str, float] = {}
    for dom, comp_w in DOMAIN_COMPOSITE_WEIGHTS.items():
        d_score, eval_cnt = _domain_det_score(dom)
        if d_score is not None and eval_cnt > 0:
            domain_scores[dom] = d_score
            evaluated_domain_weights[dom] = comp_w
        else:
            domain_scores[dom] = 0.0

    total_comp_w = sum(evaluated_domain_weights.values())
    if total_comp_w > 0:
        deterministic_composite = round(
            sum(domain_scores[dom] * (w / total_comp_w) for dom, w in evaluated_domain_weights.items()),
            1,
        )
    else:
        deterministic_composite = 0.0

    # Critical Exposure Gate evaluation (NIST / CISA Zero-Trust Hard Ceiling = 84.0%)
    critical_gate_reasons: List[str] = []
    if len(public_bindings) > 0:
        critical_gate_reasons.append(
            f"{len(public_bindings)} anonymous/public IAM binding(s) (CIS 1.15 / NIST AC-3)"
        )
    if sas_keys_over_90d > 0 and not no_key_create:
        critical_gate_reasons.append(
            f"{sas_keys_over_90d} static SA key(s) >90 days without disableServiceAccountKeyCreation (CIS 1.4/1.7 / NIST IA-5)"
        )

    ceiling_pct = 84.0 if critical_gate_reasons else 100.0
    effective_det_score = min(deterministic_composite, ceiling_pct) if critical_gate_reasons else deterministic_composite
    max_tier_by_coverage = (
        "Managed" if (bindings_incomplete or resources_incomplete or sa_keys_incomplete) else None
    )

    benchmarks = _compute_framework_benchmarks(controls)

    result: Dict[str, Any] = {
        "scope": target_scope,
        "organization_domain": org_domain,
        "methodology_version": "GCB-NIST-CIS-ZTMM-v2.1",
        "domain_weights": DOMAIN_COMPOSITE_WEIGHTS,
        "deterministic_domain_scores": domain_scores,
        "evaluated_domain_weights": evaluated_domain_weights,
        "not_evaluated_domains": [dom for dom in DOMAIN_COMPOSITE_WEIGHTS if dom not in evaluated_domain_weights],
        "deterministic_composite_score": deterministic_composite,
        "deterministic_maturity_tier": classify_maturity_tier(effective_det_score, max_tier=max_tier_by_coverage),
        "coverage": coverage,
        "coverage_warnings": list(coverage.get("coverage_warnings") or []),
        "data_completeness_pct": float(coverage.get("data_completeness_pct", 100.0)),
        "total_user_managed_keys": total_user_managed_keys,
        "principal_compliance_counts": {
            "internal": {
                "total_principals_evaluated": len(internal_principals),
                "compliant_principals": len(compliant_internal_set),
            },
            "external": {
                "total_principals_evaluated": len(external_principals),
                "compliant_principals": len(compliant_external_set),
            },
            "workload": {
                "total_principals_evaluated": total_sas,
                "compliant_principals": compliant_workload_count,
            },
        },
        "critical_exposure_gate": {
            "triggered": bool(critical_gate_reasons),
            "ceiling_score_pct": ceiling_pct,
            "reasons": critical_gate_reasons,
        },
        "framework_benchmarks": [b.model_dump() for b in benchmarks],
        "control_evaluations": [c.model_dump() for c in controls],
    }
    _SCORING_BASELINE_CACHE[cache_key] = (now, result)
    return result


def synthesize_final_framework_scorecard(
    *,
    baseline: Dict[str, Any],
    total_bindings_analyzed: int,
    overprivileged_bindings_count: int,
    excess_permissions_eliminated: int,
    critical_findings: int,
    high_findings: int,
    medium_findings: int,
    low_findings: int,
    internal_delta: float = 0.0,
    external_delta: float = 0.0,
    workload_delta: float = 0.0,
    least_privilege_delta: float = 0.0,
    resilience_delta: float = 0.0,
    agentic_rationale: str = "",
) -> PostureScorecard:
    """Combines the 18-control deterministic baseline with bounded [-5, +5] ADK calibrations and explicit cap separation."""
    det = baseline["deterministic_domain_scores"]

    d_int = _clamp(internal_delta, -5.0, 5.0)
    d_ext = _clamp(external_delta, -5.0, 5.0)
    d_wkl = _clamp(workload_delta, -5.0, 5.0)
    d_lpi = _clamp(least_privilege_delta, -5.0, 5.0)
    d_grp = _clamp(resilience_delta, -5.0, 5.0)

    final_int = round(_clamp(det["INTERNAL_IDENTITIES"] + d_int, 0.0, 100.0), 1)
    final_ext = round(_clamp(det["EXTERNAL_IDENTITIES"] + d_ext, 0.0, 100.0), 1)
    final_wkl = round(_clamp(det["WORKLOAD_IDENTITIES"] + d_wkl, 0.0, 100.0), 1)
    final_lpi = round(_clamp(det["LEAST_PRIVILEGE"] + d_lpi, 0.0, 100.0), 1)
    final_grp = round(_clamp(det["GRAPH_RESILIENCE"] + d_grp, 0.0, 100.0), 1)

    eval_weights = baseline.get("evaluated_domain_weights") or DOMAIN_COMPOSITE_WEIGHTS
    total_w = sum(eval_weights.values()) or 1.0
    domain_finals = {
        "INTERNAL_IDENTITIES": final_int,
        "EXTERNAL_IDENTITIES": final_ext,
        "WORKLOAD_IDENTITIES": final_wkl,
        "LEAST_PRIVILEGE": final_lpi,
        "GRAPH_RESILIENCE": final_grp,
    }
    raw_overall = sum(domain_finals[dom] * (w / total_w) for dom, w in eval_weights.items())
    pre_cap_score = round(_clamp(raw_overall, 0.0, 100.0), 1)

    det_composite = float(baseline["deterministic_composite_score"])
    calibration_delta = round(_clamp(pre_cap_score - det_composite, -5.0, 5.0), 1)

    gate = baseline.get("critical_exposure_gate") or {}
    cap_applied: Optional[str] = None
    post_cap = pre_cap_score
    if gate.get("triggered") and pre_cap_score > float(gate.get("ceiling_score_pct", 84.0)):
        post_cap = float(gate["ceiling_score_pct"])
        cap_applied = "; ".join(gate.get("reasons") or [])

    final_overall = round(_clamp(post_cap, 0.0, 100.0), 1)
    critical_cap_delta = round(final_overall - pre_cap_score, 1)

    coverage_info = baseline.get("coverage") or {}
    cov_warnings = list(baseline.get("coverage_warnings") or coverage_info.get("coverage_warnings") or [])
    completeness_pct = float(baseline.get("data_completeness_pct", coverage_info.get("data_completeness_pct", 100.0)))
    max_tier = (
        "Managed"
        if (
            coverage_info.get("bindings_incomplete")
            or coverage_info.get("resources_incomplete")
            or coverage_info.get("sa_keys_incomplete")
        )
        else None
    )

    # Domains with zero evaluated controls keep their numeric 0.0 score but are listed so consumers render N/A
    if "not_evaluated_domains" in baseline:
        not_evaluated_domains = [str(d) for d in (baseline.get("not_evaluated_domains") or [])]
    elif "evaluated_domain_weights" in baseline:
        evaluated_domains = baseline.get("evaluated_domain_weights") or {}
        not_evaluated_domains = [dom for dom in DOMAIN_COMPOSITE_WEIGHTS if dom not in evaluated_domains]
    else:
        not_evaluated_domains = []

    controls_models = [FrameworkControlEvaluation.model_validate(c) for c in baseline["control_evaluations"]]
    benchmark_models = [FrameworkBenchmarkScore.model_validate(b) for b in baseline["framework_benchmarks"]]

    return PostureScorecard(
        scope=baseline["scope"],
        organization_domain=baseline["organization_domain"],
        overall_posture_score=final_overall,
        maturity_tier=classify_maturity_tier(final_overall, max_tier=max_tier),
        internal_identities_score=final_int,
        external_identities_score=final_ext,
        workload_identities_score=final_wkl,
        least_privilege_index=final_lpi,
        impersonation_resilience_score=final_grp,
        total_bindings_analyzed=total_bindings_analyzed,
        overprivileged_bindings_count=overprivileged_bindings_count,
        excess_permissions_eliminated=excess_permissions_eliminated,
        critical_findings=critical_findings,
        high_findings=high_findings,
        medium_findings=medium_findings,
        low_findings=low_findings,
        deterministic_composite_score=det_composite,
        agentic_calibration_delta=calibration_delta,
        critical_cap_delta=critical_cap_delta,
        pre_cap_score=pre_cap_score,
        agentic_calibration_rationale=agentic_rationale.strip(),
        critical_exposure_cap_applied=cap_applied,
        coverage_warnings=cov_warnings,
        data_completeness_pct=completeness_pct,
        not_evaluated_domains=not_evaluated_domains,
        framework_benchmarks=benchmark_models,
        control_evaluations=controls_models,
    )


def evaluate_iam_framework_scorecard(scope: str = "") -> str:
    """Evaluates the 18-control deterministic IAM framework baseline across Google Cloud Blueprint, NIST 800-53r5, NIST CSF 2.0, CIS GCP v3.0, and CISA ZTMM v2.0.

    Args:
        scope: Target GCP Organization or Multi-Project scope (e.g., 'organizations/123456789012').

    Returns:
        JSON string with exact numerator/denominator control scores, domain baseline scores, principal compliance counts, coverage completeness, and framework alignment benchmarks.
    """
    baseline = compute_iam_framework_baseline(scope=scope)
    return json.dumps(baseline, indent=2)
