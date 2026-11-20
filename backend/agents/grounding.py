"""Deterministic Python grounding layer for Google ADK LLM outputs (`backend/agents/grounding.py`).

Every finding, attack path, and least-privilege recommendation emitted by an LLM specialist agent
MUST be cross-checked against collected live GCP telemetry before entering the Posture Acceleration Book,
Scorecard severity tallies, UI views, or executive reports:
1. Triad findings: principal must exist in collected bindings or asset inventory; role (when provided)
   must exist for that principal in collected bindings; resource must belong to the assessed scope.
   Ungrounded items are dropped and counted; surviving findings receive deterministic unique IDs.
2. Attack paths: every consecutive pair `(hop_sequence[i], hop_sequence[i+1])` must be a real
   directed edge in the live NetworkX graph `G`. `toxic_combinations_count` and
   `escalation_paths_count` are calculated deterministically in Python.
3. Recommendations: current `(principal, current_role)` must exist in collected bindings;
   `permissions_granted_count` is overwritten from the live IAM Roles API, and
   `permissions_exercised_90d` is overwritten from the bounded Cloud Audit Log sample.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx

from backend.models.findings import (
    AttackPathFinding,
    GcpIamPostureFinding,
    LeastPrivilegeRecommendation,
    RiskSeverity,
)
from backend.tools.cai_collector import parse_assessment_scope

logger = logging.getLogger(__name__)

_SEVERITY_ORDER: Dict[RiskSeverity, int] = {
    RiskSeverity.CRITICAL: 0,
    RiskSeverity.HIGH: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.LOW: 3,
}

_NON_ROLE_PLACEHOLDERS: Set[str] = {"", "n/a", "none", "null", "-", "unknown"}


def _norm_principal(raw: str) -> str:
    return str(raw or "").strip().lower()


def _principal_identifier(raw: str) -> str:
    val = _norm_principal(raw)
    return val.split(":", 1)[-1] if ":" in val else val


def _extract_resource_project_id(resource: str) -> str:
    m = re.search(r"(?:^|/)projects/([a-z][a-z0-9-]{4,28}[a-z0-9])(?:/|$)", str(resource or ""))
    return m.group(1) if m else ""


def _extract_resource_org_id(resource: str) -> str:
    m = re.search(r"(?:^|/)organizations/([0-9]{1,32})(?:/|$)", str(resource or ""))
    return m.group(1) if m else ""


def _extract_resource_folder_id(resource: str) -> str:
    m = re.search(r"(?:^|/)folders/([0-9]{1,32})(?:/|$)", str(resource or ""))
    return m.group(1) if m else ""


def _resource_in_scope(
    resource: str,
    *,
    target_scope: str,
    known_resources: Set[str],
    known_projects: Set[str],
) -> bool:
    """Returns True if `resource` matches collected resources or lies within `target_scope`."""
    res = str(resource or "").strip()
    if not res:
        return True
    res_low = res.lower()
    if res_low in known_resources:
        return True

    parsed = parse_assessment_scope(target_scope)
    if parsed.canonical_scope.lower() in res_low:
        return True

    res_org = _extract_resource_org_id(res)
    if res_org:
        if parsed.organization_id:
            return res_org == parsed.organization_id
        return False

    res_proj = _extract_resource_project_id(res)
    if res_proj:
        if parsed.project_ids:
            return res_proj in set(parsed.project_ids)
        if known_projects:
            return res_proj in known_projects
        return parsed.mode == "ORG_ALL"

    res_folder = _extract_resource_folder_id(res)
    if res_folder:
        if parsed.mode == "FOLDER":
            return parsed.canonical_scope == f"folders/{res_folder}"
        return parsed.mode == "ORG_ALL"

    return False


def ground_triad_findings(
    findings: Iterable[GcpIamPostureFinding],
    *,
    bindings: List[Dict[str, Any]],
    resources: Optional[List[Dict[str, Any]]] = None,
    target_scope: str = "",
) -> Tuple[List[GcpIamPostureFinding], int]:
    """Filters and deterministically renumbers Triad findings strictly grounded in live telemetry."""
    binding_principals_full: Set[str] = set()
    binding_principals_id: Set[str] = set()
    roles_by_principal_full: Dict[str, Set[str]] = {}
    roles_by_principal_id: Dict[str, Set[str]] = {}
    known_resources: Set[str] = set()
    known_projects: Set[str] = set()

    for b in bindings or []:
        p_full = _norm_principal(b.get("principal", ""))
        p_id = _principal_identifier(p_full)
        role_norm = str(b.get("role") or "").strip().lower()
        res_norm = str(b.get("resource") or "").strip().lower()
        pid = str(b.get("project_id") or "").strip()
        if p_full:
            binding_principals_full.add(p_full)
            roles_by_principal_full.setdefault(p_full, set())
            if role_norm:
                roles_by_principal_full[p_full].add(role_norm)
        if p_id:
            binding_principals_id.add(p_id)
            roles_by_principal_id.setdefault(p_id, set())
            if role_norm:
                roles_by_principal_id[p_id].add(role_norm)
        if res_norm:
            known_resources.add(res_norm)
        if pid and pid not in ("org-or-folder", "unknown-project"):
            known_projects.add(pid)

    inventory_principals_id: Set[str] = set()
    for r in resources or []:
        rname = str(r.get("name") or "").strip()
        if rname:
            known_resources.add(rname.lower())
        pid = str(r.get("project_id") or "").strip()
        if pid and pid not in ("org-or-folder", "unknown-project"):
            known_projects.add(pid)
        if r.get("asset_type") == "iam.googleapis.com/ServiceAccount":
            attrs = r.get("additional_attributes") or {}
            ver = r.get("versioned_resource") or {}
            email = str(attrs.get("email") or ver.get("email") or rname.rsplit("/serviceAccounts/", 1)[-1]).strip().lower()
            if email:
                inventory_principals_id.add(email)
                binding_principals_full.add(f"serviceaccount:{email}")

    grounded: List[GcpIamPostureFinding] = []
    dropped = 0

    for item in findings or []:
        p_full = _norm_principal(item.principal)
        p_id = _principal_identifier(p_full)
        role_raw = str(item.role or "").strip()
        role_low = role_raw.lower()

        principal_exists = (
            (p_full in binding_principals_full)
            or (p_id in binding_principals_id)
            or (p_id in inventory_principals_id)
        )
        if not principal_exists:
            logger.info("Grounding dropped ungrounded finding principal='%s'", item.principal)
            dropped += 1
            continue

        if role_low not in _NON_ROLE_PLACEHOLDERS:
            matched_roles = roles_by_principal_full.get(p_full) or roles_by_principal_id.get(p_id) or set()
            if role_low not in matched_roles:
                logger.info(
                    "Grounding dropped finding with ungrounded role '%s' for principal '%s'",
                    item.role,
                    item.principal,
                )
                dropped += 1
                continue

        if target_scope and not _resource_in_scope(
            item.resource,
            target_scope=target_scope,
            known_resources=known_resources,
            known_projects=known_projects,
        ):
            logger.info(
                "Grounding dropped finding with out-of-scope resource '%s' (scope='%s')",
                item.resource,
                target_scope,
            )
            dropped += 1
            continue

        grounded.append(item.model_copy(update={"scope": target_scope or item.scope}))

    # Deterministic ordering & unique sequential IDs
    grounded.sort(
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 9),
            _norm_principal(f.principal),
            str(f.role or "").lower(),
            str(f.resource or "").lower(),
            str(f.title or "").lower(),
        )
    )
    renumbered: List[GcpIamPostureFinding] = []
    for idx, f in enumerate(grounded, start=1):
        renumbered.append(f.model_copy(update={"finding_id": f"IAM-{idx:03d}"}))

    return renumbered, dropped


def ground_attack_paths(
    paths: Iterable[AttackPathFinding],
    *,
    graph: nx.DiGraph,
    base_escalation_paths_count: int = 0,
) -> Tuple[List[AttackPathFinding], int, int, int]:
    """Verifies every consecutive hop in `hop_sequence` is a real directed edge in `graph`.

    Returns `(grounded_paths, dropped_count, deterministic_escalation_count, deterministic_toxic_count)`.
    """
    grounded: List[AttackPathFinding] = []
    dropped = 0
    seen_hops: Set[Tuple[str, ...]] = set()

    for p in paths or []:
        seq = [str(n).strip() for n in (p.hop_sequence or []) if str(n).strip()]
        if len(seq) < 2:
            dropped += 1
            continue

        all_edges_exist = True
        for u, v in zip(seq, seq[1:]):
            if not graph.has_edge(u, v):
                all_edges_exist = False
                break
        if not all_edges_exist:
            logger.info("Grounding dropped ungrounded attack path '%s': hops=%s", p.path_id, seq)
            dropped += 1
            continue

        hop_key = tuple(seq)
        if hop_key in seen_hops:
            continue
        seen_hops.add(hop_key)
        grounded.append(
            p.model_copy(
                update={
                    "hop_sequence": seq,
                    "entry_principal": seq[0],
                    "target_crown_jewel": seq[-1],
                }
            )
        )

    grounded.sort(
        key=lambda p: (
            _SEVERITY_ORDER.get(p.severity, 9),
            -len(p.hop_sequence),
            p.entry_principal.lower(),
            p.target_crown_jewel.lower(),
        )
    )
    renumbered = [p.model_copy(update={"path_id": f"AP-{idx:03d}"}) for idx, p in enumerate(grounded, start=1)]

    # Deterministic escalation path count from verified graph + grounded paths
    grounded_escalation_cnt = sum(
        1
        for p in renumbered
        if any(graph.edges[u, v].get("is_escalation_edge") for u, v in zip(p.hop_sequence, p.hop_sequence[1:]))
    )
    deterministic_escalation_count = max(int(base_escalation_paths_count or 0), grounded_escalation_cnt)

    # Deterministic toxic combination count computed strictly in Python from grounded paths & graph structure
    toxic_keys: Set[Tuple[str, str, str]] = set()
    for p in renumbered:
        if len(p.hop_sequence) >= 3 or any(
            graph.edges[u, v].get("is_escalation_edge") for u, v in zip(p.hop_sequence, p.hop_sequence[1:])
        ):
            toxic_keys.add((p.entry_principal, p.target_crown_jewel, p.toxic_combination_type))

    # Also detect graph-structural toxic combinations: any node that has BOTH an incoming escalation/external vector
    # AND an outgoing escalation edge to a privileged target/SA
    for nid in graph.nodes:
        in_esc = any(d.get("is_escalation_edge") for _, _, d in graph.in_edges(nid, data=True))
        out_esc = any(d.get("is_escalation_edge") for _, _, d in graph.out_edges(nid, data=True))
        if in_esc and out_esc:
            toxic_keys.add((str(nid), "CHAIN_BRIDGE", "SA_IMPERSONATION_CHAIN"))

    deterministic_toxic_count = len(toxic_keys)
    return renumbered, dropped, deterministic_escalation_count, deterministic_toxic_count


def ground_recommendations(
    recs: Iterable[LeastPrivilegeRecommendation],
    *,
    bindings: List[Dict[str, Any]],
    role_metadata_fn: Callable[[str], Dict[str, Any]],
    audit_usage_by_principal: Dict[str, Dict[str, Any]],
    target_scope: str = "",
) -> Tuple[List[LeastPrivilegeRecommendation], int]:
    """Grounds recommendations in collected bindings, real IAM Roles API permission counts, and audit log usage."""
    binding_pairs_full: Set[Tuple[str, str]] = set()
    binding_pairs_id: Set[Tuple[str, str]] = set()
    known_resources: Set[str] = set()
    known_projects: Set[str] = set()

    for b in bindings or []:
        p_full = _norm_principal(b.get("principal", ""))
        p_id = _principal_identifier(p_full)
        role_low = str(b.get("role") or "").strip().lower()
        res_low = str(b.get("resource") or "").strip().lower()
        pid = str(b.get("project_id") or "").strip()
        if p_full and role_low:
            binding_pairs_full.add((p_full, role_low))
        if p_id and role_low:
            binding_pairs_id.add((p_id, role_low))
        if res_low:
            known_resources.add(res_low)
        if pid and pid not in ("org-or-folder", "unknown-project"):
            known_projects.add(pid)

    # Normalize audit usage map keys to lowercase
    audit_map_norm: Dict[str, Dict[str, Any]] = {
        str(k or "").strip().lower(): v for k, v in (audit_usage_by_principal or {}).items()
    }

    grounded: List[LeastPrivilegeRecommendation] = []
    dropped = 0
    role_meta_memo: Dict[str, Dict[str, Any]] = {}

    for rec in recs or []:
        p_full = _norm_principal(rec.principal)
        p_id = _principal_identifier(p_full)
        role_raw = str(rec.current_role or "").strip()
        role_low = role_raw.lower()

        if (p_full, role_low) not in binding_pairs_full and (p_id, role_low) not in binding_pairs_id:
            logger.info(
                "Grounding dropped ungrounded recommendation principal='%s' role='%s'",
                rec.principal,
                rec.current_role,
            )
            dropped += 1
            continue

        if target_scope and rec.resource and not _resource_in_scope(
            rec.resource,
            target_scope=target_scope,
            known_resources=known_resources,
            known_projects=known_projects,
        ):
            logger.info(
                "Grounding dropped recommendation with out-of-scope resource '%s'",
                rec.resource,
            )
            dropped += 1
            continue

        # Overwrite permissions_granted_count strictly from live IAM Roles API
        if role_raw not in role_meta_memo:
            try:
                role_meta_memo[role_raw] = role_metadata_fn(role_raw) or {}
            except Exception:
                role_meta_memo[role_raw] = {}
        rmeta = role_meta_memo[role_raw]
        live_granted = rmeta.get("included_permissions_count")
        if isinstance(live_granted, int) and live_granted >= 0 and rmeta.get("http_status", 200) == 200:
            granted_cnt = live_granted
        elif isinstance(live_granted, int) and live_granted > 0:
            granted_cnt = live_granted
        else:
            granted_cnt = max(0, int(rec.permissions_granted_count or 0))

        # Overwrite observed usage strictly from bounded Cloud Audit Log sample
        pusage = audit_map_norm.get(p_id) or audit_map_norm.get(p_full) or {}
        observed_cnt = int(pusage.get("distinct_permissions_exercised_count") or 0)
        if granted_cnt > 0:
            observed_cnt = min(observed_cnt, granted_cnt)

        excess = max(0, granted_cnt - observed_cnt)
        red_pct = round((excess / granted_cnt) * 100.0, 2) if granted_cnt > 0 else 0.0

        grounded.append(
            rec.model_copy(
                update={
                    "permissions_granted_count": granted_cnt,
                    "permissions_exercised_90d": observed_cnt,
                    "excess_permissions_removed": excess,
                    "permission_reduction_pct": red_pct,
                }
            )
        )

    grounded.sort(
        key=lambda r: (
            -r.excess_permissions_removed,
            _norm_principal(r.principal),
            r.current_role.lower(),
        )
    )
    renumbered = [r.model_copy(update={"recommendation_id": f"REC-{idx:03d}"}) for idx, r in enumerate(grounded, start=1)]
    return renumbered, dropped
