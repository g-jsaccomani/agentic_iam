"""NetworkX IAM Attack Path & Toxic Combination Graph Engine (`graph_engine.py`).

Constructs a 100% live directed graph (`nx.DiGraph`) from real Google Cloud Asset Inventory
IAM bindings, Service Accounts, compute/serverless workloads, and hierarchy resources:
1. Maps human, external/domain/public, group, Workload Identity, and Service Account principals
   to real GCP resources and Service Account targets.
2. Models real GCP IAM privilege inheritance and Service Account impersonation vectors
   (`roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser`,
   `roles/iam.serviceAccountKeyAdmin`, project convenience members `projectOwner:`/`projectEditor:`,
   and runtime workload-to-SA bindings).
3. Computes NetworkX centrality (`betweenness_centrality`, `degree_centrality`) and extracts
   real topological simple paths for reasoning by the Google ADK `attack_path_agent`.
4. Dynamically renders high-DPI attack-path topology PNG diagrams (`render_attack_graph_png`)
   for executive reports and UI views without any hardcoded coordinates or synthetic nodes.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
import networkx as nx

from backend.config import settings
from backend.models.findings import (
    AttackPathEdge,
    AttackPathGraphSummary,
    AttackPathNode,
    RiskSeverity,
)
from backend.session_vault import register_cache_purge_hook
from backend.tools.cai_collector import (
    active_cache_namespace,
    collect_live_iam_bindings,
    collect_live_resources,
    extract_attached_workload_service_accounts,
    extract_sa_owning_project,
    is_default_service_account_email,
    is_google_managed_service_agent,
    normalize_gcp_scope,
)

logger = logging.getLogger(__name__)

_GRAPH_CACHE_TTL_SECONDS = 180.0
_GRAPH_OBJ_CACHE: Dict[Tuple[str, str], Tuple[float, nx.DiGraph, AttackPathGraphSummary]] = {}


def _purge_graph_caches(session_id: str) -> None:
    prefix = f"{session_id}:"
    for k in [key for key in list(_GRAPH_OBJ_CACHE.keys()) if key[0].startswith(prefix)]:
        _GRAPH_OBJ_CACHE.pop(k, None)


register_cache_purge_hook(_purge_graph_caches)

# Roles that confer high-impact escalation, policy mutation, or SA impersonation capabilities in GCP
ESCALATION_ROLE_VECTORS: Dict[str, str] = {
    "roles/owner": "resourcemanager.*.setIamPolicy & *.* (Primitive Owner)",
    "roles/editor": "Primitive Editor broad write + projectEditor resource inheritance",
    "roles/resourcemanager.organizationAdmin": "resourcemanager.organizations.setIamPolicy",
    "roles/resourcemanager.folderAdmin": "resourcemanager.folders.setIamPolicy",
    "roles/resourcemanager.projectIamAdmin": "resourcemanager.projects.setIamPolicy",
    "roles/iam.securityAdmin": "iam.*.setIamPolicy & resourcemanager.*.setIamPolicy",
    "roles/iam.organizationRoleAdmin": "iam.roles.update (Custom Role privilege injection)",
    "roles/iam.roleAdmin": "iam.roles.update (Custom Role privilege injection)",
    "roles/iam.serviceAccountAdmin": "iam.serviceAccounts.setIamPolicy / actAs",
    "roles/iam.serviceAccountTokenCreator": "iam.serviceAccounts.getAccessToken / signBlob",
    "roles/iam.serviceAccountUser": "iam.serviceAccounts.actAs (Workload SA attachment)",
    "roles/iam.serviceAccountKeyAdmin": "iam.serviceAccountKeys.create (Persistent key minting)",
    "roles/iam.workloadIdentityUser": "iam.serviceAccounts.getAccessToken (Federated impersonation)",
    "roles/compute.admin": "compute.instances.create / setMetadata / setServiceAccount",
    "roles/compute.instanceAdmin.v1": "compute.instances.setMetadata / setServiceAccount",
    "roles/run.admin": "run.services.create / update (Runtime SA execution)",
    "roles/run.builder": "cloudbuild.builds.create / run.services.* (Build & runtime SA)",
    "roles/cloudbuild.builds.editor": "cloudbuild.builds.create (Cloud Build SA execution)",
    "roles/cloudfunctions.admin": "cloudfunctions.functions.create (Runtime SA execution)",
    "roles/cloudfunctions.developer": "cloudfunctions.functions.update (Runtime SA execution)",
    "roles/storage.admin": "storage.buckets.setIamPolicy / storage.objects.*",
    "roles/storage.legacyBucketOwner": "storage.buckets.setIamPolicy / storage.objects.*",
    "roles/bigquery.admin": "bigquery.datasets.update / bigquery.jobs.create",
    "roles/orgpolicy.policyAdmin": "orgpolicy.policy.set (Guardrail disablement)",
}

SA_IMPERSONATION_OR_EXECUTION_ROLES: Set[str] = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/compute.admin",
    "roles/compute.instanceAdmin.v1",
    "roles/run.admin",
    "roles/cloudfunctions.admin",
    "roles/cloudfunctions.developer",
}


def _short_resource_label(resource_uri: str) -> str:
    """Formats a Cloud Asset Inventory resource URI into a compact, readable graph label."""
    clean = resource_uri.strip()
    if clean.startswith("//"):
        parts = clean[2:].split("/", 1)
        service = parts[0].split(".")[0]
        rest = parts[1] if len(parts) > 1 else clean
        tail = "/".join(rest.split("/")[-2:]) if "/" in rest else rest
        return f"{service}:\n{tail}"
    return clean


def _short_principal_label(principal: str) -> str:
    """Formats an IAM principal string into a readable badge label."""
    if ":" not in principal:
        return principal
    prefix, ident = principal.split(":", 1)
    if "@" in ident and len(ident) > 28:
        local, dom = ident.split("@", 1)
        return f"{prefix}:{local}\n@{dom}"
    return f"{prefix}:\n{ident}"


def _principal_node_type_and_risk(binding: Dict[str, Any]) -> Tuple[str, RiskSeverity]:
    """Determines AttackPathNode `node_type` and baseline `risk_level` from live binding classification."""
    ptype = binding.get("principal_type", "user")
    role = binding.get("role", "")
    is_ext = bool(binding.get("is_external"))
    is_default_sa = bool(binding.get("is_default_sa"))
    is_escalating = role in ESCALATION_ROLE_VECTORS

    if ptype == "public":
        return "external_user", RiskSeverity.CRITICAL
    if is_ext:
        return "external_user", (RiskSeverity.CRITICAL if is_escalating else RiskSeverity.HIGH)
    if ptype == "service_account":
        if is_default_sa and is_escalating:
            return "service_account", RiskSeverity.CRITICAL
        return "service_account", (RiskSeverity.HIGH if is_escalating else RiskSeverity.MEDIUM)
    if ptype == "group":
        return "group", (RiskSeverity.MEDIUM if is_escalating else RiskSeverity.LOW)
    if ptype == "domain":
        return ("external_user" if is_ext else "group"), (RiskSeverity.HIGH if is_escalating else RiskSeverity.MEDIUM)
    if ptype == "project_convenience_member":
        return "role", (RiskSeverity.HIGH if "Owner" in binding.get("principal", "") or "Editor" in binding.get("principal", "") else RiskSeverity.MEDIUM)
    # Direct human user or WIF principal
    if role in ("roles/owner", "roles/resourcemanager.organizationAdmin", "roles/iam.securityAdmin"):
        return "user", RiskSeverity.CRITICAL
    return "user", (RiskSeverity.HIGH if is_escalating else RiskSeverity.MEDIUM)


def _merge_severity(a: RiskSeverity, b: RiskSeverity) -> RiskSeverity:
    order = {
        RiskSeverity.INFORMATIONAL: 0,
        RiskSeverity.LOW: 1,
        RiskSeverity.MEDIUM: 2,
        RiskSeverity.HIGH: 3,
        RiskSeverity.CRITICAL: 4,
    }
    return a if order[a] >= order[b] else b


def build_iam_privilege_graph(
    scope: str = "",
    *,
    force_refresh: bool = False,
) -> Tuple[nx.DiGraph, AttackPathGraphSummary]:
    """Builds a 100% live NetworkX directed IAM privilege & escalation graph for `scope`."""
    target_scope = normalize_gcp_scope(scope)
    ck = (active_cache_namespace(), target_scope)
    now_mono = time.monotonic()
    if not force_refresh and ck in _GRAPH_OBJ_CACHE:
        ts, cached_g, cached_sum = _GRAPH_OBJ_CACHE[ck]
        if (now_mono - ts) < _GRAPH_CACHE_TTL_SECONDS:
            return cached_g, cached_sum

    bindings = collect_live_iam_bindings(target_scope, force_refresh=force_refresh)
    try:
        resources = collect_live_resources(target_scope, force_refresh=force_refresh)
    except Exception as exc:
        logger.warning("collect_live_resources partial warning on %s: %s", target_scope, exc)
        resources = []

    G = nx.DiGraph()
    nodes_map: Dict[str, AttackPathNode] = {}
    edges_map: Dict[Tuple[str, str, str], AttackPathEdge] = {}

    def upsert_node(
        node_id: str,
        label: str,
        node_type: str,
        risk_level: RiskSeverity,
        project_id: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        if node_id in nodes_map:
            existing = nodes_map[node_id]
            existing.risk_level = _merge_severity(existing.risk_level, risk_level)
            if attributes:
                existing.attributes.update(attributes)
        else:
            nodes_map[node_id] = AttackPathNode(
                node_id=node_id,
                label=label,
                node_type=node_type,
                risk_level=risk_level,
                project_id=project_id,
                attributes=attributes or {},
            )

    def add_edge_unique(
        source: str,
        target: str,
        relationship: str,
        permission_vector: str,
        is_escalation_edge: bool,
        weight: float = 1.0,
    ) -> None:
        if source == target:
            return
        key = (source, target, relationship)
        if key not in edges_map:
            edges_map[key] = AttackPathEdge(
                source=source,
                target=target,
                relationship=relationship,
                permission_vector=permission_vector,
                is_escalation_edge=is_escalation_edge,
                weight=weight,
            )

    # Track customer/default Service Accounts per project for real IAM inheritance edges
    project_customer_sas: Dict[str, Set[str]] = {}
    project_owners: Dict[str, Set[str]] = {}
    project_editors: Dict[str, Set[str]] = {}

    for r in resources:
        atype = r.get("asset_type", "")
        proj_id = r.get("project_id") or target_scope
        attrs = r.get("additional_attributes") or {}
        vres = r.get("versioned_resource") or {}
        if atype == "iam.googleapis.com/ServiceAccount":
            sa_email = str(
                vres.get("email")
                or attrs.get("email")
                or r["name"].rsplit("/serviceAccounts/", 1)[-1]
            ).strip()
            if sa_email and not is_google_managed_service_agent(f"serviceAccount:{sa_email}"):
                sa_nid = f"serviceAccount:{sa_email}"
                sa_owner_proj = extract_sa_owning_project(sa_email) or proj_id
                if sa_owner_proj and not sa_owner_proj.startswith(("organizations/", "folders/")):
                    project_customer_sas.setdefault(sa_owner_proj, set()).add(sa_nid)
                upsert_node(
                    node_id=sa_nid,
                    label=_short_principal_label(sa_nid),
                    node_type="service_account",
                    risk_level=RiskSeverity.HIGH if is_default_service_account_email(sa_email) else RiskSeverity.MEDIUM,
                    project_id=sa_owner_proj,
                    attributes={"default_sa": is_default_service_account_email(sa_email), "asset_name": r["name"]},
                )
        elif atype in ("compute.googleapis.com/Instance", "run.googleapis.com/Service"):
            w_name = r.get("display_name") or r["name"].rsplit("/", 1)[-1]
            w_prefix = "vm" if "Instance" in atype else "cloudrun"
            w_nid = f"{w_prefix}:{proj_id}/{w_name}"
            upsert_node(
                node_id=w_nid,
                label=f"{w_prefix.upper()}:\n{w_name}",
                node_type="workload",
                risk_level=RiskSeverity.MEDIUM,
                project_id=proj_id,
                attributes={"asset_type": atype, "location": r.get("location", ""), "asset_name": r["name"]},
            )
            # Shared helper extracts attached runtime SAs from BOTH additional_attributes and versioned_resource
            for sa_email in extract_attached_workload_service_accounts(r):
                sa_nid = f"serviceAccount:{sa_email}"
                if not is_google_managed_service_agent(sa_nid):
                    sa_owner_proj = extract_sa_owning_project(sa_email) or proj_id
                    if sa_owner_proj and not sa_owner_proj.startswith(("organizations/", "folders/")):
                        project_customer_sas.setdefault(sa_owner_proj, set()).add(sa_nid)
                    upsert_node(
                        node_id=sa_nid,
                        label=_short_principal_label(sa_nid),
                        node_type="service_account",
                        risk_level=RiskSeverity.HIGH if is_default_service_account_email(sa_email) else RiskSeverity.MEDIUM,
                        project_id=sa_owner_proj,
                        attributes={"default_sa": is_default_service_account_email(sa_email)},
                    )
                    add_edge_unique(
                        source=w_nid,
                        target=sa_nid,
                        relationship="Attached Runtime SA",
                        permission_vector="iam.serviceAccounts.implicitMetadataToken",
                        is_escalation_edge=True,
                    )

    # Process live IAM bindings (excluding noisy platform-internal Google robot agents unless external)
    relevant_bindings = [b for b in bindings if not b.get("is_google_service_agent")]

    for b in relevant_bindings:
        principal = b["principal"]
        role = b["role"]
        resource = b["resource"]
        proj_id = b.get("project_id") or target_scope
        ntype, nrisk = _principal_node_type_and_risk(b)

        sa_owner_for_node = extract_sa_owning_project(principal) if ntype == "service_account" else ""
        upsert_node(
            node_id=principal,
            label=_short_principal_label(principal),
            node_type=ntype,
            risk_level=nrisk,
            project_id=sa_owner_for_node or proj_id,
            attributes={
                "principal_type": b.get("principal_type"),
                "domain": b.get("domain"),
                "is_external": bool(b.get("is_external")),
                "is_default_sa": bool(b.get("is_default_sa")),
            },
        )

        # Index SAs strictly under their OWN owning project (never under a foreign project where they hold a binding)
        if ntype == "service_account" and sa_owner_for_node and not sa_owner_for_node.startswith(("organizations/", "folders/")):
            project_customer_sas.setdefault(sa_owner_for_node, set()).add(principal)

        if resource == f"//cloudresourcemanager.googleapis.com/projects/{proj_id}":
            if role == "roles/owner":
                project_owners.setdefault(proj_id, set()).add(principal)
            elif role == "roles/editor":
                project_editors.setdefault(proj_id, set()).add(principal)

        # Determine target node: if resource is an IAM ServiceAccount, point directly to the SA node!
        if "/serviceAccounts/" in resource and "iam.googleapis.com" in resource:
            target_sa_email = resource.rsplit("/serviceAccounts/", 1)[-1]
            target_nid = f"serviceAccount:{target_sa_email}"
            upsert_node(
                node_id=target_nid,
                label=_short_principal_label(target_nid),
                node_type="service_account",
                risk_level=RiskSeverity.HIGH,
                project_id=proj_id,
                attributes={"default_sa": is_default_service_account_email(target_sa_email)},
            )
        else:
            target_nid = f"res:{resource}"
            is_crown = any(
                tok in resource
                for tok in ("/organizations/", "/folders/", "storage.googleapis.com", "bigquery.googleapis.com", "/projects/")
            )
            upsert_node(
                node_id=target_nid,
                label=_short_resource_label(resource),
                node_type="resource",
                risk_level=RiskSeverity.HIGH if is_crown and role in ESCALATION_ROLE_VECTORS else RiskSeverity.MEDIUM,
                project_id=proj_id,
                attributes={"resource_uri": resource, "asset_type": b.get("asset_type", "")},
            )

        is_esc = (
            role in ESCALATION_ROLE_VECTORS
            or bool(b.get("is_external"))
            or principal.startswith(("projectOwner:", "projectEditor:"))
        )
        perm_vec = ESCALATION_ROLE_VECTORS.get(role, f"Granted via {role}")
        add_edge_unique(
            source=principal,
            target=target_nid,
            relationship=role,
            permission_vector=perm_vec,
            is_escalation_edge=is_esc,
        )

    # Connect GCP project convenience members (`projectOwner:<pid>`, `projectEditor:<pid>`) to real holders
    for pid, owners in project_owners.items():
        conv_owner = f"projectOwner:{pid}"
        if conv_owner in nodes_map:
            for holder in owners:
                add_edge_unique(
                    source=holder,
                    target=conv_owner,
                    relationship="roles/owner (Project Convenience Member)",
                    permission_vector="Inherited projectOwner ACL membership",
                    is_escalation_edge=True,
                )
    for pid, editors in project_editors.items():
        conv_editor = f"projectEditor:{pid}"
        if conv_editor in nodes_map:
            for holder in editors:
                add_edge_unique(
                    source=holder,
                    target=conv_editor,
                    relationship="roles/editor (Project Convenience Member)",
                    permission_vector="Inherited projectEditor ACL membership",
                    is_escalation_edge=True,
                )

    # Connect project-scoped SA impersonation/workload admin bindings to active customer/default SAs in that project
    for b in relevant_bindings:
        role = b["role"]
        proj_id = b.get("project_id", "")
        principal = b["principal"]
        if (
            role in SA_IMPERSONATION_OR_EXECUTION_ROLES
            and b["resource"] == f"//cloudresourcemanager.googleapis.com/projects/{proj_id}"
        ):
            for sa_nid in project_customer_sas.get(proj_id, set()):
                if sa_nid != principal:
                    add_edge_unique(
                        source=principal,
                        target=sa_nid,
                        relationship=f"{role} (Project-Wide SA Reach)",
                        permission_vector=ESCALATION_ROLE_VECTORS.get(role, role),
                        is_escalation_edge=True,
                    )

    # Populate NetworkX DiGraph
    nodes_list = list(nodes_map.values())
    edges_list = list(edges_map.values())

    for n in nodes_list:
        G.add_node(
            n.node_id,
            label=n.label,
            node_type=n.node_type,
            risk_level=n.risk_level.value,
            project_id=n.project_id,
            **n.attributes,
        )
    for e in edges_list:
        G.add_edge(
            e.source,
            e.target,
            relationship=e.relationship,
            permission_vector=e.permission_vector,
            is_escalation_edge=e.is_escalation_edge,
            weight=e.weight,
        )

    # Compute real NetworkX centrality metrics (sampled k when > 500 nodes to prevent O(V*E) stalls)
    n_nodes = G.number_of_nodes()
    if n_nodes > 500:
        betweenness = nx.betweenness_centrality(G, k=min(100, n_nodes), seed=42)
    elif n_nodes > 1:
        betweenness = nx.betweenness_centrality(G)
    else:
        betweenness = {n: 0.0 for n in G.nodes}

    degree_cent = nx.degree_centrality(G) if n_nodes > 1 else {n: 0.0 for n in G.nodes}
    centrality_ranking = sorted(
        [
            {
                "node_id": nid,
                "node_type": G.nodes[nid].get("node_type", ""),
                "betweenness_centrality": round(betweenness.get(nid, 0.0), 4),
                "degree_centrality": round(degree_cent.get(nid, 0.0), 4),
                "out_degree": int(G.out_degree(nid)),
                "in_degree": int(G.in_degree(nid)),
                "combined_chokepoint_score": round(
                    (betweenness.get(nid, 0.0) * 0.6 + degree_cent.get(nid, 0.0) * 0.4) * 100.0,
                    2,
                ),
            }
            for nid in G.nodes
            if G.nodes[nid].get("node_type") in ("service_account", "workload", "user", "external_user", "group", "role")
        ],
        key=lambda x: (x["betweenness_centrality"], x["degree_centrality"], x["out_degree"]),
        reverse=True,
    )

    # Compute bounded topological max chain depth & escalation path count via risk-prioritized helper
    bounded_paths = extract_raw_topological_paths(G, max_paths=50, max_depth=4, time_budget_seconds=3.0)
    max_chain_depth = max((int(p.get("hop_count") or 0) for p in bounded_paths), default=0)
    escalation_paths_detected = sum(1 for p in bounded_paths if p.get("has_escalation_edge"))

    if max_chain_depth == 0 and G.number_of_edges() > 0:
        max_chain_depth = 1

    summary = AttackPathGraphSummary(
        scope=target_scope,
        total_nodes=G.number_of_nodes(),
        total_edges=G.number_of_edges(),
        escalation_paths_count=escalation_paths_detected,
        toxic_combinations_count=0,
        max_chain_depth=max_chain_depth,
        high_centrality_principals=centrality_ranking[:10],
        nodes=nodes_list,
        edges=edges_list,
        critical_paths=[],
    )
    _GRAPH_OBJ_CACHE[ck] = (time.monotonic(), G, summary)
    return G, summary


def extract_raw_topological_paths(
    G: nx.DiGraph,
    limit: int = 30,
    *,
    max_paths: Optional[int] = None,
    max_depth: int = 4,
    max_sources: int = 60,
    max_targets: int = 60,
    max_candidates: int = 250,
    time_budget_seconds: float = 5.0,
) -> List[Dict[str, Any]]:
    """Extracts bounded, risk-prioritized topological simple paths from NetworkX `G` within a strict time budget."""
    eff_limit = int(max_paths if max_paths is not None else limit)
    eff_max_candidates = max(eff_limit, int(max_candidates))
    deadline = time.monotonic() + max(0.25, float(time_budget_seconds))

    def _source_priority(nid: str) -> Tuple[int, int, int]:
        nt = str(G.nodes[nid].get("node_type") or "")
        esc_out = sum(1 for _, _, d in G.out_edges(nid, data=True) if d.get("is_escalation_edge"))
        type_rank = {"external_user": 4, "workload": 3, "user": 2, "group": 2, "service_account": 1}.get(nt, 0)
        return (type_rank, esc_out, int(G.out_degree(nid)))

    def _target_priority(nid: str) -> Tuple[int, int, int]:
        nt = str(G.nodes[nid].get("node_type") or "")
        esc_in = sum(1 for _, _, d in G.in_edges(nid, data=True) if d.get("is_escalation_edge"))
        type_rank = {"resource": 2, "service_account": 1}.get(nt, 0)
        return (type_rank, esc_in, int(G.in_degree(nid)))

    sources = sorted(
        [
            nid
            for nid in G.nodes
            if G.nodes[nid].get("node_type") in ("external_user", "user", "group", "workload", "service_account")
            and G.out_degree(nid) > 0
        ],
        key=_source_priority,
        reverse=True,
    )[:max_sources]

    targets = sorted(
        [
            nid
            for nid in G.nodes
            if G.nodes[nid].get("node_type") in ("resource", "service_account")
            and G.in_degree(nid) > 0
        ],
        key=_target_priority,
        reverse=True,
    )[:max_targets]

    target_set = set(targets)
    candidates: List[Dict[str, Any]] = []
    seen_paths: Set[Tuple[str, ...]] = set()

    for src in sources:
        if time.monotonic() >= deadline or len(candidates) >= eff_max_candidates:
            break
        # Pre-filter targets reachable within `max_depth` hops from `src` via single-source BFS
        reachable = nx.single_source_shortest_path_length(G, src, cutoff=max_depth)
        reachable_targets = [dst for dst in targets if dst != src and dst in reachable and dst in target_set]
        for dst in reachable_targets:
            if time.monotonic() >= deadline or len(candidates) >= eff_max_candidates:
                break
            per_pair_count = 0
            try:
                for path in nx.all_simple_paths(G, source=src, target=dst, cutoff=max_depth):
                    if time.monotonic() >= deadline or len(candidates) >= eff_max_candidates:
                        break
                    per_pair_count += 1
                    if per_pair_count > 5:
                        break
                    key = tuple(path)
                    if key in seen_paths:
                        continue
                    hops = len(path) - 1
                    edge_details = []
                    has_escalation = False
                    for i in range(hops):
                        edata = G.edges[path[i], path[i + 1]]
                        if edata.get("is_escalation_edge"):
                            has_escalation = True
                        edge_details.append(
                            {
                                "from": path[i],
                                "to": path[i + 1],
                                "relationship": edata.get("relationship", ""),
                                "permission_vector": edata.get("permission_vector", ""),
                                "is_escalation_edge": bool(edata.get("is_escalation_edge")),
                            }
                        )
                    if not has_escalation and hops < 2:
                        continue
                    seen_paths.add(key)
                    candidates.append(
                        {
                            "entry_principal": src,
                            "entry_node_type": G.nodes[src].get("node_type", ""),
                            "target_node": dst,
                            "target_node_type": G.nodes[dst].get("node_type", ""),
                            "hop_count": hops,
                            "hop_sequence": path,
                            "edges": edge_details,
                            "has_escalation_edge": has_escalation,
                        }
                    )
            except nx.NetworkXNoPath:
                continue

    # Prioritize escalation edges, external principals, and multi-hop chains
    candidates.sort(
        key=lambda c: (
            1 if c.get("has_escalation_edge") else 0,
            1 if c["entry_node_type"] == "external_user" else 0,
            c["hop_count"],
        ),
        reverse=True,
    )
    return candidates[:eff_limit]


def analyze_iam_attack_paths(scope: str = "") -> str:
    """Builds the live NetworkX IAM privilege graph and returns a bounded summary of nodes, edges, centrality, and paths.

    Args:
        scope: Target GCP resource scope (e.g., 'organizations/123456789012' or 'organizations/123456789012/projects:my-project').

    Returns:
        JSON string containing live NetworkX graph metrics, centrality rankings, a bounded top-risk subset of nodes/edges
        with exact totals, and bounded candidate escalation paths.
    """
    G, summary = build_iam_privilege_graph(scope)
    raw_paths = extract_raw_topological_paths(G, limit=30)

    # Prioritize nodes appearing in candidate paths and high-centrality choke points
    priority_node_ids: List[str] = []
    seen_nids: Set[str] = set()
    for p in raw_paths:
        for hop in p.get("hop_sequence") or []:
            if hop not in seen_nids:
                seen_nids.add(hop)
                priority_node_ids.append(hop)
    for hc in summary.high_centrality_principals:
        nid = hc.get("node_id", "")
        if nid and nid not in seen_nids:
            seen_nids.add(nid)
            priority_node_ids.append(nid)

    nodes_by_id = {n.node_id: n for n in summary.nodes}
    selected_nodes = [nodes_by_id[nid] for nid in priority_node_ids if nid in nodes_by_id]
    if len(selected_nodes) < 60:
        for n in summary.nodes:
            if n.node_id not in seen_nids:
                seen_nids.add(n.node_id)
                selected_nodes.append(n)
                if len(selected_nodes) >= 60:
                    break
    selected_nodes = selected_nodes[:60]
    selected_node_set = {n.node_id for n in selected_nodes}

    selected_edges = [
        e for e in summary.edges if e.is_escalation_edge or (e.source in selected_node_set and e.target in selected_node_set)
    ][:100]

    payload = summary.model_dump()
    payload["nodes"] = [n.model_dump() for n in selected_nodes]
    payload["edges"] = [e.model_dump() for e in selected_edges]
    payload["nodes_returned"] = len(selected_nodes)
    payload["edges_returned"] = len(selected_edges)
    payload["nodes_truncated"] = summary.total_nodes > len(selected_nodes)
    payload["edges_truncated"] = summary.total_edges > len(selected_edges)
    payload["raw_topological_paths"] = raw_paths
    payload["telemetry_source"] = "LIVE_NETWORKX_OVER_GCP_CLOUD_ASSET_INVENTORY"
    return json.dumps(payload, indent=2)


def _select_render_subgraph(
    G: nx.DiGraph,
    graph_summary: Optional[AttackPathGraphSummary] = None,
    max_nodes: int = 16,
) -> nx.DiGraph:
    """Selects the most security-critical connected subgraph when total node count exceeds readable canvas density."""
    if G.number_of_nodes() <= max_nodes:
        return G

    priority_nodes: List[str] = []
    if graph_summary and graph_summary.critical_paths:
        for cp in graph_summary.critical_paths:
            for hop in cp.hop_sequence:
                if hop in G.nodes and hop not in priority_nodes:
                    priority_nodes.append(hop)

    # Add external principals and high-centrality nodes
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
    ranked_remaining = sorted(
        G.nodes,
        key=lambda n: (
            1 if G.nodes[n].get("node_type") == "external_user" else 0,
            severity_rank.get(str(G.nodes[n].get("risk_level", "MEDIUM")), 1),
            G.degree(n),
        ),
        reverse=True,
    )
    for n in ranked_remaining:
        if len(priority_nodes) >= max_nodes:
            break
        if n not in priority_nodes:
            priority_nodes.append(n)

    # Ensure every selected principal has at least one neighbor included if space permits
    final_set = list(priority_nodes[:max_nodes])
    for n in list(final_set):
        if len(final_set) >= max_nodes:
            break
        if not any(nbr in final_set for nbr in list(G.successors(n)) + list(G.predecessors(n))):
            succs = list(G.successors(n))
            if succs and succs[0] not in final_set:
                final_set.append(succs[0])

    return G.subgraph(final_set).copy()


def _compute_layered_positions(H: nx.DiGraph) -> Dict[str, Tuple[float, float]]:
    """Computes deterministic 4-column left-to-right topological coordinates for any live graph `H`."""
    columns: Dict[int, List[str]] = {0: [], 1: [], 2: [], 3: []}
    col_x = {0: 0.06, 1: 0.36, 2: 0.66, 3: 0.94}

    for nid in H.nodes:
        ntype = H.nodes[nid].get("node_type", "user")
        if ntype in ("external_user", "user"):
            columns[0].append(nid)
        elif ntype in ("group", "workload", "role"):
            columns[1].append(nid)
        elif ntype == "service_account":
            columns[2].append(nid)
        else:
            columns[3].append(nid)

    # Rebalance empty middle columns cleanly
    pos: Dict[str, Tuple[float, float]] = {}
    for col_idx, node_ids in columns.items():
        if not node_ids:
            continue
        node_ids_sorted = sorted(
            node_ids,
            key=lambda n: (0 if H.nodes[n].get("node_type") == "external_user" else 1, n),
        )
        count = len(node_ids_sorted)
        for i, nid in enumerate(node_ids_sorted):
            if count == 1:
                y = 0.50
            else:
                y = 0.86 - (i * (0.76 / (count - 1)))
            pos[nid] = (col_x[col_idx], y)
    return pos


def render_attack_graph_png(
    output_path: Optional[Path] = None,
    scope: str = "",
    graph_summary: Optional[AttackPathGraphSummary] = None,
    dark_mode: bool = False,
) -> Path:
    """Renders the live NetworkX IAM Attack Path & Impersonation Graph to a high-DPI PNG diagram."""
    target_scope = normalize_gcp_scope(scope or (graph_summary.scope if graph_summary else ""))
    if graph_summary and graph_summary.nodes:
        G = nx.DiGraph()
        for n in graph_summary.nodes:
            G.add_node(
                n.node_id,
                label=n.label,
                node_type=n.node_type,
                risk_level=n.risk_level.value,
                project_id=n.project_id,
                **n.attributes,
            )
        for e in graph_summary.edges:
            if e.source in G.nodes and e.target in G.nodes:
                G.add_edge(
                    e.source,
                    e.target,
                    relationship=e.relationship,
                    permission_vector=e.permission_vector,
                    is_escalation_edge=e.is_escalation_edge,
                    weight=e.weight,
                )
    else:
        G, graph_summary = build_iam_privilege_graph(target_scope)

    from backend.tools.cai_collector import active_export_dir

    default_name = "attack_path_graph_dark.png" if dark_mode else "attack_path_graph.png"
    target_path = output_path or (active_export_dir() / default_name)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    H = _select_render_subgraph(G, graph_summary=graph_summary, max_nodes=16)
    pos = _compute_layered_positions(H)

    fig_bg = "#1B1E26" if dark_mode else "#FFFFFF"
    ax_bg = "#14161B" if dark_mode else "#F8FAFC"
    title_fg = "#F1F5F9" if dark_mode else "#0F172A"
    node_lbl_bg = "#232732" if dark_mode else "#FFFFFF"
    node_lbl_fg = "#F1F5F9" if dark_mode else "#0F172A"
    node_ring = "#2C3240" if dark_mode else "#0F172A"
    legend_bg = "#1B1E26" if dark_mode else "#FFFFFF"
    legend_edge = "#2C3240" if dark_mode else "#CBD5E1"

    fig = Figure(figsize=(13.5, 7.0), dpi=220)
    FigureCanvasAgg(fig)
    ax = fig.add_subplot(111)
    fig.patch.set_facecolor(fig_bg)
    ax.set_facecolor(ax_bg)

    color_map = {
        "user": "#1A73E8",            # AISPR Google Blue: Internal Identity
        "external_user": "#E03131",   # AISPR Danger Red: External / Public Principal
        "group": "#4DABF7",           # Sky Blue: Group / Domain Principal
        "role": "#F59F00",            # AISPR Amber: Project Convenience ACL
        "workload": "#748FFC",        # Indigo: Compute / Cloud Run Workload
        "service_account": "#F59F00", # AISPR Amber: Service Account Choke Point
        "resource": "#2B8A3E",        # AISPR Success Green: GCP Target Resource
    }

    critical_edge_pairs: Set[Tuple[str, str]] = set()
    if graph_summary and graph_summary.critical_paths:
        for cp in graph_summary.critical_paths:
            for i in range(len(cp.hop_sequence) - 1):
                critical_edge_pairs.add((cp.hop_sequence[i], cp.hop_sequence[i + 1]))

    if H.number_of_nodes() == 0:
        ax.text(
            0.5,
            0.5,
            f"No non-service-agent IAM bindings found in scope: {target_scope}",
            fontsize=11,
            fontweight="bold",
            color=node_lbl_fg,
            ha="center",
            va="center",
            parse_math=False,
        )
    else:
        for u, v, data in H.edges(data=True):
            x1, y1 = pos[u]
            x2, y2 = pos[v]
            is_crit = (u, v) in critical_edge_pairs or bool(data.get("is_escalation_edge"))
            edge_color = "#E03131" if is_crit else "#64748B"
            ax.annotate(
                "",
                xy=(x2, y2),
                xytext=(x1, y1),
                arrowprops=dict(
                    arrowstyle="-|>,head_length=0.8,head_width=0.42",
                    color=edge_color,
                    lw=1.8 if is_crit else 1.15,
                    shrinkA=30,
                    shrinkB=34,
                    connectionstyle="arc3,rad=0.05",
                ),
                zorder=2,
            )
            mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0 + 0.035
            rel_label = str(data.get("relationship", "")).replace("roles/", "")
            if len(rel_label) > 34:
                rel_label = rel_label[:31] + "..."
            edge_txt_fg = ("#FFA8A8" if is_crit else "#94A3B8") if dark_mode else ("#7F1D1D" if is_crit else "#334155")
            edge_box_bg = ("#2A1A1F" if is_crit else "#1B1E26") if dark_mode else ("#FEF2F2" if is_crit else "#F1F5F9")
            edge_box_bd = ("#E03131" if is_crit else "#2C3240") if dark_mode else ("#FCA5A5" if is_crit else "#CBD5E1")
            ax.text(
                mx,
                my,
                rel_label,
                fontsize=6.8,
                fontweight="bold",
                color=edge_txt_fg,
                ha="center",
                va="center",
                bbox=dict(
                    boxstyle="round,pad=0.18",
                    facecolor=edge_box_bg,
                    edgecolor=edge_box_bd,
                    lw=0.7,
                ),
                zorder=4,
                parse_math=False,
            )

        for n in H.nodes:
            x, y = pos[n]
            lbl = H.nodes[n].get("label", n)
            c = color_map.get(H.nodes[n].get("node_type", "user"), "#1A73E8")
            ax.scatter([x], [y], s=1500, c=[c], edgecolors=node_ring, linewidths=1.3, zorder=3)
            ax.text(
                x,
                y - 0.075,
                lbl,
                fontsize=7.2,
                fontweight="bold",
                color=node_lbl_fg,
                ha="center",
                va="top",
                bbox=dict(boxstyle="round,pad=0.24", facecolor=node_lbl_bg, edgecolor=c, lw=1.1),
                zorder=5,
                parse_math=False,
            )

    legend_handles = [
        mpatches.Patch(color="#1A73E8", label="Internal Identity"),
        mpatches.Patch(color="#E03131", label="External / Cross-Domain Principal"),
        mpatches.Patch(color="#4DABF7", label="Group / Domain"),
        mpatches.Patch(color="#748FFC", label="Compute / Cloud Run Workload"),
        mpatches.Patch(color="#F59F00", label="Service Account"),
        mpatches.Patch(color="#2B8A3E", label="GCP Target Resource"),
    ]
    leg = ax.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.08),
        ncol=3,
        frameon=True,
        facecolor=legend_bg,
        edgecolor=legend_edge,
        fontsize=8.0,
        labelcolor=title_fg,
    )
    leg.get_frame().set_linewidth(0.8)

    sub_note = (
        f" (Top {H.number_of_nodes()} of {G.number_of_nodes()} live nodes)"
        if G.number_of_nodes() > H.number_of_nodes()
        else f" ({G.number_of_nodes()} live nodes, {G.number_of_edges()} live edges)"
    )
    fig.suptitle(
        f"IAM Privilege & Escalation Topology — {target_scope}{sub_note}",
        fontsize=11.5,
        fontweight="bold",
        color=title_fg,
        y=0.99,
        parse_math=False,
    )
    ax.set_xlim(-0.06, 1.08)
    ax.set_ylim(-0.14, 0.98)
    ax.axis("off")

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    fig.savefig(str(target_path), dpi=220, bbox_inches="tight", facecolor=fig_bg)
    fig.clear()
    return target_path
