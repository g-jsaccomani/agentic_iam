"""Live GCP IAM Recommender, Policy Analyzer, Policy Simulator & IaC Packager (`recommender_tool.py`).

Zero-Trust Multi-User Isolation:
- Queries `recommender.googleapis.com`, `policyanalyzer.googleapis.com`, `policysimulator.googleapis.com`,
  `iam.googleapis.com/v1/roles/*`, and `logging.googleapis.com` strictly using the active user's
  `InspectionSession` token (via `gcp_rest_request`).
- Partitions audit log caches and writes Terraform remediation `.zip` bundles strictly inside the
  user's isolated `session_export_dir` (`/tmp/agentic_iam_sessions/<session_id>`).
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.models.findings import (
    IaCAgentOutput,
    IaCRemediationBundle,
    PolicySimulationValidation,
)
from backend.session_vault import (
    register_cache_purge_hook,
    run_pool_map_with_context,
)
from backend.tools.cai_collector import (
    active_cache_namespace,
    active_export_dir,
    active_organization_domain,
    active_organization_id,
    assert_scope_allowed,
    collect_live_iam_bindings,
    collect_live_org_policies,
    collect_live_resources,
    discover_accessible_projects_in_scope,
    gcp_rest_request,
    normalize_gcp_scope,
    parse_assessment_scope,
)

logger = logging.getLogger(__name__)

_ROLE_META_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_ROLE_CACHE_TTL_SECONDS = 600.0
_AUDIT_USAGE_CACHE: Dict[Tuple[Any, ...], Tuple[float, Dict[str, Any]]] = {}

DEFAULT_AUDIT_LOG_MAX_ENTRIES = int(os.getenv("IAM_AUDIT_LOG_MAX_ENTRIES", "1000"))
DEFAULT_AUDIT_LOG_TIME_BUDGET_SECONDS = float(os.getenv("IAM_AUDIT_LOG_TIME_BUDGET_SECONDS", "10.0"))
DEFAULT_AUDIT_LOG_PAGE_SIZE = 250


def _purge_recommender_caches(session_id: str) -> None:
    prefix = f"{session_id}:"
    for k in [key for key in list(_AUDIT_USAGE_CACHE.keys()) if key[0].startswith(prefix)]:
        _AUDIT_USAGE_CACHE.pop(k, None)


register_cache_purge_hook(_purge_recommender_caches)


def get_live_role_metadata(role_name: str) -> Dict[str, Any]:
    """Queries `iam.googleapis.com/v1/{role_name}` to retrieve real `includedPermissions` count and title."""
    from backend.validators import quote_gcp_resource_path, validate_iam_role_name

    try:
        clean_role = validate_iam_role_name(role_name)
    except ValueError:
        return {
            "role": str(role_name or "").strip(),
            "title": str(role_name or "").strip(),
            "stage": "INVALID",
            "included_permissions_count": 0,
            "included_permissions": [],
            "sample_permissions": [],
            "status": "INVALID_ROLE_NAME",
        }

    now = time.monotonic()
    # Public predefined roles (`roles/*`) have tenant-agnostic permission lists; ONLY successful responses are cached
    if clean_role.startswith("roles/") and clean_role in _ROLE_META_CACHE:
        ts, cached = _ROLE_META_CACHE[clean_role]
        if (now - ts) < _ROLE_CACHE_TTL_SECONDS:
            return cached

    url = f"https://iam.googleapis.com/v1/{quote_gcp_resource_path(clean_role)}"

    try:
        code, data = gcp_rest_request("GET", url, timeout=15.0)
        if code == 200 and isinstance(data, dict):
            perms = list(data.get("includedPermissions") or [])
            meta = {
                "role": clean_role,
                "title": data.get("title", clean_role),
                "stage": data.get("stage", ""),
                "included_permissions_count": len(perms),
                "included_permissions": perms,
                "sample_permissions": perms[:20],
                "status": "LIVE_IAM_ROLES_API",
            }
            if clean_role.startswith("roles/"):
                _ROLE_META_CACHE[clean_role] = (now, meta)
            return meta
        return {
            "role": clean_role,
            "title": clean_role,
            "stage": "UNKNOWN",
            "included_permissions_count": 0,
            "included_permissions": [],
            "sample_permissions": [],
            "status": f"HTTP_{code}",
        }
    except Exception as exc:
        return {
            "role": clean_role,
            "title": clean_role,
            "stage": "ERROR",
            "included_permissions_count": 0,
            "included_permissions": [],
            "sample_permissions": [],
            "status": f"ERR_{type(exc).__name__}",
        }


def _parse_iso_ts(raw: str) -> Optional[datetime.datetime]:
    txt = (raw or "").strip()
    if not txt:
        return None
    try:
        dt = datetime.datetime.fromisoformat(txt.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except ValueError:
        return None


def _collect_cloud_audit_usage_by_principal(
    project_ids: List[str],
    days_back: int = 30,
    *,
    max_entries: Optional[int] = None,
    time_budget_seconds: Optional[float] = None,
    page_size: int = DEFAULT_AUDIT_LOG_PAGE_SIZE,
) -> Dict[str, Any]:
    """Queries live Cloud Audit Logs (`logging.googleapis.com/v2/entries:list`) with bounded pagination and time budget."""
    total_projects_in_scope = len(project_ids)
    entry_cap = max(1, int(max_entries if max_entries is not None else DEFAULT_AUDIT_LOG_MAX_ENTRIES))
    budget_sec = max(0.05, float(time_budget_seconds if time_budget_seconds is not None else DEFAULT_AUDIT_LOG_TIME_BUDGET_SECONDS))
    effective_page_size = max(1, min(1000, int(page_size)))
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    cutoff_iso = (now_utc - datetime.timedelta(days=days_back)).isoformat()
    query_end_iso = now_utc.isoformat()

    if not project_ids:
        return {
            "logging_api_status": "NO_PROJECTS_IN_SCOPE",
            "is_sample": False,
            "sample_size": 0,
            "max_entries_cap": entry_cap,
            "time_budget_seconds": budget_sec,
            "pages_fetched": 0,
            "truncated_by_cap": False,
            "truncated_by_time_budget": False,
            "window_start": "",
            "window_end": "",
            "window": {
                "start": "",
                "end": "",
                "requested_lookback_days": days_back,
            },
            "projects_queried": [],
            "projects_queried_count": 0,
            "total_projects_in_scope": 0,
            "projects_queried_over_total": "0/0",
            "lookback_days": days_back,
            "total_audit_log_entries_sampled": 0,
            "total_authorization_grants_observed": 0,
            "total_authorization_denials_observed": 0,
            "principal_usage": {},
        }

    queried_projects = list(project_ids[:10])
    cache_key = (
        active_cache_namespace(),
        tuple(sorted(queried_projects)),
        total_projects_in_scope,
        days_back,
        entry_cap,
        round(budget_sec, 3),
    )
    now = time.monotonic()
    if cache_key in _AUDIT_USAGE_CACHE:
        ts, cached_res = _AUDIT_USAGE_CACHE[cache_key]
        if (now - ts) < 60.0:
            return cached_res

    resource_names = [f"projects/{pid}" for pid in queried_projects]
    log_filter = f'logName:"cloudaudit.googleapis.com" AND timestamp>="{cutoff_iso}"'

    principal_stats: Dict[str, Dict[str, Any]] = {}
    observed_dts: List[Tuple[datetime.datetime, str]] = []
    total_entries = 0
    granted_calls = 0
    denied_calls = 0
    api_status = "UNKNOWN"
    pages_fetched = 0
    truncated_by_cap = False
    truncated_by_time_budget = False
    next_page_token = ""
    started_at = time.monotonic()

    try:
        while total_entries < entry_cap:
            if pages_fetched > 0 and (time.monotonic() - started_at) >= budget_sec:
                truncated_by_time_budget = True
                break

            remaining = entry_cap - total_entries
            req_page_size = min(effective_page_size, remaining)
            body: Dict[str, Any] = {
                "resourceNames": resource_names,
                "filter": log_filter,
                "orderBy": "timestamp desc",
                "pageSize": req_page_size,
            }
            if next_page_token:
                body["pageToken"] = next_page_token

            rem_budget = max(1.0, budget_sec - (time.monotonic() - started_at))
            code, data = gcp_rest_request(
                "POST",
                "https://logging.googleapis.com/v2/entries:list",
                json_body=body,
                timeout=min(15.0, rem_budget),
            )
            pages_fetched += 1
            api_status = f"HTTP_{code}"
            if code != 200 or not isinstance(data, dict):
                break

            raw_entries = data.get("entries") or []
            page_token = str(data.get("nextPageToken") or "").strip()

            if len(raw_entries) > remaining:
                entries = raw_entries[:remaining]
                truncated_by_cap = True
            else:
                entries = raw_entries

            total_entries += len(entries)
            for entry in entries:
                raw_ts = str(entry.get("timestamp") or entry.get("receiveTimestamp") or "").strip()
                dt_parsed = _parse_iso_ts(raw_ts)
                if dt_parsed is not None:
                    observed_dts.append((dt_parsed, dt_parsed.isoformat()))

                proto = entry.get("protoPayload") or {}
                email = ((proto.get("authenticationInfo") or {}).get("principalEmail") or "").strip()
                method_name = proto.get("methodName") or ""
                service_name = proto.get("serviceName") or ""
                res_name = proto.get("resourceName") or ""
                auth_infos = proto.get("authorizationInfo") or []

                if email:
                    pstat = principal_stats.setdefault(
                        email,
                        {
                            "audit_events_count": 0,
                            "methods_observed": set(),
                            "permissions_exercised": set(),
                            "services_used": set(),
                            "sample_resources": set(),
                            "denied_events_count": 0,
                        },
                    )
                    pstat["audit_events_count"] += 1
                    if method_name:
                        pstat["methods_observed"].add(method_name)
                    if service_name:
                        pstat["services_used"].add(service_name)
                    if res_name and len(pstat["sample_resources"]) < 5:
                        pstat["sample_resources"].add(res_name)
                    for ai in auth_infos:
                        perm = ai.get("permission")
                        granted = bool(ai.get("granted", True))
                        if granted:
                            granted_calls += 1
                            if perm:
                                pstat["permissions_exercised"].add(perm)
                        else:
                            denied_calls += 1
                            pstat["denied_events_count"] += 1

            next_page_token = page_token
            if not next_page_token:
                break
            if total_entries >= entry_cap:
                truncated_by_cap = True
                break
            if (time.monotonic() - started_at) >= budget_sec:
                truncated_by_time_budget = True
                break
    except Exception as exc:
        api_status = f"ERR_{type(exc).__name__}: {exc}"

    if observed_dts:
        observed_dts.sort(key=lambda pair: pair[0])
        window_start = observed_dts[0][1]
        window_end = observed_dts[-1][1]
    else:
        window_start = cutoff_iso
        window_end = query_end_iso

    is_sample = bool(
        truncated_by_cap
        or truncated_by_time_budget
        or bool(next_page_token)
        or len(queried_projects) < total_projects_in_scope
        or api_status != "HTTP_200"
    )

    serialized_principals: Dict[str, Any] = {}
    for email, st in principal_stats.items():
        serialized_principals[email] = {
            "audit_events_count": st["audit_events_count"],
            "distinct_methods_count": len(st["methods_observed"]),
            "distinct_permissions_exercised_count": len(st["permissions_exercised"]),
            "permissions_exercised": sorted(st["permissions_exercised"])[:30],
            "methods_observed": sorted(st["methods_observed"])[:25],
            "services_used": sorted(st["services_used"]),
            "sample_resources": sorted(st["sample_resources"]),
            "denied_events_count": st["denied_events_count"],
        }

    result = {
        "logging_api_status": api_status,
        "is_sample": is_sample,
        "sample_size": total_entries,
        "max_entries_cap": entry_cap,
        "time_budget_seconds": budget_sec,
        "pages_fetched": pages_fetched,
        "truncated_by_cap": truncated_by_cap,
        "truncated_by_time_budget": truncated_by_time_budget,
        "window_start": window_start,
        "window_end": window_end,
        "window": {
            "start": window_start,
            "end": window_end,
            "requested_lookback_days": days_back,
        },
        "projects_queried": queried_projects,
        "projects_queried_count": len(queried_projects),
        "total_projects_in_scope": total_projects_in_scope,
        "projects_queried_over_total": f"{len(queried_projects)}/{total_projects_in_scope}",
        "lookback_days": days_back,
        "total_audit_log_entries_sampled": total_entries,
        "total_authorization_grants_observed": granted_calls,
        "total_authorization_denials_observed": denied_calls,
        "principal_usage": serialized_principals,
    }
    _AUDIT_USAGE_CACHE[cache_key] = (now, result)
    return result


def _query_recommender_and_insights(scopes_to_query: List[str], *, coverage_scope: str = "") -> Dict[str, Any]:
    from backend.tools.cai_collector import CollectionStatus, gcp_paginated_request, record_collection_status
    from backend.validators import quote_gcp_resource_path

    recommendations: List[Dict[str, Any]] = []
    insights: List[Dict[str, Any]] = []
    scope_statuses: Dict[str, Dict[str, str]] = {}

    max_scopes = max(1, int(os.getenv("IAM_MAX_RECOMMENDER_SCOPES", "50")))
    total_scopes = len(scopes_to_query)
    selected_scopes = scopes_to_query[:max_scopes]

    for sc in selected_scopes:
        q_sc = quote_gcp_resource_path(sc)
        rec_url = f"https://recommender.googleapis.com/v1/{q_sc}/locations/global/recommenders/google.iam.policy.Recommender/recommendations"
        ins_url = f"https://recommender.googleapis.com/v1/{q_sc}/locations/global/insightTypes/google.iam.policy.Insight/insights"
        st_entry: Dict[str, str] = {}

        rec_items, rec_st = gcp_paginated_request(
            "GET",
            rec_url,
            results_key="recommendations",
            collector="iam_recommender",
            scope=sc,
            params={"pageSize": 100},
            timeout=12.0,
            max_pages=10,
        )
        st_entry["recommender_status"] = f"HTTP_{rec_st.http_status}" if rec_st.http_status else (rec_st.error or "ERR")
        for item in rec_items:
            recommendations.append(
                {
                    "name": item.get("name", ""),
                    "scope": sc,
                    "description": item.get("description", ""),
                    "recommender_subtype": item.get("recommenderSubtype", ""),
                    "priority": item.get("priority", ""),
                    "last_refresh_time": item.get("lastRefreshTime", ""),
                    "primary_impact": item.get("primaryImpact", {}),
                    "content": item.get("content", {}),
                    "state_info": item.get("stateInfo", {}),
                }
            )

        ins_items, ins_st = gcp_paginated_request(
            "GET",
            ins_url,
            results_key="insights",
            collector="iam_insights",
            scope=sc,
            params={"pageSize": 100},
            timeout=12.0,
            max_pages=10,
        )
        st_entry["insights_status"] = f"HTTP_{ins_st.http_status}" if ins_st.http_status else (ins_st.error or "ERR")
        for ins in ins_items:
            insights.append(
                {
                    "name": ins.get("name", ""),
                    "scope": sc,
                    "description": ins.get("description", ""),
                    "insight_subtype": ins.get("insightSubtype", ""),
                    "severity": ins.get("severity", ""),
                    "observation_period": ins.get("observationPeriod", ""),
                    "content": ins.get("content", {}),
                }
            )

        scope_statuses[sc] = st_entry

    if coverage_scope and total_scopes > max_scopes:
        record_collection_status(
            coverage_scope,
            "iam_recommender_scopes",
            CollectionStatus(
                collector="iam_recommender_scopes",
                scope=coverage_scope,
                complete=False,
                pages_fetched=len(selected_scopes),
                items_collected=len(recommendations) + len(insights),
                cutoff_reason="CAP_EVALUATED",
                evaluated_count=len(selected_scopes),
                total_candidates=total_scopes,
            ),
        )

    return {
        "scope_api_statuses": scope_statuses,
        "scopes_evaluated": len(selected_scopes),
        "total_scopes_available": total_scopes,
        "active_recommender_items_count": len(recommendations),
        "active_policy_insights_count": len(insights),
        "recommendations": recommendations,
        "insights": insights,
    }


def _query_policy_analyzer_sa_activities(project_ids: List[str], *, coverage_scope: str = "") -> Dict[str, Any]:
    from backend.tools.cai_collector import CollectionStatus, gcp_paginated_request, record_collection_status
    from backend.validators import quote_path_segment

    sa_activities: List[Dict[str, Any]] = []
    statuses: Dict[str, str] = {}
    max_projects = max(1, int(os.getenv("IAM_MAX_POLICY_ANALYZER_PROJECTS", "50")))
    total_projects = len(project_ids)
    selected_projects = project_ids[:max_projects]

    for pid in selected_projects:
        q_pid = quote_path_segment(pid)
        for act_type in ("serviceAccountLastAuthentication", "serviceAccountKeyLastAuthentication"):
            url = (
                f"https://policyanalyzer.googleapis.com/v1/projects/{q_pid}/locations/global/"
                f"activityTypes/{act_type}/activities:query"
            )
            acts, act_st = gcp_paginated_request(
                "GET",
                url,
                results_key="activities",
                collector="policy_analyzer",
                scope=f"projects/{pid}",
                params={"pageSize": 100},
                timeout=12.0,
                max_pages=10,
            )
            statuses[f"{pid}:{act_type}"] = f"HTTP_{act_st.http_status}" if act_st.http_status else (act_st.error or "ERR")
            for act in acts:
                sa_activities.append(
                    {
                        "project_id": pid,
                        "activity_type": act_type,
                        "full_resource_name": act.get("fullResourceName", ""),
                        "activity": act.get("activity", {}),
                        "observation_period": act.get("observationPeriod", {}),
                    }
                )

    if coverage_scope and total_projects > max_projects:
        record_collection_status(
            coverage_scope,
            "policy_analyzer_projects",
            CollectionStatus(
                collector="policy_analyzer_projects",
                scope=coverage_scope,
                complete=False,
                pages_fetched=len(selected_projects),
                items_collected=len(sa_activities),
                cutoff_reason="CAP_EVALUATED",
                evaluated_count=len(selected_projects),
                total_candidates=total_projects,
            ),
        )

    return {
        "api_statuses": statuses,
        "projects_evaluated": len(selected_projects),
        "total_projects_available": total_projects,
        "activities_count": len(sa_activities),
        "activities": sa_activities,
    }


def fetch_iam_role_recommendations(scope: str = "") -> str:
    """Collects live GCP IAM Recommender items, Policy Analyzer SA auth telemetry, IAM Role permission counts, and Cloud Audit Log usage.

    Args:
        scope: Target GCP Organization or Multi-Project scope.

    Returns:
        JSON string containing 100% live Recommender API items, Policy Analyzer activities, IAM role permission counts, and principal audit usage.
    """
    from backend.tools.cai_collector import CollectionStatus, record_collection_status

    parsed = assert_scope_allowed(scope)
    target_scope = parsed.canonical_scope
    bindings = collect_live_iam_bindings(target_scope)
    project_ids = discover_accessible_projects_in_scope(target_scope)

    scopes_to_query: List[str] = []
    if parsed.organization_scope:
        scopes_to_query.append(parsed.organization_scope)
    for pid in project_ids:
        proj_scope = f"projects/{pid}"
        if proj_scope not in scopes_to_query:
            scopes_to_query.append(proj_scope)

    recommender_data = _query_recommender_and_insights(scopes_to_query, coverage_scope=target_scope)
    policy_analyzer_data = _query_policy_analyzer_sa_activities(project_ids, coverage_scope=target_scope)
    audit_usage = _collect_cloud_audit_usage_by_principal(project_ids, days_back=30)

    non_agent_bindings = [b for b in bindings if not b.get("is_google_service_agent")]
    all_distinct_roles = sorted({b["role"] for b in non_agent_bindings if b.get("role")})
    # Predefined roles (`roles/*`) are NEVER truncated by alphabetical ordering!
    predefined_roles = [r for r in all_distinct_roles if r.startswith("roles/")]
    custom_roles = [r for r in all_distinct_roles if not r.startswith("roles/")]
    max_custom_roles = max(1, int(os.getenv("IAM_MAX_CUSTOM_ROLE_METADATA", "200")))
    distinct_roles = predefined_roles + custom_roles[:max_custom_roles]
    if len(custom_roles) > max_custom_roles:
        record_collection_status(
            target_scope,
            "role_metadata",
            CollectionStatus(
                collector="role_metadata",
                scope=target_scope,
                complete=False,
                items_collected=len(distinct_roles),
                cutoff_reason="CAP_EVALUATED",
                evaluated_count=len(distinct_roles),
                total_candidates=len(all_distinct_roles),
            ),
        )
    role_metas = run_pool_map_with_context(get_live_role_metadata, distinct_roles, max_workers=8)
    role_metadata_map: Dict[str, Dict[str, Any]] = {r: m for r, m in zip(distinct_roles, role_metas)}

    principal_usage_map = audit_usage.get("principal_usage", {})
    binding_exposure_records: List[Dict[str, Any]] = []
    for b in non_agent_bindings:
        principal = b["principal"]
        email_part = principal.split(":", 1)[-1] if ":" in principal else principal
        rmeta = role_metadata_map.get(b["role"], {})
        pusage = principal_usage_map.get(email_part, {})
        granted_cnt = int(rmeta.get("included_permissions_count", 0))
        exercised_cnt = int(pusage.get("distinct_permissions_exercised_count", 0))
        binding_exposure_records.append(
            {
                "principal": principal,
                "principal_type": b.get("principal_type"),
                "domain": b.get("domain"),
                "is_external": bool(b.get("is_external")),
                "is_default_sa": bool(b.get("is_default_sa")),
                "role": b["role"],
                "role_title": rmeta.get("title", b["role"]),
                "resource": b["resource"],
                "project_id": b.get("project_id"),
                "condition": b.get("condition"),
                "granted_permissions_count": granted_cnt,
                "observed_permissions_exercised_in_audit_logs": exercised_cnt,
                "observed_permissions_sample": pusage.get("permissions_exercised", [])[:15],
                "observed_methods_sample": pusage.get("methods_observed", [])[:15],
                "audit_events_observed": int(pusage.get("audit_events_count", 0)),
            }
        )

    payload = {
        "scope": target_scope,
        "scope_mode": parsed.mode,
        "organization_id": parsed.organization_id or active_organization_id(),
        "organization_domain": active_organization_domain(),
        "projects_evaluated": project_ids,
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "telemetry_source": "LIVE_GCP_RECOMMENDER_POLICY_ANALYZER_IAM_ROLES_AND_AUDIT_LOGS",
        "recommender_api": recommender_data,
        "policy_analyzer_api": policy_analyzer_data,
        "cloud_audit_log_usage": audit_usage,
        "non_service_agent_bindings_analyzed": len(binding_exposure_records),
        "live_binding_permission_exposure": sorted(
            binding_exposure_records,
            key=lambda x: (-x["granted_permissions_count"], not x["is_external"]),
        )[:180],
    }
    return json.dumps(payload, indent=2)


def collect_change_impact_evidence(scope: str = "") -> str:
    """Collects bounded Cloud Audit Log sample evidence and existing Policy Simulator metadata (no replay executed)."""
    from backend.validators import quote_gcp_resource_path

    parsed = assert_scope_allowed(scope)
    target_scope = parsed.canonical_scope
    project_ids = discover_accessible_projects_in_scope(target_scope)

    simulator_scopes: List[str] = []
    if parsed.organization_scope:
        simulator_scopes.append(parsed.organization_scope)
    for pid in project_ids[:6]:
        ps = f"projects/{pid}"
        if ps not in simulator_scopes:
            simulator_scopes.append(ps)

    replay_records: List[Dict[str, Any]] = []
    simulator_statuses: Dict[str, str] = {}
    for sc in simulator_scopes:
        sim_url = f"https://policysimulator.googleapis.com/v1/{quote_gcp_resource_path(sc)}/locations/global/replays"
        try:
            code, data = gcp_rest_request("GET", sim_url, params={"pageSize": 50}, timeout=12.0)
            simulator_statuses[sc] = f"HTTP_{code}"
            if code == 200 and isinstance(data, dict):
                for rep in data.get("replays", []):
                    replay_records.append(
                        {
                            "name": rep.get("name", ""),
                            "state": rep.get("state", ""),
                            "results_summary": rep.get("resultsSummary", {}),
                        }
                    )
        except Exception as exc:
            simulator_statuses[sc] = f"ERR_{type(exc).__name__}"

    audit_usage = _collect_cloud_audit_usage_by_principal(project_ids, days_back=90)
    org_policies = collect_live_org_policies(target_scope)

    payload = {
        "scope": target_scope,
        "scope_mode": parsed.mode,
        "projects_evaluated": project_ids,
        "projects_queried_count": audit_usage["projects_queried_count"],
        "total_projects_in_scope": audit_usage["total_projects_in_scope"],
        "projects_queried_over_total": audit_usage["projects_queried_over_total"],
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "telemetry_source": "LIVE_GCP_CLOUD_AUDIT_LOG_SAMPLE_AND_EXISTING_REPLAY_METADATA",
        "simulation_executed": False,
        "is_sample": audit_usage["is_sample"],
        "sample_size": audit_usage["sample_size"],
        "window_start": audit_usage["window_start"],
        "window_end": audit_usage["window_end"],
        "window": audit_usage["window"],
        "policy_simulator_api": {
            "replay_executed": False,
            "scope_statuses": simulator_statuses,
            "existing_replays_count": len(replay_records),
            "replays": replay_records,
        },
        "cloud_audit_log_sample": audit_usage,
        "effective_organization_policies": org_policies,
    }
    return json.dumps(payload, indent=2)


def inspect_iac_target_environment(scope: str = "") -> str:
    """Collects live GCP scope hierarchy, non-service-agent IAM bindings, Service Accounts, WIF pools, and Org Policies for Terraform generation."""
    parsed = assert_scope_allowed(scope)
    target_scope = parsed.canonical_scope
    bindings = collect_live_iam_bindings(target_scope)
    org_policies = collect_live_org_policies(target_scope)
    project_ids = discover_accessible_projects_in_scope(target_scope)
    try:
        resources = collect_live_resources(target_scope)
    except Exception as exc:
        logger.warning("collect_live_resources warning in inspect_iac_target_environment: %s", exc)
        resources = []

    non_agent_bindings = [b for b in bindings if not b.get("is_google_service_agent")][:180]
    sa_list = [r for r in resources if r.get("asset_type") == "iam.googleapis.com/ServiceAccount"]
    wif_pools = [r for r in resources if r.get("asset_type") == "iam.googleapis.com/WorkloadIdentityPool"]
    buckets = [r for r in resources if r.get("asset_type") == "storage.googleapis.com/Bucket"]

    payload = {
        "scope": target_scope,
        "scope_mode": parsed.mode,
        "organization_id": parsed.organization_id or active_organization_id(),
        "organization_domain": active_organization_domain(),
        "primary_project_id": project_ids[0] if project_ids else "",
        "discovered_project_ids": project_ids,
        "non_service_agent_bindings": non_agent_bindings,
        "service_accounts": [
            {
                "name": s["name"],
                "project_id": s.get("project_id", ""),
            }
            # Prompt-size cap only (nothing is scored from this list); totals are reported below.
            for s in sa_list[:40]
        ],
        "service_accounts_total": len(sa_list),
        "service_accounts_listed_over_total": f"{min(len(sa_list), 40)}/{len(sa_list)}",
        "workload_identity_pools": [w["name"] for w in wif_pools],
        "storage_buckets": [
            {"name": b["name"], "project_id": b.get("project_id", ""), "location": b.get("location", "")}
            for b in buckets[:30]
        ],
        "effective_organization_policies": org_policies,
    }
    return json.dumps(payload, indent=2)


def _ground_impact_estimates_from_sample(
    simulations: List[PolicySimulationValidation],
    audit_sample: Optional[Dict[str, Any]],
) -> List[PolicySimulationValidation]:
    """Overwrites displayed event counts and window bounds strictly from Python-computed audit log sample metrics."""
    sample = audit_sample if isinstance(audit_sample, dict) else {}
    sample_size = int(sample.get("sample_size") or 0)
    is_sample = bool(sample.get("is_sample", True))
    window_start = str(sample.get("window_start") or "")
    window_end = str(sample.get("window_end") or "")
    principal_usage = sample.get("principal_usage") if isinstance(sample.get("principal_usage"), dict) else {}

    grounded: List[PolicySimulationValidation] = []
    for sim in simulations:
        raw_principal = (sim.principal or "").strip()
        email_part = raw_principal.split(":", 1)[-1].strip() if ":" in raw_principal else raw_principal
        if email_part and email_part in principal_usage:
            observed_count = int((principal_usage.get(email_part) or {}).get("audit_events_count") or 0)
        elif "@" not in email_part:
            # Scope-wide or Org Policy change estimate reflects the full collected sample size
            observed_count = sample_size
        else:
            observed_count = 0

        grounded.append(
            PolicySimulationValidation(
                simulation_id=sim.simulation_id,
                target_resource=sim.target_resource,
                principal=sim.principal,
                proposed_change_summary=sim.proposed_change_summary,
                access_replay_90d_calls_tested=observed_count,
                sample_events_observed=observed_count,
                sample_window_start=window_start,
                sample_window_end=window_end,
                is_sample=is_sample,
                production_breakage_detected=sim.production_breakage_detected,
                blocked_legitimate_calls=0,
                excess_risk_eliminated_pct=sim.excess_risk_eliminated_pct,
                simulator_verdict=sim.simulator_verdict,
            )
        )
    return grounded


def package_terraform_remediation_files(
    iac_output: IaCAgentOutput,
    scope: str = "",
    output_dir: Optional[Path] = None,
    audit_sample: Optional[Dict[str, Any]] = None,
    *,
    bindings: Optional[List[Dict[str, Any]]] = None,
    strict: bool = True,
) -> IaCRemediationBundle:
    """Validates `iac_output.plan` against live telemetry, deterministically renders HCL + MANUAL_STEPS.md, and writes ZIP."""
    from backend.tools.iac_renderer import render_iac_plan, validate_iac_plan

    parsed = parse_assessment_scope(scope)
    target_scope = parsed.canonical_scope
    effective_bindings = bindings
    if effective_bindings is None:
        if iac_output.plan.replace_role_bindings:
            effective_bindings = collect_live_iam_bindings(target_scope)
        else:
            effective_bindings = []

    validated_plan, rejected_reasons = validate_iac_plan(
        iac_output.plan,
        bindings=effective_bindings,
        target_scope=target_scope,
        strict=strict,
    )

    project_ids = list(parsed.project_ids)
    if not project_ids and effective_bindings:
        project_ids = sorted(
            {
                str(b.get("project_id") or "")
                for b in effective_bindings
                if b.get("project_id") and b.get("project_id") not in ("org-or-folder", "unknown-project")
            }
        )
    rendered = render_iac_plan(
        validated_plan,
        target_scope=target_scope,
        org_id=parsed.organization_id or active_organization_id(),
        org_domain=active_organization_domain(),
        primary_project_id=project_ids[0] if project_ids else "",
    )

    target_dir = output_dir or active_export_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    tf_dir = target_dir / "terraform_remediation_bundle"
    tf_dir.mkdir(parents=True, exist_ok=True)

    for fname, content in rendered.items():
        (tf_dir / fname).write_text(content, encoding="utf-8")

    zip_path = target_dir / "agentic_iam_terraform_remediation_bundle.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, content in rendered.items():
            zf.writestr(f"terraform_remediation_bundle/{fname}", content)

    sample = audit_sample if isinstance(audit_sample, dict) else {}
    grounded_estimates = _ground_impact_estimates_from_sample(iac_output.policy_simulations, sample)

    return IaCRemediationBundle(
        bundle_id=iac_output.bundle_id,
        scope=target_scope,
        main_tf=rendered["main.tf"],
        iam_tf=rendered["iam.tf"],
        pam_entitlements_tf=rendered["pam_entitlements.tf"],
        org_policies_tf=rendered["org_policies.tf"],
        variables_tf=rendered["variables.tf"],
        manual_steps_md=rendered["MANUAL_STEPS.md"],
        rejected_plan_actions=rejected_reasons,
        policy_simulations=grounded_estimates,
        audit_sample_is_sample=bool(sample.get("is_sample", True)),
        audit_sample_size=int(sample.get("sample_size") or 0),
        audit_sample_window_start=str(sample.get("window_start") or ""),
        audit_sample_window_end=str(sample.get("window_end") or ""),
        audit_projects_queried=int(sample.get("projects_queried_count") or 0),
        audit_total_projects_in_scope=int(sample.get("total_projects_in_scope") or 0),
        bundle_zip_path=str(zip_path),
    )
