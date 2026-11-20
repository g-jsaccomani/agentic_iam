"""Cloud Identity & Workspace Directory Live Collector (`directory_collector.py`).

Queries live Google Cloud Identity API (`cloudidentity.googleapis.com`), Workspace Admin SDK
Directory API (`admin.googleapis.com`), Cloud Audit Logs (`logging.googleapis.com`), and live
Cloud Asset Inventory principal telemetry to inspect:
- Real human (`user:`), group (`group:`), and domain (`domain:`) principals bound in IAM
- Live Cloud Identity / Workspace Directory users & security groups (when API & delegation are enabled)
- Direct user assignment vs. Group-based RBAC ratio
- Real Cloud Audit Log recent activity per human principal

Contains ZERO hardcoded/synthetic user counts, fake MFA percentages, or fabricated accounts.
"""

from __future__ import annotations

import datetime
import json
import logging
from typing import Any, Dict, List, Set

from backend.config import settings
from backend.tools.cai_collector import (
    collect_live_iam_bindings,
    discover_accessible_projects_in_scope,
    gcp_rest_request,
    normalize_gcp_scope,
)

logger = logging.getLogger(__name__)


def _collect_recent_principal_audit_activity(projects: List[str]) -> Dict[str, Dict[str, Any]]:
    """Queries Cloud Logging Audit API for recent authentication/authorization events per principal."""
    if not projects:
        return {}
    resource_names = [f"projects/{p}" for p in projects[:10]]
    body = {
        "resourceNames": resource_names,
        "filter": 'logName:"cloudaudit.googleapis.com"',
        "orderBy": "timestamp desc",
        "pageSize": 250,
    }
    activity_by_email: Dict[str, Dict[str, Any]] = {}
    try:
        code, data = gcp_rest_request(
            "POST",
            "https://logging.googleapis.com/v2/entries:list",
            json_body=body,
            timeout=15.0,
        )
        if code == 200:
            for entry in data.get("entries", []):
                proto = entry.get("protoPayload") or {}
                email = ((proto.get("authenticationInfo") or {}).get("principalEmail") or "").strip().lower()
                if not email:
                    continue
                ts = entry.get("timestamp", "")
                rec = activity_by_email.setdefault(
                    email,
                    {"observed_audit_events": 0, "latest_timestamp": ts, "methods_sample": set()},
                )
                rec["observed_audit_events"] += 1
                if ts and ts > rec["latest_timestamp"]:
                    rec["latest_timestamp"] = ts
                method = proto.get("methodName")
                if method and len(rec["methods_sample"]) < 8:
                    rec["methods_sample"].add(method)
    except Exception as exc:
        logger.debug("Cloud Logging audit lookup warning: %s", exc)

    return {
        email: {
            "observed_audit_events": info["observed_audit_events"],
            "latest_timestamp": info["latest_timestamp"],
            "methods_sample": sorted(info["methods_sample"]),
        }
        for email, info in activity_by_email.items()
    }


def collect_cloud_identity_posture(scope: str = "", customer_id: str = "") -> str:
    """Collects live Cloud Identity, Workspace Directory, and IAM human/group principal posture.

    Args:
        scope: Target GCP resource scope (e.g., 'organizations/123456789012' or 'organizations/123456789012/projects:my-project').
        customer_id: Workspace / Cloud Identity customer ID (defaults to configured `my_customer`).

    Returns:
        JSON string containing live Directory/Cloud Identity API responses and real IAM principal governance metrics.
    """
    target_scope = normalize_gcp_scope(scope)
    cid = (customer_id or settings.workspace_customer_id).strip()
    from backend.tools.cai_collector import active_organization_domain
    org_domain = active_organization_domain().lower().strip()

    bindings = collect_live_iam_bindings(target_scope)
    projects = discover_accessible_projects_in_scope(target_scope)
    audit_activity = _collect_recent_principal_audit_activity(projects)

    # Extract real human, group, domain, and public principals from live CAI bindings
    internal_users: Dict[str, Set[str]] = {}
    external_users: Dict[str, Set[str]] = {}
    groups: Dict[str, Set[str]] = {}
    domains: Dict[str, Set[str]] = {}
    public_principals: Dict[str, Set[str]] = {}

    for b in bindings:
        p = b["principal"]
        role = b["role"]
        ptype = b.get("principal_type")
        if ptype == "user":
            email = p.split(":", 1)[-1].lower()
            if b.get("is_external"):
                external_users.setdefault(email, set()).add(role)
            else:
                internal_users.setdefault(email, set()).add(role)
        elif ptype == "group":
            g_email = p.split(":", 1)[-1].lower()
            groups.setdefault(g_email, set()).add(role)
        elif ptype == "domain":
            dom = p.split(":", 1)[-1].lower()
            domains.setdefault(dom, set()).add(role)
        elif ptype == "public":
            public_principals.setdefault(p, set()).add(role)

    # Probe live Admin SDK Directory API (read-only, paginated)
    from backend.tools.cai_collector import gcp_paginated_request, record_collection_status
    import os

    max_dir_users = max(100, int(os.getenv("IAM_MAX_DIRECTORY_USERS", "2000")))
    dir_users, dir_status = gcp_paginated_request(
        "GET",
        "https://admin.googleapis.com/admin/directory/v1/users",
        results_key="users",
        collector="directory_users",
        scope=target_scope,
        params={"customer": cid, "maxResults": 200},
        timeout=10.0,
        max_items=max_dir_users,
    )
    if dir_status.http_status == 200 and dir_status.pages_fetched > 0:
        record_collection_status(target_scope, "directory_users", dir_status)
        enrolled_2sv = sum(1 for u in dir_users if u.get("isEnrolledIn2Sv"))
        enforced_2sv = sum(1 for u in dir_users if u.get("isEnforcedIn2Sv"))
        admin_users_status: Dict[str, Any] = {
            "reachable": True,
            "http_status": 200,
            "complete": dir_status.complete,
            "cutoff_reason": dir_status.cutoff_reason,
            "directory_users_returned": len(dir_users),
            "mfa_2sv_enrolled_count": enrolled_2sv,
            "mfa_2sv_enforced_count": enforced_2sv,
            "mfa_2sv_enrolled_pct": round((enrolled_2sv / max(len(dir_users), 1)) * 100.0, 2),
            "users": [
                {
                    "primaryEmail": u.get("primaryEmail"),
                    "isAdmin": u.get("isAdmin", False),
                    "isDelegatedAdmin": u.get("isDelegatedAdmin", False),
                    "isEnrolledIn2Sv": u.get("isEnrolledIn2Sv", False),
                    "isEnforcedIn2Sv": u.get("isEnforcedIn2Sv", False),
                    "suspended": u.get("suspended", False),
                    "lastLoginTime": u.get("lastLoginTime"),
                }
                for u in dir_users[:50]
            ],
        }
    else:
        admin_users_status = {
            "reachable": False,
            "http_status": dir_status.http_status,
            "detail": dir_status.error or f"HTTP_{dir_status.http_status}",
        }

    # Probe live Cloud Identity Groups API (read-only, paginated)
    ci_groups, grp_status = gcp_paginated_request(
        "GET",
        "https://cloudidentity.googleapis.com/v1/groups",
        results_key="groups",
        collector="cloud_identity_groups",
        scope=target_scope,
        params={"parent": f"customers/{cid}", "pageSize": 200},
        timeout=10.0,
        max_items=max_dir_users,
    )
    if grp_status.http_status == 200 and grp_status.pages_fetched > 0:
        record_collection_status(target_scope, "cloud_identity_groups", grp_status)
        cloud_identity_groups_status: Dict[str, Any] = {
            "reachable": True,
            "http_status": 200,
            "complete": grp_status.complete,
            "groups_count": len(ci_groups),
            "groups": [
                {
                    "name": grp.get("name"),
                    "groupKey": (grp.get("groupKey") or {}).get("id"),
                    "displayName": grp.get("displayName"),
                    "labels": grp.get("labels", {}),
                }
                for grp in ci_groups[:50]
            ],
        }
    else:
        cloud_identity_groups_status = {
            "reachable": False,
            "http_status": grp_status.http_status,
            "detail": grp_status.error or f"HTTP_{grp_status.http_status}",
        }

    direct_user_bindings_count = sum(1 for b in bindings if b.get("principal_type") == "user")
    group_bindings_count = sum(1 for b in bindings if b.get("principal_type") == "group")
    total_human_or_group = direct_user_bindings_count + group_bindings_count

    telemetry: Dict[str, Any] = {
        "scope": target_scope,
        "customer_id": cid,
        "primary_organization_domain": org_domain,
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "telemetry_source": "LIVE_GCP_ADMIN_DIRECTORY_CLOUD_IDENTITY_AND_CAI",
        "workspace_directory_api": admin_users_status,
        "cloud_identity_groups_api": cloud_identity_groups_status,
        "iam_bound_principals_summary": {
            "internal_users_count": len(internal_users),
            "external_users_count": len(external_users),
            "groups_bound_in_iam_count": len(groups),
            "domains_bound_in_iam_count": len(domains),
            "public_principals_count": len(public_principals),
            "direct_user_bindings_count": direct_user_bindings_count,
            "group_rbac_bindings_count": group_bindings_count,
            "group_rbac_adoption_pct": round(
                (group_bindings_count / max(total_human_or_group, 1)) * 100.0, 2
            )
            if total_human_or_group > 0
            else 100.0,
        },
        "internal_user_principals": [
            {
                "email": email,
                "roles": sorted(roles),
                "recent_audit_activity": audit_activity.get(email),
            }
            for email, roles in sorted(internal_users.items())
        ],
        "external_user_principals": [
            {
                "email": email,
                "roles": sorted(roles),
                "is_consumer_gmail": email.endswith(("@gmail.com", "@googlemail.com")),
                "recent_audit_activity": audit_activity.get(email),
            }
            for email, roles in sorted(external_users.items())
        ],
        "domain_principals": [
            {
                "domain": dom,
                "is_external_domain": dom != org_domain,
                "roles": sorted(roles),
            }
            for dom, roles in sorted(domains.items())
        ],
        "group_principals": [
            {"group_email": g_email, "roles": sorted(roles)}
            for g_email, roles in sorted(groups.items())
        ],
        "public_principals": [
            {"principal": pub, "roles": sorted(roles)}
            for pub, roles in sorted(public_principals.items())
        ],
    }
    return json.dumps(telemetry, indent=2)
