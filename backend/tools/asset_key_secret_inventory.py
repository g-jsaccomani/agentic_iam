"""Comprehensive Live Accounts, Service Accounts, Keys, KMS, Secrets, API Keys & WIF Collector (`asset_key_secret_inventory.py`).

100% Read-Only & Metadata-Only Governance:
- Inspects IAM bindings, Service Accounts, SA Keys (`USER_MANAGED` & `SYSTEM_MANAGED`), Secret Manager
  metadata (`Secret` & `SecretVersion` — NEVER calls `:access` on secret payloads), Cloud KMS `KeyRing` &
  `CryptoKey` rotation/protection/SoD posture, Google Cloud API Keys restriction metadata (never calls
  `:getKeyString`), Custom IAM Roles escalation permissions, Workload Identity Pools/Providers, and
  effective Organization Policies.
- Strictly partitioned per authenticated `InspectionSession` (`active_cache_namespace()`).
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.models.findings import (
    AccountPrincipalRecord,
    AccountsKeysSecretsInventory,
    AccountsKeysSecretsSummaryKPIs,
    ApiKeyMetadataRecord,
    CustomIamRoleRecord,
    KmsCryptoKeyRecord,
    OrgPolicyPostureRecord,
    SecretMetadataRecord,
    ServiceAccountKeyRecord,
    ServiceAccountRecord,
    WifPoolProviderRecord,
)
from backend.session_vault import register_cache_purge_hook, run_pool_map_with_context
from backend.tools.cai_collector import (
    active_cache_namespace,
    collect_live_iam_bindings,
    collect_live_org_policies,
    collect_live_resources,
    discover_accessible_projects_in_scope,
    extract_attached_workload_service_accounts,
    extract_sa_owning_project,
    gcp_rest_request,
    get_org_project_membership_context,
    is_default_service_account_email,
    is_google_managed_service_agent,
    normalize_gcp_scope,
    parse_assessment_scope,
)
from backend.tools.recommender_tool import (
    _collect_cloud_audit_usage_by_principal,
    get_live_role_metadata,
)

logger = logging.getLogger(__name__)

_INVENTORY_CACHE: Dict[Tuple[str, str], Tuple[float, AccountsKeysSecretsInventory]] = {}
_INVENTORY_TTL_SECONDS = 120.0

SECRET_ACCESS_PERMS: Set[str] = {
    "secretmanager.versions.access",
}
KMS_ADMIN_PERMS: Set[str] = {
    "cloudkms.cryptoKeys.setIamPolicy",
    "cloudkms.keyRings.setIamPolicy",
    "cloudkms.cryptoKeyVersions.destroy",
    "cloudkms.cryptoKeys.update",
}
KMS_CRYPTO_USE_PERMS: Set[str] = {
    "cloudkms.cryptoKeyVersions.useToDecrypt",
    "cloudkms.cryptoKeyVersions.useToEncrypt",
    "cloudkms.cryptoKeyVersions.useToSign",
    "cloudkms.cryptoKeyVersions.useToVerify",
    "cloudkms.cryptoKeyVersions.macSign",
}
# Minimal fallback permission sets used ONLY when the IAM Roles API is unavailable (e.g., 403).
# Note: `roles/editor` is intentionally excluded from Secret Manager readers and KMS crypto users.
_FALLBACK_ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "roles/secretmanager.secretAccessor": {"secretmanager.versions.access"},
    "roles/secretmanager.admin": {"secretmanager.versions.access"},
    "roles/cloudkms.admin": {"cloudkms.cryptoKeys.setIamPolicy", "cloudkms.keyRings.setIamPolicy", "cloudkms.cryptoKeyVersions.destroy"},
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": {"cloudkms.cryptoKeyVersions.useToDecrypt", "cloudkms.cryptoKeyVersions.useToEncrypt"},
    "roles/cloudkms.cryptoKeyDecrypter": {"cloudkms.cryptoKeyVersions.useToDecrypt"},
    "roles/cloudkms.cryptoKeyEncrypter": {"cloudkms.cryptoKeyVersions.useToEncrypt"},
    "roles/cloudkms.signerVerifier": {"cloudkms.cryptoKeyVersions.useToSign", "cloudkms.cryptoKeyVersions.useToVerify"},
    "roles/cloudkms.signer": {"cloudkms.cryptoKeyVersions.useToSign"},
    "roles/owner": {
        "secretmanager.versions.access",
        "cloudkms.cryptoKeys.setIamPolicy",
        "cloudkms.cryptoKeyVersions.useToDecrypt",
    },
}
SA_IMPERSONATION_ROLES: Set[str] = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.serviceAccountAdmin",
}
STANDING_ADMIN_ROLES: Set[str] = {
    "roles/owner",
    "roles/editor",
    "roles/resourcemanager.organizationAdmin",
    "roles/iam.securityAdmin",
    "roles/iam.organizationRoleAdmin",
}
DANGEROUS_CUSTOM_ROLE_PERMS: Set[str] = {
    "iam.roles.update",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccountKeys.create",
    "iam.serviceAccounts.actAs",
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    "deploymentmanager.deployments.create",
}


def _purge_inventory_cache(session_id: str) -> None:
    prefix = f"{session_id}:"
    for k in [key for key in list(_INVENTORY_CACHE.keys()) if key[0].startswith(prefix)]:
        _INVENTORY_CACHE.pop(k, None)


register_cache_purge_hook(_purge_inventory_cache)


def _parse_iso_days_ago(ts_str: Optional[str], now_utc: datetime.datetime) -> int:
    if not ts_str:
        return 0
    try:
        dt = datetime.datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        return max(0, (now_utc - dt).days)
    except ValueError:
        return 0


def _parse_duration_days(dur_str: Optional[str]) -> Optional[int]:
    """Converts protobuf duration string like '7776000s' to integer days (90)."""
    if not dur_str:
        return None
    s = str(dur_str).strip().lower()
    if s.endswith("s"):
        try:
            secs = float(s[:-1])
            return max(1, int(round(secs / 86400.0)))
        except ValueError:
            return None
    return None


def _has_temporal_cel(cond: Optional[str]) -> bool:
    if not cond:
        return False
    return bool(re.search(r"request\.time\s*<=?\s*timestamp\s*\(", cond, flags=re.IGNORECASE))


def _resolve_role_permissions_map(
    bindings: List[Dict[str, Any]],
    resources: List[Dict[str, Any]],
) -> Dict[str, Set[str]]:
    """Resolves `includedPermissions` per role from CAI custom roles and the live IAM Roles API."""
    role_perms: Dict[str, Set[str]] = {}

    # 1. Seed custom roles directly from CAI iam.googleapis.com/Role resources
    for r in resources:
        if r.get("asset_type") != "iam.googleapis.com/Role":
            continue
        vres = r.get("versioned_resource") or {}
        rname = str(vres.get("name") or "")
        if not rname and "//iam.googleapis.com/" in str(r.get("name") or ""):
            rname = str(r["name"]).split("//iam.googleapis.com/", 1)[-1]
        perms = vres.get("includedPermissions")
        if rname and isinstance(perms, list):
            role_perms[rname] = {str(p) for p in perms if isinstance(p, str)}

    # 2. Query live IAM Roles API for all bound roles not already resolved from CAI
    unique_roles = sorted({str(b.get("role") or "").strip() for b in bindings if b.get("role")})
    missing_roles = [rl for rl in unique_roles if rl not in role_perms]
    if missing_roles:
        metas = run_pool_map_with_context(get_live_role_metadata, missing_roles, max_workers=8)
        for rl, meta in zip(missing_roles, metas):
            if isinstance(meta, dict) and meta.get("status") == "LIVE_IAM_ROLES_API":
                role_perms[rl] = {str(p) for p in (meta.get("included_permissions") or [])}
            else:
                role_perms[rl] = set(_FALLBACK_ROLE_PERMISSIONS.get(rl, set()))

    return role_perms


def _extract_folder_id_from_resource(resource_uri: str) -> Optional[str]:
    m = re.search(r"/folders/([0-9]+)(?:/|$)", str(resource_uri or ""))
    if m:
        return f"folders/{m.group(1)}"
    return None


def _build_project_folder_ancestry_map(
    target_scope: str,
    resources: List[Dict[str, Any]],
    proj_num_map: Dict[str, str],
) -> Dict[str, Set[str]]:
    """Maps `<project_id>` -> set of ancestor folder resource names (`folders/<id>`)."""
    ancestry: Dict[str, Set[str]] = {}

    try:
        parsed = parse_assessment_scope(target_scope)
        if parsed.organization_scope:
            org_meta = get_org_project_membership_context(parsed.organization_scope, coverage_scope=target_scope)
            for pid, fset in (org_meta.get("project_folders") or {}).items():
                ancestry.setdefault(pid, set()).update(fset)
    except Exception:
        pass

    for r in resources:
        pid = _resolve_pid(str(r.get("project_id") or ""), str(r.get("project") or ""), proj_num_map)
        if not pid or pid == "organization":
            continue
        fset = ancestry.setdefault(pid, set())
        for fld in (r.get("folders") or []):
            fs = str(fld or "").strip()
            if fs:
                fset.add(fs if fs.startswith("folders/") else f"folders/{fs}")
        for anc in (r.get("ancestors") or []):
            a_str = str(anc or "").strip()
            if a_str.startswith("folders/"):
                fset.add(a_str)
        parent_fld = _extract_folder_id_from_resource(str(r.get("parent_full_resource_name") or ""))
        if parent_fld:
            fset.add(parent_fld)

    return ancestry


def _build_project_num_map(resources: List[Dict[str, Any]], bindings: List[Dict[str, Any]]) -> Dict[str, str]:
    """Maps `projects/<number>` -> `<project_id>` from CAI parent metadata."""
    mapping: Dict[str, str] = {}
    for r in resources:
        p_ref = str(r.get("project") or "")
        p_id = str(r.get("project_id") or "")
        if p_ref.startswith("projects/") and p_id and not p_id.isdigit() and p_id != "unknown-project":
            mapping[p_ref] = p_id
            mapping[p_ref.split("/", 1)[1]] = p_id
    for b in bindings:
        p_id = str(b.get("project_id") or "")
        res = str(b.get("resource") or "")
        m = re.search(r"/projects/(\d+)/", res)
        if m and p_id and not p_id.isdigit():
            mapping[m.group(1)] = p_id
            mapping[f"projects/{m.group(1)}"] = p_id
    return mapping


def _resolve_pid(raw_pid: str, raw_proj_ref: str, num_map: Dict[str, str]) -> str:
    if raw_pid and not raw_pid.isdigit() and raw_pid != "unknown-project":
        return raw_pid
    if raw_proj_ref in num_map:
        return num_map[raw_proj_ref]
    clean_num = raw_proj_ref.replace("projects/", "").strip()
    if clean_num in num_map:
        return num_map[clean_num]
    if raw_pid in num_map:
        return num_map[raw_pid]
    return raw_pid or clean_num or "organization"


def build_accounts_keys_secrets_inventory(
    scope: str = "",
    force_refresh: bool = False,
) -> AccountsKeysSecretsInventory:
    """Collects the complete live Accounts, SAs, Keys, Secrets, KMS, API Keys, Custom Roles & WIF inventory."""
    target_scope = normalize_gcp_scope(scope)
    ck = (active_cache_namespace(), target_scope)
    now_mono = time.monotonic()
    if not force_refresh and ck in _INVENTORY_CACHE:
        ts, cached = _INVENTORY_CACHE[ck]
        if (now_mono - ts) < _INVENTORY_TTL_SECONDS:
            return cached

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    bindings = collect_live_iam_bindings(target_scope, force_refresh=force_refresh)
    resources = collect_live_resources(target_scope, force_refresh=force_refresh)
    org_policies_raw = collect_live_org_policies(target_scope)
    project_ids = discover_accessible_projects_in_scope(target_scope)
    audit_usage = _collect_cloud_audit_usage_by_principal(project_ids, days_back=30)
    principal_usage_map = audit_usage.get("principal_usage") or {}

    proj_num_map = _build_project_num_map(resources, bindings)
    role_perms_map = _resolve_role_permissions_map(bindings, resources)
    project_folder_ancestry = _build_project_folder_ancestry_map(target_scope, resources, proj_num_map)

    def _role_has_any_perm(role_name: str, target_perms: Set[str]) -> bool:
        return bool(role_perms_map.get(role_name, set()) & target_perms)

    # -------------------------------------------------------------------------
    # 1. HUMAN, GROUP, DOMAIN, EXTERNAL & PUBLIC ACCOUNTS LEDGER
    # -------------------------------------------------------------------------
    acc_agg: Dict[str, Dict[str, Any]] = {}
    google_agents_seen: Set[str] = set()

    for b in bindings:
        p = b["principal"]
        if b.get("is_google_service_agent"):
            google_agents_seen.add(p)
            continue
        ptype = b.get("principal_type") or "other"
        if ptype == "service_account":
            continue

        rec = acc_agg.setdefault(
            p,
            {
                "principal": p,
                "raw_type": ptype,
                "domain": b.get("domain") or "",
                "is_external": bool(b.get("is_external")),
                "roles": set(),
                "bindings_count": 0,
                "projects": set(),
                "is_standing_admin": False,
                "can_access_secrets": False,
                "can_use_or_admin_kms": False,
                "can_impersonate_sa": False,
                "has_cel_condition": False,
            },
        )
        role = b["role"]
        cond = b.get("condition")
        rec["roles"].add(role)
        rec["bindings_count"] += 1
        pid = _resolve_pid(str(b.get("project_id") or ""), "", proj_num_map)
        if pid:
            rec["projects"].add(pid)
        if cond:
            rec["has_cel_condition"] = True
        if role in STANDING_ADMIN_ROLES and not _has_temporal_cel(cond):
            rec["is_standing_admin"] = True
        if _role_has_any_perm(role, SECRET_ACCESS_PERMS):
            rec["can_access_secrets"] = True
        if _role_has_any_perm(role, KMS_ADMIN_PERMS) or _role_has_any_perm(role, KMS_CRYPTO_USE_PERMS):
            rec["can_use_or_admin_kms"] = True
        if role in SA_IMPERSONATION_ROLES:
            rec["can_impersonate_sa"] = True

    accounts_out: List[AccountPrincipalRecord] = []
    for p, info in acc_agg.items():
        email_part = p.split(":", 1)[-1] if ":" in p else p
        is_gmail = email_part.lower().endswith(("@gmail.com", "@googlemail.com"))
        rt = info["raw_type"]
        if rt == "public":
            label_type = "Public Anonymous"
        elif rt == "deleted":
            label_type = "Deleted Principal"
        elif is_gmail:
            label_type = "Consumer Gmail"
        elif rt == "user" and info["is_external"]:
            label_type = "External User"
        elif rt == "user":
            label_type = "Internal User"
        elif rt == "group":
            label_type = "External Group" if info["is_external"] else "Security Group"
        elif rt == "domain":
            label_type = "External Domain" if info["is_external"] else "Primary Domain"
        elif p.startswith(("projectOwner:", "projectEditor:", "projectViewer:")):
            label_type = "Convenience ACL"
        else:
            label_type = rt.title()

        aud_cnt = int((principal_usage_map.get(email_part) or {}).get("audit_events_count") or 0)
        if rt == "public" or (info["is_external"] and info["is_standing_admin"]) or is_gmail:
            risk = "CRITICAL"
        elif info["is_standing_admin"] or info["is_external"] or label_type == "Convenience ACL":
            risk = "HIGH"
        elif rt in ("user", "deleted") or info["can_impersonate_sa"] or info["can_access_secrets"]:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        accounts_out.append(
            AccountPrincipalRecord(
                principal=p,
                principal_type=label_type,
                domain=info["domain"] or "—",
                is_external=info["is_external"],
                roles=sorted(info["roles"]),
                bindings_count=info["bindings_count"],
                projects=sorted(info["projects"]),
                is_standing_admin=info["is_standing_admin"],
                can_access_secrets=info["can_access_secrets"],
                can_use_or_admin_kms=info["can_use_or_admin_kms"],
                can_impersonate_sa=info["can_impersonate_sa"],
                has_cel_condition=info["has_cel_condition"],
                audit_events_30d=aud_cnt,
                risk_level=risk,
            )
        )

    risk_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    accounts_out.sort(key=lambda a: (risk_rank.get(a.risk_level, 4), -a.bindings_count, a.principal))

    # -------------------------------------------------------------------------
    # 2. SERVICE ACCOUNTS & SA KEYS (USER_MANAGED + SYSTEM_MANAGED) LEDGER
    # -------------------------------------------------------------------------
    workload_attachments: Dict[str, Set[str]] = {}
    for r in resources:
        if r["asset_type"] in ("compute.googleapis.com/Instance", "run.googleapis.com/Service"):
            w_label = f"{'VM' if 'Instance' in r['asset_type'] else 'CloudRun'}:{r.get('display_name') or r['name'].rsplit('/', 1)[-1]}"
            for em in extract_attached_workload_service_accounts(r):
                workload_attachments.setdefault(em.strip(), set()).add(w_label)

    sa_roles_map: Dict[str, Set[str]] = {}
    for b in bindings:
        if b["principal"].startswith("serviceAccount:") and not b.get("is_google_service_agent"):
            em = b["principal"].split(":", 1)[1].strip()
            sa_roles_map.setdefault(em, set()).add(b["role"])

    sa_map: Dict[str, Dict[str, Any]] = {}
    unique_id_to_email: Dict[str, str] = {}

    for r in resources:
        if r["asset_type"] != "iam.googleapis.com/ServiceAccount":
            continue
        vres = r.get("versioned_resource") or {}
        attrs = r.get("additional_attributes") or {}
        em = str(vres.get("email") or attrs.get("email") or r["name"].rsplit("/serviceAccounts/", 1)[-1]).strip()
        if not em or "@" not in em:
            continue
        if is_google_managed_service_agent(f"serviceAccount:{em}"):
            google_agents_seen.add(f"serviceAccount:{em}")
            continue
        uid = str(vres.get("uniqueId") or attrs.get("uniqueId") or "")
        if uid:
            unique_id_to_email[uid] = em
        pid = _resolve_pid(str(r.get("project_id") or ""), str(r.get("project") or ""), proj_num_map)
        if not pid or pid == "organization":
            pid = extract_sa_owning_project(em) or "external-or-org"
        sa_map[em] = {
            "email": em,
            "project_id": pid,
            "display_name": str(vres.get("displayName") or r.get("display_name") or em),
            "disabled": bool(vres.get("disabled") or r.get("state") == "DISABLED"),
            "user_keys": 0,
            "system_keys": 0,
            "oldest_user_key_days": 0,
        }

    for em in sa_roles_map:
        if em not in sa_map and not is_google_managed_service_agent(f"serviceAccount:{em}"):
            sa_map[em] = {
                "email": em,
                "project_id": extract_sa_owning_project(em) or "external-or-org",
                "display_name": em,
                "disabled": False,
                "user_keys": 0,
                "system_keys": 0,
                "oldest_user_key_days": 0,
            }

    # Use the single canonical SA key collector shared with Scorecard so user-managed key counts always match
    from backend.tools.cai_collector import collect_unified_service_account_keys

    unified_sa_keys = collect_unified_service_account_keys(
        target_scope,
        bindings=bindings,
        resources=resources,
        force_refresh=force_refresh,
    )
    sa_keys_dedup: Dict[str, ServiceAccountKeyRecord] = {}
    for krec in unified_sa_keys.get("all_keys") or []:
        sa_em = str(krec.get("sa_email") or "").strip().lower()
        sa_em = unique_id_to_email.get(sa_em, sa_em)
        if not sa_em or is_google_managed_service_agent(f"serviceAccount:{sa_em}"):
            continue
        kid = str(krec.get("key_id") or "")
        pid = _resolve_pid(str(krec.get("project_id") or ""), "", proj_num_map)
        valid_after = str(krec.get("valid_after_time") or "")
        valid_before = str(krec.get("valid_before_time") or "")
        sa_keys_dedup[f"{sa_em}:{kid}"] = ServiceAccountKeyRecord(
            key_id=kid[:16],
            sa_email=sa_em,
            project_id=pid,
            key_type=str(krec.get("key_type") or "UNKNOWN"),
            key_origin=str(krec.get("key_origin") or "GOOGLE_PROVIDED"),
            key_algorithm=str(krec.get("key_algorithm") or "KEY_ALG_RSA_2048"),
            valid_after_time=valid_after[:19].replace("T", " "),
            valid_before_time=valid_before[:19].replace("T", " "),
            age_days=int(krec.get("age_days") or 0),
            risk_level=str(krec.get("risk_level") or "HIGH"),
        )

    for kr in sa_keys_dedup.values():
        srec = sa_map.get(kr.sa_email)
        if srec:
            if kr.key_type == "USER_MANAGED":
                srec["user_keys"] += 1
                srec["oldest_user_key_days"] = max(srec["oldest_user_key_days"], kr.age_days)
            elif kr.key_type == "SYSTEM_MANAGED":
                srec["system_keys"] += 1

    sa_records_out: List[ServiceAccountRecord] = []
    for em, sinfo in sa_map.items():
        roles_list = sorted(sa_roles_map.get(em, set()))
        em_low = em.lower()
        if em_low.endswith("-compute@developer.gserviceaccount.com"):
            subtype = "Default Compute SA"
        elif em_low.endswith("@appspot.gserviceaccount.com"):
            subtype = "Default AppEngine SA"
        elif em_low.endswith("@cloudbuild.gserviceaccount.com"):
            subtype = "Default Cloud Build SA"
        else:
            subtype = "Custom SA"

        sec_kms = any(
            _role_has_any_perm(r, SECRET_ACCESS_PERMS)
            or _role_has_any_perm(r, KMS_ADMIN_PERMS)
            or _role_has_any_perm(r, KMS_CRYPTO_USE_PERMS)
            for r in roles_list
        )
        has_prim = any(r in ("roles/owner", "roles/editor") for r in roles_list)
        if sinfo["oldest_user_key_days"] > 90 or (subtype != "Custom SA" and has_prim):
            srisk = "CRITICAL"
        elif sinfo["user_keys"] > 0 or has_prim or (subtype != "Custom SA" and len(roles_list) > 0):
            srisk = "HIGH"
        elif sec_kms:
            srisk = "MEDIUM"
        else:
            srisk = "LOW"

        sa_records_out.append(
            ServiceAccountRecord(
                email=em,
                project_id=sinfo["project_id"],
                display_name=sinfo["display_name"],
                sa_subtype=subtype,
                disabled=sinfo["disabled"],
                user_managed_keys_count=sinfo["user_keys"],
                system_managed_keys_count=sinfo["system_keys"],
                oldest_user_key_age_days=sinfo["oldest_user_key_days"],
                granted_roles=roles_list,
                attached_workloads=sorted(workload_attachments.get(em, set())),
                can_access_secrets_or_kms=sec_kms,
                risk_level=srisk,
            )
        )
    sa_records_out.sort(key=lambda s: (risk_rank.get(s.risk_level, 4), -s.user_managed_keys_count, s.email))
    sa_keys_out = sorted(
        sa_keys_dedup.values(),
        key=lambda k: (0 if k.key_type == "USER_MANAGED" else 1, -k.age_days, k.sa_email),
    )

    # -------------------------------------------------------------------------
    # 3. SECRET MANAGER SECRETS GOVERNANCE LEDGER (100% METADATA-ONLY)
    # -------------------------------------------------------------------------
    enabled_secret_versions: Dict[Tuple[str, str], int] = {}
    total_enabled_versions = 0
    for r in resources:
        if r["asset_type"] == "secretmanager.googleapis.com/SecretVersion":
            st = str(r.get("state") or (r.get("versioned_resource") or {}).get("state") or "ENABLED").upper()
            if "ENABLED" in st:
                pid = _resolve_pid(str(r.get("project_id") or ""), str(r.get("project") or ""), proj_num_map)
                m_sec = re.search(r"/secrets/([^/]+)/versions/", r["name"])
                if m_sec:
                    key_sv = (pid, m_sec.group(1))
                    enabled_secret_versions[key_sv] = enabled_secret_versions.get(key_sv, 0) + 1
                    total_enabled_versions += 1

    # Index secret accessors strictly from `includedPermissions` (`secretmanager.versions.access`),
    # scoping folder bindings ONLY to projects whose ancestry includes that folder.
    org_wide_secret_holders: Set[str] = set()
    folder_secret_holders: Dict[str, Set[str]] = {}
    proj_secret_holders: Dict[str, Set[str]] = {}
    direct_secret_holders: Dict[str, Set[str]] = {}
    primitive_holders_by_proj: Dict[str, Set[str]] = {}
    folder_primitives: Dict[str, Set[str]] = {}
    org_wide_primitives: Set[str] = set()

    for b in bindings:
        if b.get("is_google_service_agent"):
            continue
        rl = b["role"]
        pr = b["principal"]
        res = b["resource"]
        pid = _resolve_pid(str(b.get("project_id") or ""), "", proj_num_map)
        if _role_has_any_perm(rl, SECRET_ACCESS_PERMS):
            folder_ref = _extract_folder_id_from_resource(res)
            if "/secrets/" in res:
                sec_short = res.rsplit("/secrets/", 1)[-1].split("/")[0]
                direct_secret_holders.setdefault(f"{pid}/{sec_short}", set()).add(pr)
            elif "/organizations/" in res:
                org_wide_secret_holders.add(pr)
                if rl == "roles/owner":
                    org_wide_primitives.add(pr)
            elif folder_ref:
                folder_secret_holders.setdefault(folder_ref, set()).add(pr)
                if rl == "roles/owner":
                    folder_primitives.setdefault(folder_ref, set()).add(pr)
            else:
                proj_secret_holders.setdefault(pid, set()).add(pr)
                if rl == "roles/owner":
                    primitive_holders_by_proj.setdefault(pid, set()).add(pr)

    secrets_out: List[SecretMetadataRecord] = []
    for r in resources:
        if r["asset_type"] != "secretmanager.googleapis.com/Secret":
            continue
        vres = r.get("versioned_resource") or {}
        pid = _resolve_pid(str(r.get("project_id") or ""), str(r.get("project") or ""), proj_num_map)
        sec_name = r["name"].rsplit("/secrets/", 1)[-1]

        repl = vres.get("replication") or {}
        if "userManaged" in repl:
            locs = [
                str(rep.get("location") or "")
                for rep in ((repl.get("userManaged") or {}).get("replicas") or [])
                if isinstance(rep, dict)
            ]
            repl_str = f"USER_MANAGED ({', '.join(locs) or 'regional'})"
            um_cmek = next(
                (
                    (rep.get("customerManagedEncryption") or {}).get("kmsKeyName")
                    for rep in ((repl.get("userManaged") or {}).get("replicas") or [])
                    if isinstance(rep, dict) and (rep.get("customerManagedEncryption") or {}).get("kmsKeyName")
                ),
                "",
            )
        else:
            repl_str = "AUTOMATIC"
            um_cmek = ((repl.get("automatic") or {}).get("customerManagedEncryption") or {}).get("kmsKeyName") or ""

        kms_list = r.get("kms_keys") or []
        cmek_key = str(
            um_cmek
            or ((vres.get("customerManagedEncryption") or {}).get("kmsKeyName") or "")
            or (kms_list[0] if kms_list else "")
        )
        enc_type = "CMEK" if cmek_key else "GOOGLE_MANAGED"

        rot = vres.get("rotation") or {}
        next_rot = str(rot.get("nextRotationTime") or "")
        rot_days = _parse_duration_days(rot.get("rotationPeriod"))
        rot_cfg = bool(next_rot or rot_days)

        exp_ttl = str(vres.get("expireTime") or vres.get("ttl") or "")
        c_time = str(vres.get("createTime") or r.get("create_time") or "")[:19].replace("T", " ")

        anc_folders = project_folder_ancestry.get(pid, set())
        inherited_folder_acc: Set[str] = set()
        inherited_folder_prim: Set[str] = set()
        for fid in anc_folders:
            inherited_folder_acc.update(folder_secret_holders.get(fid, set()))
            inherited_folder_prim.update(folder_primitives.get(fid, set()))

        accessors = (
            direct_secret_holders.get(f"{pid}/{sec_name}", set())
            | proj_secret_holders.get(pid, set())
            | inherited_folder_acc
            | org_wide_secret_holders
        )
        prim_acc = primitive_holders_by_proj.get(pid, set()) | inherited_folder_prim | org_wide_primitives

        if len(prim_acc) > 2 and not rot_cfg:
            sec_risk = "HIGH"
        elif not rot_cfg or enc_type == "GOOGLE_MANAGED":
            sec_risk = "MEDIUM"
        else:
            sec_risk = "LOW"

        secrets_out.append(
            SecretMetadataRecord(
                secret_name=sec_name,
                project_id=pid,
                replication_policy=repl_str,
                encryption_type=enc_type,
                kms_key_name=cmek_key,
                active_versions_count=enabled_secret_versions.get((pid, sec_name), 0),
                rotation_configured=rot_cfg,
                rotation_period_days=rot_days,
                next_rotation_time=next_rot[:19].replace("T", " "),
                expire_or_ttl=exp_ttl[:19].replace("T", " "),
                created_at=c_time,
                accessor_principals=sorted(accessors)[:15],
                accessor_principals_total=len(accessors),
                broad_primitive_accessors_count=len(prim_acc),
                risk_level=sec_risk,
            )
        )
    secrets_out.sort(key=lambda s: (risk_rank.get(s.risk_level, 4), s.project_id, s.secret_name))

    # -------------------------------------------------------------------------
    # 4. CLOUD KMS KEYRINGS, CRYPTOKEYS & SEPARATION-OF-DUTIES LEDGER
    # -------------------------------------------------------------------------
    keyrings_count = sum(1 for r in resources if r["asset_type"] == "cloudkms.googleapis.com/KeyRing")

    # Identify KMS Admin + Encrypter/Decrypter SoD violations strictly from `includedPermissions`,
    # scoping folder bindings ONLY to projects under that folder.
    kms_admins_by_proj: Dict[str, Set[str]] = {}
    kms_users_by_proj: Dict[str, Set[str]] = {}
    folder_kms_admins: Dict[str, Set[str]] = {}
    folder_kms_users: Dict[str, Set[str]] = {}
    org_kms_admins: Set[str] = set()
    org_kms_users: Set[str] = set()

    for b in bindings:
        if b.get("is_google_service_agent"):
            continue
        rl = b["role"]
        pr = b["principal"]
        res = b["resource"]
        pid = _resolve_pid(str(b.get("project_id") or ""), "", proj_num_map)
        folder_ref = _extract_folder_id_from_resource(res)
        is_kms_adm = _role_has_any_perm(rl, KMS_ADMIN_PERMS) and (
            rl != "roles/owner" or not _has_temporal_cel(b.get("condition"))
        )
        is_kms_use = _role_has_any_perm(rl, KMS_CRYPTO_USE_PERMS)
        if is_kms_adm:
            if "/organizations/" in res:
                org_kms_admins.add(pr)
            elif folder_ref:
                folder_kms_admins.setdefault(folder_ref, set()).add(pr)
            else:
                kms_admins_by_proj.setdefault(pid, set()).add(pr)
        if is_kms_use:
            if "/organizations/" in res:
                org_kms_users.add(pr)
            elif folder_ref:
                folder_kms_users.setdefault(folder_ref, set()).add(pr)
            else:
                kms_users_by_proj.setdefault(pid, set()).add(pr)

    kms_out: List[KmsCryptoKeyRecord] = []
    all_sod_principals: Set[str] = set()
    for r in resources:
        if r["asset_type"] != "cloudkms.googleapis.com/CryptoKey":
            continue
        vres = r.get("versioned_resource") or {}
        pid = _resolve_pid(str(r.get("project_id") or ""), str(r.get("project") or ""), proj_num_map)
        loc = str(r.get("location") or "global")
        key_short = r["name"].rsplit("/cryptoKeys/", 1)[-1]
        kr_short = r["name"].split("/keyRings/", 1)[-1].split("/cryptoKeys/", 1)[0] if "/keyRings/" in r["name"] else "—"

        purpose = str(vres.get("purpose") or "ENCRYPT_DECRYPT")
        vtpl = vres.get("versionTemplate") or {}
        prot = str(vtpl.get("protectionLevel") or "SOFTWARE")
        alg = str(vtpl.get("algorithm") or "GOOGLE_SYMMETRIC_ENCRYPTION")
        rot_days = _parse_duration_days(vres.get("rotationPeriod"))
        next_rot = str(vres.get("nextRotationTime") or "")[:19].replace("T", " ")

        # CIS GCP 1.10: Symmetric ENCRYPT_DECRYPT keys require <=90d rotation; asymmetric keys use manual version rotation
        if purpose == "ENCRYPT_DECRYPT":
            rot_ok = rot_days is not None and rot_days <= 90
        else:
            rot_ok = True

        anc_folders = project_folder_ancestry.get(pid, set())
        fld_admins: Set[str] = set()
        fld_users: Set[str] = set()
        for fid in anc_folders:
            fld_admins.update(folder_kms_admins.get(fid, set()))
            fld_users.update(folder_kms_users.get(fid, set()))

        p_admins = kms_admins_by_proj.get(pid, set()) | fld_admins | org_kms_admins
        p_users = kms_users_by_proj.get(pid, set()) | fld_users | org_kms_users
        sod_conflicts = sorted(p_admins & p_users)
        all_sod_principals.update(sod_conflicts)

        if purpose == "ENCRYPT_DECRYPT" and not rot_ok and sod_conflicts:
            k_risk = "HIGH"
        elif (purpose == "ENCRYPT_DECRYPT" and not rot_ok) or sod_conflicts:
            k_risk = "MEDIUM"
        else:
            k_risk = "LOW"

        kms_out.append(
            KmsCryptoKeyRecord(
                crypto_key_name=key_short,
                key_ring=kr_short,
                project_id=pid,
                location=loc,
                purpose=purpose,
                protection_level=prot,
                algorithm=alg,
                rotation_period_days=rot_days,
                rotation_compliant_90d=rot_ok,
                next_rotation_time=next_rot,
                sod_conflict_principals=sod_conflicts[:8],
                risk_level=k_risk,
            )
        )
    kms_out.sort(key=lambda k: (risk_rank.get(k.risk_level, 4), k.project_id, k.crypto_key_name))

    # -------------------------------------------------------------------------
    # 5. GOOGLE CLOUD API KEYS LEDGER (METADATA-ONLY)
    # -------------------------------------------------------------------------
    api_keys_out: List[ApiKeyMetadataRecord] = []
    for r in resources:
        if r["asset_type"] != "apikeys.googleapis.com/Key":
            continue
        vres = r.get("versioned_resource") or {}
        pid = _resolve_pid(str(r.get("project_id") or ""), str(r.get("project") or ""), proj_num_map)
        uid = str(vres.get("uid") or r["name"].rsplit("/", 1)[-1])
        dname = str(vres.get("displayName") or r.get("display_name") or uid)
        ctime = str(vres.get("createTime") or r.get("create_time") or "")
        age_d = _parse_iso_days_ago(ctime, now_utc)

        restr = vres.get("restrictions") or {}
        api_targets = [
            str(t.get("service") or "")
            for t in (restr.get("apiTargets") or [])
            if isinstance(t, dict) and t.get("service")
        ]
        if "serverKeyRestrictions" in restr:
            rmode = "SERVER_IP"
        elif "browserKeyRestrictions" in restr:
            bh = (restr.get("browserKeyRestrictions") or {}).get("allowedReferrers") or []
            rmode = "BROWSER_REFERRER" if bh else "BROWSER_OPEN_REFERRER"
        elif "androidKeyRestrictions" in restr:
            rmode = "ANDROID_APP"
        elif "iosKeyRestrictions" in restr:
            rmode = "IOS_APP"
        elif api_targets:
            rmode = "API_TARGETS_ONLY"
        else:
            rmode = "UNRESTRICTED"

        unrestricted = rmode in ("UNRESTRICTED", "BROWSER_OPEN_REFERRER") and len(api_targets) == 0
        if unrestricted:
            ak_risk = "CRITICAL" if age_d > 90 else "HIGH"
        elif age_d > 90 or rmode == "BROWSER_OPEN_REFERRER":
            ak_risk = "MEDIUM"
        else:
            ak_risk = "LOW"

        api_keys_out.append(
            ApiKeyMetadataRecord(
                display_name=dname,
                key_uid=uid[:18],
                project_id=pid,
                created_at=ctime[:19].replace("T", " "),
                age_days=age_d,
                restriction_mode=rmode,
                restricted_services=api_targets[:10],
                is_unrestricted=unrestricted,
                risk_level=ak_risk,
            )
        )
    api_keys_out.sort(key=lambda a: (risk_rank.get(a.risk_level, 4), -a.age_days, a.project_id))

    # -------------------------------------------------------------------------
    # 6. CUSTOM IAM ROLES LEDGER
    # -------------------------------------------------------------------------
    role_bind_counts: Dict[str, int] = {}
    for b in bindings:
        role_bind_counts[b["role"]] = role_bind_counts.get(b["role"], 0) + 1

    custom_roles_out: List[CustomIamRoleRecord] = []
    for r in resources:
        if r["asset_type"] != "iam.googleapis.com/Role":
            continue
        vres = r.get("versioned_resource") or {}
        if vres.get("deleted"):
            continue
        rname = str(vres.get("name") or r["name"].replace("//iam.googleapis.com/", ""))
        slevel = "ORGANIZATION" if rname.startswith("organizations/") else "PROJECT"
        pid = _resolve_pid(str(r.get("project_id") or ""), str(r.get("project") or ""), proj_num_map)
        perms = list(vres.get("includedPermissions") or [])
        esc_perms = sorted(set(perms) & DANGEROUS_CUSTOM_ROLE_PERMS)
        assigned_cnt = role_bind_counts.get(rname, 0)

        if esc_perms and assigned_cnt > 0:
            cr_risk = "CRITICAL"
        elif esc_perms:
            cr_risk = "HIGH"
        elif len(perms) > 250:
            cr_risk = "MEDIUM"
        else:
            cr_risk = "LOW"

        custom_roles_out.append(
            CustomIamRoleRecord(
                role_name=rname,
                title=str(vres.get("title") or r.get("display_name") or rname.rsplit("/", 1)[-1]),
                scope_level=slevel,
                project_or_org=pid if slevel == "PROJECT" else rname.split("/roles/", 1)[0],
                stage=str(vres.get("stage") or "GA"),
                included_permissions_count=len(perms),
                escalation_permissions=esc_perms,
                assigned_bindings_count=assigned_cnt,
                risk_level=cr_risk,
            )
        )
    custom_roles_out.sort(key=lambda c: (risk_rank.get(c.risk_level, 4), -c.assigned_bindings_count, c.role_name))

    # -------------------------------------------------------------------------
    # 7. WORKLOAD IDENTITY POOLS & PROVIDERS + ORG POLICIES LEDGER
    # -------------------------------------------------------------------------
    wif_pools_raw = [r for r in resources if r["asset_type"] == "iam.googleapis.com/WorkloadIdentityPool"]
    wif_provs_raw = [r for r in resources if r["asset_type"] == "iam.googleapis.com/WorkloadIdentityPoolProvider"]
    wif_out: List[WifPoolProviderRecord] = []
    pools_with_providers: Set[str] = set()

    for pr in wif_provs_raw:
        vres = pr.get("versioned_resource") or {}
        pid = _resolve_pid(str(pr.get("project_id") or ""), str(pr.get("project") or ""), proj_num_map)
        raw_n = pr["name"]
        pool_short = raw_n.split("/workloadIdentityPools/", 1)[-1].split("/providers/", 1)[0]
        prov_short = raw_n.rsplit("/providers/", 1)[-1]
        pools_with_providers.add(f"{pid}/{pool_short}")
        oidc = vres.get("oidc") or {}
        aws = vres.get("aws") or {}
        issuer = str(oidc.get("issuerUri") or ("aws:" + str(aws.get("accountId", "")) if aws else "") or "—")
        attr_cond = str(vres.get("attributeCondition") or "").strip()
        has_cond = bool(attr_cond)
        wif_out.append(
            WifPoolProviderRecord(
                pool_name=pool_short,
                provider_name=prov_short,
                project_id=pid,
                issuer_uri=issuer,
                state=str(vres.get("state") or pr.get("state") or "ACTIVE"),
                has_attribute_condition=has_cond,
                attribute_condition=attr_cond,
                risk_level="LOW" if has_cond else "CRITICAL",
            )
        )

    for pl in wif_pools_raw:
        pid = _resolve_pid(str(pl.get("project_id") or ""), str(pl.get("project") or ""), proj_num_map)
        pool_short = pl["name"].rsplit("/workloadIdentityPools/", 1)[-1]
        if f"{pid}/{pool_short}" not in pools_with_providers:
            wif_out.append(
                WifPoolProviderRecord(
                    pool_name=pool_short,
                    provider_name="(No Provider Configured)",
                    project_id=pid,
                    issuer_uri="—",
                    state=str(pl.get("state") or "ACTIVE"),
                    has_attribute_condition=True,
                    attribute_condition="—",
                    risk_level="LOW",
                )
            )

    org_pol_out: List[OrgPolicyPostureRecord] = []
    for cname, cval in sorted(org_policies_raw.items()):
        org_pol_out.append(
            OrgPolicyPostureRecord(
                constraint=cname,
                enforced=cval.get("enforced"),
                evaluated_on=str(cval.get("evaluated_on") or ""),
                status=str(cval.get("status") or ""),
            )
        )

    # -------------------------------------------------------------------------
    # 8. COMPUTE EXECUTIVE SUMMARY KPIS
    # -------------------------------------------------------------------------
    user_sa_keys = [k for k in sa_keys_out if k.key_type == "USER_MANAGED"]
    sys_sa_keys = [k for k in sa_keys_out if k.key_type != "USER_MANAGED"]

    kpis = AccountsKeysSecretsSummaryKPIs(
        human_and_group_accounts_total=len(accounts_out),
        internal_users_count=sum(1 for a in accounts_out if a.principal_type == "Internal User"),
        external_and_public_principals_count=sum(1 for a in accounts_out if a.is_external or a.principal_type == "Public Anonymous"),
        consumer_gmail_accounts_count=sum(1 for a in accounts_out if a.principal_type == "Consumer Gmail"),
        security_groups_count=sum(1 for a in accounts_out if "Group" in a.principal_type),
        standing_admin_accounts_count=sum(1 for a in accounts_out if a.is_standing_admin),
        principals_with_secret_or_kms_access=(
            sum(1 for a in accounts_out if a.can_access_secrets or a.can_use_or_admin_kms)
            + sum(1 for s in sa_records_out if s.can_access_secrets_or_kms)
        ),
        service_accounts_total=len(sa_records_out),
        google_service_agents_count=len(google_agents_seen),
        default_sas_with_roles_count=sum(
            1 for s in sa_records_out if s.sa_subtype != "Custom SA" and len(s.granted_roles) > 0
        ),
        disabled_sas_count=sum(1 for s in sa_records_out if s.disabled),
        user_managed_sa_keys_total=len(user_sa_keys),
        sa_keys_over_90d_count=sum(1 for k in user_sa_keys if k.age_days > 90),
        user_uploaded_sa_keys_count=sum(1 for k in user_sa_keys if k.key_origin == "USER_PROVIDED"),
        system_managed_sa_keys_total=len(sys_sa_keys),
        secrets_total_count=len(secrets_out),
        secret_versions_enabled_count=total_enabled_versions,
        secrets_unrotated_count=sum(1 for s in secrets_out if not s.rotation_configured),
        secrets_without_cmek_count=sum(1 for s in secrets_out if s.encryption_type != "CMEK"),
        kms_keyrings_count=keyrings_count,
        kms_cryptokeys_total=len(kms_out),
        kms_keys_missing_90d_rotation_count=sum(1 for k in kms_out if not k.rotation_compliant_90d),
        kms_hsm_keys_count=sum(1 for k in kms_out if k.protection_level == "HSM"),
        kms_sod_conflicts_count=len(all_sod_principals),
        api_keys_total_count=len(api_keys_out),
        unrestricted_api_keys_count=sum(1 for a in api_keys_out if a.is_unrestricted),
        api_keys_over_90d_count=sum(1 for a in api_keys_out if a.age_days > 90),
        custom_roles_total_count=len(custom_roles_out),
        custom_roles_with_escalation_perms_count=sum(1 for c in custom_roles_out if len(c.escalation_permissions) > 0),
        wif_pools_count=len(wif_pools_raw),
        wif_providers_count=len(wif_provs_raw),
        unconditioned_wif_providers_count=sum(
            1 for w in wif_out if w.provider_name != "(No Provider Configured)" and not w.has_attribute_condition
        ),
        org_policies_enforced_count=sum(1 for o in org_pol_out if o.enforced is True),
        org_policies_evaluated_count=len(org_pol_out),
    )

    inventory = AccountsKeysSecretsInventory(
        scope=target_scope,
        kpis=kpis,
        accounts=accounts_out,
        service_accounts=sa_records_out,
        sa_keys=sa_keys_out,
        secrets=secrets_out,
        kms_keys=kms_out,
        api_keys=api_keys_out,
        custom_roles=custom_roles_out,
        wif_providers=wif_out,
        org_policies=org_pol_out,
        audit_sample_is_sample=bool(audit_usage.get("is_sample", True)),
        audit_sample_size=int(audit_usage.get("sample_size") or 0),
        audit_sample_window_start=str(audit_usage.get("window_start") or ""),
        audit_sample_window_end=str(audit_usage.get("window_end") or ""),
        audit_projects_queried=int(audit_usage.get("projects_queried_count") or 0),
        audit_total_projects_in_scope=int(audit_usage.get("total_projects_in_scope") or 0),
    )
    _INVENTORY_CACHE[ck] = (now_mono, inventory)
    return inventory


def collect_accounts_keys_secrets_inventory(scope: str = "") -> str:
    """Collects live indicators and ledgers across Accounts, Service Accounts, SA Keys, Secret Manager Secrets, Cloud KMS Keys, API Keys, Custom Roles, and WIF Pools.

    Args:
        scope: Target GCP Organization or Multi-Project scope.

    Returns:
        JSON string containing executive KPIs and per-asset posture records (100% metadata-only; never reads secret payloads).
    """
    inv = build_accounts_keys_secrets_inventory(scope=scope)
    return inv.model_dump_json(indent=2)
