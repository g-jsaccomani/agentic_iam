"""Enterprise Customer Onboarding & User-Driven Impersonation Kit Engine (`onboarding_manager.py`).

Implements Zero-Trust Multi-User Onboarding:
1. `discover_organization_hierarchy`: Discovers accessible GCP Organizations and `ACTIVE` projects
   strictly using the authenticated user's (or impersonated Service Account's) token.
2. `generate_customer_onboarding_kit`: Generates tailored, zero-key onboarding scripts (`customer_iam_onboarding.sh`,
   `customer_iam_onboarding.tf`, `HOW_TO_ONBOARD.md`, `.zip`) that create `sa-iam-assessor@<CUSTOMER_SEED_PROJECT>`
   with 6 strictly read-only Org roles AND grant `roles/iam.serviceAccountTokenCreator` ONLY to the
   authenticated user (`user:<caller_email>`) — never to the Cloud Run host SA.
3. `verify_customer_onboarding_readiness`: Executes 6 live, concurrent read-only GCP pre-flight probes
   within the user's isolated session context.
"""

from __future__ import annotations

import datetime
import io
import json
import re
import shlex
import time
import unicodedata
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.session_vault import (
    configured_delegation_sa_email,
    get_active_inspection_session,
    platform_runtime_sa_email,
    run_pool_map_with_context,
)
from backend.tools.cai_collector import (
    active_organization_domain,
    active_organization_id,
    ephemeral_oauth_token_context,
    gcp_rest_request,
)

STRICT_READ_ONLY_ORG_ROLES: Tuple[Dict[str, str], ...] = (
    {
        "role": "roles/browser",
        "purpose": "Traverse Organization, Folder, and Project hierarchy metadata",
    },
    {
        "role": "roles/cloudasset.viewer",
        "purpose": "Query Cloud Asset Inventory IAM bindings, Service Accounts, Keys, and WIF pools",
    },
    {
        "role": "roles/iam.securityReviewer",
        "purpose": "Inspect IAM policies, Custom Role permission counts, and Service Account key metadata",
    },
    {
        "role": "roles/orgpolicy.policyViewer",
        "purpose": "Evaluate effective Organization Policy guardrails (Domain Restricted Sharing, SA Key disablement)",
    },
    {
        "role": "roles/recommender.viewer",
        "purpose": "Read IAM Recommender least-privilege insights and Policy Analyzer authentication telemetry",
    },
    {
        "role": "roles/logging.viewer",
        "purpose": "Correlate 30/90-day Cloud Audit Log permission usage for right-sizing and Policy Simulator validation",
    },
)

REQUIRED_CUSTOMER_APIS: Tuple[str, ...] = (
    "cloudasset.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "orgpolicy.googleapis.com",
    "recommender.googleapis.com",
    "policyanalyzer.googleapis.com",
    "policysimulator.googleapis.com",
    "logging.googleapis.com",
)


def _clean_org_id(raw_org_id: Optional[str]) -> str:
    from backend.validators import validate_org_id

    val = (raw_org_id or active_organization_id() or "").strip()
    return validate_org_id(val, allow_empty=True)


def discover_organization_hierarchy(
    organization_id: Optional[str] = None,
    ephemeral_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Discovers accessible GCP Organizations and all ACTIVE projects strictly for the connected user session."""
    from backend.validators import quote_gcp_resource_path

    target_org_id = _clean_org_id(organization_id)

    with ephemeral_oauth_token_context(ephemeral_token):
        accessible_orgs: List[Dict[str, str]] = []
        o_code, o_data = gcp_rest_request(
            "GET",
            "https://cloudresourcemanager.googleapis.com/v3/organizations:search",
            timeout=12.0,
        )
        if o_code == 200 and isinstance(o_data, dict):
            for org in o_data.get("organizations", []):
                o_name = org.get("name", "")
                oid = o_name.split("/")[-1] if "/" in o_name else o_name
                if oid:
                    accessible_orgs.append(
                        {
                            "organization_id": oid,
                            "organization_scope": f"organizations/{oid}",
                            "display_name": org.get("displayName") or oid,
                            "state": org.get("state", "ACTIVE"),
                        }
                    )

        if not target_org_id and accessible_orgs:
            target_org_id = accessible_orgs[0]["organization_id"]

        org_scope = f"organizations/{target_org_id}" if target_org_id else ""
        org_display_name = active_organization_domain()
        for o in accessible_orgs:
            if o["organization_id"] == target_org_id:
                org_display_name = o["display_name"]
                break

        # If target_org_id was explicitly provided, attempt direct GET to resolve displayName
        if org_scope and not org_display_name:
            d_code, d_data = gcp_rest_request(
                "GET",
                f"https://cloudresourcemanager.googleapis.com/v3/{quote_gcp_resource_path(org_scope)}",
                timeout=8.0,
            )
            if d_code == 200 and isinstance(d_data, dict):
                org_display_name = d_data.get("displayName") or org_scope

        active_projects: List[Dict[str, Any]] = []
        inactive_count = 0
        seen_pids: Set[str] = set()
        discovery_source = "CLOUD_ASSET_INVENTORY_ORG_SEARCH"
        project_discovery_t0 = time.perf_counter()
        project_discovery_http_status = 0
        project_discovery_error = ""

        if org_scope:
            p_code, p_data = gcp_rest_request(
                "GET",
                f"https://cloudasset.googleapis.com/v1/{quote_gcp_resource_path(org_scope)}:searchAllResources",
                params={"assetTypes": "cloudresourcemanager.googleapis.com/Project", "pageSize": 500},
                timeout=15.0,
            )
            project_discovery_http_status = int(p_code)
            if p_code == 200 and isinstance(p_data, dict):
                for item in p_data.get("results", []):
                    res_name = item.get("name", "")
                    pid = res_name.rsplit("/projects/", 1)[-1].split("/")[0] if "/projects/" in res_name else ""
                    if not pid or pid in seen_pids:
                        continue
                    st = (item.get("state") or "ACTIVE").upper()
                    if st != "ACTIVE":
                        inactive_count += 1
                        continue
                    seen_pids.add(pid)
                    pnum = (item.get("project") or "").split("/")[-1]
                    folders = item.get("folders") or []
                    active_projects.append(
                        {
                            "project_id": pid,
                            "project_number": pnum,
                            "project_scope": f"projects/{pid}",
                            "display_name": item.get("displayName") or pid,
                            "state": st,
                            "folders": folders,
                            "create_time": item.get("createTime"),
                        }
                    )
            else:
                discovery_source = f"CRM_V3_PROJECTS_SEARCH_FALLBACK (CAI HTTP {p_code})"
                if isinstance(p_data, dict):
                    project_discovery_error = str((p_data.get("error") or {}).get("message") or f"CAI HTTP {p_code}")[:220]

        discovery_warnings: List[str] = []
        if not active_projects:
            crm_code, crm_data = gcp_rest_request(
                "GET",
                "https://cloudresourcemanager.googleapis.com/v3/projects:search",
                params={"pageSize": 300},
                timeout=12.0,
            )
            project_discovery_http_status = int(crm_code)
            if crm_code != 200 and isinstance(crm_data, dict):
                project_discovery_error = str((crm_data.get("error") or {}).get("message") or f"CRM HTTP {crm_code}")[:220]
            folder_org_cache: Dict[str, Optional[str]] = {}

            def _resolve_folder_root_org(folder_res: str) -> Optional[str]:
                """Walks CRM v3 folder ancestry up to its root `organizations/<id>`, or None if unverifiable."""
                cur = folder_res.strip()
                visited: Set[str] = set()
                chain: List[str] = []
                for _ in range(10):
                    if cur in folder_org_cache:
                        root_org = folder_org_cache[cur]
                        for c_item in chain:
                            folder_org_cache[c_item] = root_org
                        return root_org
                    if cur in visited or not cur.startswith("folders/"):
                        break
                    visited.add(cur)
                    chain.append(cur)
                    f_id = cur.split("/", 1)[1]
                    if not f_id.isdigit():
                        break
                    f_code, f_data = gcp_rest_request(
                        "GET",
                        f"https://cloudresourcemanager.googleapis.com/v3/folders/{f_id}",
                        timeout=8.0,
                    )
                    if f_code != 200 or not isinstance(f_data, dict):
                        break
                    parent_val = str(f_data.get("parent") or "").strip()
                    if parent_val.startswith("organizations/"):
                        root_org = parent_val.split("/", 1)[1]
                        for c_item in chain:
                            folder_org_cache[c_item] = root_org
                        return root_org
                    if parent_val.startswith("folders/"):
                        cur = parent_val
                        continue
                    break
                for c_item in chain:
                    folder_org_cache[c_item] = None
                return None

            if crm_code == 200 and isinstance(crm_data, dict):
                unverified_count = 0
                for prj in crm_data.get("projects", []):
                    pid = prj.get("projectId", "")
                    st = (prj.get("state") or "").upper()
                    if not pid or pid in seen_pids:
                        continue
                    if st != "ACTIVE":
                        inactive_count += 1
                        continue
                    parent = str(prj.get("parent") or "").strip()

                    # Strictly enforce organization ancestry whenever an organization is targeted
                    if target_org_id:
                        resolved_org: Optional[str] = None
                        if parent.startswith("organizations/"):
                            resolved_org = parent.split("/", 1)[1]
                        elif parent.startswith("folders/"):
                            resolved_org = _resolve_folder_root_org(parent)

                        if resolved_org is None:
                            unverified_count += 1
                            continue
                        if resolved_org != target_org_id:
                            continue
                    else:
                        if parent.startswith("organizations/"):
                            target_org_id = parent.split("/", 1)[1]
                            org_scope = parent
                        elif parent.startswith("folders/"):
                            root_org = _resolve_folder_root_org(parent)
                            if root_org:
                                target_org_id = root_org
                                org_scope = f"organizations/{root_org}"
                            else:
                                unverified_count += 1
                                continue
                        else:
                            unverified_count += 1
                            continue

                    seen_pids.add(pid)
                    pnum = (prj.get("name") or "").split("/")[-1]
                    active_projects.append(
                        {
                            "project_id": pid,
                            "project_number": pnum,
                            "project_scope": f"projects/{pid}",
                            "display_name": prj.get("displayName") or pid,
                            "state": st,
                            "folders": [parent] if parent.startswith("folders/") else [],
                            "create_time": prj.get("createTime"),
                        }
                    )
                if unverified_count > 0:
                    discovery_warnings.append(
                        f"Excluded {unverified_count} project(s) from CRM fallback because their organization "
                        f"ancestry could not be verified (missing folder/organization read permissions)."
                    )

        active_projects.sort(key=lambda x: x["project_id"])
        known_ids = {o["organization_id"] for o in accessible_orgs}
        if target_org_id and target_org_id not in known_ids:
            accessible_orgs.insert(
                0,
                {
                    "organization_id": target_org_id,
                    "organization_scope": org_scope,
                    "display_name": org_display_name or org_scope,
                    "state": "CONNECTED",
                },
            )

        project_discovery_latency_ms = max(0, int((time.perf_counter() - project_discovery_t0) * 1000))
        return {
            "organization_id": target_org_id,
            "organization_scope": org_scope,
            "organization_display_name": org_display_name or org_scope,
            "discovery_source": discovery_source,
            "discovery_warnings": discovery_warnings,
            "project_discovery_http_status": project_discovery_http_status,
            "project_discovery_latency_ms": project_discovery_latency_ms,
            "project_discovery_error": project_discovery_error,
            "accessible_organizations": accessible_orgs,
            "active_projects_count": len(active_projects),
            "inactive_projects_excluded_count": inactive_count,
            "projects": active_projects,
        }


# Strict validation patterns shared by onboarding_manager and FastAPI request schemas
ONBOARDING_CUSTOMER_NAME_PATTERN = r"^[A-Za-z0-9À-ÖØ-öø-ÿ .,&()'-]+$"
ONBOARDING_ORG_ID_PATTERN = r"^(?:(?:organizations/)?[0-9]{1,30})?$"
ONBOARDING_DOMAIN_PATTERN = (
    r"^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59}[a-z0-9]))?$"
)
ONBOARDING_GCP_ID_PATTERN = r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$"
ONBOARDING_SEED_PROJECT_PATTERN = r"^(?:[a-z][a-z0-9-]{4,28}[a-z0-9])?$"
ONBOARDING_MODE_PATTERN = r"^(?:impersonated_sa|direct_user)$"
_EMAIL_CORE_PATTERN = (
    r"[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59}[A-Za-z0-9])"
)
ONBOARDING_IMPERSONATOR_PATTERN = rf"^(?:(?:(?:user|group):)?{_EMAIL_CORE_PATTERN})?$"

_RE_CUSTOMER_NAME = re.compile(rf"{ONBOARDING_CUSTOMER_NAME_PATTERN[:-1]}\Z")
_RE_ORG_ID_DIGITS = re.compile(r"^[0-9]{1,30}\Z")
_RE_DOMAIN_NONEMPTY = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59}[a-z0-9])\Z"
)
_RE_GCP_ID = re.compile(rf"{ONBOARDING_GCP_ID_PATTERN[:-1]}\Z")
_RE_EMAIL_CORE = re.compile(rf"^{_EMAIL_CORE_PATTERN}\Z")


def _reject_control_chars(value: str, field_name: str) -> None:
    for ch in value:
        if ord(ch) < 32 or ord(ch) == 127 or unicodedata.category(ch).startswith("C"):
            raise ValueError(f"{field_name} must not contain newlines or control characters.")


def _validate_customer_name(customer_name: str) -> str:
    if not isinstance(customer_name, str):
        raise ValueError("customer_name must be a string.")
    _reject_control_chars(customer_name, "customer_name")
    cleaned = customer_name.strip(" ")
    if not (1 <= len(cleaned) <= 80) or not _RE_CUSTOMER_NAME.match(cleaned):
        raise ValueError(
            "customer_name must be 1 to 80 characters containing only letters, digits, spaces, "
            "and . , & ( ) - '."
        )
    return cleaned


def _validate_organization_id(organization_id: str) -> str:
    if organization_id is None:
        return "<YOUR_NUMERIC_ORG_ID>"
    if not isinstance(organization_id, str):
        raise ValueError("organization_id must be a string.")
    _reject_control_chars(organization_id, "organization_id")
    cleaned = organization_id.strip(" ")
    if not cleaned:
        return "<YOUR_NUMERIC_ORG_ID>"
    if cleaned.startswith("organizations/"):
        cleaned = cleaned[len("organizations/"):]
    if not _RE_ORG_ID_DIGITS.match(cleaned):
        raise ValueError("GCP Organization ID must be numeric (e.g., '123456789012').")
    return cleaned


def _validate_organization_domain(organization_domain: str) -> str:
    if not isinstance(organization_domain, str):
        raise ValueError("organization_domain must be a string.")
    _reject_control_chars(organization_domain, "organization_domain")
    cleaned = organization_domain.strip(" ")
    if not cleaned:
        return ""
    if len(cleaned) > 253 or not _RE_DOMAIN_NONEMPTY.match(cleaned):
        raise ValueError(
            "organization_domain must be empty or a valid lowercase DNS domain (e.g., 'acme.com')."
        )
    return cleaned


def _validate_seed_project_id(seed_project_id: str) -> str:
    if not isinstance(seed_project_id, str):
        raise ValueError("seed_project_id must be a string.")
    _reject_control_chars(seed_project_id, "seed_project_id")
    cleaned = seed_project_id.strip(" ")
    if not cleaned:
        return "<SEED_PROJECT_ID>"
    if not _RE_GCP_ID.match(cleaned):
        raise ValueError(
            "seed_project_id must be empty or match ^[a-z][a-z0-9-]{4,28}[a-z0-9]$."
        )
    return cleaned


def _validate_sa_account_id(sa_account_id: str) -> str:
    if not isinstance(sa_account_id, str):
        raise ValueError("sa_account_id must be a string.")
    _reject_control_chars(sa_account_id, "sa_account_id")
    cleaned = sa_account_id.strip(" ")
    if not _RE_GCP_ID.match(cleaned):
        raise ValueError("sa_account_id must match ^[a-z][a-z0-9-]{4,28}[a-z0-9]$.")
    return cleaned


def _validate_onboarding_mode(onboarding_mode: str) -> str:
    if not isinstance(onboarding_mode, str) or onboarding_mode not in ("impersonated_sa", "direct_user"):
        raise ValueError("onboarding_mode must be 'impersonated_sa' or 'direct_user'.")
    return onboarding_mode


def _validate_impersonator_user_email(impersonator_user_email: str) -> Tuple[str, str]:
    if not isinstance(impersonator_user_email, str):
        raise ValueError("impersonator_user_email must be a string.")
    _reject_control_chars(impersonator_user_email, "impersonator_user_email")
    cleaned = impersonator_user_email.strip(" ")
    if not cleaned:
        return "user:<YOUR_GOOGLE_EMAIL>", "<YOUR_GOOGLE_EMAIL>"

    if ":" in cleaned:
        prefix, raw_email = cleaned.split(":", 1)
        if prefix not in ("user", "group"):
            raise ValueError(
                "impersonator_user_email may only use an optional 'user:' or 'group:' prefix; "
                "'domain:', 'serviceAccount:', 'allUsers', and other prefixes are rejected."
            )
    else:
        prefix = "user"
        raw_email = cleaned

    if (
        len(raw_email) > 254
        or not _RE_EMAIL_CORE.match(raw_email)
        or ".." in raw_email.split("@", 1)[0]
    ):
        raise ValueError(
            "impersonator_user_email must be empty or a valid email address with optional 'user:' or 'group:' prefix."
        )

    normalized_email = raw_email.lower()
    return f"{prefix}:{normalized_email}", normalized_email


def _hcl_string_literal(value: str) -> str:
    """Encodes a string as a safe Terraform HCL literal via json.dumps with template escaping."""
    escaped = value.replace("${", "$${").replace("%{", "%%{")
    return json.dumps(escaped)


def generate_customer_onboarding_kit(
    *,
    customer_name: str = "Enterprise Customer",
    organization_id: str,
    organization_domain: str = "",
    seed_project_id: str = "",
    onboarding_mode: str = "impersonated_sa",
    impersonator_user_email: str = "",
    sa_account_id: str = "sa-iam-assessor",
    enable_persistent_auto_renew: bool = False,
) -> Dict[str, Any]:
    """Generates the Zero-Footprint Read-Only Customer Onboarding Kit for User-Driven Impersonation or Direct Access.

    `enable_persistent_auto_renew` is an explicit opt-in (default off). Only when it is requested AND the
    deployment enabled `IAM_ENABLE_PERSISTENT_DELEGATION` does the kit additionally grant the platform runtime
    Service Account `roles/iam.serviceAccountTokenCreator` on the customer's assessor SA. By default the kit
    grants nothing to the platform.
    """
    cust_clean = _validate_customer_name(customer_name)
    clean_org = _validate_organization_id(organization_id)
    dom_clean = _validate_organization_domain(organization_domain)
    seed_clean = _validate_seed_project_id(seed_project_id)
    mode_clean = _validate_onboarding_mode(onboarding_mode)
    user_member, user_clean_raw = _validate_impersonator_user_email(impersonator_user_email)
    clean_sa_id = _validate_sa_account_id(sa_account_id)

    target_sa_email = f"{clean_sa_id}@{seed_clean}.iam.gserviceaccount.com"
    auto_renew = bool(enable_persistent_auto_renew) and mode_clean == "impersonated_sa"
    delegation_sa = ""
    delegation_sa_member = ""
    if auto_renew:
        delegation_sa = configured_delegation_sa_email().strip()
        if not delegation_sa:
            raise ValueError(
                "Persistent auto-renew is not enabled on this deployment "
                "(the operator must set IAM_ENABLE_PERSISTENT_DELEGATION=true to offer it)."
            )
        _reject_control_chars(delegation_sa, "delegation_sa")
        if not _RE_EMAIL_CORE.match(delegation_sa):
            raise ValueError("Configured persistent delegation Service Account email is invalid.")
        delegation_sa_member = f"serviceAccount:{delegation_sa}"

    # The offboarding snippet always removes the platform runtime SA binding when that SA is known, so a
    # customer that ran an older kit (which granted it by default) can revoke it with the same command.
    revoke_runtime_sa_member = ""
    runtime_sa = platform_runtime_sa_email().strip()
    if runtime_sa and _RE_EMAIL_CORE.match(runtime_sa) and not any(ord(ch) < 32 or ord(ch) == 127 for ch in runtime_sa):
        revoke_runtime_sa_member = f"serviceAccount:{runtime_sa}"

    is_impersonation = mode_clean == "impersonated_sa"
    org_reader_member = f"serviceAccount:{target_sa_email}" if is_impersonation else user_member

    roles_list = [r["role"] for r in STRICT_READ_ONLY_ORG_ROLES]
    apis_space = " \\\n    ".join(REQUIRED_CUSTOMER_APIS)

    # Single-assignment shlex-quoted header block (defense in depth: zero dynamic values elsewhere)
    bash_config_lines = [
        f"CUSTOMER_NAME={shlex.quote(cust_clean)}",
        f"DEFAULT_ORG_ID={shlex.quote(clean_org)}",
        f"DEFAULT_SEED_PROJECT_ID={shlex.quote(seed_clean)}",
        f"AUTHORIZED_USER_MEMBER={shlex.quote(user_member)}",
    ]
    if is_impersonation:
        bash_config_lines.extend(
            [
                f"SA_ACCOUNT_ID={shlex.quote(clean_sa_id)}",
                f"AUTHORIZED_USER_EMAIL={shlex.quote(user_clean_raw)}",
                f"ORG_DOMAIN_HINT={shlex.quote(dom_clean or 'your-domain.com')}",
            ]
        )
        if auto_renew:
            bash_config_lines.append(f"DELEGATION_SA_MEMBER={shlex.quote(delegation_sa_member)}")
    bash_config_block = "\n".join(bash_config_lines)

    if is_impersonation:
        bash_mode_header = (
            "Service Account Impersonation (Zero Static Keys + Optional Persistent Auto-Renew)"
            if auto_renew
            else "Service Account Impersonation (Zero Static Keys)"
        )
        bash_derived_vars = (
            'SA_EMAIL="${SA_ACCOUNT_ID}@${SEED_PROJECT_ID}.iam.gserviceaccount.com"\n'
            'SA_DESCRIPTION="Strictly read-only identity impersonated by authorized user ${AUTHORIZED_USER_EMAIL} (Zero JSON Keys)"\n'
            'ORG_READER_MEMBER="serviceAccount:${SA_EMAIL}"'
        )
        step_one_line = (
            'printf \'▶️ [1/4] Enabling Read-Only Telemetry & IAM Credentials APIs on %s...\\n\' "${SEED_PROJECT_ID}"'
        )
        sa_setup_bash = """
printf '▶️ [2/4] Creating Read-Only Assessor Service Account (%s)...\\n' "${SA_EMAIL}"
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${SEED_PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_ACCOUNT_ID}" \\
    --display-name="Agentic IAM Read-Only Posture Assessor" \\
    --description="${SA_DESCRIPTION}" \\
    --project="${SEED_PROJECT_ID}" --quiet
fi

printf '▶️ [3/4] Granting Impersonation (Service Account Token Creator) to %s...\\n' "${AUTHORIZED_USER_MEMBER}"
if ! gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \\
  --project="${SEED_PROJECT_ID}" \\
  --member="${AUTHORIZED_USER_MEMBER}" \\
  --role="roles/iam.serviceAccountTokenCreator" \\
  --condition=None --quiet >/dev/null; then
  printf '❌ Blocked by Domain Restricted Sharing (constraints/iam.allowedPolicyMemberDomains) on project %s.\\n' "${SEED_PROJECT_ID}"
  printf '   Either authorize an internal user (@%s) OR allow the consultant Cloud Identity ID ONLY on project %s.\\n' "${ORG_DOMAIN_HINT}" "${SEED_PROJECT_ID}"
  exit 1
fi
"""
        if auto_renew:
            # Explicit opt-in only. The customer can still skip it at run time with ENABLE_PERSISTENT_AUTO_RENEW=false.
            sa_setup_bash += """
# OPTIONAL Persistent Auto-Renew (explicitly requested for this kit).
# This grants the assessment PLATFORM's runtime Service Account the right to mint tokens for the read-only
# assessor SA. The platform keeps standing read-only access until you remove this binding, even after the
# consultant's own access is revoked. Skip it with: ENABLE_PERSISTENT_AUTO_RENEW=false ./customer_iam_onboarding.sh ...
if [[ "${ENABLE_PERSISTENT_AUTO_RENEW:-true}" == "true" ]]; then
  printf '🔄 Enabling OPTIONAL Persistent Auto-Renew Delegation for %s...\\n' "${DELEGATION_SA_MEMBER}"
  gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \\
    --project="${SEED_PROJECT_ID}" \\
    --member="${DELEGATION_SA_MEMBER}" \\
    --role="roles/iam.serviceAccountTokenCreator" \\
    --condition=None --quiet >/dev/null || echo "⚠️  Optional persistent delegation skipped (Domain Restricted Sharing); 1h OAuth renewal remains active."
fi
"""
        step_org_line = 'printf \'▶️ [4/4] Granting 6 Strictly Read-Only Roles on organizations/%s...\\n\' "${ORG_ID}"'
        completion_reader_line = 'printf \'   • Target Service Account to Impersonate: %s\\n\' "${SA_EMAIL}"'
    else:
        bash_mode_header = "Direct User Read-Only Access"
        bash_derived_vars = 'ORG_READER_MEMBER="${AUTHORIZED_USER_MEMBER}"'
        step_one_line = (
            'printf \'▶️ [1/2] Enabling Read-Only Telemetry & IAM Credentials APIs on %s...\\n\' "${SEED_PROJECT_ID}"'
        )
        sa_setup_bash = ""
        step_org_line = (
            'printf \'▶️ [2/2] Granting 6 Strictly Read-Only Roles on organizations/%s directly to %s...\\n\' '
            '"${ORG_ID}" "${AUTHORIZED_USER_MEMBER}"'
        )
        completion_reader_line = 'printf \'   • Authorized Direct Reader: %s\\n\' "${AUTHORIZED_USER_MEMBER}"'

    gcloud_bindings_str = "\n\n".join(
        f'gcloud organizations add-iam-policy-binding "${{ORG_ID}}" \\\n'
        f'  --member="${{ORG_READER_MEMBER}}" \\\n'
        f'  --role="{role}" \\\n'
        f'  --condition=None --quiet >/dev/null'
        for role in roles_list
    )

    q_org = shlex.quote(clean_org)
    q_seed = shlex.quote(seed_clean)
    q_org_reader = shlex.quote(org_reader_member)
    q_target_sa = shlex.quote(target_sa_email)
    q_user_member = shlex.quote(user_member)
    q_revoke_runtime_member = shlex.quote(revoke_runtime_sa_member)

    revoke_lines_list = [
        f"gcloud organizations remove-iam-policy-binding {q_org} --member={q_org_reader} --role={shlex.quote(r)} --condition=None --quiet >/dev/null || true"
        for r in roles_list
    ]
    if is_impersonation:
        revoke_lines_list.append(
            f"gcloud iam service-accounts remove-iam-policy-binding {q_target_sa} --member={q_user_member} --role='roles/iam.serviceAccountTokenCreator' --quiet >/dev/null || true"
        )
        if revoke_runtime_sa_member:
            revoke_lines_list.append(
                f"gcloud iam service-accounts remove-iam-policy-binding {q_target_sa} --member={q_revoke_runtime_member} --role='roles/iam.serviceAccountTokenCreator' --quiet >/dev/null || true"
            )
    revoke_lines = "\n".join(revoke_lines_list)

    bash_script = f"""#!/usr/bin/env bash
# ==============================================================================
# Agentic IAM Accelerator — Zero-Trust Customer Onboarding Script
# Connection Mode: {bash_mode_header}
# ==============================================================================
set -euo pipefail

{bash_config_block}

ORG_ID="${{DEFAULT_ORG_ID}}"
if [[ $# -ge 1 && -n "${{1}}" ]]; then
  ORG_ID="${{1}}"
fi
SEED_PROJECT_ID="${{DEFAULT_SEED_PROJECT_ID}}"
if [[ $# -ge 2 && -n "${{2}}" ]]; then
  SEED_PROJECT_ID="${{2}}"
fi
{bash_derived_vars}

echo "=============================================================================="
echo "🛡️  AGENTIC IAM ACCELERATOR • READ-ONLY ORGANIZATION ONBOARDING"
printf '   Customer        : %s\\n' "${{CUSTOMER_NAME}}"
printf '   Organization ID : organizations/%s\\n' "${{ORG_ID}}"
printf '   Seed Project    : %s\\n' "${{SEED_PROJECT_ID}}"
printf '   Authorized User : %s\\n' "${{AUTHORIZED_USER_MEMBER}}"
echo "=============================================================================="

{step_one_line}
gcloud services enable \\
    {apis_space} \\
    --project="${{SEED_PROJECT_ID}}" --quiet
{sa_setup_bash}
{step_org_line}
{gcloud_bindings_str}

echo "=============================================================================="
echo "✅ ONBOARDING COMPLETE!"
{completion_reader_line}
echo "   • Next Step: Return to Agentic IAM Accelerator -> Connect Target Organization"
echo "=============================================================================="
"""

    tf_roles_hcl = ",\n    ".join(_hcl_string_literal(r) for r in roles_list)
    tf_apis_hcl = ",\n    ".join(_hcl_string_literal(a) for a in REQUIRED_CUSTOMER_APIS)

    if is_impersonation:
        tf_sa_description = _hcl_string_literal(
            f"Strictly read-only identity impersonated by {user_clean_raw} (Zero JSON Keys)"
        )
        tf_sa_block = f"""
resource "google_service_account" "iam_assessor" {{
  account_id   = {_hcl_string_literal(clean_sa_id)}
  display_name = "Agentic IAM Read-Only Posture Assessor"
  description  = {tf_sa_description}
  project      = var.seed_project_id
}}

resource "google_service_account_iam_member" "allow_user_impersonation" {{
  service_account_id = google_service_account.iam_assessor.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = var.authorized_impersonator_member
  depends_on         = [google_project_service.readonly_telemetry_apis]
}}
"""
        if auto_renew:
            # Explicit opt-in only; the customer can still disable it with -var enable_persistent_auto_renew=false
            tf_sa_block += f"""
# OPTIONAL persistent auto-renew (explicitly requested for this kit). Grants the assessment PLATFORM's runtime
# Service Account the right to mint tokens for the read-only assessor SA. The platform keeps standing read-only
# access until this binding is removed, even after the consultant's own access is revoked.
variable "enable_persistent_auto_renew" {{
  type        = bool
  default     = true
  description = "Set to false to NOT grant the assessment platform runtime Service Account token-minting rights."
}}

resource "google_service_account_iam_member" "allow_persistent_auto_renew" {{
  count              = var.enable_persistent_auto_renew ? 1 : 0
  service_account_id = google_service_account.iam_assessor.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = {_hcl_string_literal(delegation_sa_member)}
  depends_on         = [google_project_service.readonly_telemetry_apis]
}}
"""
        tf_org_member_expr = '"serviceAccount:${google_service_account.iam_assessor.email}"'
        tf_output_block = """
output "target_service_account_to_impersonate" {
  value       = google_service_account.iam_assessor.email
  description = "Paste this Service Account email in Agentic IAM Accelerator -> Connect Target Organization"
}
"""
    else:
        tf_sa_block = ""
        tf_org_member_expr = "var.authorized_impersonator_member"
        tf_output_block = """
output "authorized_direct_reader" {
  value       = var.authorized_impersonator_member
  description = "Direct user principal granted read-only Organization visibility"
}
"""

    terraform_hcl = f"""# ==============================================================================
# Agentic IAM Accelerator — Declarative Zero-Trust Customer Onboarding (Terraform)
# ==============================================================================

terraform {{
  required_version = ">= 1.5.0"
  required_providers {{
    google = {{
      source  = "hashicorp/google"
      version = "~> 5.0"
    }}
  }}
}}

variable "organization_id" {{
  type        = string
  default     = {_hcl_string_literal(clean_org)}
  description = "Customer GCP Organization numeric ID"
}}

variable "seed_project_id" {{
  type        = string
  default     = {_hcl_string_literal(seed_clean)}
  description = "Seed project hosting the read-only Service Account and inspection APIs"
}}

variable "authorized_impersonator_member" {{
  type        = string
  default     = {_hcl_string_literal(user_member)}
  description = "Authenticated user authorized to impersonate the read-only Service Account"
}}

locals {{
  required_apis = [
    {tf_apis_hcl}
  ]

  readonly_org_roles = [
    {tf_roles_hcl}
  ]
}}

resource "google_project_service" "readonly_telemetry_apis" {{
  for_each           = toset(local.required_apis)
  project            = var.seed_project_id
  service            = each.value
  disable_on_destroy = false
}}
{tf_sa_block}
resource "google_organization_iam_member" "agentic_iam_readonly_bindings" {{
  for_each = toset(local.readonly_org_roles)
  org_id   = var.organization_id
  role     = each.value
  member   = {tf_org_member_expr}
}}

output "onboarded_organization_scope" {{
  value = "organizations/${{var.organization_id}}"
}}
{tf_output_block}"""

    if auto_renew:
        guide_isolation_line = (
            "- **Isolated Per-User Workspace:** Each consultant works in a private, encrypted workspace. "
            f"Because OPTIONAL persistent auto-renew was requested for this kit, the platform runtime Service Account "
            f"`{delegation_sa}` is granted `roles/iam.serviceAccountTokenCreator` on `{target_sa_email}` "
            "(see \"Optional Persistent Auto-Renew\" below). It receives no other role."
        )
        guide_impersonation_line = (
            f"- **User-Driven Impersonation (`generateAccessToken`):** `{user_member}` and, for auto-renew, "
            f"`serviceAccount:{delegation_sa}` receive `roles/iam.serviceAccountTokenCreator` on `{target_sa_email}` "
            "(no static JSON keys ever created)."
        )
        guide_auto_renew_section = f"""
## Optional Persistent Auto-Renew (enabled in this kit)
- **What is granted:** `roles/iam.serviceAccountTokenCreator` on `{target_sa_email}` to the assessment platform's runtime Service Account `{delegation_sa}`.
- **Why:** the platform can renew the 1-hour read-only token without the consultant signing in again.
- **What it means for you:** the platform holds standing read-only access to `organizations/{clean_org}` until you remove this binding. Revoking the consultant's own access does NOT remove it.
- **How to skip it:** run the script with `ENABLE_PERSISTENT_AUTO_RENEW=false`, or apply Terraform with `-var enable_persistent_auto_renew=false`.
- **How to revoke it later:** run the offboarding snippet at the end of this guide (it removes both bindings).
"""
    else:
        guide_isolation_line = (
            "- **100% Isolated Per-User Session:** The platform host Service Account receives **zero** permissions "
            "on your Organization."
        )
        guide_impersonation_line = (
            f"- **User-Driven Impersonation (`generateAccessToken`):** Only `{user_member}` receives "
            f"`roles/iam.serviceAccountTokenCreator` on `{target_sa_email}` (no static JSON keys ever created)."
        )
        guide_auto_renew_section = ""

    guide_md = f"""# Zero-Trust Customer Onboarding Guide — {cust_clean} (`organizations/{clean_org}`)

## Security & Multi-Tenant Isolation Guarantees
{guide_isolation_line}
{guide_impersonation_line}
- **Full Auditability:** Every API call in your Cloud Audit Logs records `{target_sa_email}` together with `serviceAccountDelegationInfo` identifying `{user_clean_raw}`.
{guide_auto_renew_section}
## Step 1 — Run Onboarding in Customer Environment (~30 seconds)
Execute `customer_iam_onboarding.sh` in Google Cloud Shell (or apply `customer_iam_onboarding.tf` via GitOps):
```bash
chmod +x customer_iam_onboarding.sh && ./customer_iam_onboarding.sh {q_org} {q_seed}
```

## Step 2 — Connect & Impersonate in Agentic IAM Console
1. Generate a short-lived user token (or authorize via OAuth):
```bash
gcloud auth print-access-token
```
2. Paste your token and target Service Account (`{target_sa_email}`) in **Connect Target Organization** -> click **Connect, Impersonate & Discover Projects**.

## Post-Engagement Offboarding (1-Command Revoke)
```bash
{revoke_lines}
```
"""

    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "customer_name": cust_clean,
        "organization_id": clean_org,
        "organization_scope": f"organizations/{clean_org}",
        "organization_domain": dom_clean,
        "seed_project_id": seed_clean,
        "onboarding_mode": mode_clean,
        "target_service_account": target_sa_email if is_impersonation else None,
        "authorized_user_member": user_member,
        "readonly_roles": list(STRICT_READ_ONLY_ORG_ROLES),
        "required_apis": list(REQUIRED_CUSTOMER_APIS),
        "bash_script": bash_script,
        "terraform_hcl": terraform_hcl,
        "guide_markdown": guide_md,
        "offboarding_revoke_snippet": revoke_lines,
    }


def build_onboarding_kit_zip(kit: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    safe_org = "".join(ch for ch in str(kit.get("organization_id", "org")) if ch.isalnum()) or "customer"
    prefix = f"agentic_iam_onboarding_{safe_org}"
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{prefix}/customer_iam_onboarding.sh", kit["bash_script"])
        zf.writestr(f"{prefix}/customer_iam_onboarding.tf", kit["terraform_hcl"])
        zf.writestr(f"{prefix}/HOW_TO_ONBOARD.md", kit["guide_markdown"])
    return buf.getvalue()


def _build_drs_aware_remediation(
    clean_org: str,
    required_role: str,
    error_message: str,
    sess: Any,
    org_display_name: str,
) -> str:
    """Builds an accurate remediation hint respecting Domain Restricted Sharing (`allowedPolicyMemberDomains`)."""
    err_lower = (error_message or "").lower()
    if "quota project" in err_lower:
        return (
            "Switch Connection Mode to 'Service Account Impersonation' (sa-iam-assessor@<SEED_PROJECT>.iam.gserviceaccount.com) "
            "or ensure recommender.googleapis.com + roles/serviceusage.serviceUsageConsumer are enabled on at least one project."
        )
    if sess is not None and not sess.impersonated_sa_email:
        user_dom = sess.owner_email.split("@")[-1].lower() if "@" in sess.owner_email else ""
        clean_org_dom = (org_display_name or "").strip().lower()
        if user_dom and clean_org_dom and "." in clean_org_dom and user_dom != clean_org_dom:
            return (
                f"External user domain (@{user_dom}) cannot be bound directly on organizations/{clean_org} when "
                f"constraints/iam.allowedPolicyMemberDomains (DRS) is enforced for '{clean_org_dom}'. "
                f"Use 'Service Account Impersonation' with sa-iam-assessor@<CUSTOMER_SEED_PROJECT>.iam.gserviceaccount.com instead."
            )
        return f'gcloud organizations add-iam-policy-binding {clean_org} --member="user:{sess.owner_email}" --role="{required_role}" --condition=None'

    sa_member = f"serviceAccount:{sess.impersonated_sa_email}" if (sess and sess.impersonated_sa_email) else "serviceAccount:sa-iam-assessor@<SEED_PROJECT>.iam.gserviceaccount.com"
    return f'gcloud organizations add-iam-policy-binding {clean_org} --member="{sa_member}" --role="{required_role}" --condition=None'


def verify_customer_onboarding_readiness(
    *,
    organization_id: str = "",
    customer_name: str = "",
    organization_domain: str = "",
    ephemeral_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Runs 6 live, strictly read-only GCP API pre-flight probes using the user's or impersonated token."""
    with ephemeral_oauth_token_context(ephemeral_token):
        hierarchy = discover_organization_hierarchy(organization_id, ephemeral_token=ephemeral_token)
        clean_org = hierarchy.get("organization_id") or _clean_org_id(organization_id)
        if not clean_org or not clean_org.isdigit():
            raise ValueError(
                "Could not auto-discover a numeric GCP Organization ID. Please enter the target GCP Organization ID explicitly."
            )

        org_scope = f"organizations/{clean_org}"
        org_disp = hierarchy.get("organization_display_name") or organization_domain.strip() or org_scope
        projects = hierarchy.get("projects") or []

        # Prioritize security/iam/governance seed projects first when sampling project-level telemetry APIs
        def _proj_priority(p: Dict[str, Any]) -> Tuple[int, str]:
            pid = p.get("project_id", "")
            low = pid.lower()
            if any(k in low for k in ("iam", "sec", "gov", "audit")):
                return (0, pid)
            return (1, pid)

        prioritized_projects = [p["project_id"] for p in sorted(projects, key=_proj_priority) if p.get("project_id")]
        sample_proj = prioritized_projects[0] if prioritized_projects else ""

        sess = get_active_inspection_session()
        candidate_projs: List[str] = []
        if sess and sess.quota_project_id:
            candidate_projs.append(sess.quota_project_id)
        for pid in prioritized_projects:
            if pid not in candidate_projs:
                candidate_projs.append(pid)

        def _run_single_probe(probe_name: str) -> Dict[str, Any]:
            if probe_name == "ORG_VISIBILITY":
                t0 = time.monotonic()
                code, data = gcp_rest_request(
                    "GET", f"https://cloudresourcemanager.googleapis.com/v3/{org_scope}", timeout=10.0
                )
                ms = int((time.monotonic() - t0) * 1000)
                ok = code == 200
                err_msg = (data.get("error") or {}).get("message", f"HTTP {code}")[:220] if not ok else ""
                return {
                    "check_id": "ORG_VISIBILITY",
                    "title": "1. Organization Hierarchy Metadata (CRM v3)",
                    "required_role": "roles/browser",
                    "status": "PASS" if ok else "WARN",
                    "http_status": code,
                    "latency_ms": ms,
                    "detail": (
                        f"Resolved {data.get('displayName', org_scope)} ({data.get('state', 'ACTIVE')})"
                        if ok
                        else err_msg
                    ),
                    "remediation": (
                        None
                        if ok
                        else _build_drs_aware_remediation(clean_org, "roles/browser", err_msg, sess, org_disp)
                    ),
                }

            if probe_name == "PROJECT_DISCOVERY":
                ok = len(projects) > 0
                real_status = int(hierarchy.get("project_discovery_http_status") or 0)
                real_latency = int(hierarchy.get("project_discovery_latency_ms") or 0)
                disc_err = str(hierarchy.get("project_discovery_error") or "").strip()
                err_msg = (
                    disc_err
                    if (not ok and disc_err)
                    else (f"0 active projects visible under {org_scope}" if not ok else "")
                )
                return {
                    "check_id": "PROJECT_DISCOVERY",
                    "title": "2. Organization Active Project Discovery (CAI / CRM)",
                    "required_role": "roles/cloudasset.viewer",
                    "status": "PASS" if ok else "FAIL",
                    "http_status": real_status,
                    "latency_ms": real_latency,
                    "detail": (
                        f"Discovered {len(projects)} ACTIVE GCP project(s) across {org_scope}"
                        if ok
                        else err_msg
                    ),
                    "remediation": (
                        None
                        if ok
                        else _build_drs_aware_remediation(clean_org, "roles/cloudasset.viewer", err_msg, sess, org_disp)
                    ),
                }

            if probe_name == "CAI_IAM_POLICIES":
                t0 = time.monotonic()
                probe_target = org_scope if org_scope else f"projects/{sample_proj}"
                code, data = gcp_rest_request(
                    "GET",
                    f"https://cloudasset.googleapis.com/v1/{probe_target}:searchAllIamPolicies",
                    params={"pageSize": 25},
                    timeout=12.0,
                )
                ms = int((time.monotonic() - t0) * 1000)
                ok = code == 200
                cnt = len(data.get("results", [])) if ok else 0
                err_msg = (data.get("error") or {}).get("message", f"HTTP {code}")[:220] if not ok else ""
                return {
                    "check_id": "CAI_IAM_POLICIES",
                    "title": "3. Organization IAM Policy Graph Search (CAI)",
                    "required_role": "roles/iam.securityReviewer",
                    "status": "PASS" if ok else "FAIL",
                    "http_status": code,
                    "latency_ms": ms,
                    "detail": (
                        f"Live IAM policy stream verified ({cnt} sample policy docs returned)"
                        if ok
                        else err_msg
                    ),
                    "remediation": (
                        None
                        if ok
                        else _build_drs_aware_remediation(clean_org, "roles/iam.securityReviewer", err_msg, sess, org_disp)
                    ),
                }

            if probe_name == "ORG_POLICIES":
                t0 = time.monotonic()
                code, data = gcp_rest_request(
                    "POST",
                    f"https://cloudresourcemanager.googleapis.com/v1/{org_scope}:getEffectiveOrgPolicy",
                    json_body={"constraint": "constraints/iam.disableServiceAccountKeyCreation"},
                    timeout=10.0,
                )
                ms = int((time.monotonic() - t0) * 1000)
                ok = code == 200
                enforced = bool((data.get("booleanPolicy") or {}).get("enforced", False)) if ok else None
                err_msg = (data.get("error") or {}).get("message", f"HTTP {code}")[:220] if not ok else ""
                return {
                    "check_id": "ORG_POLICIES",
                    "title": "4. Effective Organization Policy Guardrails",
                    "required_role": "roles/orgpolicy.policyViewer",
                    "status": "PASS" if ok else "WARN",
                    "http_status": code,
                    "latency_ms": ms,
                    "detail": (
                        f"Constraint inspection active (disableServiceAccountKeyCreation enforced={enforced})"
                        if ok
                        else err_msg
                    ),
                    "remediation": (
                        None
                        if ok
                        else _build_drs_aware_remediation(clean_org, "roles/orgpolicy.policyViewer", err_msg, sess, org_disp)
                    ),
                }

            if probe_name == "IAM_RECOMMENDER":
                if not candidate_projs:
                    return {
                        "check_id": "IAM_RECOMMENDER",
                        "title": "5. IAM Recommender & Least-Privilege Insights",
                        "required_role": "roles/recommender.viewer",
                        "status": "WARN",
                        "http_status": 0,
                        "latency_ms": 0,
                        "detail": "Skipped (no active project discovered to sample)",
                        "remediation": None,
                    }
                t0 = time.monotonic()
                last_code = 403
                last_err = ""
                verified_proj = ""
                for cand in candidate_projs[:6]:
                    url = (
                        f"https://recommender.googleapis.com/v1/projects/{cand}/locations/global/"
                        "recommenders/google.iam.policy.Recommender/recommendations"
                    )
                    code, data = gcp_rest_request(
                        "GET", url, params={"pageSize": 10}, timeout=10.0, quota_project=cand
                    )
                    last_code = code
                    if code == 200:
                        verified_proj = cand
                        if sess is not None and not sess.quota_project_id:
                            sess.quota_project_id = cand
                        break
                    last_err = (data.get("error") or {}).get("message", f"HTTP {code}")[:220]
                ms = int((time.monotonic() - t0) * 1000)
                ok = bool(verified_proj)
                return {
                    "check_id": "IAM_RECOMMENDER",
                    "title": "5. IAM Recommender & Least-Privilege Insights",
                    "required_role": "roles/recommender.viewer",
                    "status": "PASS" if ok else "WARN",
                    "http_status": 200 if ok else last_code,
                    "latency_ms": ms,
                    "detail": (
                        f"Recommender API verified on projects/{verified_proj}"
                        if ok
                        else last_err
                    ),
                    "remediation": (
                        None
                        if ok
                        else _build_drs_aware_remediation(clean_org, "roles/recommender.viewer", last_err, sess, org_disp)
                    ),
                }

            # CLOUD_AUDIT_LOGS
            if not candidate_projs:
                return {
                    "check_id": "CLOUD_AUDIT_LOGS",
                    "title": "6. Cloud Audit Logs Authorization Stream",
                    "required_role": "roles/logging.viewer",
                    "status": "WARN",
                    "http_status": 0,
                    "latency_ms": 0,
                    "detail": "Skipped (no active project discovered to sample)",
                    "remediation": None,
                }
            t0 = time.monotonic()
            last_code = 403
            last_err = ""
            verified_log_proj = ""
            cnt = 0
            for cand in candidate_projs[:3]:
                code, data = gcp_rest_request(
                    "POST",
                    "https://logging.googleapis.com/v2/entries:list",
                    json_body={
                        "resourceNames": [f"projects/{cand}"],
                        "filter": 'logName:"cloudaudit.googleapis.com"',
                        "orderBy": "timestamp desc",
                        "pageSize": 5,
                    },
                    timeout=12.0,
                    quota_project=cand,
                )
                last_code = code
                if code == 200:
                    verified_log_proj = cand
                    cnt = len(data.get("entries", []))
                    break
                last_err = (data.get("error") or {}).get("message", f"HTTP {code}")[:220]
            ms = int((time.monotonic() - t0) * 1000)
            ok = bool(verified_log_proj)
            return {
                "check_id": "CLOUD_AUDIT_LOGS",
                "title": "6. Cloud Audit Logs Authorization Stream",
                "required_role": "roles/logging.viewer",
                "status": "PASS" if ok else "WARN",
                "http_status": 200 if ok else last_code,
                "latency_ms": ms,
                "detail": (
                    f"Cloud Audit Log stream reachable on projects/{verified_log_proj} ({cnt} recent events sampled)"
                    if ok
                    else last_err
                ),
                "remediation": (
                    None
                    if ok
                    else _build_drs_aware_remediation(clean_org, "roles/logging.viewer", last_err, sess, org_disp)
                ),
            }

        probe_ids = [
            "ORG_VISIBILITY",
            "PROJECT_DISCOVERY",
            "CAI_IAM_POLICIES",
            "ORG_POLICIES",
            "IAM_RECOMMENDER",
            "CLOUD_AUDIT_LOGS",
        ]
        checks = run_pool_map_with_context(_run_single_probe, probe_ids, max_workers=6)

    pass_count = sum(1 for c in checks if c["status"] == "PASS")
    fail_critical = any(
        c["status"] == "FAIL" and c["check_id"] in ("PROJECT_DISCOVERY", "CAI_IAM_POLICIES")
        for c in checks
    )
    overall_ready = not fail_critical and len(projects) > 0

    resolved_domain = (
        organization_domain.strip()
        or hierarchy.get("organization_display_name")
        or f"organizations/{clean_org}"
    )

    return {
        "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "organization_id": clean_org,
        "organization_scope": org_scope,
        "organization_display_name": resolved_domain,
        "customer_name": customer_name.strip() or resolved_domain,
        "resolved_quota_project_id": sess.quota_project_id if sess else "",
        "ready_for_scan": overall_ready,
        "checks_passed": pass_count,
        "checks_total": len(checks),
        "checks": checks,
        "active_projects_count": len(projects),
        "accessible_organizations": hierarchy.get("accessible_organizations", []),
        "projects": projects,
    }
