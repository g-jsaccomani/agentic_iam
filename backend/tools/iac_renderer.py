"""Deterministic Terraform/OpenTofu HCL validator and fixed-template renderer (`backend/tools/iac_renderer.py`).

Replaces free-form LLM HCL generation (T06) with a strict fail-closed pipeline:
1. Validates every field of a typed `IaCPlan` against live collected IAM bindings, assessed GCP scope,
   strict identifier/email/role regexes, `KEY_IAM_ORG_CONSTRAINTS`, and a deny-list banning any grant
   of `roles/owner`, `roles/editor`, or IAM administrative roles/permissions.
2. Deterministically renders `.tf` files strictly from fixed templates using JSON-encoded literals
   (`json.dumps`) with HCL interpolation escaping (`$${`, `%%{`).
3. Emits ONLY non-authoritative allowlisted resource types (`google_*_iam_member`,
   `google_org_policy_policy`, `google_privileged_access_manager_entitlement`,
   `google_*_iam_custom_role`) with ZERO `provisioner`, `data`, `module`, `*_iam_policy`, or
   `*_iam_binding` blocks.
4. Emits all binding removal steps into `MANUAL_STEPS.md` as `gcloud` commands with `shlex.quote`.
5. Prepends `# CONSULTATIVE DRAFT, UNVALIDATED. Review before applying.` to every `.tf` file.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from backend.models.findings import (
    CreateCustomRoleAction,
    CreatePamEntitlementAction,
    EnforceOrgPolicyAction,
    IaCPlan,
    ReplaceRoleBindingAction,
)
from backend.tools.cai_collector import (
    KEY_IAM_ORG_CONSTRAINTS,
    is_scope_contained,
    parse_assessment_scope,
)
from backend.validators import (
    FOLDER_ID_RE,
    ORG_ID_RE,
    PROJECT_ID_RE,
    ROLE_NAME_RE,
)

HCL_DRAFT_HEADER = "# CONSULTATIVE DRAFT, UNVALIDATED. Review before applying.\n"

ALLOWED_TF_RESOURCE_TYPES: FrozenSet[str] = frozenset(
    {
        "google_organization_iam_member",
        "google_folder_iam_member",
        "google_project_iam_member",
        "google_org_policy_policy",
        "google_privileged_access_manager_entitlement",
        "google_organization_iam_custom_role",
        "google_project_iam_custom_role",
    }
)

FORBIDDEN_GRANT_ROLES: FrozenSet[str] = frozenset(
    {
        "roles/owner",
        "roles/editor",
        "roles/iam.securityadmin",
        "roles/iam.roleadmin",
        "roles/iam.organizationroleadmin",
        "roles/iam.serviceaccountadmin",
        "roles/iam.serviceaccountkeyadmin",
        "roles/iam.serviceaccounttokencreator",
        "roles/iam.workloadidentitypooladmin",
        "roles/resourcemanager.organizationadmin",
        "roles/resourcemanager.folderadmin",
        "roles/resourcemanager.folderiamadmin",
        "roles/resourcemanager.projectiamadmin",
        "roles/orgpolicy.policyadmin",
        "roles/billing.admin",
    }
)

FORBIDDEN_CUSTOM_ROLE_PERMISSIONS: FrozenSet[str] = frozenset(
    {
        "iam.serviceAccountKeys.create",
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
        "iam.serviceAccounts.implicitDelegation",
        "iam.roles.create",
        "iam.roles.update",
        "iam.roles.delete",
        "orgpolicy.policies.create",
        "orgpolicy.policies.update",
        "orgpolicy.policies.delete",
    }
)

# Privileged Access Manager entitlement `max_request_duration` bounds, in seconds.
# Source: Google Cloud PAM documentation (supported range 30 minutes to 168 hours / 7 days), as reported
# by a web search on 2026-11-19; re-check the PAM docs if the platform limit changes.
MIN_PAM_REQUEST_DURATION_SECONDS = 1800
MAX_PAM_REQUEST_DURATION_SECONDS = 604800

_KEY_CONSTRAINTS_SET: FrozenSet[str] = frozenset(KEY_IAM_ORG_CONSTRAINTS)
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]{1,128}@[a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,63}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,63}$")
_ENTITLEMENT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,62}$")
_CUSTOM_ROLE_ID_RE = re.compile(r"^[a-zA-Z0-9_.]{3,64}$")
_DURATION_RE = re.compile(r"^[0-9]{2,6}s$")
_PERMISSION_RE = re.compile(r"^[a-z0-9]+\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$")
_LIST_VALUE_RE = re.compile(r"^[A-Za-z0-9._:/@-]{1,128}$")
_LOCATION_RE = re.compile(r"^[a-z0-9-]{2,32}$")
_TF_IDENT_CLEAN_RE = re.compile(r"[^a-z0-9_]+")
_BLOCK_HEADER_RE = re.compile(r"^\s*(resource|data|module|provisioner|terraform|provider|variable|locals|output)\b(.*)$")
_RESOURCE_DECL_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')


def _hcl_str(val: str) -> str:
    """Encodes a string literal safely for HCL using `json.dumps` and escapes HCL template directives."""
    cleaned = str(val or "").replace("\r", " ").replace("\x00", "")
    escaped_interp = cleaned.replace("${", "$${").replace("%{", "%%{")
    return json.dumps(escaped_interp, ensure_ascii=True)


def _hcl_comment(val: str) -> str:
    """Renders a single-line HCL comment stripped of control characters and newlines."""
    cleaned = re.sub(r"[\r\n\x00-\x1f\x7f]+", " ", str(val or "")).strip()
    return cleaned[:240]


def _tf_resource_name(prefix: str, seed: str, index: int) -> str:
    slug = _TF_IDENT_CLEAN_RE.sub("_", str(seed or "").lower()).strip("_")
    slug = slug[:40] or "item"
    return f"{prefix}_{index:02d}_{slug}"


def _validate_principal(principal: str) -> str:
    """Validates a GCP IAM member string (`user:`, `group:`, `serviceAccount:`, `domain:`)."""
    raw = str(principal or "").strip()
    if ":" not in raw:
        raise ValueError(f"Invalid IAM principal '{principal}': missing member type prefix.")
    prefix, ident = raw.split(":", 1)
    ident = ident.strip()
    if prefix in ("user", "group", "serviceAccount"):
        if not _EMAIL_RE.match(ident):
            raise ValueError(f"Invalid email in IAM principal '{principal}'.")
        return f"{prefix}:{ident}"
    if prefix == "domain":
        if not _DOMAIN_RE.match(ident):
            raise ValueError(f"Invalid domain in IAM principal '{principal}'.")
        return f"domain:{ident}"
    raise ValueError(f"Unsupported or unsafe IAM principal type in '{principal}'.")


def _normalize_single_resource_scope(raw_resource: str) -> Tuple[str, str, str]:
    """Normalizes a GCP resource URI or scope to `(kind, identifier, canonical)` where kind in org/folder/project."""
    val = str(raw_resource or "").strip()
    if val.startswith("//cloudresourcemanager.googleapis.com/"):
        val = val[len("//cloudresourcemanager.googleapis.com/") :]
    elif val.startswith("//"):
        parts = val.split("/", 3)
        val = parts[3] if len(parts) >= 4 else val

    if val.startswith("organizations/"):
        oid = val.split("/", 2)[1]
        if not ORG_ID_RE.match(oid):
            raise ValueError(f"Invalid organization resource '{raw_resource}'.")
        return "organization", oid, f"organizations/{oid}"
    if val.startswith("folders/"):
        fid = val.split("/", 2)[1]
        if not FOLDER_ID_RE.match(fid):
            raise ValueError(f"Invalid folder resource '{raw_resource}'.")
        return "folder", fid, f"folders/{fid}"
    if val.startswith("projects/"):
        pid = val.split("/", 2)[1]
        if not PROJECT_ID_RE.match(pid):
            raise ValueError(f"Invalid project resource '{raw_resource}'.")
        return "project", pid, f"projects/{pid}"
    raise ValueError(
        f"Unsupported or invalid GCP resource scope '{raw_resource}'. "
        f"Expected organizations/<digits>, folders/<digits>, or projects/<project-id>."
    )


def _assert_resource_within_target_scope(
    canonical_resource: str,
    target_scope: str,
    known_projects: Set[str],
) -> None:
    allowed = parse_assessment_scope(target_scope)
    if canonical_resource.startswith("projects/"):
        pid = canonical_resource.split("/", 1)[1]
        if allowed.project_ids and pid not in set(allowed.project_ids):
            raise ValueError(
                f"Resource '{canonical_resource}' is outside allowed project scope '{allowed.canonical_scope}'."
            )
        if allowed.mode == "ORG_ALL" and known_projects and pid not in known_projects:
            raise ValueError(
                f"Project '{canonical_resource}' was not discovered in assessed scope '{allowed.canonical_scope}'."
            )
        return
    cand = parse_assessment_scope(canonical_resource)
    if not is_scope_contained(cand, allowed):
        raise ValueError(
            f"Resource '{canonical_resource}' is outside assessed scope '{allowed.canonical_scope}'."
        )


def _assert_safe_grant_role(role: str) -> str:
    cleaned = str(role or "").strip()
    if not ROLE_NAME_RE.match(cleaned):
        raise ValueError(f"Invalid IAM role name '{role}'.")
    low = cleaned.lower()
    if low in FORBIDDEN_GRANT_ROLES or low.endswith("iamadmin") or low.endswith("securityadmin"):
        raise ValueError(
            f"Refused to grant privileged or IAM administrative role '{cleaned}'."
        )
    return cleaned


def validate_iac_plan(
    plan: IaCPlan,
    *,
    bindings: List[Dict[str, Any]],
    target_scope: str,
    strict: bool = True,
) -> Tuple[IaCPlan, List[str]]:
    """Validates every action in `IaCPlan` against live collected bindings, scope, constraints, and least-privilege rules.

    When `strict=True`, raises `ValueError` if ANY action is invalid or forbidden.
    When `strict=False`, returns a sanitized `IaCPlan` containing ONLY valid actions plus `rejected_reasons`.
    """
    errors: List[str] = []

    binding_pairs: Set[Tuple[str, str]] = set()
    known_projects: Set[str] = set()
    for b in bindings or []:
        p_norm = str(b.get("principal") or "").strip().lower()
        r_norm = str(b.get("role") or "").strip().lower()
        if p_norm and r_norm:
            binding_pairs.add((p_norm, r_norm))
        pid = str(b.get("project_id") or "").strip()
        if pid and PROJECT_ID_RE.match(pid):
            known_projects.add(pid)

    valid_org_policies: List[EnforceOrgPolicyAction] = []
    for idx, act in enumerate(plan.enforce_org_policies):
        try:
            constraint = str(act.constraint or "").strip()
            if constraint not in _KEY_CONSTRAINTS_SET:
                raise ValueError(
                    f"Org policy constraint '{constraint}' is not in KEY_IAM_ORG_CONSTRAINTS."
                )
            _, _, canon_scope = _normalize_single_resource_scope(act.target_scope)
            _assert_resource_within_target_scope(canon_scope, target_scope, known_projects)
            cleaned_vals: List[str] = []
            for v in act.allowed_values or []:
                vs = str(v or "").strip()
                if not _LIST_VALUE_RE.match(vs):
                    raise ValueError(f"Invalid Org Policy list value '{v}'.")
                cleaned_vals.append(vs)
            valid_org_policies.append(
                act.model_copy(
                    update={
                        "constraint": constraint,
                        "target_scope": canon_scope,
                        "allowed_values": cleaned_vals,
                    }
                )
            )
        except ValueError as exc:
            errors.append(f"enforce_org_policies[{idx}]: {exc}")

    valid_pam: List[CreatePamEntitlementAction] = []
    for idx, act in enumerate(plan.create_pam_entitlements):
        try:
            eid = str(act.entitlement_id or "").strip()
            if not _ENTITLEMENT_ID_RE.match(eid):
                raise ValueError(f"Invalid PAM entitlement_id '{eid}'.")
            _, _, canon_parent = _normalize_single_resource_scope(act.parent_scope)
            _assert_resource_within_target_scope(canon_parent, target_scope, known_projects)
            loc = str(act.location or "global").strip()
            if not _LOCATION_RE.match(loc):
                raise ValueError(f"Invalid PAM location '{loc}'.")
            if not act.eligible_principals:
                raise ValueError("PAM entitlement requires at least one eligible principal.")
            elig = [_validate_principal(p) for p in act.eligible_principals]
            approvers = [_validate_principal(p) for p in (act.approver_principals or [])]
            role = _assert_safe_grant_role(act.granted_role)
            dur = str(act.max_request_duration or "3600s").strip()
            if not _DURATION_RE.match(dur):
                raise ValueError(f"Invalid PAM max_request_duration '{dur}'.")
            dur_seconds = int(dur[:-1])
            if not (MIN_PAM_REQUEST_DURATION_SECONDS <= dur_seconds <= MAX_PAM_REQUEST_DURATION_SECONDS):
                raise ValueError(
                    f"PAM max_request_duration '{dur}' is outside the allowed range "
                    f"{MIN_PAM_REQUEST_DURATION_SECONDS}s-{MAX_PAM_REQUEST_DURATION_SECONDS}s."
                )
            valid_pam.append(
                act.model_copy(
                    update={
                        "entitlement_id": eid,
                        "parent_scope": canon_parent,
                        "location": loc,
                        "eligible_principals": elig,
                        "approver_principals": approvers,
                        "granted_role": role,
                        "max_request_duration": dur,
                    }
                )
            )
        except ValueError as exc:
            errors.append(f"create_pam_entitlements[{idx}]: {exc}")

    valid_replacements: List[ReplaceRoleBindingAction] = []
    for idx, act in enumerate(plan.replace_role_bindings):
        try:
            principal = _validate_principal(act.principal)
            current_role = str(act.current_role or "").strip()
            if not ROLE_NAME_RE.match(current_role):
                raise ValueError(f"Invalid current_role '{current_role}'.")
            if (principal.lower(), current_role.lower()) not in binding_pairs:
                raise ValueError(
                    f"Principal '{principal}' with role '{current_role}' does not exist in collected IAM bindings."
                )
            new_role = str(act.new_role or "").strip()
            if new_role:
                new_role = _assert_safe_grant_role(new_role)
            _, _, canon_res = _normalize_single_resource_scope(act.resource)
            _assert_resource_within_target_scope(canon_res, target_scope, known_projects)
            valid_replacements.append(
                act.model_copy(
                    update={
                        "principal": principal,
                        "current_role": current_role,
                        "new_role": new_role,
                        "resource": canon_res,
                    }
                )
            )
        except ValueError as exc:
            errors.append(f"replace_role_bindings[{idx}]: {exc}")

    valid_custom_roles: List[CreateCustomRoleAction] = []
    for idx, act in enumerate(plan.create_custom_roles):
        try:
            rid = str(act.role_id or "").strip()
            if not _CUSTOM_ROLE_ID_RE.match(rid):
                raise ValueError(f"Invalid custom role_id '{rid}'.")
            kind, _, canon_scope = _normalize_single_resource_scope(act.target_scope)
            if kind not in ("organization", "project"):
                raise ValueError("Custom roles can only be created at organization or project scope.")
            _assert_resource_within_target_scope(canon_scope, target_scope, known_projects)
            if not act.permissions:
                raise ValueError("Custom role must declare at least one permission.")
            cleaned_perms: List[str] = []
            for perm in act.permissions:
                ps = str(perm or "").strip()
                if not _PERMISSION_RE.match(ps):
                    raise ValueError(f"Invalid IAM permission syntax '{perm}'.")
                if ps in FORBIDDEN_CUSTOM_ROLE_PERMISSIONS or ps.lower().endswith(".setiampolicy"):
                    raise ValueError(
                        f"Refused to include privileged IAM administration permission '{ps}' in custom role."
                    )
                if ps not in cleaned_perms:
                    cleaned_perms.append(ps)
            stage = str(act.stage or "GA").strip().upper()
            if stage not in ("GA", "BETA", "ALPHA"):
                raise ValueError(f"Invalid custom role stage '{stage}'.")
            valid_custom_roles.append(
                act.model_copy(
                    update={
                        "role_id": rid,
                        "target_scope": canon_scope,
                        "permissions": cleaned_perms,
                        "stage": stage,
                    }
                )
            )
        except ValueError as exc:
            errors.append(f"create_custom_roles[{idx}]: {exc}")

    if strict and errors:
        raise ValueError("IaC plan validation failed: " + "; ".join(errors))

    cleaned_plan = IaCPlan(
        enforce_org_policies=valid_org_policies,
        create_pam_entitlements=valid_pam,
        replace_role_bindings=valid_replacements,
        create_custom_roles=valid_custom_roles,
    )
    return cleaned_plan, errors


def _gcloud_remove_binding_cmd(resource_canonical: str, principal: str, role: str) -> str:
    kind, ident, _ = _normalize_single_resource_scope(resource_canonical)
    if kind == "organization":
        base = ["gcloud", "organizations", "remove-iam-policy-binding", ident]
    elif kind == "folder":
        base = ["gcloud", "resource-manager", "folders", "remove-iam-policy-binding", ident]
    else:
        base = ["gcloud", "projects", "remove-iam-policy-binding", ident]
    base.extend(["--member", principal, "--role", role])
    return " ".join(shlex.quote(tok) for tok in base)


def render_iac_plan(
    plan: IaCPlan,
    *,
    target_scope: str,
    org_id: str = "",
    org_domain: str = "",
    primary_project_id: str = "",
) -> Dict[str, str]:
    """Deterministically renders a validated `IaCPlan` to HCL `.tf` files and `MANUAL_STEPS.md`."""
    parsed = parse_assessment_scope(target_scope)
    eff_org = org_id or parsed.organization_id or ""
    eff_proj = primary_project_id or (parsed.project_ids[0] if parsed.project_ids else "")

    main_tf = (
        HCL_DRAFT_HEADER
        + f"# Target Scope: {_hcl_comment(parsed.canonical_scope)}\n\n"
        + 'terraform {\n'
        + '  required_version = ">= 1.6.0"\n'
        + '  required_providers {\n'
        + '    google = {\n'
        + '      source  = "hashicorp/google"\n'
        + '      version = "~> 6.0"\n'
        + '    }\n'
        + '    google-beta = {\n'
        + '      source  = "hashicorp/google-beta"\n'
        + '      version = "~> 6.0"\n'
        + '    }\n'
        + '  }\n'
        + '}\n\n'
        + 'provider "google" {\n'
        + '  user_project_override = true\n'
        + '}\n\n'
        + 'provider "google-beta" {\n'
        + '  user_project_override = true\n'
        + '}\n'
    )

    variables_tf = (
        HCL_DRAFT_HEADER
        + "\n"
        + 'variable "organization_id" {\n'
        + '  description = "Assessed GCP Organization ID"\n'
        + '  type        = string\n'
        + f"  default     = {_hcl_str(eff_org)}\n"
        + '}\n\n'
        + 'variable "organization_domain" {\n'
        + '  description = "Assessed primary Cloud Identity domain"\n'
        + '  type        = string\n'
        + f"  default     = {_hcl_str(org_domain)}\n"
        + '}\n\n'
        + 'variable "primary_project_id" {\n'
        + '  description = "Primary GCP Project ID in assessed scope"\n'
        + '  type        = string\n'
        + f"  default     = {_hcl_str(eff_proj)}\n"
        + '}\n'
    )

    # iam.tf: custom roles + non-authoritative google_*_iam_member resources ONLY
    iam_blocks: List[str] = [HCL_DRAFT_HEADER]
    for idx, cr in enumerate(plan.create_custom_roles, start=1):
        kind, ident, _ = _normalize_single_resource_scope(cr.target_scope)
        res_type = (
            "google_organization_iam_custom_role"
            if kind == "organization"
            else "google_project_iam_custom_role"
        )
        parent_attr = "org_id" if kind == "organization" else "project"
        rname = _tf_resource_name("custom_role", cr.role_id, idx)
        perms_hcl = ",\n".join(f"    {_hcl_str(p)}" for p in cr.permissions)
        iam_blocks.append(
            f'resource "{res_type}" "{rname}" {{\n'
            f"  {parent_attr} = {_hcl_str(ident)}\n"
            f"  role_id     = {_hcl_str(cr.role_id)}\n"
            f"  title       = {_hcl_str(cr.title)}\n"
            f"  description = {_hcl_str(cr.description or 'Consultative least-privilege custom role')}\n"
            f"  stage       = {_hcl_str(cr.stage)}\n"
            f"  permissions = [\n{perms_hcl}\n  ]\n"
            f"}}\n"
        )

    for idx, rb in enumerate(plan.replace_role_bindings, start=1):
        if not rb.new_role:
            continue
        kind, ident, _ = _normalize_single_resource_scope(rb.resource)
        if kind == "organization":
            res_type, scope_attr = "google_organization_iam_member", "org_id"
        elif kind == "folder":
            res_type, scope_attr = "google_folder_iam_member", "folder"
        else:
            res_type, scope_attr = "google_project_iam_member", "project"
        rname = _tf_resource_name("iam_member", f"{rb.principal}_{rb.new_role}", idx)
        cond_block = ""
        if rb.condition_expression:
            cond_block = (
                "  condition {\n"
                f"    title      = {_hcl_str(rb.condition_title or 'Scoped least-privilege condition')}\n"
                f"    expression = {_hcl_str(rb.condition_expression)}\n"
                "  }\n"
            )
        iam_blocks.append(
            f"# Replaces {_hcl_comment(rb.current_role)} (manual removal command in MANUAL_STEPS.md)\n"
            f'resource "{res_type}" "{rname}" {{\n'
            f"  {scope_attr} = {_hcl_str(ident)}\n"
            f"  role    = {_hcl_str(rb.new_role)}\n"
            f"  member  = {_hcl_str(rb.principal)}\n"
            f"{cond_block}"
            f"}}\n"
        )

    if len(iam_blocks) == 1:
        iam_blocks.append("# No non-authoritative IAM member or custom role additions proposed in this draft.\n")
    iam_tf = "\n".join(iam_blocks)

    # pam_entitlements.tf
    pam_blocks: List[str] = [HCL_DRAFT_HEADER]
    for idx, pam in enumerate(plan.create_pam_entitlements, start=1):
        rname = _tf_resource_name("pam_entitlement", pam.entitlement_id, idx)
        elig_hcl = ",\n".join(f"      {_hcl_str(p)}" for p in pam.eligible_principals)
        approver_block = ""
        if pam.approver_principals:
            app_hcl = ",\n".join(f"          {_hcl_str(p)}" for p in pam.approver_principals)
            approver_block = (
                "  approval_workflow {\n"
                "    manual_approvals {\n"
                "      require_approver_justification = true\n"
                "      steps {\n"
                "        approvals_needed = 1\n"
                "        approvers {\n"
                "          principals = [\n"
                f"{app_hcl}\n"
                "          ]\n"
                "        }\n"
                "      }\n"
                "    }\n"
                "  }\n"
            )
        pam_blocks.append(
            f'resource "google_privileged_access_manager_entitlement" "{rname}" {{\n'
            f"  provider             = google-beta\n"
            f"  entitlement_id       = {_hcl_str(pam.entitlement_id)}\n"
            f"  location             = {_hcl_str(pam.location)}\n"
            f"  parent               = {_hcl_str(pam.parent_scope)}\n"
            f"  max_request_duration = {_hcl_str(pam.max_request_duration)}\n"
            f"  eligible_users {{\n"
            f"    principals = [\n{elig_hcl}\n    ]\n"
            f"  }}\n"
            f"  privileged_access {{\n"
            f"    gcp_iam_access {{\n"
            f"      resource_type = {_hcl_str('cloudresourcemanager.googleapis.com/' + ('Organization' if pam.parent_scope.startswith('organizations/') else 'Folder' if pam.parent_scope.startswith('folders/') else 'Project'))}\n"
            f"      resource      = {_hcl_str('//cloudresourcemanager.googleapis.com/' + pam.parent_scope)}\n"
            f"      role_bindings {{\n"
            f"        role = {_hcl_str(pam.granted_role)}\n"
            f"      }}\n"
            f"    }}\n"
            f"  }}\n"
            f"  requester_justification_config {{\n"
            f"    unstructured {{}}\n"
            f"  }}\n"
            f"{approver_block}"
            f"}}\n"
        )
    if len(pam_blocks) == 1:
        pam_blocks.append("# No Privileged Access Manager entitlements proposed in this draft.\n")
    pam_entitlements_tf = "\n".join(pam_blocks)

    # org_policies.tf
    org_blocks: List[str] = [HCL_DRAFT_HEADER]
    for idx, op in enumerate(plan.enforce_org_policies, start=1):
        short_name = op.constraint.split("/", 1)[-1]
        rname = _tf_resource_name("org_policy", short_name, idx)
        policy_name = f"{op.target_scope}/policies/{short_name}"
        if op.allowed_values:
            vals_hcl = ",\n".join(f"          {_hcl_str(v)}" for v in op.allowed_values)
            rule_body = (
                "      values {\n"
                f"        allowed_values = [\n{vals_hcl}\n        ]\n"
                "      }\n"
            )
        else:
            rule_body = f"      enforce = {'TRUE' if op.enforce else 'FALSE'}\n"
            # Terraform google_org_policy_policy expects string "TRUE"/"FALSE"
            rule_body = f"      enforce = {_hcl_str('TRUE' if op.enforce else 'FALSE')}\n"
        org_blocks.append(
            f'resource "google_org_policy_policy" "{rname}" {{\n'
            f"  name   = {_hcl_str(policy_name)}\n"
            f"  parent = {_hcl_str(op.target_scope)}\n"
            f"  spec {{\n"
            f"    rules {{\n"
            f"{rule_body}"
            f"    }}\n"
            f"  }}\n"
            f"}}\n"
        )
    if len(org_blocks) == 1:
        org_blocks.append("# No Organization Policy enforcements proposed in this draft.\n")
    org_policies_tf = "\n".join(org_blocks)

    # MANUAL_STEPS.md (all binding removals via shlex.quote)
    manual_lines: List[str] = [
        "# Manual Remediation Steps (CONSULTATIVE DRAFT, UNVALIDATED)",
        "",
        "> **Review before applying.** Terraform resources in this bundle are strictly non-authoritative",
        "> (`google_*_iam_member`) and will NOT remove pre-existing over-privileged bindings automatically.",
        "> After validating that replacement least-privilege bindings and/or PAM entitlements work without",
        "> disruption, execute the quoted `gcloud` commands below through your change-management pipeline.",
        "",
        f"- **Target Scope:** `{parsed.canonical_scope}`",
        "",
    ]
    if plan.replace_role_bindings:
        manual_lines.append("## 1. Remove Legacy Over-Privileged Bindings")
        manual_lines.append("")
        for idx, rb in enumerate(plan.replace_role_bindings, start=1):
            cmd = _gcloud_remove_binding_cmd(rb.resource, rb.principal, rb.current_role)
            manual_lines.append(
                f"### Step {idx}: Remove `{rb.current_role}` from `{rb.principal}` on `{rb.resource}`"
            )
            if rb.new_role:
                manual_lines.append(f"- **Replacement role provisioned in `iam.tf`:** `{rb.new_role}`")
            else:
                manual_lines.append("- **Action:** Revoke unused / excessive binding (no replacement role).")
            if rb.rationale:
                manual_lines.append(f"- **Rationale:** {_hcl_comment(rb.rationale)}")
            manual_lines.append("")
            manual_lines.append("```bash")
            manual_lines.append(cmd)
            manual_lines.append("```")
            manual_lines.append("")
    else:
        manual_lines.append("No manual IAM binding removals were scheduled in this draft.")
        manual_lines.append("")

    manual_steps_md = "\n".join(manual_lines)

    tf_files = {
        "main.tf": main_tf,
        "variables.tf": variables_tf,
        "iam.tf": iam_tf,
        "pam_entitlements.tf": pam_entitlements_tf,
        "org_policies.tf": org_policies_tf,
    }
    assert_hcl_matches_allowlist(tf_files)

    result = dict(tf_files)
    result["MANUAL_STEPS.md"] = manual_steps_md
    return result


def assert_hcl_matches_allowlist(tf_files: Dict[str, str]) -> None:
    """Static fail-closed verifier ensuring generated HCL uses ONLY allowlisted non-authoritative resource types."""
    for fname, content in tf_files.items():
        if not fname.endswith(".tf"):
            continue
        if not content.startswith(HCL_DRAFT_HEADER):
            raise ValueError(f"{fname}: missing mandatory consultative draft header.")

        depth = 0
        in_str = False
        escaped = False
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Check forbidden block declarations (ignore attribute assignments such as `resource = "..."`)
            m_blk = _BLOCK_HEADER_RE.match(line)
            if m_blk and not m_blk.group(2).lstrip().startswith("="):
                kw = m_blk.group(1)
                if kw in ("provisioner", "data", "module"):
                    raise ValueError(f"{fname}:{line_no}: forbidden HCL block '{kw}'.")
                if kw == "resource":
                    m_res = _RESOURCE_DECL_RE.match(line)
                    if not m_res:
                        raise ValueError(f"{fname}:{line_no}: malformed resource declaration.")
                    res_type = m_res.group(1)
                    if res_type.endswith("_iam_policy") or res_type.endswith("_iam_binding"):
                        raise ValueError(
                            f"{fname}:{line_no}: authoritative IAM resource '{res_type}' is forbidden."
                        )
                    if res_type not in ALLOWED_TF_RESOURCE_TYPES:
                        raise ValueError(
                            f"{fname}:{line_no}: resource type '{res_type}' is not in ALLOWED_TF_RESOURCE_TYPES."
                        )
            # Track brace balance ignoring quoted strings
            for ch in line:
                if escaped:
                    escaped = False
                    continue
                if ch == "\\" and in_str:
                    escaped = True
                    continue
                if ch == '"':
                    in_str = not in_str
                    continue
                if not in_str:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth < 0:
                            raise ValueError(f"{fname}:{line_no}: unbalanced closing brace in HCL.")
        if in_str or depth != 0:
            raise ValueError(f"{fname}: unbalanced quotes or braces in generated HCL (depth={depth}).")
