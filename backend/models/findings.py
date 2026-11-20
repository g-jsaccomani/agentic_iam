"""BigQuery & Pydantic schemas for the Agentic IAM Accelerator.

Aligned with CSPR `GcpIamAuditFinding` (exposed both as `GcpIamPostureFinding` and
aliased as `GcpIamAuditFinding` for backward compatibility with CSPR BigQuery pipelines).
Framed strictly under the Google Shared Responsibility Model as an IAM Posture Assessment,
Modernization, and Least-Privilege Acceleration Engine powered by Google ADK + Vertex AI (`location=global`).
"""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class RiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class IdentityTriadCategory(str, Enum):
    INTERNAL = "INTERNAL_IDENTITIES"
    EXTERNAL = "EXTERNAL_IDENTITIES"
    WORKLOAD_SA = "SERVICE_ACCOUNTS_WORKLOAD"


class AdkToolCallRecord(BaseModel):
    """Real Google ADK tool execution trace record."""

    agent: str
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0
    status: str = "ok"


class AdkTokenUsage(BaseModel):
    """Real Vertex AI token consumption reported by Google ADK `usage_metadata`."""

    input_tokens: int = 0
    output_tokens: int = 0
    thought_tokens: int = 0
    total_tokens: int = 0


class AdkExecutionTelemetry(BaseModel):
    """End-to-end Google ADK + Vertex AI execution telemetry (`model_version`, `tokens`, `tool_calls`)."""

    requested_model: str
    model_version: str
    model_versions: List[str] = Field(default_factory=list)
    location: str = "global"
    agents_invoked: List[str] = Field(default_factory=list)
    llm_steps: int = 0
    tokens: AdkTokenUsage = Field(default_factory=AdkTokenUsage)
    tool_calls: List[AdkToolCallRecord] = Field(default_factory=list)
    latency_ms: float = 0.0
    ungrounded_findings_dropped: int = 0
    ungrounded_items_dropped_by_agent: Dict[str, int] = Field(default_factory=dict)


class GcpIamPostureFinding(BaseModel):
    """Canonical IAM Posture & Modernization Finding (aligned with CSPR GcpIamAuditFinding BigQuery schema)."""

    finding_id: str = Field(..., description="Deterministic finding identifier (e.g., IAM-TRIAD-001)")
    cspr_view_id: str = Field(default="iam-posture", description="CSPR AutoFinding view ID mapping (e.g., iam-2eus, iam-xl3c, iam-p1ri, iam-d067)")
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of finding evaluation",
    )
    scope: str = Field(..., description="Assessed GCP resource scope (e.g., organizations/123456789012)")
    project_id: str = Field(..., description="GCP Project ID or Organization scope where binding resides")
    triad_category: IdentityTriadCategory = Field(..., description="Identity Triad classification")
    severity: RiskSeverity = Field(..., description="Posture risk severity tier")
    title: str = Field(..., description="Concise executive title of the IAM posture finding")
    principal: str = Field(..., description="IAM member principal (user:, group:, serviceAccount:, domain:, allUsers)")
    role: str = Field(..., description="Granted IAM role (e.g., roles/owner, roles/iam.serviceAccountTokenCreator)")
    resource: str = Field(..., description="Full Cloud Asset Inventory resource URI")
    condition_expression: Optional[str] = Field(default=None, description="IAM Condition CEL expression if present")
    risk_vector: str = Field(..., description="Technical risk vector (e.g., Direct User Assignment, Impersonation Chain, Static Key >90d)")
    evidence_summary: str = Field(..., description="Verbatim telemetry evidence from CAI / Recommender / Directory")
    recommended_modernization: str = Field(..., description="Target least-privilege role, PAM JIT entitlement, or WIF migration")
    remediation_wave: str = Field(default="Wave 1 (Days 0-30)", description="Implementation wave in Posture Acceleration Roadmap")
    auto_remediable_iac: bool = Field(default=True, description="Whether IaC Specialist generated Terraform remediation")
    framework_citations: List[str] = Field(
        default_factory=list,
        description="Security framework control citations (e.g., Google Cloud Blueprint GCB-IAM-02, NIST SP 800-53 AC-6(5), CIS GCP v3.0 1.5)",
    )

    @classmethod
    def bigquery_schema(cls) -> List[Dict[str, str]]:
        """Returns the BigQuery table schema definition for `iam_posture_lake.iam_posture_findings`."""
        return [
            {"name": "finding_id", "type": "STRING", "mode": "REQUIRED"},
            {"name": "cspr_view_id", "type": "STRING", "mode": "NULLABLE"},
            {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
            {"name": "scope", "type": "STRING", "mode": "REQUIRED"},
            {"name": "project_id", "type": "STRING", "mode": "REQUIRED"},
            {"name": "triad_category", "type": "STRING", "mode": "REQUIRED"},
            {"name": "severity", "type": "STRING", "mode": "REQUIRED"},
            {"name": "title", "type": "STRING", "mode": "REQUIRED"},
            {"name": "principal", "type": "STRING", "mode": "REQUIRED"},
            {"name": "role", "type": "STRING", "mode": "REQUIRED"},
            {"name": "resource", "type": "STRING", "mode": "REQUIRED"},
            {"name": "condition_expression", "type": "STRING", "mode": "NULLABLE"},
            {"name": "risk_vector", "type": "STRING", "mode": "REQUIRED"},
            {"name": "evidence_summary", "type": "STRING", "mode": "REQUIRED"},
            {"name": "recommended_modernization", "type": "STRING", "mode": "REQUIRED"},
            {"name": "remediation_wave", "type": "STRING", "mode": "NULLABLE"},
            {"name": "auto_remediable_iac", "type": "BOOLEAN", "mode": "NULLABLE"},
            {"name": "framework_citations", "type": "STRING", "mode": "REPEATED"},
        ]


# Explicit CSPR schema alias as requested in architecture specification
GcpIamAuditFinding = GcpIamPostureFinding


class IdentityTriadMetrics(BaseModel):
    """Quantitative metrics for one pillar of the Identity Triad."""

    category: IdentityTriadCategory
    display_name: str
    posture_score: float = Field(..., ge=0.0, le=100.0, description="0-100% posture maturity score for this pillar")
    total_principals_evaluated: int
    compliant_principals: int
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    key_anti_patterns_detected: List[str] = Field(default_factory=list)
    modernization_priorities: List[str] = Field(default_factory=list)
    telemetry_metrics: Dict[str, Any] = Field(default_factory=dict)


class IdentityTriadMatrix(BaseModel):
    """Complete 3-pillar Identity Triad evaluation (Internal vs. External vs. Workload Service Accounts)."""

    scope: str
    internal_identities: IdentityTriadMetrics
    external_identities: IdentityTriadMetrics
    workload_service_accounts: IdentityTriadMetrics
    findings: List[GcpIamPostureFinding] = Field(default_factory=list)


class AttackPathNode(BaseModel):
    """Node in the NetworkX IAM Privilege Escalation & Impersonation Graph."""

    node_id: str
    label: str
    node_type: str = Field(..., description="user | external_user | group | service_account | workload | resource | role")
    risk_level: RiskSeverity = RiskSeverity.MEDIUM
    project_id: str = ""
    attributes: Dict[str, Any] = Field(default_factory=dict)


class AttackPathEdge(BaseModel):
    """Directed edge in the NetworkX IAM Privilege Escalation & Impersonation Graph."""

    source: str
    target: str
    relationship: str = Field(..., description="e.g., roles/iam.serviceAccountTokenCreator, iam.serviceAccounts.actAs, roles/owner")
    permission_vector: str
    is_escalation_edge: bool = True
    weight: float = 1.0


class AttackPathFinding(BaseModel):
    """Multi-hop privilege escalation path or toxic combination synthesized by Attack Path Agent over NetworkX."""

    path_id: str
    title: str
    severity: RiskSeverity
    entry_principal: str
    target_crown_jewel: str
    hop_sequence: List[str]
    permissions_exploited: List[str]
    toxic_combination_type: str = Field(
        ...,
        description="SA_IMPERSONATION_CHAIN | GCE_METADATA_ESCALATION | CLOUDBUILD_SA_ABUSE | ORG_POLICY_BYPASS | PRIMITIVE_STANDING_PRIVILEGE",
    )
    blast_radius_score: float = Field(..., ge=0.0, le=10.0)
    mitigation_control: str


class AttackPathGraphSummary(BaseModel):
    """NetworkX Graph analysis output for IAM impersonation chains and toxic combinations."""

    scope: str
    total_nodes: int
    total_edges: int
    escalation_paths_count: int
    toxic_combinations_count: int
    max_chain_depth: int
    high_centrality_principals: List[Dict[str, Any]] = Field(default_factory=list)
    nodes: List[AttackPathNode] = Field(default_factory=list)
    edges: List[AttackPathEdge] = Field(default_factory=list)
    critical_paths: List[AttackPathFinding] = Field(default_factory=list)


class LeastPrivilegeRecommendation(BaseModel):
    """90-day IAM Recommender & ADK Persona Synthesis output converting excess roles to Custom Roles or PAM JIT."""

    recommendation_id: str
    principal: str
    resource: str
    current_role: str
    recommended_action: str = Field(..., description="REPLACE_WITH_CUSTOM_ROLE | MIGRATE_TO_PAM_JIT | REVOKE_UNUSED_BINDING | DOWNGRADE_PREDEFINED_ROLE")
    proposed_role_or_entitlement: str
    observation_window_days: int = 90
    permissions_granted_count: int
    permissions_exercised_90d: int
    excess_permissions_removed: int
    permission_reduction_pct: float
    persona_classification: str = Field(..., description="Platform Admin | Data Analyst | Cloud Run Deployer | Break-Glass Emergency | Workload Service Account | External Collaborator")
    pam_jit_eligible: bool = False
    pam_max_duration: str = "3600s"
    pam_approver_group: Optional[str] = None


ALLOWED_IMPACT_VERDICTS: tuple[str, ...] = (
    "NO_CONFLICT_IN_SAMPLE",
    "REVIEW_REQUIRED",
    "LIKELY_BREAKING",
)


class PolicySimulationValidation(BaseModel):
    """Advisory change-impact estimate grounded in a bounded Cloud Audit Log sample (no Policy Simulator replay executed)."""

    simulation_id: str
    target_resource: str
    principal: str
    proposed_change_summary: str
    access_replay_90d_calls_tested: int = 0
    sample_events_observed: int = 0
    sample_window_start: str = ""
    sample_window_end: str = ""
    is_sample: bool = True
    production_breakage_detected: bool = False
    blocked_legitimate_calls: int = 0
    excess_risk_eliminated_pct: float
    simulator_verdict: str = Field(
        default="REVIEW_REQUIRED",
        description="NO_CONFLICT_IN_SAMPLE | REVIEW_REQUIRED | LIKELY_BREAKING",
    )

    @field_validator("simulator_verdict", mode="before")
    @classmethod
    def _normalize_verdict(cls, v: Any) -> str:
        val = str(v or "").strip().upper()
        if val in ALLOWED_IMPACT_VERDICTS:
            return val
        if val == "BREAKAGE_RISK":
            return "LIKELY_BREAKING"
        return "REVIEW_REQUIRED"


class IaCRemediationBundle(BaseModel):
    """Advisory Terraform / OpenTofu remediation modules synthesized by ADK `iac_generator` (unvalidated)."""

    bundle_id: str
    scope: str
    generated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    main_tf: str
    iam_tf: str
    pam_entitlements_tf: str
    org_policies_tf: str
    variables_tf: str
    manual_steps_md: str = ""
    rejected_plan_actions: List[str] = Field(default_factory=list)
    policy_simulations: List[PolicySimulationValidation] = Field(default_factory=list)
    audit_sample_is_sample: bool = True
    audit_sample_size: int = 0
    audit_sample_window_start: str = ""
    audit_sample_window_end: str = ""
    audit_projects_queried: int = 0
    audit_total_projects_in_scope: int = 0
    bundle_zip_path: Optional[str] = None


class FrameworkControlEvaluation(BaseModel):
    """Auditable, deterministic control evaluation grounded in Google Cloud, NIST, CIS, and CISA ZTMM."""

    control_id: str
    domain: str = Field(
        ...,
        description="INTERNAL_IDENTITIES | EXTERNAL_IDENTITIES | WORKLOAD_IDENTITIES | LEAST_PRIVILEGE | GRAPH_RESILIENCE",
    )
    control_title: str
    framework_mappings: List[str] = Field(default_factory=list)
    formula_expression: str
    numerator: float
    denominator: float
    unit_label: str
    deterministic_score_pct: float = Field(..., ge=0.0, le=100.0)
    domain_weight_pct: float = Field(..., ge=0.0, le=100.0)
    status: str = Field(default="PASS", description="PASS | PARTIAL | FAIL | UNDELEGATED | NOT_EVALUATED")
    evidence_summary: str


class FrameworkBenchmarkScore(BaseModel):
    """Aggregated posture alignment percentage against an authoritative security benchmark."""

    framework_id: str
    framework_name: str
    alignment_score_pct: float = Field(..., ge=0.0, le=100.0)
    controls_passed: int = Field(..., ge=0)
    controls_evaluated: int = Field(..., ge=0)
    primary_focus: str


class PostureScorecard(BaseModel):
    """Executive IAM Posture Scorecard (0-100%) synthesized over live GCP & ADK specialist outputs."""

    scope: str
    organization_domain: str
    overall_posture_score: float = Field(..., ge=0.0, le=100.0)
    maturity_tier: str = Field(..., description="Foundational | Developing | Managed | Zero-Trust Accelerated")
    internal_identities_score: float
    external_identities_score: float
    workload_identities_score: float
    least_privilege_index: float
    impersonation_resilience_score: float
    total_bindings_analyzed: int
    overprivileged_bindings_count: int
    excess_permissions_eliminated: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    scoring_methodology: str = (
        "Hybrid Deterministic Control Engine (18 Controls) + Bounded Agentic Contextual Calibration "
        "(Google Cloud Security Blueprint / NIST SP 800-53r5 / NIST CSF 2.0 / CIS GCP v3.0 / CISA ZTMM v2.0)"
    )
    deterministic_composite_score: float = 0.0
    agentic_calibration_delta: float = 0.0
    critical_cap_delta: float = 0.0
    pre_cap_score: float = 0.0
    agentic_calibration_rationale: str = ""
    critical_exposure_cap_applied: Optional[str] = None
    coverage_warnings: List[str] = Field(default_factory=list)
    data_completeness_pct: float = Field(default=100.0, ge=0.0, le=100.0)
    not_evaluated_domains: List[str] = Field(default_factory=list)
    framework_benchmarks: List[FrameworkBenchmarkScore] = Field(default_factory=list)
    control_evaluations: List[FrameworkControlEvaluation] = Field(default_factory=list)


class AccountPrincipalRecord(BaseModel):
    """Live IAM account/principal record (human user, external user, group, domain, public, or convenience ACL)."""

    principal: str
    principal_type: str
    domain: str
    is_external: bool = False
    roles: List[str] = Field(default_factory=list)
    bindings_count: int = 0
    projects: List[str] = Field(default_factory=list)
    is_standing_admin: bool = False
    can_access_secrets: bool = False
    can_use_or_admin_kms: bool = False
    can_impersonate_sa: bool = False
    has_cel_condition: bool = False
    audit_events_30d: int = 0
    risk_level: str = "LOW"


class ServiceAccountRecord(BaseModel):
    """Live customer or default Google Cloud Service Account record."""

    email: str
    project_id: str
    display_name: str
    sa_subtype: str = Field(default="Custom SA", description="Custom SA | Default Compute SA | Default AppEngine SA")
    disabled: bool = False
    user_managed_keys_count: int = 0
    system_managed_keys_count: int = 0
    oldest_user_key_age_days: int = 0
    granted_roles: List[str] = Field(default_factory=list)
    attached_workloads: List[str] = Field(default_factory=list)
    can_access_secrets_or_kms: bool = False
    risk_level: str = "LOW"


class ServiceAccountKeyRecord(BaseModel):
    """Live Service Account cryptographic key metadata record (zero private key access)."""

    key_id: str
    sa_email: str
    project_id: str
    key_type: str = Field(default="USER_MANAGED", description="USER_MANAGED | SYSTEM_MANAGED")
    key_origin: str = ""
    key_algorithm: str = ""
    valid_after_time: str = ""
    valid_before_time: str = ""
    age_days: int = 0
    risk_level: str = "LOW"


class SecretMetadataRecord(BaseModel):
    """Live Secret Manager secret governance metadata record (100% metadata-only — zero secret payload access)."""

    secret_name: str
    project_id: str
    replication_policy: str = "AUTOMATIC"
    encryption_type: str = Field(default="GOOGLE_MANAGED", description="CMEK | GOOGLE_MANAGED")
    kms_key_name: str = ""
    active_versions_count: int = 0
    rotation_configured: bool = False
    rotation_period_days: Optional[int] = None
    next_rotation_time: str = ""
    expire_or_ttl: str = ""
    created_at: str = ""
    accessor_principals: List[str] = Field(default_factory=list)
    accessor_principals_total: int = 0
    broad_primitive_accessors_count: int = 0
    risk_level: str = "LOW"


class KmsCryptoKeyRecord(BaseModel):
    """Live Cloud KMS KeyRing & CryptoKey posture record."""

    crypto_key_name: str
    key_ring: str
    project_id: str
    location: str
    purpose: str = "ENCRYPT_DECRYPT"
    protection_level: str = "SOFTWARE"
    algorithm: str = ""
    rotation_period_days: Optional[int] = None
    rotation_compliant_90d: bool = False
    next_rotation_time: str = ""
    sod_conflict_principals: List[str] = Field(default_factory=list)
    risk_level: str = "LOW"


class ApiKeyMetadataRecord(BaseModel):
    """Live Google Cloud API Key metadata & restriction posture record (never exposes raw key string)."""

    display_name: str
    key_uid: str
    project_id: str
    created_at: str = ""
    age_days: int = 0
    restriction_mode: str = "UNRESTRICTED"
    restricted_services: List[str] = Field(default_factory=list)
    is_unrestricted: bool = True
    risk_level: str = "HIGH"


class CustomIamRoleRecord(BaseModel):
    """Live Custom IAM Role definition & privilege-escalation permission check."""

    role_name: str
    title: str
    scope_level: str = "PROJECT"
    project_or_org: str = ""
    stage: str = "GA"
    included_permissions_count: int = 0
    escalation_permissions: List[str] = Field(default_factory=list)
    assigned_bindings_count: int = 0
    risk_level: str = "LOW"


class WifPoolProviderRecord(BaseModel):
    """Live Workload Identity Federation Pool & OIDC/AWS Provider posture record."""

    pool_name: str
    provider_name: str = "—"
    project_id: str
    issuer_uri: str = ""
    state: str = "ACTIVE"
    has_attribute_condition: bool = False
    attribute_condition: str = ""
    risk_level: str = "LOW"


class OrgPolicyPostureRecord(BaseModel):
    """Live effective Organization Policy constraint status."""

    constraint: str
    enforced: Optional[bool] = None
    evaluated_on: str = ""
    status: str = ""


class AccountsKeysSecretsSummaryKPIs(BaseModel):
    """Executive KPI indicators across Accounts, Service Accounts, Keys, KMS, Secrets, API Keys & WIF."""

    human_and_group_accounts_total: int = 0
    internal_users_count: int = 0
    external_and_public_principals_count: int = 0
    consumer_gmail_accounts_count: int = 0
    security_groups_count: int = 0
    standing_admin_accounts_count: int = 0
    principals_with_secret_or_kms_access: int = 0
    service_accounts_total: int = 0
    google_service_agents_count: int = 0
    default_sas_with_roles_count: int = 0
    disabled_sas_count: int = 0
    user_managed_sa_keys_total: int = 0
    sa_keys_over_90d_count: int = 0
    user_uploaded_sa_keys_count: int = 0
    system_managed_sa_keys_total: int = 0
    secrets_total_count: int = 0
    secret_versions_enabled_count: int = 0
    secrets_unrotated_count: int = 0
    secrets_without_cmek_count: int = 0
    kms_keyrings_count: int = 0
    kms_cryptokeys_total: int = 0
    kms_keys_missing_90d_rotation_count: int = 0
    kms_hsm_keys_count: int = 0
    kms_sod_conflicts_count: int = 0
    api_keys_total_count: int = 0
    unrestricted_api_keys_count: int = 0
    api_keys_over_90d_count: int = 0
    custom_roles_total_count: int = 0
    custom_roles_with_escalation_perms_count: int = 0
    wif_pools_count: int = 0
    wif_providers_count: int = 0
    unconditioned_wif_providers_count: int = 0
    org_policies_enforced_count: int = 0
    org_policies_evaluated_count: int = 0


class AccountsKeysSecretsInventory(BaseModel):
    """Complete live Accounts, Service Accounts, Keys, KMS, Secrets, API Keys, Custom Roles & WIF Inventory."""

    scope: str
    collected_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    kpis: AccountsKeysSecretsSummaryKPIs = Field(default_factory=AccountsKeysSecretsSummaryKPIs)
    accounts: List[AccountPrincipalRecord] = Field(default_factory=list)
    service_accounts: List[ServiceAccountRecord] = Field(default_factory=list)
    sa_keys: List[ServiceAccountKeyRecord] = Field(default_factory=list)
    secrets: List[SecretMetadataRecord] = Field(default_factory=list)
    kms_keys: List[KmsCryptoKeyRecord] = Field(default_factory=list)
    api_keys: List[ApiKeyMetadataRecord] = Field(default_factory=list)
    custom_roles: List[CustomIamRoleRecord] = Field(default_factory=list)
    wif_providers: List[WifPoolProviderRecord] = Field(default_factory=list)
    org_policies: List[OrgPolicyPostureRecord] = Field(default_factory=list)
    audit_sample_is_sample: bool = True
    audit_sample_size: int = 0
    audit_sample_window_start: str = ""
    audit_sample_window_end: str = ""
    audit_projects_queried: int = 0
    audit_total_projects_in_scope: int = 0


class PostureAccelerationBook(BaseModel):
    """Master deliverable synthesized by the Root Coordinator Agent across all 5 specialist planes."""

    scope: str
    organization_domain: str
    generated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    advisory_disclaimer: str = (
        "Consultative Advisory Positioning: Prepared under the Google Cloud Shared Responsibility Model as an "
        "IAM Posture Assessment, Modernization, and Least-Privilege Acceleration deliverable. This document does "
        "not constitute a regulatory audit or formal compliance certification."
    )
    scorecard: PostureScorecard
    triad_matrix: IdentityTriadMatrix
    attack_graph: AttackPathGraphSummary
    recommendations: List[LeastPrivilegeRecommendation]
    iac_bundle: IaCRemediationBundle
    asset_inventory: Optional[AccountsKeysSecretsInventory] = None
    executive_narrative_markdown: str = ""
    deliverable_paths: Dict[str, str] = Field(default_factory=dict)
    telemetry: Optional[AdkExecutionTelemetry] = None


# ---------------------------------------------------------------------------
# Strict Vertex AI Controlled-Generation Schemas for Google ADK Sub-Agents
# (Zero untyped Dict[str, Any] properties to guarantee Vertex AI compatibility)
# ---------------------------------------------------------------------------

def _clamp_calibration_delta(val: Any) -> float:
    import math

    try:
        fval = float(val)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(fval):
        return 0.0
    return max(-5.0, min(5.0, fval))


class TriadPillarSynthesis(BaseModel):
    """Structured pillar output produced by the ADK `triad_analyzer` agent."""

    posture_score: float = Field(..., ge=0.0, le=100.0)
    total_principals_evaluated: int = Field(..., ge=0)
    compliant_principals: int = Field(..., ge=0)
    agentic_calibration_delta: float = Field(
        default=0.0,
        description="Bounded [-5.0, +5.0] contextual adjustment over deterministic control baseline (clamped automatically)",
    )
    agentic_calibration_rationale: str = Field(
        default="",
        description="Evidence-grounded explanation citing Google Cloud Blueprint / NIST / CIS controls for the contextual calibration",
    )
    key_anti_patterns_detected: List[str] = Field(default_factory=list)
    modernization_priorities: List[str] = Field(default_factory=list)

    @field_validator("agentic_calibration_delta", mode="before")
    @classmethod
    def _validate_delta(cls, v: Any) -> float:
        return _clamp_calibration_delta(v)


class TriadAgentOutput(BaseModel):
    """Structured output schema for `triad_analyzer`."""

    internal_identities: TriadPillarSynthesis
    external_identities: TriadPillarSynthesis
    workload_service_accounts: TriadPillarSynthesis
    findings: List[GcpIamPostureFinding] = Field(default_factory=list)


class AttackPathAgentOutput(BaseModel):
    """Structured output schema for `attack_path_agent`."""

    critical_paths: List[AttackPathFinding] = Field(default_factory=list)
    toxic_combinations_count: int = Field(..., ge=0)
    impersonation_resilience_score: float = Field(..., ge=0.0, le=100.0)
    agentic_calibration_delta: float = Field(
        default=0.0,
        description="Bounded [-5.0, +5.0] contextual adjustment over deterministic NetworkX resilience baseline (clamped automatically)",
    )
    agentic_calibration_rationale: str = Field(
        default="",
        description="Evidence-grounded explanation citing MITRE ATT&CK / NIST / CISA ZTMM controls for the contextual calibration",
    )

    @field_validator("agentic_calibration_delta", mode="before")
    @classmethod
    def _validate_delta(cls, v: Any) -> float:
        return _clamp_calibration_delta(v)


class RecommenderAgentOutput(BaseModel):
    """Structured output schema for `recommender_agent`."""

    recommendations: List[LeastPrivilegeRecommendation] = Field(default_factory=list)
    least_privilege_index: float = Field(..., ge=0.0, le=100.0)
    agentic_calibration_delta: float = Field(
        default=0.0,
        description="Bounded [-5.0, +5.0] contextual adjustment over deterministic Least-Privilege baseline (clamped automatically)",
    )
    agentic_calibration_rationale: str = Field(
        default="",
        description="Evidence-grounded explanation citing NIST AC-6 / Google Cloud Blueprint GCB-IAM-06 for the contextual calibration",
    )

    @field_validator("agentic_calibration_delta", mode="before")
    @classmethod
    def _validate_delta(cls, v: Any) -> float:
        return _clamp_calibration_delta(v)


class EnforceOrgPolicyAction(BaseModel):
    """Typed action to enforce a Google Cloud Organization Policy constraint."""

    constraint: str = Field(..., description="Constraint ID in KEY_IAM_ORG_CONSTRAINTS (e.g., constraints/iam.disableServiceAccountKeyCreation)")
    target_scope: str = Field(..., description="GCP scope (organizations/<digits>, folders/<digits>, or projects/<project-id>)")
    enforce: bool = True
    allowed_values: List[str] = Field(default_factory=list, description="Optional list values for list constraints such as allowedPolicyMemberDomains")
    rationale: str = ""


class CreatePamEntitlementAction(BaseModel):
    """Typed action to create a Privileged Access Manager (PAM) JIT entitlement."""

    entitlement_id: str = Field(..., description="Lowercase kebab-case entitlement ID (e.g., platform-admin-jit)")
    parent_scope: str = Field(..., description="organizations/<digits>, folders/<digits>, or projects/<project-id>")
    location: str = "global"
    eligible_principals: List[str] = Field(..., description="List of IAM principals eligible to request JIT elevation (e.g., group:platform@example.com)")
    approver_principals: List[str] = Field(default_factory=list, description="Optional approver group/user principals")
    granted_role: str = Field(..., description="Least-privilege IAM role granted during JIT window (never roles/owner, roles/editor, or IAM admin)")
    max_request_duration: str = "3600s"
    rationale: str = ""


class ReplaceRoleBindingAction(BaseModel):
    """Typed action replacing an existing IAM binding via non-authoritative member grant + manual removal command."""

    principal: str = Field(..., description="Exact principal observed in live bindings (e.g., user:alice@example.com)")
    current_role: str = Field(..., description="Exact current IAM role observed for this principal in live bindings")
    new_role: str = Field(default="", description="Replacement least-privilege IAM role (empty string for revoke-only); never roles/owner, roles/editor, or IAM admin")
    resource: str = Field(..., description="Target GCP resource scope (organizations/<digits>, folders/<digits>, or projects/<project-id>)")
    condition_title: Optional[str] = None
    condition_expression: Optional[str] = None
    rationale: str = ""


class CreateCustomRoleAction(BaseModel):
    """Typed action to create a tightly scoped custom IAM role."""

    role_id: str = Field(..., description="Custom role ID (e.g., leastPrivilegeStorageViewer)")
    target_scope: str = Field(..., description="organizations/<digits> or projects/<project-id>")
    title: str
    description: str = ""
    permissions: List[str] = Field(..., description="Explicit list of least-privilege IAM permissions (no setIamPolicy or key creation)")
    stage: str = "GA"


class IaCPlan(BaseModel):
    """Strict structured remediation plan returned by `iac_generator` and deterministically rendered to HCL by Python."""

    enforce_org_policies: List[EnforceOrgPolicyAction] = Field(default_factory=list)
    create_pam_entitlements: List[CreatePamEntitlementAction] = Field(default_factory=list)
    replace_role_bindings: List[ReplaceRoleBindingAction] = Field(default_factory=list)
    create_custom_roles: List[CreateCustomRoleAction] = Field(default_factory=list)


class IaCAgentOutput(BaseModel):
    """Structured output schema for `iac_generator` (typed plan rendered deterministically by Python)."""

    bundle_id: str = "IAC-DRAFT-001"
    plan: IaCPlan = Field(default_factory=IaCPlan)
    policy_simulations: List[PolicySimulationValidation] = Field(default_factory=list)


class CoordinatorAgentOutput(BaseModel):
    """Structured output schema for `iam_coordinator` executive synthesis."""

    overall_posture_score: float = Field(..., ge=0.0, le=100.0)
    maturity_tier: str = Field(..., description="Foundational | Developing | Managed | Zero-Trust Accelerated")
    least_privilege_index: float = Field(..., ge=0.0, le=100.0)
    impersonation_resilience_score: float = Field(..., ge=0.0, le=100.0)
    agentic_calibration_rationale: str = Field(
        default="",
        description="Concise CISO synthesis explaining the deterministic 18-control baseline, specialist agentic calibrations, and framework alignment",
    )
    executive_narrative_markdown: str
