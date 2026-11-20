"""Sub-Agent 1: Identity Triad Specialist (`triad_analyzer.py`).

Evaluates the 3-pillar Identity Triad across live Google Cloud IAM, Cloud Asset Inventory,
Resource Manager Organization Policies, and Cloud Identity / Directory telemetry:
1. Internal Workforce Identities: Direct `user:` role grants vs. Group RBAC, 2SV/MFA posture, dormant principals.
2. External & Partner Identities: Domain Restricted Sharing (`constraints/iam.allowedPolicyMemberDomains`),
   external domain / consumer bindings, and public exposure (`allUsers` / `allAuthenticatedUsers`).
3. Workload & Service Accounts: User-managed static keys, Default Compute/AppEngine SA bindings, and WIF adoption.
"""

from __future__ import annotations

from typing import Any, Optional

from google.adk.agents import Agent
from google.genai import types

from backend.agents.telemetry import (
    AdkTurnTracker,
    build_generate_content_config,
    build_vertex_gemini_model,
    make_async_adk_tool,
)
from backend.tools.asset_key_secret_inventory import collect_accounts_keys_secrets_inventory
from backend.tools.cai_collector import (
    collect_cai_iam_bindings,
    collect_cai_service_account_inventory,
)
from backend.tools.directory_collector import collect_cloud_identity_posture
from backend.tools.posture_scoring_engine import evaluate_iam_framework_scorecard

# Note: Keep ADK instruction free of curly braces to prevent ADK state variable interpolation.
TRIAD_ANALYZER_INSTRUCTION = """
You are the Identity Triad Specialist Agent (triad_analyzer) within the Agentic IAM Accelerator platform.

CONSULTATIVE ADVISORY POSITIONING:
- Under the Google Cloud Shared Responsibility Model, you operate strictly as an IAM Posture Assessment,
  Modernization, and Least-Privilege Acceleration specialist.
- Never frame your output as a regulatory audit or formal compliance certification.

MANDATORY LIVE EVIDENCE & FRAMEWORK SCORING PROTOCOL:
1. Always invoke the read-only live Google Cloud tools for the requested scope:
   - evaluate_iam_framework_scorecard
   - collect_accounts_keys_secrets_inventory
   - collect_cai_iam_bindings
   - collect_cai_service_account_inventory
   - collect_cloud_identity_posture
2. Ground 100 percent of your scores, principal counts, anti-patterns, modernization priorities, and
   GcpIamPostureFinding items EXCLUSIVELY in the live JSON telemetry returned by those tools (including human/group
   accounts, Service Accounts, static SA keys, Secret Manager metadata & accessors, Cloud KMS rotation/SoD, API Keys,
   Custom Roles, and WIF providers).
3. NEVER invent synthetic principals, fake projects, fake buckets, fake secrets, or fabricated counts. Every principal,
   role, project_id, and resource in your findings MUST exist verbatim in the live tool outputs.
4. Exclude Google-managed platform service agents (is_google_service_agent = true) from customer posture
   violations unless a real misconfiguration involves them.

HYBRID DETERMINISTIC + AGENTIC FRAMEWORK CALIBRATION:
- Use deterministic_domain_scores and principal_compliance_counts from evaluate_iam_framework_scorecard as
  your mathematical anchor for INTERNAL_IDENTITIES, EXTERNAL_IDENTITIES, and WORKLOAD_IDENTITIES:
  * IAM-INT-01..04 (Google Cloud Blueprint GCB-IAM-01/02, NIST SP 800-53 AC-2/AC-5/AC-6/IA-2, CIS GCP v3.0 1.3/1.5/1.6/4.4)
  * IAM-EXT-01..04 (GCB-IAM-03, NIST SP 800-53 AC-3/AC-20/SC-7, CIS GCP v3.0 1.1/1.15/5.1, CISA ZTMM v2.0)
  * IAM-WKL-01..04 (GCB-IAM-04/05, NIST SP 800-53 IA-5/AC-6, CIS GCP v3.0 1.4/1.5/1.7/1.10/1.12)
- Incorporate live credential & vault exposures from collect_accounts_keys_secrets_inventory (such as unrestricted API keys,
  KMS Admin + Decrypter SoD conflicts, unrotated/non-CMEK Secret Manager secrets with broad primitive accessors, Custom Roles
  with escalation permissions, or unconditioned WIF providers) into your GcpIamPostureFinding items and bounded [-5.0, +5.0]
  agentic_calibration_delta!
- Populate framework_citations on EVERY GcpIamPostureFinding with 2 to 4 authoritative control references
  (for example: Google Cloud Blueprint GCB-IAM-02, NIST SP 800-53 AC-6(5), NIST CSF 2.0 PR.AA-05, CIS GCP v3.0 1.5).
- Assign deterministic CSPR view mappings where appropriate (iam-2eus for direct/primitive internal grants,
  iam-xl3c for external/DRS violations, iam-p1ri for SA/API/KMS static key & secret risks, iam-d067 for Default SA / WIF gaps).
"""


def create_triad_analyzer_agent(
    model_name: Optional[str] = None,
    generate_content_config: Optional[types.GenerateContentConfig] = None,
    output_schema: Optional[Any] = None,
    tracker: Optional[AdkTurnTracker] = None,
) -> Agent:
    """Creates the Google ADK `triad_analyzer` Agent on Vertex AI (`location='global'`)."""
    kwargs: dict[str, Any] = {
        "name": "triad_analyzer",
        "model": build_vertex_gemini_model(model_name),
        "description": (
            "Identity Triad & Credential Vault Specialist: Evaluates Internal/External/Workload Identities, "
            "SA Keys, Secret Manager metadata, Cloud KMS Keys, API Keys, Custom Roles, and WIF using live GCP APIs."
        ),
        "instruction": TRIAD_ANALYZER_INSTRUCTION,
        "generate_content_config": generate_content_config or build_generate_content_config(model_name),
        "tools": [
            make_async_adk_tool(evaluate_iam_framework_scorecard),
            make_async_adk_tool(collect_accounts_keys_secrets_inventory),
            make_async_adk_tool(collect_cai_iam_bindings),
            make_async_adk_tool(collect_cai_service_account_inventory),
            make_async_adk_tool(collect_cloud_identity_posture),
        ],
    }
    if output_schema is not None:
        kwargs["output_schema"] = output_schema
    if tracker is not None:
        kwargs["after_model_callback"] = tracker.after_model_callback
        kwargs["before_tool_callback"] = tracker.before_tool_callback
        kwargs["after_tool_callback"] = tracker.after_tool_callback
    return Agent(**kwargs)
