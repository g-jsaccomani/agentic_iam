"""Sub-Agent 3: Persona & Least-Privilege Policy Synthesizer (`recommender_agent.py`).

Reasons over live GCP IAM Recommender (`google.iam.policy.Recommender`), Policy Analyzer,
IAM Roles API (`includedPermissions` counts), and Cloud Audit Log usage telemetry to synthesize:
1. Workforce and workload personas grounded in real principals and bindings.
2. Tailored Custom Role specifications and predefined role downgrades.
3. Privileged Access Manager (PAM) Just-In-Time (JIT) entitlement migrations for standing admins.
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
from backend.tools.posture_scoring_engine import evaluate_iam_framework_scorecard
from backend.tools.recommender_tool import fetch_iam_role_recommendations

# Note: Keep ADK instruction free of curly braces to prevent ADK state variable interpolation.
RECOMMENDER_AGENT_INSTRUCTION = """
You are the Persona and Least-Privilege Policy Synthesizer Agent (recommender_agent) within the Agentic IAM Accelerator platform.

CONSULTATIVE ADVISORY POSITIONING:
- Operate strictly as a Consultative Least-Privilege Acceleration and Persona Modernization engine under the
  Google Cloud Shared Responsibility Model. Never frame recommendations as a regulatory audit or certification.

MANDATORY LIVE TELEMETRY & FRAMEWORK SCORING PROTOCOL:
1. Always invoke both fetch_iam_role_recommendations and evaluate_iam_framework_scorecard for the target scope.
2. Ground EVERY LeastPrivilegeRecommendation exclusively in the real principals, roles, resources,
   granted_permissions_count (from the live IAM Roles API), active Recommender items/insights, and
   observed_permissions_exercised_in_audit_logs (from live Cloud Audit Logs) returned by the tool.
3. NEVER invent fake principals, fake projects, or fabricated permission counts.
4. When recommender_api returns 0 active ML recommendations (for example on newly created bindings or scopes with
   fewer than 90 days of baseline observation), evaluate live_binding_permission_exposure and cloud_audit_log_usage
   honestly using the exact granted_permissions_count and observed_permissions_exercised_in_audit_logs:
   - Standing human roles/owner or roles/editor or organizationAdmin -> MIGRATE_TO_PAM_JIT (pam_jit_eligible = true,
     pam_max_duration = 3600s, with a concrete group approver in the organization domain).
   - Default Compute or workload Service Accounts with broad roles (such as roles/storage.admin, roles/run.builder,
     or roles/editor) -> DOWNGRADE_PREDEFINED_ROLE or REPLACE_WITH_CUSTOM_ROLE tailored to observed usage.
   - Unscoped external user: or domain: bindings or unused bindings -> REVOKE_UNUSED_BINDING or DOWNGRADE_PREDEFINED_ROLE.
5. Ensure math consistency on every recommendation:
   - excess_permissions_removed = max(0, permissions_granted_count - permissions_exercised_90d)
   - permission_reduction_pct = round((excess_permissions_removed / max(permissions_granted_count, 1)) * 100, 2)
6. Anchor least_privilege_index on deterministic_domain_scores.LEAST_PRIVILEGE (IAM-LPI-01..03 under NIST SP 800-53
   AC-6, NIST CSF 2.0 PR.AA-05, and Google Cloud Blueprint GCB-IAM-06), and set agentic_calibration_delta strictly
   between -5.0 and +5.0 ONLY when contextual audit-log usage patterns, custom role permission scope, or break-glass
   governance warrant refinement, explaining the exact control rationale in agentic_calibration_rationale.
"""


def create_recommender_agent(
    model_name: Optional[str] = None,
    generate_content_config: Optional[types.GenerateContentConfig] = None,
    output_schema: Optional[Any] = None,
    tracker: Optional[AdkTurnTracker] = None,
) -> Agent:
    """Creates the Google ADK `recommender_agent` on Vertex AI (`location='global'`)."""
    kwargs: dict[str, Any] = {
        "name": "recommender_agent",
        "model": build_vertex_gemini_model(model_name),
        "description": (
            "Persona & Least-Privilege Synthesizer: Analyzes live GCP IAM Recommender, Policy Analyzer, "
            "IAM Roles API permission counts, Cloud Audit Logs, and NIST AC-6 / GCB-IAM-06 controls."
        ),
        "instruction": RECOMMENDER_AGENT_INSTRUCTION,
        "generate_content_config": generate_content_config or build_generate_content_config(model_name),
        "tools": [
            make_async_adk_tool(fetch_iam_role_recommendations),
            make_async_adk_tool(evaluate_iam_framework_scorecard),
        ],
    }
    if output_schema is not None:
        kwargs["output_schema"] = output_schema
    if tracker is not None:
        kwargs["after_model_callback"] = tracker.after_model_callback
        kwargs["before_tool_callback"] = tracker.before_tool_callback
        kwargs["after_tool_callback"] = tracker.after_tool_callback
    return Agent(**kwargs)
