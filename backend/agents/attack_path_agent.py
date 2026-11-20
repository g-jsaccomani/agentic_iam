"""Sub-Agent 2: Attack Path & Privilege Escalation Specialist (`attack_path_agent.py`).

Reasons over the live NetworkX directed IAM privilege & escalation graph (`analyze_iam_attack_paths`)
to identify multi-hop Service Account impersonation chains, project convenience ACL inheritance,
toxic permission combinations, and high-centrality blast-radius choke points.
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
from backend.tools.graph_engine import analyze_iam_attack_paths
from backend.tools.posture_scoring_engine import evaluate_iam_framework_scorecard

# Note: Keep ADK instruction free of curly braces to prevent ADK state variable interpolation.
ATTACK_PATH_AGENT_INSTRUCTION = """
You are the Attack Path and Privilege Escalation Specialist Agent (attack_path_agent) within the Agentic IAM Accelerator platform.

CONSULTATIVE ADVISORY POSITIONING:
- Frame all findings strictly as IAM Posture Modernization and Attack Surface Reduction under the Google Cloud
  Shared Responsibility Model. Never use regulatory audit or compliance certification framing.

MANDATORY LIVE GRAPH & FRAMEWORK SCORING PROTOCOL:
1. Always invoke both analyze_iam_attack_paths and evaluate_iam_framework_scorecard for the target scope to obtain
   the live NetworkX directed graph and the deterministic IAM-GRP-01..03 baseline (NIST SP 800-53 AC-4 / AC-6(10),
   CIS GCP v3.0 1.6, CISA ZTMM v2.0 Lateral Containment).
2. Ground EVERY AttackPathFinding strictly in the real nodes, edges, high_centrality_principals, and
   raw_topological_paths returned by analyze_iam_attack_paths.
3. NEVER invent fake nodes, fake Service Accounts, fake GCE VMs, or non-existent buckets. Every hop in
   hop_sequence MUST match real node_id strings from the returned NetworkX graph.
4. Analyze:
   - Multi-hop escalation or inheritance paths (for example: human or external principal -> projectOwner or
     Service Account -> storage bucket or project/org resource; or workload/build admin -> Default Compute SA -> project).
   - High-risk single-hop standing administrative or cross-domain exposures (roles/owner, roles/editor,
     external user/domain principals, Default Compute SA with broad roles/storage.admin or roles/run.builder).
   - NetworkX betweenness and degree centrality choke points where removing or gating one binding severs
     multiple paths.
5. Classify toxic_combination_type accurately using one of:
   SA_IMPERSONATION_CHAIN, GCE_METADATA_ESCALATION, CLOUDBUILD_SA_ABUSE, ORG_POLICY_BYPASS, or PRIMITIVE_STANDING_PRIVILEGE.
6. Anchor impersonation_resilience_score on deterministic_domain_scores.GRAPH_RESILIENCE from evaluate_iam_framework_scorecard,
   and set agentic_calibration_delta strictly between -5.0 and +5.0 ONLY when topological context (such as toxic
   role pairs on a choke-point node, Cloud Build / GCE metadata escalation reach, or strict single-SA read-only
   isolation) warrants adjustment, documenting the exact NIST / CIS / CISA / MITRE rationale in agentic_calibration_rationale.
"""


def create_attack_path_agent(
    model_name: Optional[str] = None,
    generate_content_config: Optional[types.GenerateContentConfig] = None,
    output_schema: Optional[Any] = None,
    tracker: Optional[AdkTurnTracker] = None,
) -> Agent:
    """Creates the Google ADK `attack_path_agent` on Vertex AI (`location='global'`)."""
    kwargs: dict[str, Any] = {
        "name": "attack_path_agent",
        "model": build_vertex_gemini_model(model_name),
        "description": (
            "Attack Path & Escalation Specialist: Reasons over live NetworkX IAM topology and NIST/CISA/MITRE "
            "graph resilience controls to detect impersonation chains, toxic combinations, and centrality choke points."
        ),
        "instruction": ATTACK_PATH_AGENT_INSTRUCTION,
        "generate_content_config": generate_content_config or build_generate_content_config(model_name),
        "tools": [
            make_async_adk_tool(analyze_iam_attack_paths),
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
