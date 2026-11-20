"""Executive IAM Posture Scorecard Component (`frontend/components/posture_scorecard.py`).

Renders the live ADK-synthesized 0–100% IAM Posture Score with AISPR dark matte palette
(`#1B1E26` surface, `#232732` track, `#1A73E8` / `#2B8A3E` / `#F59F00` / `#E03131` accents).
"""

from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from backend.models.findings import PostureScorecard


def _score_color(score: float) -> str:
    if score >= 75.0:
        return "#2B8A3E"
    if score >= 50.0:
        return "#F59F00"
    return "#E03131"


def render_posture_scorecard(scorecard: PostureScorecard, escalation_paths_count: int = 0) -> None:
    """Renders the minimalist AISPR-styled Executive IAM Posture Scorecard in Streamlit."""
    st.markdown("#### Posture Health Overview")
    st.caption(
        f"Scope: `{scorecard.scope}` ({scorecard.organization_domain}) • "
        f"Bindings Analyzed: `{scorecard.total_bindings_analyzed}`"
    )

    col_gauge, col_kpis = st.columns([1.1, 2.1])

    with col_gauge:
        bar_col = _score_color(scorecard.overall_posture_score)
        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=scorecard.overall_posture_score,
                number={"suffix": "%", "font": {"size": 36, "color": "#F1F5F9", "family": "Inter"}},
                title={
                    "text": f"Tier: {scorecard.maturity_tier}",
                    "font": {"size": 13, "color": "#94A3B8", "family": "Inter"},
                },
                gauge={
                    "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#64748B", "tickfont": {"color": "#94A3B8"}},
                    "bar": {"color": bar_col, "thickness": 0.65},
                    "bgcolor": "#232732",
                    "borderwidth": 1,
                    "bordercolor": "#2C3240",
                },
            )
        )
        fig.update_layout(
            height=250,
            margin=dict(l=20, r=20, t=42, b=12),
            paper_bgcolor="#1B1E26",
            plot_bgcolor="#1B1E26",
            font={"family": "Inter, sans-serif", "color": "#F1F5F9"},
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_kpis:
        r1c1, r1c2, r1c3 = st.columns(3)
        r1c1.metric(
            label="Internal Workforce",
            value=f"{scorecard.internal_identities_score}%",
            delta=f"{scorecard.total_bindings_analyzed} bindings",
        )
        r1c2.metric(
            label="External & DRS",
            value=f"{scorecard.external_identities_score}%",
            delta=scorecard.organization_domain,
        )
        r1c3.metric(
            label="Workload & SAs",
            value=f"{scorecard.workload_identities_score}%",
            delta=f"{scorecard.overprivileged_bindings_count} optimizable",
        )

        r2c1, r2c2, r2c3 = st.columns(3)
        r2c1.metric(
            label="Least-Privilege Index",
            value=f"{scorecard.least_privilege_index}%",
            delta=f"-{scorecard.excess_permissions_eliminated:,} perms",
        )
        r2c2.metric(
            label="Impersonation Resilience",
            value=f"{scorecard.impersonation_resilience_score}%",
            delta=f"{escalation_paths_count} escalation paths",
        )
        r2c3.metric(
            label="Critical / High Gaps",
            value=f"{scorecard.critical_findings + scorecard.high_findings}",
            delta=f"{scorecard.critical_findings} Crit • {scorecard.high_findings} High",
        )
