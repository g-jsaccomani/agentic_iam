"""Identity Triad Breakdown Component (`frontend/components/triad_breakdown.py`).

Renders the live ADK-evaluated 3-pillar Identity Triad Matrix in AISPR minimalist style.
"""

from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from backend.models.findings import IdentityTriadMatrix


def render_triad_breakdown(triad: IdentityTriadMatrix) -> None:
    """Renders the Identity Triad Matrix comparison and findings explorer in AISPR style."""
    st.markdown("#### Identity Triad Matrix")

    pillars = [
        triad.internal_identities,
        triad.external_identities,
        triad.workload_service_accounts,
    ]

    cols = st.columns(3)
    for col, p in zip(cols, pillars):
        with col:
            st.markdown(f"**{p.display_name}**")
            st.progress(
                min(100, max(0, int(round(p.posture_score)))),
                text=f"{p.posture_score}% ({p.compliant_principals}/{p.total_principals_evaluated} compliant)",
            )
            if p.key_anti_patterns_detected:
                st.caption("Anti-patterns: " + " • ".join(p.key_anti_patterns_detected[:2]))
            if p.modernization_priorities:
                st.caption("Priority: " + p.modernization_priorities[0])

    compliance_ratios = [
        round((p.compliant_principals / max(p.total_principals_evaluated, 1)) * 100.0, 1)
        for p in pillars
    ]
    fig = go.Figure(
        data=[
            go.Bar(
                name="Posture Score (%)",
                x=[p.display_name for p in pillars],
                y=[p.posture_score for p in pillars],
                marker_color="#1A73E8",
            ),
            go.Bar(
                name="Compliant Principals (%)",
                x=[p.display_name for p in pillars],
                y=compliance_ratios,
                marker_color="#2B8A3E",
            ),
        ]
    )
    fig.update_layout(
        barmode="group",
        height=280,
        paper_bgcolor="#1B1E26",
        plot_bgcolor="#1B1E26",
        font={"family": "Inter, sans-serif", "color": "#F1F5F9", "size": 12},
        yaxis={"title": "Score (%)", "gridcolor": "#2C3240", "range": [0, 105]},
        xaxis={"gridcolor": "#2C3240"},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1},
        margin=dict(l=20, r=20, t=35, b=20),
    )
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Identity Triad Findings")
    rows = [
        {
            "Finding ID": f.finding_id,
            "View": f.cspr_view_id,
            "Pillar": f.triad_category.value,
            "Severity": f.severity.value,
            "Principal": f.principal,
            "Role": f.role,
            "Risk Vector": f.risk_vector,
            "Modernization": f.recommended_modernization,
        }
        for f in triad.findings
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)
