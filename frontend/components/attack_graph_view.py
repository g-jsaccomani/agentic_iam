"""Attack Path Graph View Component (`frontend/components/attack_graph_view.py`).

Displays the live NetworkX IAM Privilege Escalation & Toxic Combination Graph
in AISPR dark matte style (`dark_mode=True`).
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from backend.models.findings import AttackPathGraphSummary
from backend.tools.graph_engine import render_attack_graph_png


def render_attack_graph_view(attack_graph: AttackPathGraphSummary, graph_png_path: Path) -> None:
    """Renders the live NetworkX IAM Attack Path & Impersonation Graph in AISPR dark mode."""
    st.markdown("#### NetworkX Privilege & Escalation Topology")
    st.caption(
        f"Scope: `{attack_graph.scope}` • Nodes: `{attack_graph.total_nodes}` • "
        f"Edges: `{attack_graph.total_edges}` • "
        f"Escalation Paths: `{attack_graph.escalation_paths_count}` • "
        f"Toxic Combinations: `{attack_graph.toxic_combinations_count}`"
    )

    render_attack_graph_png(graph_png_path, attack_graph.scope, graph_summary=attack_graph, dark_mode=True)

    if graph_png_path.exists():
        st.image(str(graph_png_path), use_container_width=True)

    col_paths, col_centrality = st.columns([1.6, 1.0])

    with col_paths:
        st.markdown("#### Critical Escalation Chains")
        if not attack_graph.critical_paths:
            st.success("No multi-hop escalation chains detected in scope.")
        for path in attack_graph.critical_paths:
            with st.expander(f"{path.path_id} • {path.title} (Blast Radius: {path.blast_radius_score}/10)", expanded=True):
                st.markdown(f"- **Vector:** `{path.toxic_combination_type}`")
                st.markdown(f"- **Chain:** `{' -> '.join(path.hop_sequence)}`")
                st.markdown(f"- **Mitigation:** {path.mitigation_control}")

    with col_centrality:
        st.markdown("#### Choke-Point Centrality")
        st.dataframe(attack_graph.high_centrality_principals, use_container_width=True, hide_index=True)
