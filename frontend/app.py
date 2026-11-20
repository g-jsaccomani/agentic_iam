"""Streamlit Interactive Console (`frontend/app.py`) — Zero-Trust Clean-Slate AISPR Design System.

Minimalist Google Cloud Security Consulting aesthetic matching AISPR:
- Palette: `#14161B` background, `#1B1E26` surface, `#232732` surface-variant, `#2C3240` border, `#1A73E8` primary
- Typography: `Inter` UI font & `JetBrains Mono` code/telemetry font
- Clean-Slate Per-User Session Isolation (`backend/session_vault.py`): zero preloaded Organization data
- Service Account Impersonation (`iamcredentials.generateAccessToken`) or Direct User Read-Only Access
- Organization-Level Multi-Project Scope Picker (1..N projects or Full Organization)
- Standardized Vertex AI Engine: `gemini-3.1-pro-preview-customtools` (`location='global'`)
"""

from __future__ import annotations

import base64
import html
import re
import secrets
import sys
from pathlib import Path

import streamlit as st

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.agents.coordinator import (
    run_coordinator_chat_sync,
    run_posture_book_assessment_sync,
)
from backend.config import (
    DEFAULT_VERTEX_LOCATION,
    DEFAULT_VERTEX_MODEL,
)
from backend.identity_guard import verify_google_token
from backend.report_generator import generate_all_executive_deliverables
from backend.session_vault import (
    bind_inspection_session_context,
    get_inspection_session,
    store_inspection_session,
    update_session_organization_metadata,
    wipe_inspection_session,
)
from backend.tools.onboarding_manager import (
    build_onboarding_kit_zip,
    discover_organization_hierarchy,
    generate_customer_onboarding_kit,
    verify_customer_onboarding_readiness,
)
from frontend.components.attack_graph_view import render_attack_graph_view
from frontend.components.posture_scorecard import render_posture_scorecard
from frontend.components.triad_breakdown import render_triad_breakdown

AISPR_STREAMLIT_CSS = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  html, body, [class*="css"], .stApp {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    background-color: #14161B !important;
    color: #F1F5F9 !important;
  }
  code, pre, .stCodeBlock {
    font-family: 'JetBrains Mono', monospace !important;
  }
  section[data-testid="stSidebar"] {
    background-color: #1B1E26 !important;
    border-right: 1px solid #2C3240 !important;
  }
  div[data-testid="stMetric"] {
    background-color: #1B1E26 !important;
    border: 1px solid #2C3240 !important;
    border-radius: 8px !important;
    padding: 0.95rem 1.1rem !important;
  }
  div[data-testid="stMetricLabel"] p {
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
    color: #94A3B8 !important;
  }
  div[data-testid="stMetricValue"] {
    font-weight: 800 !important;
    color: #F1F5F9 !important;
  }
  .stTabs [data-baseweb="tab-list"] {
    background-color: #181B22;
    border: 1px solid #2C3240;
    border-radius: 8px;
    padding: 4px;
    gap: 4px;
  }
  .stTabs [data-baseweb="tab"] {
    border-radius: 6px;
    font-size: 0.82rem;
    font-weight: 600;
    color: #94A3B8;
    padding: 6px 14px;
  }
  .stTabs [aria-selected="true"] {
    background-color: #1B1E26 !important;
    color: #FFFFFF !important;
    border: 1px solid #2C3240 !important;
  }
  .aispr-header {
    background: #1B1E26;
    border: 1px solid #2C3240;
    border-radius: 8px;
    padding: 0.9rem 1.25rem;
    margin-bottom: 1.1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
  }
  .aispr-brand { display: flex; align-items: center; gap: 12px; }
  .aispr-logo {
    width: 38px;
    height: 38px;
    background: transparent;
    border-radius: 0;
    object-fit: contain;
    display: block;
    flex-shrink: 0;
  }
  .aispr-title { font-size: 1.08rem; font-weight: 700; color: #FFFFFF; }
  .aispr-sub { font-size: 0.75rem; color: #94A3B8; }
  .aispr-badge {
    background: #232732;
    border: 1px solid #2C3240;
    padding: 4px 12px;
    border-radius: 6px;
    font-size: 0.76rem;
    font-weight: 600;
    color: #8AB4F8;
    font-family: 'JetBrains Mono', monospace;
  }
  .aispr-advisory {
    background: rgba(26, 115, 232, 0.07);
    border-left: 3px solid #1A73E8;
    padding: 8px 12px;
    border-radius: 0 6px 6px 0;
    font-size: 0.76rem;
    color: #94A3B8;
    margin-top: 1.2rem;
  }
</style>
"""


_MD_IMAGE_INLINE_RE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
_MD_IMAGE_REF_RE = re.compile(r"!\[([^\]]*)\]\[[^\]]*\]")
_HTML_ACTIVE_TAG_RE = re.compile(r"<\s*/?\s*(?:img|svg|iframe|script|object|embed|link|style|meta)\b[^>]*>", re.IGNORECASE)


def sanitize_llm_markdown_for_streamlit(text: str) -> str:
    """Strips Markdown image loads and active HTML tags from LLM text before rendering in Streamlit.

    Prevents prompt-injection data exfiltration via remote image fetches (`![](https://...)`)
    or raw HTML embeds while preserving readable Markdown text and code blocks.
    """
    if not text:
        return ""
    cleaned = _MD_IMAGE_INLINE_RE.sub(
        lambda m: f"[Image removed: {(m.group(1) or 'remote image').strip()}]",
        text,
    )
    cleaned = _MD_IMAGE_REF_RE.sub(
        lambda m: f"[Image removed: {(m.group(1) or 'remote image').strip()}]",
        cleaned,
    )
    cleaned = _HTML_ACTIVE_TAG_RE.sub("[HTML element removed]", cleaned)
    return cleaned


def _brand_logo_data_uri() -> str:
    logo_path = ROOT_DIR / "backend" / "static" / "logo_badge.png"
    if logo_path.exists():
        b64 = base64.b64encode(logo_path.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{b64}"
    return ""


def _render_onboarding_generator(default_user_email: str = "") -> None:
    st.markdown("#### Zero-Key Read-Only Customer Organization Onboarding Kit")
    col_a, col_b = st.columns(2)
    with col_a:
        ob_cust = st.text_input("Customer Name", value="", placeholder="e.g., Acme Financial Corp")
        ob_org = st.text_input("Customer GCP Organization ID", value="", placeholder="e.g., 123456789012")
        ob_dom = st.text_input("Primary Domain", value="", placeholder="e.g., acme.com")
    with col_b:
        ob_seed = st.text_input("Customer Seed Project ID", value="", placeholder="e.g., prj-sec-governance")
        ob_mode = st.selectbox("Onboarding Mode", options=["impersonated_sa", "direct_user"])
        ob_email = st.text_input("Authorized User Email (Impersonator)", value=default_user_email, placeholder="you@company.com")

    if not ob_org.strip(" "):
        st.info("Enter the Customer GCP Organization ID above to preview and download the zero-key Cloud Shell & Terraform onboarding kit.")
        return

    try:
        kit = generate_customer_onboarding_kit(
            customer_name=ob_cust if ob_cust != "" else "Enterprise Customer",
            organization_id=ob_org,
            organization_domain=ob_dom,
            seed_project_id=ob_seed,
            onboarding_mode=ob_mode,
            impersonator_user_email=ob_email,
        )
        st.download_button(
            label="Download Complete Onboarding Kit (.zip)",
            data=build_onboarding_kit_zip(kit),
            file_name=f"agentic_iam_onboarding_{kit['organization_id']}.zip",
            mime="application/zip",
        )
        kt1, kt2, kt3 = st.tabs(["Cloud Shell (.sh)", "Terraform (.tf)", "Guide & Offboarding"])
        with kt1:
            st.code(kit["bash_script"], language="bash")
        with kt2:
            st.code(kit["terraform_hcl"], language="hcl")
        with kt3:
            st.markdown(kit["guide_markdown"])
    except ValueError as exc:
        st.error(str(exc))


def main() -> None:
    favicon_path = ROOT_DIR / "backend" / "static" / "favicon.png"
    st.set_page_config(
        page_title="Agentic IAM Accelerator | Clean-Slate Console",
        page_icon=str(favicon_path) if favicon_path.exists() else None,
        layout="wide",
    )
    st.markdown(AISPR_STREAMLIT_CSS, unsafe_allow_html=True)

    if "iam_session_id" not in st.session_state:
        st.session_state["iam_session_id"] = secrets.token_hex(16)
    if "iam_owner_email" not in st.session_state:
        st.session_state["iam_owner_email"] = ""

    sid = st.session_state["iam_session_id"]
    owner_email = st.session_state["iam_owner_email"]
    sess = get_inspection_session(sid, owner_email) if owner_email else None

    scope_input = ""
    run_scan_clicked = False

    with st.sidebar:
        st.markdown("### Zero-Trust Target Session")
        if sess is None:
            conn_mode = st.selectbox(
                "Connection Mode",
                options=["impersonated_sa", "direct_user"],
                format_func=lambda m: "SA Impersonation (Recommended)" if m == "impersonated_sa" else "Direct User Read-Only Access",
            )
            target_sa = ""
            conn_org_id = st.text_input("Target Organization ID (Digits, Optional)", value="", placeholder="Auto-discovered if blank")
            if conn_mode == "impersonated_sa":
                target_sa = st.text_input(
                    "Target Service Account Email",
                    value="",
                    placeholder="sa-iam-assessor@seed-proj.iam.gserviceaccount.com",
                )
                sa_parts = target_sa.strip().split("@") if target_sa.strip().endswith(".iam.gserviceaccount.com") else []
                sa_n = sa_parts[0] if len(sa_parts) == 2 else "sa-iam-assessor"
                seed_step = (
                    f'SEED_PROJECT_ID="{sa_parts[1].split(".")[0]}"'
                    if len(sa_parts) == 2
                    else 'SEED_PROJECT_ID="${DEVSHELL_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}" && { [ -n "$SEED_PROJECT_ID" ] && [ "$SEED_PROJECT_ID" != "(unset)" ] || SEED_PROJECT_ID=$(gcloud projects list --filter="lifecycleState:ACTIVE" --limit=1 --format="value(projectId)"); } && [ -n "$SEED_PROJECT_ID" ]'
                )
                org_step = (
                    f'ORG_ID="{conn_org_id.strip()}"'
                    if conn_org_id.strip().isdigit()
                    else 'ORG_ID=$(gcloud projects get-ancestors "${SEED_PROJECT_ID}" --format="value(type,id)" 2>/dev/null | awk \'$1=="organization"{print $2}\') && { [ -n "$ORG_ID" ] || ORG_ID=$(gcloud organizations list --limit=1 --format="value(ID)"); } && [ -n "$ORG_ID" ]'
                )
                one_line_cmd = (
                    f'{seed_step} && AUTHORIZED_USER_EMAIL="$(gcloud config get-value account 2>/dev/null)" && [ -n "$AUTHORIZED_USER_EMAIL" ] && '
                    f'SA_NAME="{sa_n}" && SA_EMAIL="${{SA_NAME}}@${{SEED_PROJECT_ID}}.iam.gserviceaccount.com" && '
                    'gcloud services enable cloudasset.googleapis.com cloudresourcemanager.googleapis.com iam.googleapis.com iamcredentials.googleapis.com orgpolicy.googleapis.com recommender.googleapis.com policyanalyzer.googleapis.com policysimulator.googleapis.com logging.googleapis.com --project="${SEED_PROJECT_ID}" && '
                    f'{org_step} && '
                    '(gcloud iam service-accounts describe "${SA_EMAIL}" --project="${SEED_PROJECT_ID}" >/dev/null 2>&1 || (gcloud iam service-accounts create "${SA_NAME}" --display-name="Agentic IAM Read-Only Assessor" --project="${SEED_PROJECT_ID}" && sleep 5)) && '
                    'gcloud projects add-iam-policy-binding "${SEED_PROJECT_ID}" --member="serviceAccount:${SA_EMAIL}" --role="roles/serviceusage.serviceUsageConsumer" --condition=None --quiet >/dev/null && '
                    'gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" --project="${SEED_PROJECT_ID}" --member="user:${AUTHORIZED_USER_EMAIL}" --role="roles/iam.serviceAccountTokenCreator" --condition=None --quiet >/dev/null && '
                    'for ROLE in roles/browser roles/cloudasset.viewer roles/iam.securityReviewer roles/orgpolicy.policyViewer roles/recommender.viewer roles/logging.viewer; do gcloud organizations add-iam-policy-binding "${ORG_ID}" --member="serviceAccount:${SA_EMAIL}" --role="${ROLE}" --condition=None --quiet >/dev/null; done && '
                    'echo "Service Account: ${SA_EMAIL} | Org ID: ${ORG_ID}"'
                )
                with st.expander("1-Line SA Setup (gcloud)", expanded=False):
                    st.caption("Paste in Cloud Shell (auto-detects Project & Org ID):")
                    st.code(one_line_cmd, language="bash")
            user_token = st.text_input("Google OAuth2 Access Token", value="", type="password", placeholder="ya29.a0...")
            opt_bq = st.text_input("Optional Customer BQ Table", value="", placeholder="project.dataset.table")

            if st.button("Connect & Verify Readiness", use_container_width=True, type="primary"):
                try:
                    ident = verify_google_token(user_token.strip())
                    sess = store_inspection_session(
                        session_id=sid,
                        owner_email=ident.email,
                        user_access_token=user_token.strip(),
                        connection_mode=conn_mode,
                        target_sa_email=target_sa.strip(),
                        organization_id=conn_org_id.strip(),
                        optional_customer_bq_table=opt_bq.strip(),
                    )
                    with bind_inspection_session_context(sess):
                        readiness = verify_customer_onboarding_readiness(organization_id=conn_org_id.strip())
                    update_session_organization_metadata(
                        sid,
                        ident.email,
                        organization_id=readiness.get("organization_id", ""),
                        organization_domain=readiness.get("organization_display_name", ""),
                    )
                    st.session_state["iam_owner_email"] = ident.email
                    st.session_state["iam_readiness"] = readiness
                    st.rerun()
                except Exception as exc:
                    st.error(f"Connection failed: {exc}")
        else:
            st.success(f"Connected as `{sess.owner_email}` ({sess.effective_identity_label})")
            if st.button("Disconnect & Wipe Session", use_container_width=True):
                wipe_inspection_session(sid, sess.owner_email)
                st.session_state.pop("iam_book", None)
                st.session_state.pop("iam_readiness", None)
                st.session_state["iam_owner_email"] = ""
                st.rerun()

            with bind_inspection_session_context(sess):
                hierarchy = discover_organization_hierarchy(sess.organization_id or None)
                orgs = hierarchy.get("accessible_organizations") or []
                org_ids = [o["organization_id"] for o in orgs] or ([sess.organization_id] if sess.organization_id else [])
                org_labels = {o["organization_id"]: f"organizations/{o['organization_id']} ({o['display_name']})" for o in orgs}

                st.markdown("### Organization & Project Scope")
                selected_org_id = st.selectbox(
                    "GCP Organization",
                    options=org_ids,
                    format_func=lambda oid: org_labels.get(oid, f"organizations/{oid}"),
                )
                if selected_org_id and selected_org_id != hierarchy.get("organization_id"):
                    hierarchy = discover_organization_hierarchy(selected_org_id)

                active_projects = hierarchy.get("projects") or []
                proj_ids = [p["project_id"] for p in active_projects]
                proj_labels = {p["project_id"]: f"{p['display_name']} ({p['project_id']})" for p in active_projects}

                scan_all_org = st.checkbox("Scan Entire Organization (All Active Projects)", value=False)
                if scan_all_org or not proj_ids:
                    scope_input = f"organizations/{selected_org_id}"
                else:
                    chosen_projs = st.multiselect(
                        "Select 1 or Multiple Projects",
                        options=proj_ids,
                        default=proj_ids[:1],
                        format_func=lambda pid: proj_labels.get(pid, pid),
                    )
                    scope_input = (
                        f"organizations/{selected_org_id}/projects:{','.join(sorted(chosen_projs))}"
                        if chosen_projs
                        else f"organizations/{selected_org_id}"
                    )

                st.caption(f"Canonical Scope: `{scope_input}`")
                st.caption(f"Engine: `{DEFAULT_VERTEX_MODEL}` (`{DEFAULT_VERTEX_LOCATION}`)")

                run_scan_clicked = st.button("Run Live ADK Scan", use_container_width=True, type="primary")

                if st.button("Generate DOCX / PDF / ZIP", use_container_width=True):
                    with st.spinner(f"Executing 5-Plane Google ADK ({DEFAULT_VERTEX_MODEL})..."):
                        generate_all_executive_deliverables(
                            scope=scope_input,
                            model_name=DEFAULT_VERTEX_MODEL,
                            force_refresh=True,
                        )
                    st.success("Ephemeral session deliverables ready below.")

                out_dir = sess.session_export_dir
                docx_file = out_dir / "Agentic_IAM_Posture_Acceleration_Report.docx"
                pdf_file = out_dir / "Agentic_IAM_Posture_Acceleration_Report.pdf"
                zip_file = out_dir / "agentic_iam_terraform_remediation_bundle.zip"

                if docx_file.exists() or pdf_file.exists() or zip_file.exists():
                    st.markdown("#### Session Deliverables")
                if docx_file.exists():
                    st.download_button(
                        label="Download Report (.docx)",
                        data=docx_file.read_bytes(),
                        file_name=docx_file.name,
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        use_container_width=True,
                    )
                if pdf_file.exists():
                    st.download_button(
                        label="Download Report (.pdf)",
                        data=pdf_file.read_bytes(),
                        file_name=pdf_file.name,
                        mime="application/pdf",
                        use_container_width=True,
                    )
                if zip_file.exists():
                    st.download_button(
                        label="Download Terraform (.zip)",
                        data=zip_file.read_bytes(),
                        file_name=zip_file.name,
                        mime="application/zip",
                        use_container_width=True,
                    )

    logo_uri = _brand_logo_data_uri()
    logo_tag = (
        f'<img class="aispr-logo" src="{logo_uri}" alt="Agentic IAM Accelerator" width="38" height="38" />'
        if logo_uri
        else ""
    )
    badge_text = html.escape(scope_input) if scope_input else "No Organization Connected (Clean-Slate)"
    st.markdown(
        f"""
        <div class="aispr-header">
          <div class="aispr-brand">
            {logo_tag}
            <div>
              <div class="aispr-title">Agentic IAM - Identity Security Posture Review</div>
              <div class="aispr-sub">Google Cloud Security Consulting | Zero-Trust Clean-Slate IAM Modernization</div>
            </div>
          </div>
          <div class="aispr-badge">{badge_text}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if sess is None:
        st.info(
            "Clean-Slate Workspace Active: zero Organization data is preloaded. "
            "Connect your target GCP Organization in the left sidebar using Service Account Impersonation "
            "(`sa-iam-assessor@...`) or Direct Read-Only Access, or generate a customer onboarding kit below."
        )
        _render_onboarding_generator()
        return

    with bind_inspection_session_context(sess):
        if run_scan_clicked:
            with st.spinner(f"Evaluating `{scope_input}` with Google ADK ({DEFAULT_VERTEX_MODEL}, global)..."):
                st.session_state["iam_book"] = run_posture_book_assessment_sync(
                    scope=scope_input,
                    model_name=DEFAULT_VERTEX_MODEL,
                    force_refresh=True,
                )

        tab_onboarding, tab_scorecard, tab_triad, tab_inv, tab_graph, tab_iac, tab_chat = st.tabs(
            [
                "Connect & Onboard Org",
                "Posture Health Dashboard",
                "Identity Triad & Findings",
                "Accounts, Keys & Secrets",
                "Attack Path Topology",
                "Least-Privilege & Terraform",
                "ADK Copilot",
            ]
        )

        with tab_onboarding:
            if "iam_readiness" in st.session_state:
                st.markdown("#### Live 6-Point Readiness Verification")
                st.dataframe(st.session_state["iam_readiness"].get("checks", []), use_container_width=True, hide_index=True)
            _render_onboarding_generator(default_user_email=sess.owner_email)

        with tab_inv:
            from backend.tools.asset_key_secret_inventory import build_accounts_keys_secrets_inventory
            live_inv = (st.session_state["iam_book"].asset_inventory if st.session_state.get("iam_book") else None) or build_accounts_keys_secrets_inventory(scope_input)
            k = live_inv.kpis
            ic1, ic2, ic3, ic4 = st.columns(4)
            ic1.metric("Accounts & Groups", k.human_and_group_accounts_total, f"{k.standing_admin_accounts_count} Standing Admins")
            ic2.metric("Service Accounts & Keys", f"{k.service_accounts_total} SAs", f"{k.user_managed_sa_keys_total} User Keys ({k.sa_keys_over_90d_count} >90d)")
            ic3.metric("Secret Manager Secrets", k.secrets_total_count, f"{k.secrets_unrotated_count} Unrotated")
            ic4.metric("KMS & API Keys", f"{k.kms_cryptokeys_total} KMS / {k.api_keys_total_count} API", f"{k.unrestricted_api_keys_count} Unrestricted API Keys")
            s1, s2, s3, s4, s5, s6 = st.tabs(
                ["Accounts", "Service Accounts", "SA Keys", "Secrets (Metadata)", "Cloud KMS Keys", "API Keys & Custom Roles"]
            )
            with s1:
                st.dataframe([x.model_dump() for x in live_inv.accounts], use_container_width=True, hide_index=True)
            with s2:
                st.dataframe([x.model_dump() for x in live_inv.service_accounts], use_container_width=True, hide_index=True)
            with s3:
                st.dataframe([x.model_dump() for x in live_inv.sa_keys], use_container_width=True, hide_index=True)
            with s4:
                st.dataframe([x.model_dump() for x in live_inv.secrets], use_container_width=True, hide_index=True)
            with s5:
                st.dataframe([x.model_dump() for x in live_inv.kms_keys], use_container_width=True, hide_index=True)
            with s6:
                st.markdown("##### Google Cloud API Keys")
                st.dataframe([x.model_dump() for x in live_inv.api_keys], use_container_width=True, hide_index=True)
                st.markdown("##### Custom IAM Roles")
                st.dataframe([x.model_dump() for x in live_inv.custom_roles], use_container_width=True, hide_index=True)

        book = st.session_state.get("iam_book")
        if book is None:
            for t in (tab_scorecard, tab_triad, tab_graph, tab_iac):
                with t:
                    st.info(f"Target session connected (`{scope_input}`). Click **Run Live ADK Scan** in the sidebar to run the 5-plane Google ADK assessment.")
        else:
            if book.telemetry:
                tel = book.telemetry
                tcol1, tcol2, tcol3, tcol4 = st.columns(4)
                tcol1.metric("Vertex AI Model", tel.model_version)
                tcol2.metric("Location", tel.location)
                tcol3.metric("ADK Tokens", f"{tel.tokens.total_tokens:,}")
                tcol4.metric("Live Tool Calls", f"{len(tel.tool_calls)}")

            with tab_scorecard:
                render_posture_scorecard(book.scorecard, book.attack_graph.escalation_paths_count)
                sc_obj = book.scorecard
                st.caption(
                    f"**18-Control Deterministic Baseline:** `{sc_obj.deterministic_composite_score}%` • "
                    f"**Bounded ADK Calibration:** `{sc_obj.agentic_calibration_delta:+.1f}%` • "
                    f"**Final Score:** `{sc_obj.overall_posture_score}% ({sc_obj.maturity_tier})`"
                )
                if sc_obj.agentic_calibration_rationale:
                    st.info(
                        f"**ADK Specialist Contextual Calibration:** "
                        f"{sanitize_llm_markdown_for_streamlit(sc_obj.agentic_calibration_rationale)}"
                    )
                if sc_obj.framework_benchmarks:
                    st.markdown("#### Security Framework Alignment Benchmarks")
                    bm_cols = st.columns(len(sc_obj.framework_benchmarks))
                    for bcol, bm in zip(bm_cols, sc_obj.framework_benchmarks):
                        bcol.metric(
                            bm.framework_name,
                            f"{bm.alignment_score_pct}%",
                            f"{bm.controls_passed}/{bm.controls_evaluated} controls >=85%",
                        )
                if sc_obj.control_evaluations:
                    st.markdown("#### 18-Control Deterministic & Framework Evaluation Matrix")
                    st.dataframe([c.model_dump() for c in sc_obj.control_evaluations], use_container_width=True, hide_index=True)
                st.markdown("#### Executive Summary")
                st.markdown(
                    sanitize_llm_markdown_for_streamlit(book.executive_narrative_markdown),
                    unsafe_allow_html=False,
                )

            with tab_triad:
                render_triad_breakdown(book.triad_matrix)

            with tab_graph:
                render_attack_graph_view(book.attack_graph, sess.session_export_dir / "attack_path_graph_dark.png")

            with tab_iac:
                st.markdown("#### Least-Privilege Role & PAM JIT Recommendations")
                st.dataframe([r.model_dump() for r in book.recommendations], use_container_width=True, hide_index=True)
                st.markdown("#### 6. Estimativa de impacto e bundle Terraform consultivo (não validado)")
                st.caption(
                    f"Bundle consultivo sem execução de Policy Simulator replay • "
                    f"{book.iac_bundle.audit_sample_size} eventos na amostra "
                    f"({(book.iac_bundle.audit_sample_window_start or '')[:10]} a {(book.iac_bundle.audit_sample_window_end or '')[:10]})."
                )
                tf_tab1, tf_tab2, tf_tab3, tf_tab4 = st.tabs(
                    ["iam.tf", "pam_entitlements.tf", "org_policies.tf", "main.tf & variables.tf"]
                )
                with tf_tab1:
                    st.code(book.iac_bundle.iam_tf, language="hcl")
                with tf_tab2:
                    st.code(book.iac_bundle.pam_entitlements_tf, language="hcl")
                with tf_tab3:
                    st.code(book.iac_bundle.org_policies_tf, language="hcl")
                with tf_tab4:
                    st.code(book.iac_bundle.main_tf + "\n" + book.iac_bundle.variables_tf, language="hcl")

        with tab_chat:
            st.markdown("#### Google ADK Multi-Agent Coordinator (`iam_coordinator`)")
            prompt_val = st.text_area(
                "Ask iam_coordinator about live IAM bindings, attack paths, or remediations:",
                value=f"Summarize the highest-priority IAM posture risks in {scope_input} and how to remediate them.",
            )
            if st.button("Ask ADK Coordinator", type="primary"):
                with st.spinner(f"Running Google ADK iam_coordinator ({DEFAULT_VERTEX_MODEL}, global)..."):
                    chat_res = run_coordinator_chat_sync(
                        prompt=prompt_val,
                        scope=scope_input,
                        caller_email=sess.owner_email,
                        model_name=DEFAULT_VERTEX_MODEL,
                    )
                st.markdown(
                    sanitize_llm_markdown_for_streamlit(chat_res["response"]),
                    unsafe_allow_html=False,
                )
                st.json(
                    {
                        "model_version": chat_res["model_version"],
                        "location": chat_res["location"],
                        "tokens": chat_res["tokens"],
                        "tool_calls": chat_res["tool_calls"],
                    }
                )


if __name__ == "__main__":
    main()
