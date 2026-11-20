"""Comprehensive Executive DOCX, PDF, Inventory JSON, Attack Path Graph & Terraform Report Generator (`report_generator.py`).

Generates complete, resilient CISO & Security Engineering deliverables from live GCP telemetry
and Google ADK `Runner` (`location='global'`) multi-agent synthesis:
  1. `Agentic_IAM_Posture_Acceleration_Report.docx` (Full 7-Section Word Book via `python-docx`)
  2. `Agentic_IAM_Posture_Acceleration_Report.pdf` (Full 7-Section Executive PDF via `reportlab` with embedded Unicode TTF fonts)
  3. `attack_path_graph.png` (High-DPI Live NetworkX Attack Path & Escalation Diagram)
  4. `agentic_iam_terraform_remediation_bundle.zip` (Advisory Terraform HCL Bundle + `MANUAL_STEPS.md`)
  5. `accounts_keys_secrets_inventory.json` + `posture_acceleration_book.json` + `iam_posture_findings.jsonl`

Both DOCX and PDF generators consume a single canonical `report_view_model(book)` so section headings,
column headers, counts, Org Policy labels, and truncated list totals match across UI, DOCX, and PDF.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import logging
import os
import re
import secrets
import struct
import textwrap
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from xml.sax.saxutils import escape as xml_escape

from docx import Document as DocxDocument
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Image as RLImage,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.doctemplate import LayoutError

from backend.agents.coordinator import run_posture_book_assessment
from backend.agents.telemetry import run_async_from_sync
from backend.config import resolve_vertex_model, settings
from backend.models.findings import (
    AccountsKeysSecretsInventory,
    PostureAccelerationBook,
)
from backend.session_vault import get_active_inspection_session
from backend.tools.asset_key_secret_inventory import build_accounts_keys_secrets_inventory
from backend.tools.cai_collector import (
    active_export_dir,
    normalize_gcp_scope,
    parse_assessment_scope,
    persist_findings_list_to_bigquery,
)
from backend.tools.graph_engine import render_attack_graph_png

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants, Font Registration & XML 1.0 Sanitization
# ---------------------------------------------------------------------------

SECTION_6_TITLE = "6. Estimativa de impacto e bundle Terraform consultivo (não validado)"

FONTS_DIR = Path(__file__).resolve().parent / "static" / "fonts"
PDF_FONT_REGULAR = "DejaVuSans"
PDF_FONT_BOLD = "DejaVuSans-Bold"
PDF_FONT_ITALIC = "DejaVuSans-Oblique"
PDF_FONT_BOLD_ITALIC = "DejaVuSans-BoldOblique"
PDF_FONT_MONO = "DejaVuSansMono"
PDF_FONT_MONO_BOLD = "DejaVuSansMono-Bold"
PDF_FONT_CJK = "HeiseiKakuGo-W5"

_PDF_FONTS_REGISTERED = False

# Invalid XML 1.0 characters: control chars except TAB (0x09), LF (0x0A), CR (0x0D),
# plus UTF-16 surrogates (0xD800-0xDFFF) and non-characters (0xFFFE, 0xFFFF).
_INVALID_XML10_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufffe\uffff]")

# CJK / East Asian glyph runs routed to ReportLab's built-in Unicode CID font
# so strings such as "日本語 →" render cleanly alongside embedded DejaVuSans TTF glyphs.
_CJK_RUN_RE = re.compile(
    r"([\u3000-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uac00-\ud7af]+)"
)

_RGB_CACHE: Dict[str, RGBColor] = {}


def _sanitize_xml10(value: Any) -> str:
    """Strips characters illegal in XML 1.0 so python-docx and ReportLab never raise ValueError."""
    if value is None:
        return ""
    return _INVALID_XML10_RE.sub("", str(value))


def sanitize_xml10(value: Any) -> str:
    """Public alias for `_sanitize_xml10`."""
    return _sanitize_xml10(value)


def _rgb(hex_color: str) -> RGBColor:
    clean = hex_color.lstrip("#").upper()
    cached = _RGB_CACHE.get(clean)
    if cached is None:
        cached = RGBColor(int(clean[0:2], 16), int(clean[2:4], 16), int(clean[4:6], 16))
        _RGB_CACHE[clean] = cached
    return cached


def _ensure_pdf_unicode_fonts() -> None:
    """Registers bundled open-source DejaVu Unicode TTF fonts and CJK fallback once per process."""
    global _PDF_FONTS_REGISTERED
    if _PDF_FONTS_REGISTERED:
        return

    font_files = {
        PDF_FONT_REGULAR: FONTS_DIR / "DejaVuSans.ttf",
        PDF_FONT_BOLD: FONTS_DIR / "DejaVuSans-Bold.ttf",
        PDF_FONT_ITALIC: FONTS_DIR / "DejaVuSans-Oblique.ttf",
        PDF_FONT_BOLD_ITALIC: FONTS_DIR / "DejaVuSans-BoldOblique.ttf",
        PDF_FONT_MONO: FONTS_DIR / "DejaVuSansMono.ttf",
        PDF_FONT_MONO_BOLD: FONTS_DIR / "DejaVuSansMono-Bold.ttf",
    }
    registered = set(pdfmetrics.getRegisteredFontNames())
    for font_name, font_path in font_files.items():
        if font_name not in registered:
            if not font_path.exists():
                raise FileNotFoundError(f"Bundled Unicode PDF font missing: {font_path}")
            pdfmetrics.registerFont(TTFont(font_name, str(font_path)))

    pdfmetrics.registerFontFamily(
        PDF_FONT_REGULAR,
        normal=PDF_FONT_REGULAR,
        bold=PDF_FONT_BOLD,
        italic=PDF_FONT_ITALIC,
        boldItalic=PDF_FONT_BOLD_ITALIC,
    )
    pdfmetrics.registerFontFamily(
        PDF_FONT_MONO,
        normal=PDF_FONT_MONO,
        bold=PDF_FONT_MONO_BOLD,
        italic=PDF_FONT_MONO,
        boldItalic=PDF_FONT_MONO_BOLD,
    )
    if PDF_FONT_CJK not in set(pdfmetrics.getRegisteredFontNames()):
        pdfmetrics.registerFont(UnicodeCIDFont(PDF_FONT_CJK))

    _PDF_FONTS_REGISTERED = True


def format_org_policy_status_label(enforced: Optional[bool]) -> str:
    """Canonical 3-state Org Policy label shared across UI, DOCX, and PDF."""
    if enforced is True:
        return "ENFORCED"
    if enforced is False:
        return "NOT ENFORCED"
    return "NOT EVALUATED"


def _format_capped_list(
    items: Sequence[Any],
    *,
    max_items: int = 10,
    total: Optional[int] = None,
    sep: str = ", ",
    empty: str = "None",
) -> str:
    """Formats a potentially long sequence with an explicit `(+N more)` suffix preserving the real total."""
    cleaned = [_sanitize_xml10(x).strip() for x in (items or []) if _sanitize_xml10(x).strip()]
    effective_total = max(int(total or 0), len(cleaned))
    if not cleaned:
        if effective_total > 0:
            return f"({effective_total} total)"
        return empty
    shown = cleaned[:max_items]
    remaining = max(0, effective_total - len(shown))
    joined = sep.join(shown)
    if remaining > 0:
        return f"{joined} (+{remaining} more)"
    return joined


def _truncate_cell_text(text: str, max_chars: int) -> str:
    clean = _sanitize_xml10(text)
    if len(clean) <= max_chars:
        return clean
    return clean[: max(16, max_chars - 16)].rstrip() + " ... [truncated]"


# ---------------------------------------------------------------------------
# Dynamic Report Metric & Formatting Helpers
# ---------------------------------------------------------------------------

def _overall_perm_reduction_pct(book: PostureAccelerationBook) -> float:
    total_granted = sum(r.permissions_granted_count for r in book.recommendations)
    total_removed = sum(r.excess_permissions_removed for r in book.recommendations)
    if total_granted <= 0:
        return 0.0
    return round((total_removed / total_granted) * 100.0, 2)


def _format_sample_window(window_start: str, window_end: str) -> str:
    s = (window_start or "").strip()
    e = (window_end or "").strip()
    if not s and not e:
        return "janela indisponível"
    s_short = s[:16].replace("T", " ") if s else "?"
    e_short = e[:16].replace("T", " ") if e else "?"
    if s[:10] and e[:10] and s[:10] != e[:10]:
        return f"{s[:10]} a {e[:10]}"
    return f"{s_short} a {e_short} UTC"


def _iac_sample_size(book: PostureAccelerationBook) -> int:
    """Returns Python-computed Cloud Audit Log sample size (never trusting LLM-authored call counts)."""
    iac_sz = int(getattr(book.iac_bundle, "audit_sample_size", 0) or 0)
    if iac_sz > 0:
        return iac_sz
    if book.asset_inventory is not None:
        return int(getattr(book.asset_inventory, "audit_sample_size", 0) or 0)
    return 0


def _iac_sample_window_label(book: PostureAccelerationBook) -> str:
    iac = book.iac_bundle
    if iac.audit_sample_window_start or iac.audit_sample_window_end:
        return _format_sample_window(iac.audit_sample_window_start, iac.audit_sample_window_end)
    if book.asset_inventory is not None and (
        book.asset_inventory.audit_sample_window_start or book.asset_inventory.audit_sample_window_end
    ):
        return _format_sample_window(
            book.asset_inventory.audit_sample_window_start,
            book.asset_inventory.audit_sample_window_end,
        )
    return "janela indisponível"


def _iac_projects_coverage_label(book: PostureAccelerationBook) -> str:
    iac = book.iac_bundle
    if iac.audit_total_projects_in_scope > 0:
        return f"{iac.audit_projects_queried}/{iac.audit_total_projects_in_scope}"
    if book.asset_inventory is not None and book.asset_inventory.audit_total_projects_in_scope > 0:
        return f"{book.asset_inventory.audit_projects_queried}/{book.asset_inventory.audit_total_projects_in_scope}"
    return "0/0"


def _pillar_basis_summary(pillar: Any) -> str:
    base = (
        f"{pillar.compliant_principals}/{pillar.total_principals_evaluated} compliant principals "
        f"({pillar.critical_findings_count} Crit, {pillar.high_findings_count} High, {pillar.medium_findings_count} Med)"
    )
    if pillar.modernization_priorities:
        return f"{base}; priorities: {'; '.join(pillar.modernization_priorities[:2])}"
    return base


def _domain_score_label(scorecard: Any, domain_key: str, score: float) -> str:
    """Formats a per-domain score cell; domains with zero evaluated controls render as N/A instead of 0.0%."""
    if domain_key in (getattr(scorecard, "not_evaluated_domains", None) or []):
        return "N/A (not evaluated)"
    return f"{score}%"


def _ensure_inventory(
    book: PostureAccelerationBook,
    *,
    allow_live_fetch: bool = False,
) -> AccountsKeysSecretsInventory:
    if book.asset_inventory is not None:
        return book.asset_inventory
    if not allow_live_fetch:
        return AccountsKeysSecretsInventory(scope=book.scope)
    try:
        inv = build_accounts_keys_secrets_inventory(book.scope)
        book.asset_inventory = inv
        return inv
    except Exception:
        return AccountsKeysSecretsInventory(scope=book.scope)


def _wrap_code_lines(code_text: str, width: int = 100) -> str:
    clean = _sanitize_xml10(code_text or "")
    wrapped: List[str] = []
    for raw_line in clean.splitlines():
        if len(raw_line) <= width:
            wrapped.append(raw_line)
        else:
            chunks = textwrap.wrap(
                raw_line,
                width=width,
                subsequent_indent="    ",
                break_long_words=True,
                break_on_hyphens=False,
            )
            wrapped.extend(chunks or [""])
    return "\n".join(wrapped)


# ---------------------------------------------------------------------------
# Lightweight Markdown Parser (Headings, Lists, Bold & Inline Code)
# ---------------------------------------------------------------------------

_INLINE_TOKEN_RE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`)")


def _parse_inline_markdown_spans(text: str) -> List[Tuple[str, str]]:
    """Splits text into typed inline spans: ('text'|'bold'|'code', content)."""
    clean = _sanitize_xml10(text)
    spans: List[Tuple[str, str]] = []
    pos = 0
    for m in _INLINE_TOKEN_RE.finditer(clean):
        if m.start() > pos:
            spans.append(("text", clean[pos : m.start()]))
        tok = m.group(0)
        if tok.startswith("**") and tok.endswith("**") and len(tok) > 4:
            spans.append(("bold", tok[2:-2]))
        elif tok.startswith("`") and tok.endswith("`") and len(tok) > 2:
            spans.append(("code", tok[1:-1]))
        else:
            spans.append(("text", tok))
        pos = m.end()
    if pos < len(clean):
        spans.append(("text", clean[pos:]))
    return spans or [("text", "")]


def _parse_markdown_blocks(md_text: str) -> List[Dict[str, Any]]:
    """Parses executive narrative Markdown into headings, bullets, numbered items, and paragraphs."""
    clean = _sanitize_xml10(md_text or "")
    blocks: List[Dict[str, Any]] = []
    para_lines: List[str] = []

    def _flush_para() -> None:
        if para_lines:
            blocks.append({"type": "paragraph", "text": " ".join(para_lines).strip()})
            para_lines.clear()

    for raw_line in clean.splitlines():
        line = raw_line.strip()
        if not line:
            _flush_para()
            continue

        m_head = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m_head:
            _flush_para()
            level = len(m_head.group(1))
            blocks.append({"type": "heading", "level": min(level + 1, 3), "text": m_head.group(2).strip()})
            continue

        m_bullet = re.match(r"^[-*•]\s+(.*)$", line)
        if m_bullet:
            _flush_para()
            blocks.append({"type": "bullet", "text": m_bullet.group(1).strip()})
            continue

        m_num = re.match(r"^(\d+)[.)]\s+(.*)$", line)
        if m_num:
            _flush_para()
            blocks.append({"type": "numbered", "number": m_num.group(1), "text": m_num.group(2).strip()})
            continue

        para_lines.append(line)

    _flush_para()
    return blocks


def _build_wave_rows(book: PostureAccelerationBook) -> List[List[str]]:
    """Builds 1 row per remediation action so large waves paginate cleanly in DOCX and PDF."""
    wave_titles = (
        "Wave 1 (Days 0-30 — Immediate Risk Containment)",
        "Wave 2 (Days 31-60 — Least-Privilege, Custom Roles & PAM JIT)",
        "Wave 3 (Days 61-90 — Keyless WIF, Guardrails & Continuous Assurance)",
    )
    wave_buckets: Dict[str, List[Tuple[str, str, str]]] = {title: [] for title in wave_titles}

    for f in book.triad_matrix.findings:
        w = (f.remediation_wave or "").lower()
        summary = f"{f.principal} ({f.role}): {f.recommended_modernization}"
        item = (f.finding_id, f.severity.value, summary)
        if "wave 3" in w or "61" in w:
            wave_buckets[wave_titles[2]].append(item)
        elif "wave 2" in w or "31" in w:
            wave_buckets[wave_titles[1]].append(item)
        else:
            wave_buckets[wave_titles[0]].append(item)

    for r in book.recommendations:
        summary = (
            f"{r.principal}: {r.recommended_action} -> {r.proposed_role_or_entitlement} "
            f"(-{r.permission_reduction_pct}%)"
        )
        item = (r.recommendation_id, "PAM_JIT" if r.pam_jit_eligible else "RIGHTSIZE", summary)
        if r.pam_jit_eligible:
            wave_buckets[wave_titles[1]].append(item)
        else:
            wave_buckets[wave_titles[2]].append(item)

    rows: List[List[str]] = []
    for w_title in wave_titles:
        items = wave_buckets[w_title]
        if not items:
            rows.append(
                [
                    w_title,
                    "BASELINE",
                    "LOW",
                    "Maintain baseline continuous monitoring and quarterly Policy Analyzer reviews.",
                ]
            )
            continue
        for item_id, sev_or_kind, summary in items:
            rows.append([w_title, item_id, sev_or_kind, summary])
    return rows


def _inventory_kpi_rows(inv: AccountsKeysSecretsInventory) -> List[List[str]]:
    k = inv.kpis
    return [
        [
            "Human, Group, Domain & External Principals",
            str(k.human_and_group_accounts_total),
            f"{k.internal_users_count} internal users | {k.security_groups_count} security groups | {k.external_and_public_principals_count} external/public ({k.consumer_gmail_accounts_count} consumer Gmail)",
            "CRITICAL" if k.consumer_gmail_accounts_count > 0 else ("HIGH" if k.external_and_public_principals_count > 0 else "LOW"),
        ],
        [
            "Standing High-Admin Accounts (24/7 Unconditioned)",
            str(k.standing_admin_accounts_count),
            f"{k.standing_admin_accounts_count} workforce/external accounts hold Owner/Editor/OrgAdmin/SecurityAdmin without temporal CEL",
            "HIGH" if k.standing_admin_accounts_count > 0 else "LOW",
        ],
        [
            "Principals with Secret Manager or KMS Reach",
            str(k.principals_with_secret_or_kms_access),
            "Total non-service-agent accounts and SAs capable of reading secrets or administering/using KMS keys",
            "MEDIUM" if k.principals_with_secret_or_kms_access > 3 else "LOW",
        ],
        [
            "Customer & Default Service Accounts",
            str(k.service_accounts_total),
            f"{k.default_sas_with_roles_count} Default Compute/AppEngine SAs hold active roles | {k.disabled_sas_count} disabled | {k.google_service_agents_count} Google service agents excluded",
            "HIGH" if k.default_sas_with_roles_count > 0 else "LOW",
        ],
        [
            "Service Account Keys (USER_MANAGED vs SYSTEM)",
            f"{k.user_managed_sa_keys_total} User / {k.system_managed_sa_keys_total} System",
            f"{k.sa_keys_over_90d_count} static keys >90 days | {k.user_uploaded_sa_keys_count} user-uploaded external public keys",
            "CRITICAL" if k.sa_keys_over_90d_count > 0 else ("HIGH" if k.user_managed_sa_keys_total > 0 else "LOW"),
        ],
        [
            "Secret Manager Secrets (Metadata-Only)",
            f"{k.secrets_total_count} Secrets ({k.secret_versions_enabled_count} active versions)",
            f"{k.secrets_unrotated_count} secrets without rotation policy | {k.secrets_without_cmek_count} using Google-managed encryption (non-CMEK)",
            "MEDIUM" if (k.secrets_unrotated_count > 0 or k.secrets_without_cmek_count > 0) else "LOW",
        ],
        [
            "Cloud KMS KeyRings & CryptoKeys",
            f"{k.kms_cryptokeys_total} Keys in {k.kms_keyrings_count} KeyRings",
            f"{k.kms_keys_missing_90d_rotation_count} symmetric keys missing <=90d rotation | {k.kms_hsm_keys_count} HSM-protected | {k.kms_sod_conflicts_count} KMS Admin+Decrypter SoD conflicts",
            "HIGH" if k.kms_sod_conflicts_count > 0 else ("MEDIUM" if k.kms_keys_missing_90d_rotation_count > 0 else "LOW"),
        ],
        [
            "Google Cloud API Keys",
            str(k.api_keys_total_count),
            f"{k.unrestricted_api_keys_count} unrestricted API keys | {k.api_keys_over_90d_count} keys older than 90 days",
            "HIGH" if k.unrestricted_api_keys_count > 0 else ("MEDIUM" if k.api_keys_over_90d_count > 0 else "LOW"),
        ],
        [
            "Custom IAM Roles",
            str(k.custom_roles_total_count),
            f"{k.custom_roles_with_escalation_perms_count} custom roles include privilege-escalation permissions (iam.roles.update, getAccessToken, setIamPolicy, actAs)",
            "HIGH" if k.custom_roles_with_escalation_perms_count > 0 else "LOW",
        ],
        [
            "Workload Identity Federation (WIF) & Org Policies",
            f"{k.wif_pools_count} Pools / {k.wif_providers_count} Providers",
            f"{k.unconditioned_wif_providers_count} unconditioned WIF providers | {k.org_policies_enforced_count}/{k.org_policies_evaluated_count} key Org Policies enforced",
            "CRITICAL" if k.unconditioned_wif_providers_count > 0 else "LOW",
        ],
    ]


# ---------------------------------------------------------------------------
# Unified Report View Model (Consumed Identically by DOCX and PDF Builders)
# ---------------------------------------------------------------------------

def report_view_model(
    book: PostureAccelerationBook,
    *,
    allow_live_fetch: bool = False,
) -> Dict[str, Any]:
    """Builds the canonical sections, subsection titles, column headers, and rows shared by DOCX & PDF."""
    sc = book.scorecard
    triad = book.triad_matrix
    ag = book.attack_graph
    iac = book.iac_bundle
    inv = _ensure_inventory(book, allow_live_fetch=allow_live_fetch)
    tel = book.telemetry
    active_model = tel.model_version if tel else settings.vertex_model_id
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    red_pct = _overall_perm_reduction_pct(book)
    sample_events = _iac_sample_size(book)
    sample_window = _iac_sample_window_label(book)
    projects_cov = _iac_projects_coverage_label(book)
    inv_window = _format_sample_window(inv.audit_sample_window_start, inv.audit_sample_window_end)

    active_sess = get_active_inspection_session()
    storage_desc = (
        f"Customer BigQuery: {active_sess.optional_customer_bq_table} (GcpIamPostureFinding)"
        if (active_sess and active_sess.optional_customer_bq_table)
        else "Isolated Ephemeral Session Vault (Zero Host Retention — JSONL / DOCX / PDF / ZIP)"
    )
    tel_summary = (
        f"{tel.model_version} (location={tel.location}) • {tel.tokens.total_tokens:,} tokens "
        f"(in={tel.tokens.input_tokens:,}, out={tel.tokens.output_tokens:,}, thought={tel.tokens.thought_tokens:,}) • "
        f"{len(tel.tool_calls)} live GCP tool calls across {', '.join(tel.agents_invoked)} in {tel.latency_ms / 1000.0:.1f}s"
        if tel
        else f"Google ADK 5-Plane Multi-Agent System • {active_model} (location=global)"
    )

    metadata_table = {
        "title": None,
        "intro": None,
        "headers": ["Engagement Metadata Field", "Live Verified Value"],
        "rows": [
            ["Assessed GCP Resource Scope", book.scope],
            ["Primary Cloud Identity Domain", book.organization_domain],
            ["Scoring & Framework Methodology", sc.scoring_methodology],
            ["Google ADK & Vertex AI Telemetry", tel_summary],
            [
                "Vault & Credential Coverage",
                f"{inv.kpis.human_and_group_accounts_total} Accounts • {inv.kpis.service_accounts_total} SAs • "
                f"{len(inv.sa_keys)} SA Keys • {inv.kpis.secrets_total_count} Secrets • "
                f"{inv.kpis.kms_cryptokeys_total} KMS Keys • {inv.kpis.api_keys_total_count} API Keys",
            ],
            ["Session Storage & Schema", storage_desc],
            ["Generated UTC Timestamp", now_str],
        ],
        "col_weights": [2.2, 5.3],
        "header_bg": "0F172A",
        "alt_bg": "F8FAFC",
        "bold_cols": (0,),
        "severity_col": None,
        "font_pt": 8.2,
    }

    # Section 1: Executive Narrative, Scorecard & 18-Control Matrix
    sec1_tables: List[Dict[str, Any]] = [
        {
            "title": None,
            "intro": None,
            "headers": ["Posture Dimension", "Verified Score", "Live Scope Metric", "Telemetry Basis & Modernization Impact"],
            "rows": [
                [
                    "Overall IAM Posture Score",
                    f"{sc.overall_posture_score}% ({sc.maturity_tier})",
                    f"{sc.total_bindings_analyzed} live bindings ({sc.data_completeness_pct:.1f}% data completeness)",
                    (
                        f"18-Control Baseline: {sc.deterministic_composite_score}% | "
                        f"Bounded ADK Calibration: {sc.agentic_calibration_delta:+.1f}% | "
                        f"Pre-Cap: {sc.pre_cap_score}% | Cap Effect: {sc.critical_cap_delta:+.1f}%"
                    ),
                ],
                [
                    "Internal Workforce Identities (22%)",
                    _domain_score_label(sc, "INTERNAL_IDENTITIES", sc.internal_identities_score),
                    f"{triad.internal_identities.compliant_principals}/{triad.internal_identities.total_principals_evaluated} compliant",
                    _pillar_basis_summary(triad.internal_identities),
                ],
                [
                    "External & Partner Boundaries (18%)",
                    _domain_score_label(sc, "EXTERNAL_IDENTITIES", sc.external_identities_score),
                    f"{triad.external_identities.compliant_principals}/{triad.external_identities.total_principals_evaluated} compliant",
                    _pillar_basis_summary(triad.external_identities),
                ],
                [
                    "Workload & Service Accounts (22%)",
                    _domain_score_label(sc, "WORKLOAD_IDENTITIES", sc.workload_identities_score),
                    f"{triad.workload_service_accounts.compliant_principals}/{triad.workload_service_accounts.total_principals_evaluated} compliant",
                    _pillar_basis_summary(triad.workload_service_accounts),
                ],
                [
                    "Least-Privilege Optimization Index (20%)",
                    _domain_score_label(sc, "LEAST_PRIVILEGE", sc.least_privilege_index),
                    f"{sc.overprivileged_bindings_count} recs",
                    f"Eliminates {sc.excess_permissions_eliminated:,} excess permissions ({red_pct:.2f}% surface reduction)",
                ],
                [
                    "Attack-Graph & Impersonation Resilience (18%)",
                    _domain_score_label(sc, "GRAPH_RESILIENCE", sc.impersonation_resilience_score),
                    f"{ag.total_nodes} nodes / {ag.total_edges} edges",
                    f"{ag.escalation_paths_count} escalation paths & {ag.toxic_combinations_count} toxic combinations (max depth: {ag.max_chain_depth})",
                ],
                [
                    "Findings Severity Distribution",
                    f"{sc.critical_findings} Crit / {sc.high_findings} High / {sc.medium_findings} Med / {sc.low_findings} Low",
                    f"Bundle {iac.bundle_id}",
                    f"Advisory Terraform HCL (unvalidated; {sample_events:,} eventos na amostra, janela {sample_window})",
                ],
            ],
            "col_weights": [1.85, 1.2, 1.15, 3.3],
            "header_bg": "1E3A8A",
            "alt_bg": "F8FAFC",
            "bold_cols": (0, 1),
            "severity_col": None,
            "font_pt": 8.0,
        }
    ]
    sec1_notes: List[str] = []
    if sc.agentic_calibration_rationale:
        sec1_notes.append(
            f"ADK Specialist Contextual Calibration ({sc.agentic_calibration_delta:+.1f}%, Pre-Cap {sc.pre_cap_score}%): "
            f"{sc.agentic_calibration_rationale}"
        )
    if sc.critical_exposure_cap_applied:
        sec1_notes.append(
            f"NIST / CISA Critical Exposure Ceiling Triggered (<=84.0%, Cap Effect {sc.critical_cap_delta:+.1f}%): "
            f"{sc.critical_exposure_cap_applied}"
        )

    if sc.framework_benchmarks:
        sec1_tables.append(
            {
                "title": "1.1 Authoritative Security Framework Alignment Benchmarks",
                "intro": None,
                "headers": ["Security Framework Benchmark", "Alignment %", "Controls >=85%", "Primary Identity & Access Focus"],
                "rows": [
                    [
                        bm.framework_name,
                        f"{bm.alignment_score_pct}%",
                        f"{bm.controls_passed} / {bm.controls_evaluated}",
                        bm.primary_focus,
                    ]
                    for bm in sc.framework_benchmarks
                ],
                "col_weights": [2.1, 0.85, 1.05, 3.5],
                "header_bg": "0F172A",
                "alt_bg": "F8FAFC",
                "bold_cols": (0, 1),
                "severity_col": None,
                "font_pt": 8.0,
            }
        )

    if sc.control_evaluations:
        sec1_tables.append(
            {
                "title": "1.2 Complete 18-Control Deterministic & Framework Audit Matrix",
                "intro": None,
                "headers": [
                    "Control ID",
                    "Status",
                    "Control Title, Formula & Frameworks",
                    "Exact Ratio (Weight)",
                    "Score",
                    "Live GCP Evidence",
                ],
                "rows": [
                    [
                        ce.control_id,
                        ce.status,
                        f"{ce.control_title}\nFrameworks: {', '.join(ce.framework_mappings)}\nFormula: {ce.formula_expression}",
                        f"{ce.numerator} / {ce.denominator}\n({ce.unit_label} • {ce.domain_weight_pct}%)",
                        f"{ce.deterministic_score_pct}%",
                        ce.evidence_summary,
                    ]
                    for ce in sc.control_evaluations
                ],
                "col_weights": [0.78, 0.72, 2.35, 0.95, 0.58, 2.12],
                "header_bg": "1E3A8A",
                "alt_bg": "F8FAFC",
                "bold_cols": (0, 4),
                "severity_col": 1,
                "font_pt": 7.7,
            }
        )

    # Section 2: Identity Triad Matrix & Findings Register
    sec2_tables = [
        {
            "title": None,
            "intro": None,
            "headers": [
                "Identity Triad Pillar",
                "Score",
                "Compliant / Evaluated",
                "All Anti-Patterns Detected",
                "All Modernization Priorities",
            ],
            "rows": [
                [
                    p.display_name,
                    _domain_score_label(sc, dom_key, p.posture_score),
                    f"{p.compliant_principals} / {p.total_principals_evaluated}\n"
                    f"({p.critical_findings_count} Crit, {p.high_findings_count} High, {p.medium_findings_count} Med)",
                    "\n".join(f"• {x}" for x in p.key_anti_patterns_detected) or "None detected",
                    "\n".join(f"• {x}" for x in p.modernization_priorities) or "Maintain continuous monitoring",
                ]
                for dom_key, p in (
                    ("INTERNAL_IDENTITIES", triad.internal_identities),
                    ("EXTERNAL_IDENTITIES", triad.external_identities),
                    ("WORKLOAD_IDENTITIES", triad.workload_service_accounts),
                )
            ],
            "col_weights": [1.3, 0.6, 1.0, 2.3, 2.3],
            "header_bg": "0F766E",
            "alt_bg": "F0FDFA",
            "bold_cols": (0, 1),
            "severity_col": None,
            "font_pt": 7.9,
        },
        {
            "title": "2.1 Complete Identity Triad Findings Register",
            "intro": None,
            "headers": [
                "Finding / View / Wave",
                "Severity",
                "Principal, Role & Resource",
                "Frameworks & Live Evidence",
                "Recommended Modernization",
            ],
            "rows": [
                [
                    f"{f.finding_id}\n[{f.cspr_view_id}]\n{f.remediation_wave}",
                    f.severity.value,
                    f"Pillar: {f.triad_category.value}\nPrincipal: {f.principal}\nRole: {f.role}\nResource: {f.resource}"
                    + (f"\nCEL: {f.condition_expression}" if f.condition_expression else ""),
                    f"Frameworks: {', '.join(f.framework_citations)}\nVector: {f.risk_vector}\nEvidence: {f.evidence_summary}",
                    f.recommended_modernization,
                ]
                for f in triad.findings
            ],
            "col_weights": [0.95, 0.7, 1.9, 2.1, 1.85],
            "header_bg": "1E293B",
            "alt_bg": "F8FAFC",
            "bold_cols": (0,),
            "severity_col": 1,
            "font_pt": 7.8,
        },
    ]

    # Section 3: Comprehensive Accounts, Service Accounts, Keys, KMS & Secrets Inventory
    sec3_tables = [
        {
            "title": "3.1 Executive Credential & Vault Indicators (KPI Summary)",
            "intro": None,
            "headers": ["Inventory Indicator", "Live Count", "Detailed Telemetry Breakdown", "Risk"],
            "rows": _inventory_kpi_rows(inv),
            "col_weights": [1.85, 1.15, 3.8, 0.7],
            "header_bg": "0F172A",
            "alt_bg": "F8FAFC",
            "bold_cols": (0, 1),
            "severity_col": 3,
            "font_pt": 7.9,
        },
        {
            "title": f"3.2 Human, Group, Domain & External Accounts Ledger ({len(inv.accounts)} Principals)",
            "intro": (
                f"Cloud Audit Log sample coverage: {inv.audit_sample_size:,} eventos na amostra "
                f"(janela: {inv_window}; projetos consultados: {inv.audit_projects_queried}/{inv.audit_total_projects_in_scope}; "
                f"is_sample={inv.audit_sample_is_sample})."
            ),
            "headers": [
                "Principal & Type",
                "Domain / Ext",
                "Bindings & Projects",
                "Privilege Flags (Admin / Secret / KMS / Impersonate / Amostra)",
                "Roles Granted",
                "Risk",
            ],
            "rows": [
                [
                    f"{a.principal}\n({a.principal_type})",
                    f"{a.domain}\nExternal={a.is_external}",
                    f"{a.bindings_count} bindings\nProjects: {_format_capped_list(a.projects, max_items=6)}",
                    (
                        f"StandingAdmin={a.is_standing_admin} | Secrets={a.can_access_secrets} | "
                        f"KMS={a.can_use_or_admin_kms} | Impersonate={a.can_impersonate_sa} | "
                        f"Eventos na amostra={a.audit_events_30d} ({inv_window})"
                    ),
                    _format_capped_list(a.roles, max_items=10),
                    a.risk_level,
                ]
                for a in inv.accounts
            ],
            "col_weights": [1.55, 0.85, 1.05, 1.6, 1.85, 0.6],
            "header_bg": "1E3A8A",
            "alt_bg": "F8FAFC",
            "bold_cols": (0,),
            "severity_col": 5,
            "font_pt": 7.5,
        },
        {
            "title": f"3.3 Service Accounts & Attached Workloads Ledger ({len(inv.service_accounts)} SAs)",
            "intro": None,
            "headers": [
                "Service Account & Subtype",
                "Project & State",
                "Keys (User / System / Max Age)",
                "Attached Workloads & Vault Reach",
                "Granted IAM Roles",
                "Risk",
            ],
            "rows": [
                [
                    f"{s.email}\n({s.sa_subtype})",
                    f"{s.project_id}\n{'DISABLED' if s.disabled else 'ENABLED'}",
                    f"User={s.user_managed_keys_count} | System={s.system_managed_keys_count}\nOldest User Key: {s.oldest_user_key_age_days}d",
                    f"Workloads: {_format_capped_list(s.attached_workloads, max_items=6)}\nSecret/KMS Access={s.can_access_secrets_or_kms}",
                    _format_capped_list(s.granted_roles, max_items=10, empty="No direct IAM bindings"),
                    s.risk_level,
                ]
                for s in inv.service_accounts
            ],
            "col_weights": [1.7, 0.95, 1.1, 1.45, 1.7, 0.6],
            "header_bg": "0F766E",
            "alt_bg": "F0FDFA",
            "bold_cols": (0,),
            "severity_col": 5,
            "font_pt": 7.5,
        },
        {
            "title": f"3.4 Service Account Cryptographic Keys Ledger ({len(inv.sa_keys)} Keys)",
            "intro": None,
            "headers": ["Key ID", "Service Account & Project", "Key Type & Origin", "Algorithm", "Created -> Expires (Age)", "Risk"],
            "rows": [
                [
                    k.key_id,
                    f"{k.sa_email}\nProject: {k.project_id}",
                    f"{k.key_type}\n({k.key_origin})",
                    k.key_algorithm,
                    f"{k.valid_after_time} -> {k.valid_before_time}\nAge: {k.age_days} days",
                    k.risk_level,
                ]
                for k in inv.sa_keys
            ],
            "col_weights": [0.95, 2.1, 1.15, 1.05, 1.6, 0.65],
            "header_bg": "7F1D1D",
            "alt_bg": "FEF2F2",
            "bold_cols": (0, 2),
            "severity_col": 5,
            "font_pt": 7.6,
        },
        {
            "title": f"3.5 Secret Manager Governance Ledger — Metadata-Only ({len(inv.secrets)} Secrets)",
            "intro": None,
            "headers": [
                "Secret Name & Project",
                "Replication & Active Versions",
                "Encryption (CMEK vs Google)",
                "Rotation & Expiry",
                "IAM Principals with Access",
                "Risk",
            ],
            "rows": [
                [
                    f"{s.secret_name}\nProject: {s.project_id}\nCreated: {s.created_at or '—'}",
                    f"{s.replication_policy}\nEnabled Versions: {s.active_versions_count}",
                    f"{s.encryption_type}" + (f"\n{s.kms_key_name}" if s.kms_key_name else ""),
                    f"Rotated={s.rotation_configured}"
                    + (f" ({s.rotation_period_days}d, next {s.next_rotation_time})" if s.rotation_configured else " (No rotation policy)")
                    + (f"\nExpire/TTL: {s.expire_or_ttl}" if s.expire_or_ttl else ""),
                    (
                        f"{max(int(getattr(s, 'accessor_principals_total', 0) or 0), len(s.accessor_principals))} principals "
                        f"({s.broad_primitive_accessors_count} Owner/Editor):\n"
                        + _format_capped_list(
                            s.accessor_principals,
                            max_items=8,
                            total=max(int(getattr(s, "accessor_principals_total", 0) or 0), len(s.accessor_principals)),
                        )
                    ),
                    s.risk_level,
                ]
                for s in inv.secrets
            ],
            "col_weights": [1.35, 1.05, 1.15, 1.25, 2.05, 0.65],
            "header_bg": "1E293B",
            "alt_bg": "F8FAFC",
            "bold_cols": (0,),
            "severity_col": 5,
            "font_pt": 7.5,
        },
        {
            "title": f"3.6 Cloud KMS KeyRings, CryptoKeys & SoD Ledger ({len(inv.kms_keys)} CryptoKeys)",
            "intro": None,
            "headers": [
                "CryptoKey & KeyRing",
                "Project & Location",
                "Purpose, Protection & Algorithm",
                "Rotation Period (<=90d SLA)",
                "KMS Admin + Decrypter SoD Conflicts",
                "Risk",
            ],
            "rows": [
                [
                    f"{k.crypto_key_name}\nKeyRing: {k.key_ring}",
                    f"{k.project_id}\n({k.location})",
                    f"{k.purpose}\n{k.protection_level} • {k.algorithm}",
                    f"{k.rotation_period_days}d (next {k.next_rotation_time})"
                    if k.rotation_period_days
                    else ("N/A (Asymmetric)" if k.purpose != "ENCRYPT_DECRYPT" else "UNROTATED"),
                    _format_capped_list(k.sod_conflict_principals, max_items=8, empty="None (Clean SoD)"),
                    k.risk_level,
                ]
                for k in inv.kms_keys
            ],
            "col_weights": [1.5, 1.05, 1.65, 1.0, 1.65, 0.65],
            "header_bg": "1E3A8A",
            "alt_bg": "F8FAFC",
            "bold_cols": (0,),
            "severity_col": 5,
            "font_pt": 7.6,
        },
        {
            "title": f"3.7 Google Cloud API Keys ({len(inv.api_keys)}) & Custom IAM Roles ({len(inv.custom_roles)})",
            "intro": None,
            "headers": ["API Key Name & UID", "Project", "Created & Age", "Restriction Mode", "Restricted Target Services", "Risk"],
            "rows": [
                [
                    f"{ak.display_name}\nUID: {ak.key_uid}",
                    ak.project_id,
                    f"{ak.created_at or '—'} ({ak.age_days}d)",
                    ak.restriction_mode,
                    _format_capped_list(ak.restricted_services, max_items=8, empty="ALL APIS ALLOWED (Unrestricted)"),
                    ak.risk_level,
                ]
                for ak in inv.api_keys
            ],
            "col_weights": [1.6, 1.05, 1.15, 1.2, 1.85, 0.65],
            "header_bg": "7C2D12",
            "alt_bg": "F8FAFC",
            "bold_cols": (0,),
            "severity_col": 5,
            "font_pt": 7.6,
        },
        {
            "title": None,
            "intro": None,
            "headers": [
                "Custom Role Name & Title",
                "Scope",
                "Stage & Bound Count",
                "Permissions Count",
                "Privilege-Escalation Permissions Present",
                "Risk",
            ],
            "rows": [
                [
                    f"{cr.title}\n({cr.role_name})",
                    f"{cr.scope_level}\n{cr.project_or_org}",
                    f"{cr.stage} • {cr.assigned_bindings_count} bindings",
                    str(cr.included_permissions_count),
                    _format_capped_list(cr.escalation_permissions, max_items=10, empty="None detected"),
                    cr.risk_level,
                ]
                for cr in inv.custom_roles
            ],
            "col_weights": [1.9, 1.2, 1.0, 0.6, 2.15, 0.65],
            "header_bg": "312E81",
            "alt_bg": "F8FAFC",
            "bold_cols": (0,),
            "severity_col": 5,
            "font_pt": 7.6,
        },
        {
            "title": "3.8 Workload Identity Federation (WIF) & Effective Organization Policies",
            "intro": None,
            "headers": ["WIF Pool & Provider", "Project & State", "External OIDC / AWS Issuer", "CEL Attribute Condition", "Risk"],
            "rows": [
                [
                    f"{w.pool_name} / {w.provider_name}",
                    f"{w.project_id} ({w.state})",
                    w.issuer_uri,
                    w.attribute_condition if w.has_attribute_condition else "MISSING ATTRIBUTE CONDITION",
                    w.risk_level,
                ]
                for w in inv.wif_providers
            ],
            "col_weights": [1.8, 1.2, 1.9, 1.95, 0.65],
            "header_bg": "0F766E",
            "alt_bg": "F8FAFC",
            "bold_cols": (0,),
            "severity_col": 4,
            "font_pt": 7.7,
        },
        {
            "title": None,
            "intro": None,
            "headers": ["Organization Policy Constraint", "Effective Status", "Evaluated Resource Scope", "Verification Telemetry"],
            "rows": [
                [
                    op.constraint,
                    format_org_policy_status_label(op.enforced),
                    op.evaluated_on,
                    f"enforced={op.enforced} ({op.status})",
                ]
                for op in inv.org_policies
            ],
            "col_weights": [2.75, 1.1, 1.85, 1.8],
            "header_bg": "0F172A",
            "alt_bg": "F8FAFC",
            "bold_cols": (0, 1),
            "severity_col": 1,
            "font_pt": 7.9,
        },
    ]

    # Section 4: Attack Path Graph & Centrality
    sec4_tables = [
        {
            "title": "4.1 NetworkX High-Centrality Choke-Point Ranking",
            "intro": None,
            "headers": [
                "Principal / Workload Node ID",
                "Node Type",
                "Betweenness Centrality",
                "Degree Centrality",
                "In / Out Edges",
                "Choke-Point Score",
            ],
            "rows": [
                [
                    str(cp.get("node_id", "")),
                    str(cp.get("node_type", "")),
                    f"{float(cp.get('betweenness_centrality', 0.0)):.4f}",
                    f"{float(cp.get('degree_centrality', 0.0)):.4f}",
                    f"in={cp.get('in_degree', 0)} / out={cp.get('out_degree', 0)}",
                    f"{cp.get('combined_chokepoint_score', 0.0)}",
                ]
                for cp in (ag.high_centrality_principals or [])[:15]
            ],
            "col_weights": [2.65, 0.95, 0.95, 0.9, 0.95, 1.1],
            "header_bg": "1E293B",
            "alt_bg": "F8FAFC",
            "bold_cols": (0, 5),
            "severity_col": None,
            "font_pt": 7.8,
        },
        {
            "title": "4.2 Discovered Escalation Chains & Toxic Permission Combinations",
            "intro": None,
            "headers": [
                "Path ID & Toxic Class",
                "Severity",
                "Blast Radius",
                "Entry Principal -> Crown Jewel",
                "Full Hop Sequence & Exploited Permissions",
                "Mitigation Control",
            ],
            "rows": [
                [
                    f"{p.path_id}\n{p.toxic_combination_type}",
                    p.severity.value,
                    f"{p.blast_radius_score} / 10.0",
                    f"From: {p.entry_principal}\nTo: {p.target_crown_jewel}",
                    _format_capped_list(p.hop_sequence, max_items=10, sep=" -> ", empty="—")
                    + "\nPermissions: "
                    + _format_capped_list(p.permissions_exploited, max_items=8, sep="; ", empty="None"),
                    p.mitigation_control,
                ]
                for p in ag.critical_paths
            ],
            "col_weights": [1.1, 0.65, 0.65, 1.4, 2.05, 1.65],
            "header_bg": "7F1D1D",
            "alt_bg": "FEF2F2",
            "bold_cols": (0, 2),
            "severity_col": 1,
            "font_pt": 7.6,
        },
    ]

    # Section 5: Least-Privilege Right-Sizing & PAM JIT
    sec5_tables = [
        {
            "title": None,
            "intro": None,
            "headers": [
                "ID & Persona",
                "Principal, Resource & Current Role",
                "Action & PAM JIT Governance",
                "Used / Granted Perms",
                "Reduction",
                "Proposed Custom Role / Entitlement",
            ],
            "rows": [
                [
                    f"{r.recommendation_id}\n({r.persona_classification})",
                    f"{r.principal}\nCurrent: {r.current_role}\nResource: {r.resource}",
                    f"{r.recommended_action}\nPAM JIT={r.pam_jit_eligible}"
                    + (
                        f" ({r.pam_max_duration}, approver={r.pam_approver_group or 'secops-approvers'})"
                        if r.pam_jit_eligible
                        else ""
                    ),
                    f"{r.permissions_exercised_90d} / {r.permissions_granted_count:,}\n(-{r.excess_permissions_removed:,} excess)",
                    f"-{r.permission_reduction_pct:.2f}%",
                    r.proposed_role_or_entitlement,
                ]
                for r in book.recommendations
            ],
            "col_weights": [0.95, 1.75, 1.35, 1.05, 0.7, 1.7],
            "header_bg": "1E3A8A",
            "alt_bg": "F8FAFC",
            "bold_cols": (0, 4),
            "severity_col": None,
            "font_pt": 7.7,
        }
    ]

    # Section 6: Estimativa de impacto e bundle Terraform consultivo (não validado)
    sec6_tables = [
        {
            "title": None,
            "intro": None,
            "headers": [
                "Estimate ID",
                "Principal & Target Resource",
                "Proposed Modernization",
                "Eventos na amostra",
                "Verdict & Risk Reduction",
            ],
            "rows": [
                [
                    s.simulation_id,
                    f"{s.principal}\n{s.target_resource}",
                    s.proposed_change_summary,
                    (
                        f"{s.sample_events_observed:,} eventos na amostra\n"
                        f"({_format_sample_window(s.sample_window_start, s.sample_window_end) if (s.sample_window_start or s.sample_window_end) else sample_window})"
                    ),
                    f"{s.simulator_verdict} (-{s.excess_risk_eliminated_pct}%)",
                ]
                for s in iac.policy_simulations
            ],
            "col_weights": [0.95, 1.8, 2.0, 1.4, 1.35],
            "header_bg": "0F766E",
            "alt_bg": "F0FDFA",
            "bold_cols": (0, 4),
            "severity_col": None,
            "font_pt": 7.8,
        }
    ]
    sec6_code_blocks = [
        {"title": "6.1 main.tf — Provider & Backend Configuration", "code": (iac.main_tf or "# Empty module").strip()},
        {"title": "6.2 variables.tf — Parameterized Organization, Domain & Approver Inputs", "code": (iac.variables_tf or "# Empty module").strip()},
        {"title": "6.3 iam.tf — Custom Roles, Group RBAC, Dedicated Workload SAs & Keyless WIF", "code": (iac.iam_tf or "# Empty module").strip()},
        {"title": "6.4 pam_entitlements.tf — Privileged Access Manager (PAM) Just-In-Time Entitlements", "code": (iac.pam_entitlements_tf or "# Empty module").strip()},
        {"title": "6.5 org_policies.tf — Preventive Organization Policy Guardrails", "code": (iac.org_policies_tf or "# Empty module").strip()},
    ]
    if getattr(iac, "manual_steps_md", ""):
        sec6_code_blocks.append(
            {
                "title": "6.6 MANUAL_STEPS.md — Manual Binding Removal Commands (Review Before Executing)",
                "code": iac.manual_steps_md.strip(),
            }
        )

    # Section 7: Phased 3-Wave Modernization Roadmap (1 row per action) & ADK Trace
    sec7_tables: List[Dict[str, Any]] = [
        {
            "title": None,
            "intro": None,
            "headers": [
                "Implementation Wave",
                "Action ID",
                "Priority / Type",
                "Prescribed Engineering & Governance Deliverable",
            ],
            "rows": _build_wave_rows(book),
            "col_weights": [1.85, 0.85, 0.85, 3.95],
            "header_bg": "1E3A8A",
            "alt_bg": "F8FAFC",
            "bold_cols": (0, 1),
            "severity_col": 2,
            "font_pt": 7.8,
        }
    ]
    if tel and tel.tool_calls:
        sec7_tables.append(
            {
                "title": "7.1 Live Google ADK Specialist Tool Call Audit Log",
                "intro": None,
                "headers": ["#", "ADK Agent", "Read-Only Tool Invoked", "Arguments", "Status", "Duration"],
                "rows": [
                    [
                        str(i),
                        tc.agent,
                        tc.tool,
                        str(tc.args),
                        tc.status.upper(),
                        f"{tc.duration_ms:.0f} ms",
                    ]
                    for i, tc in enumerate(tel.tool_calls, start=1)
                ],
                "col_weights": [0.35, 1.3, 2.05, 2.4, 0.7, 0.7],
                "header_bg": "0F172A",
                "alt_bg": "F8FAFC",
                "bold_cols": (0, 1, 2),
                "severity_col": None,
                "font_pt": 7.6,
            }
        )

    sections = [
        {
            "key": "sec_1",
            "title": "1. Executive Narrative, Posture Scorecard & Security Framework Matrix",
            "page_break_before": False,
            "intro": None,
            "narrative_markdown": book.executive_narrative_markdown,
            "notes": sec1_notes,
            "graph_placeholder": False,
            "tables": sec1_tables,
            "code_blocks": [],
        },
        {
            "key": "sec_2",
            "title": "2. Identity Triad Matrix & Complete Posture Findings Register",
            "page_break_before": True,
            "intro": None,
            "narrative_markdown": "",
            "notes": [],
            "graph_placeholder": False,
            "tables": sec2_tables,
            "code_blocks": [],
        },
        {
            "key": "sec_3",
            "title": "3. Comprehensive Accounts, Service Accounts, Keys, KMS & Secrets Inventory",
            "page_break_before": True,
            "intro": (
                "100% live, read-only metadata inventory across IAM Principals, Customer & Default Service Accounts, "
                "Service Account Cryptographic Keys (USER_MANAGED & SYSTEM_MANAGED), Secret Manager Secrets (metadata and "
                "IAM accessors only — zero secret payload reads), Cloud KMS KeyRings/CryptoKeys & Separation-of-Duties, "
                "Google Cloud API Keys, Custom IAM Roles, Workload Identity Federation, and Organization Policies."
            ),
            "narrative_markdown": "",
            "notes": [],
            "graph_placeholder": False,
            "tables": sec3_tables,
            "code_blocks": [],
        },
        {
            "key": "sec_4",
            "title": "4. NetworkX Attack Path Topology, Centrality & Escalation Chains",
            "page_break_before": True,
            "intro": (
                f"Directed graph modeling across {ag.total_nodes} nodes and {ag.total_edges} edges identified "
                f"{ag.escalation_paths_count} escalation paths and {ag.toxic_combinations_count} toxic permission combinations "
                f"(maximum chain depth: {ag.max_chain_depth} hops)."
            ),
            "narrative_markdown": "",
            "notes": [],
            "graph_placeholder": True,
            "tables": sec4_tables,
            "code_blocks": [],
        },
        {
            "key": "sec_5",
            "title": "5. Least-Privilege Right-Sizing, Custom Roles & PAM JIT Entitlements",
            "page_break_before": False,
            "intro": None,
            "narrative_markdown": "",
            "notes": [],
            "graph_placeholder": False,
            "tables": sec5_tables,
            "code_blocks": [],
        },
        {
            "key": "sec_6",
            "title": SECTION_6_TITLE,
            "page_break_before": True,
            "intro": (
                f"All advisory OpenTofu/Terraform modules were synthesized via deterministic HCL templates from the "
                f"Google ADK iac_generator ({active_model}) plan and are NOT validated by Policy Simulator replay. "
                f"Impact estimates below are based on {sample_events:,} eventos na amostra "
                f"(janela: {sample_window}; projetos consultados: {projects_cov}; is_sample={iac.audit_sample_is_sample}). "
                f"Review and validate via Policy Simulator and terraform plan in staging before applying."
            ),
            "narrative_markdown": "",
            "notes": [],
            "graph_placeholder": False,
            "tables": sec6_tables,
            "code_blocks": sec6_code_blocks,
        },
        {
            "key": "sec_7",
            "title": "7. Phased 3-Wave Modernization Roadmap & Google ADK Execution Trace",
            "page_break_before": True,
            "intro": None,
            "narrative_markdown": "",
            "notes": [],
            "graph_placeholder": False,
            "tables": sec7_tables,
            "code_blocks": [],
        },
    ]

    return {
        "kicker": "GOOGLE CLOUD SECURITY ARCHITECTURE  |  AGENTIC IAM & CREDENTIAL VAULT ACCELERATOR",
        "title": "IAM Posture, Accounts, Keys, Secrets & Least-Privilege Acceleration Book",
        "subtitle": (
            f"Scope: {book.scope} ({book.organization_domain})  •  "
            f"Engine: Google ADK + {active_model} (Vertex AI global)  •  {now_str}"
        ),
        "advisory_disclaimer": book.advisory_disclaimer,
        "coverage_warnings": list(getattr(sc, "coverage_warnings", None) or []),
        "data_completeness_pct": float(getattr(sc, "data_completeness_pct", 100.0)),
        "metadata_table": metadata_table,
        "sections": sections,
    }


# ---------------------------------------------------------------------------
# DOCX Formatting Helpers (O(N) Grid Table + XML 1.0 Safe + Markdown Rendering)
# ---------------------------------------------------------------------------

def _shade_docx_cell(cell: Any, hex_color: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color.lstrip("#"))
    tc_pr.append(shd)


def _set_docx_cell_text(
    cell: Any,
    text: str,
    *,
    bold: bool = False,
    size_pt: float = 8.4,
    color_hex: str = "1E293B",
    font_name: str = "Calibri",
    is_fresh_cell: bool = False,
) -> None:
    clean_text = _sanitize_xml10(text)
    if not is_fresh_cell and cell.text:
        cell.text = ""
    p = cell.paragraphs[0]
    run = p.add_run(clean_text)
    if bold:
        run.bold = True
    run.font.name = font_name
    run.font.size = Pt(size_pt)
    if color_hex != "0F172A":
        run.font.color.rgb = _rgb(color_hex)


def _severity_color_hex(sev: str) -> str:
    return {
        "CRITICAL": "991B1B",
        "HIGH": "B45309",
        "MEDIUM": "1D4ED8",
        "LOW": "0F766E",
        "PASS": "0F766E",
        "ENFORCED": "0F766E",
        "PARTIAL": "B45309",
        "NOT EVALUATED": "64748B",
        "NOT_EVALUATED": "64748B",
        "FAIL": "991B1B",
        "NOT ENFORCED": "B45309",
    }.get(str(sev).upper(), "334155")


def _add_docx_grid_table(
    doc: Any,
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    header_bg: str = "1E3A8A",
    alt_bg: str = "F8FAFC",
    bold_cols: Sequence[int] = (0,),
    severity_col: Optional[int] = None,
    font_pt: float = 8.1,
) -> None:
    """Renders a styled Word table in O(N) time by fetching `tbl.rows` once and `row.cells` once per row."""
    safe_rows = list(rows) if rows else [["No records discovered in evaluated scope"] + ["—"] * (len(headers) - 1)]
    bold_col_set = set(bold_cols)
    num_cols = len(headers)
    tbl = doc.add_table(rows=len(safe_rows) + 1, cols=num_cols)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER

    # Pre-fetch all rows ONCE (avoids O(N^2) XML traversal in python-docx)
    tbl_rows = list(tbl.rows)
    header_cells = list(tbl_rows[0].cells)
    hdr_size_pt = font_pt + 0.4
    for c_idx, h in enumerate(headers):
        cell = header_cells[c_idx]
        _shade_docx_cell(cell, header_bg)
        _set_docx_cell_text(
            cell,
            h,
            bold=True,
            size_pt=hdr_size_pt,
            color_hex="FFFFFF",
            is_fresh_cell=True,
        )

    # For very large tables (>200 rows), keep per-cell XML lean to preserve <3s build times
    compact_mode = len(safe_rows) > 200
    body_pt = Pt(font_pt)
    for r_idx, r_vals in enumerate(safe_rows, start=1):
        row_cells = list(tbl_rows[r_idx].cells)
        shade_alt = (r_idx % 2 == 1) and not compact_mode
        for c_idx in range(min(num_cols, len(r_vals))):
            cell = row_cells[c_idx]
            val = _sanitize_xml10(r_vals[c_idx])
            if shade_alt:
                _shade_docx_cell(cell, alt_bg)
            is_sev = severity_col == c_idx
            is_bold = (c_idx in bold_col_set) or is_sev
            if compact_mode and not is_sev and not is_bold:
                p = cell.paragraphs[0]
                run = p.add_run(val)
                run.font.size = body_pt
            else:
                col_hex = _severity_color_hex(val) if is_sev else "0F172A"
                _set_docx_cell_text(
                    cell,
                    val,
                    bold=is_bold,
                    size_pt=font_pt,
                    color_hex=col_hex,
                    is_fresh_cell=True,
                )
    doc.add_paragraph()


def _append_docx_inline_runs(paragraph: Any, text: str, *, base_size_pt: float = 9.2) -> None:
    for kind, span_text in _parse_inline_markdown_spans(text):
        if not span_text:
            continue
        run = paragraph.add_run(span_text)
        run.font.size = Pt(base_size_pt)
        if kind == "bold":
            run.bold = True
        elif kind == "code":
            run.font.name = "Courier New"
            run.font.size = Pt(base_size_pt - 0.6)


def _render_docx_markdown(doc: Any, md_text: str) -> None:
    for blk in _parse_markdown_blocks(md_text):
        btype = blk["type"]
        if btype == "heading":
            doc.add_heading(_sanitize_xml10(blk["text"]), level=int(blk.get("level", 2)))
        elif btype == "bullet":
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.22)
            p.paragraph_format.space_after = Pt(3)
            p.add_run("• ").bold = True
            _append_docx_inline_runs(p, blk["text"])
        elif btype == "numbered":
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.22)
            p.paragraph_format.space_after = Pt(3)
            p.add_run(f"{blk['number']}. ").bold = True
            _append_docx_inline_runs(p, blk["text"])
        else:
            p = doc.add_paragraph()
            p.paragraph_format.space_after = Pt(5)
            _append_docx_inline_runs(p, blk["text"])


def build_executive_docx_report(
    book: PostureAccelerationBook,
    graph_png_path: Optional[Path],
    output_path: Path,
) -> Path:
    """Builds the complete 7-section Word (.docx) IAM & Credential Vault Report from `report_view_model(book)`."""
    vm = report_view_model(book, allow_live_fetch=False)

    doc = DocxDocument()
    for section in doc.sections:
        section.top_margin = Inches(0.55)
        section.bottom_margin = Inches(0.55)
        section.left_margin = Inches(0.55)
        section.right_margin = Inches(0.55)

    # Header Banner
    kicker = doc.add_paragraph()
    kr = kicker.add_run(_sanitize_xml10(vm["kicker"]))
    kr.bold = True
    kr.font.size = Pt(9.5)
    kr.font.color.rgb = _rgb("1A73E8")

    title_p = doc.add_heading(_sanitize_xml10(vm["title"]), level=0)
    for r in title_p.runs:
        r.font.color.rgb = _rgb("0F172A")

    sub_p = doc.add_paragraph()
    sr = sub_p.add_run(_sanitize_xml10(vm["subtitle"]))
    sr.bold = True
    sr.font.size = Pt(10.2)
    sr.font.color.rgb = _rgb("0F766E")

    adv_tbl = doc.add_table(rows=1, cols=1)
    adv_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    adv_cell = adv_tbl.rows[0].cells[0]
    _shade_docx_cell(adv_cell, "EFF6FF")
    _set_docx_cell_text(adv_cell, vm["advisory_disclaimer"], size_pt=8.6, color_hex="1E3A8A", is_fresh_cell=True)
    doc.add_paragraph()

    if vm["coverage_warnings"]:
        cov_tbl = doc.add_table(rows=1, cols=1)
        cov_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cov_cell = cov_tbl.rows[0].cells[0]
        _shade_docx_cell(cov_cell, "FEF3C7")
        cov_lines = [
            f"TELEMETRY COVERAGE WARNING ({vm['data_completeness_pct']:.1f}% Data Completeness):"
        ] + [f"- {w}" for w in vm["coverage_warnings"]]
        _set_docx_cell_text(cov_cell, "\n".join(cov_lines), size_pt=8.4, color_hex="92400E", is_fresh_cell=True)
        doc.add_paragraph()

    mt = vm["metadata_table"]
    _add_docx_grid_table(
        doc,
        mt["headers"],
        mt["rows"],
        header_bg=mt["header_bg"],
        alt_bg=mt["alt_bg"],
        bold_cols=mt["bold_cols"],
        severity_col=mt["severity_col"],
        font_pt=mt["font_pt"],
    )

    for sec in vm["sections"]:
        if sec.get("page_break_before"):
            doc.add_page_break()
        doc.add_heading(_sanitize_xml10(sec["title"]), level=1)

        if sec.get("intro"):
            p = doc.add_paragraph(_sanitize_xml10(sec["intro"]))
            p.paragraph_format.space_after = Pt(5)

        if sec.get("narrative_markdown"):
            _render_docx_markdown(doc, sec["narrative_markdown"])

        if sec.get("graph_placeholder") and graph_png_path and graph_png_path.exists():
            img_p = doc.add_paragraph()
            img_p.alignment = WD_TABLE_ALIGNMENT.CENTER
            img_p.add_run().add_picture(str(graph_png_path), width=Inches(6.9))

        for tbl_spec in sec.get("tables", []):
            if tbl_spec.get("title"):
                doc.add_heading(_sanitize_xml10(tbl_spec["title"]), level=2)
            if tbl_spec.get("intro"):
                p_i = doc.add_paragraph(_sanitize_xml10(tbl_spec["intro"]))
                p_i.paragraph_format.space_after = Pt(4)
            _add_docx_grid_table(
                doc,
                tbl_spec["headers"],
                tbl_spec["rows"],
                header_bg=tbl_spec.get("header_bg", "1E3A8A"),
                alt_bg=tbl_spec.get("alt_bg", "F8FAFC"),
                bold_cols=tbl_spec.get("bold_cols", (0,)),
                severity_col=tbl_spec.get("severity_col"),
                font_pt=tbl_spec.get("font_pt", 8.0),
            )
            # Render Section 1 notes right after the primary scorecard table
            if sec["key"] == "sec_1" and tbl_spec.get("title") is None and sec.get("notes"):
                for note in sec["notes"]:
                    pn = doc.add_paragraph(_sanitize_xml10(note))
                    pn.paragraph_format.space_after = Pt(5)

        for cb in sec.get("code_blocks", []):
            doc.add_heading(_sanitize_xml10(cb["title"]), level=2)
            code_tbl = doc.add_table(rows=1, cols=1)
            code_cell = code_tbl.rows[0].cells[0]
            _shade_docx_cell(code_cell, "0F172A")
            _set_docx_cell_text(
                code_cell,
                cb["code"],
                size_pt=7.5,
                color_hex="E2E8F0",
                font_name="Courier New",
                is_fresh_cell=True,
            )
            doc.add_paragraph()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(output_path))
    return output_path


# ---------------------------------------------------------------------------
# PDF Report Builder (ReportLab Platypus — Embedded Unicode TTF + LayoutError Recovery)
# ---------------------------------------------------------------------------

def _rl_markup(text: Any) -> str:
    """XML-1.0-sanitizes, escapes, preserves newlines as `<br/>`, and routes CJK runs to Unicode CID font."""
    escaped = xml_escape(_sanitize_xml10(text)).replace("\n", "<br/>")
    return _CJK_RUN_RE.sub(rf'<font name="{PDF_FONT_CJK}">\1</font>', escaped)


def _rl_inline_markdown(text: str) -> str:
    parts: List[str] = []
    for kind, span_text in _parse_inline_markdown_spans(text):
        if not span_text:
            continue
        rendered = _rl_markup(span_text)
        if kind == "bold":
            parts.append(f"<b>{rendered}</b>")
        elif kind == "code":
            parts.append(f'<font name="{PDF_FONT_MONO}">{rendered}</font>')
        else:
            parts.append(rendered)
    return "".join(parts)


def _read_png_dimensions(png_path: Path) -> Optional[Tuple[int, int]]:
    """Reads PNG pixel dimensions from IHDR header (stdlib only) to preserve aspect ratio in PDF."""
    try:
        header = png_path.read_bytes()[:24]
        if len(header) >= 24 and header[:8] == b"\x89PNG\r\n\x1a\n" and header[12:16] == b"IHDR":
            w, h = struct.unpack(">II", header[16:24])
            if w > 0 and h > 0:
                return int(w), int(h)
    except OSError:
        pass
    return None


def _scaled_pdf_image(png_path: Path, max_w: float = 7.3 * inch, max_h: float = 4.5 * inch) -> RLImage:
    dims = _read_png_dimensions(png_path)
    if dims is None:
        return RLImage(str(png_path), width=max_w, height=3.8 * inch, kind="proportional")
    px_w, px_h = dims
    aspect = px_w / float(px_h)
    width = max_w
    height = width / aspect
    if height > max_h:
        height = max_h
        width = height * aspect
    return RLImage(str(png_path), width=width, height=height)


def _normalize_col_widths(col_weights: Sequence[float], total_width: float = 7.5 * inch) -> List[float]:
    weights = [max(0.1, float(w)) for w in col_weights]
    w_sum = sum(weights) or 1.0
    return [(w / w_sum) * total_width for w in weights]


def _build_pdf_story(
    vm: Dict[str, Any],
    graph_png_path: Optional[Path],
    *,
    max_cell_chars: int = 1200,
    max_code_lines_per_block: int = 55,
) -> List[Any]:
    styles = getSampleStyleSheet()
    kicker_style = ParagraphStyle(
        "Kicker", parent=styles["Normal"], fontName=PDF_FONT_BOLD, fontSize=8.5, textColor=colors.HexColor("#1A73E8"), spaceAfter=4
    )
    title_style = ParagraphStyle(
        "DocTitle", parent=styles["Heading1"], fontName=PDF_FONT_BOLD, fontSize=15.5, leading=19.5, textColor=colors.HexColor("#0F172A"), spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "DocSub", parent=styles["Normal"], fontName=PDF_FONT_BOLD, fontSize=9.0, textColor=colors.HexColor("#0F766E"), spaceAfter=8
    )
    h1_style = ParagraphStyle(
        "SectionH1", parent=styles["Heading2"], fontName=PDF_FONT_BOLD, fontSize=12.0, leading=15.0, textColor=colors.HexColor("#1E3A8A"), spaceBefore=10, spaceAfter=5
    )
    h2_style = ParagraphStyle(
        "SectionH2", parent=styles["Heading3"], fontName=PDF_FONT_BOLD, fontSize=10.0, leading=13.0, textColor=colors.HexColor("#0F172A"), spaceBefore=7, spaceAfter=4
    )
    h3_style = ParagraphStyle(
        "SectionH3", parent=styles["Heading4"], fontName=PDF_FONT_BOLD, fontSize=9.0, leading=12.0, textColor=colors.HexColor("#1E293B"), spaceBefore=5, spaceAfter=3
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"], fontName=PDF_FONT_REGULAR, fontSize=8.4, leading=11.8, textColor=colors.HexColor("#1E293B"), spaceAfter=5
    )
    bullet_style = ParagraphStyle(
        "BulletItem", parent=body_style, leftIndent=14, firstLineIndent=-8, spaceAfter=3
    )
    cell_style = ParagraphStyle(
        "Cell", parent=styles["Normal"], fontName=PDF_FONT_REGULAR, fontSize=7.2, leading=9.5, textColor=colors.HexColor("#0F172A"), wordWrap="CJK"
    )
    cell_bold_style = ParagraphStyle(
        "CellBold", parent=cell_style, fontName=PDF_FONT_BOLD
    )
    header_cell_style = ParagraphStyle(
        "HeaderCell", parent=cell_style, fontName=PDF_FONT_BOLD, textColor=colors.white
    )
    code_style = ParagraphStyle(
        "CodeBlock",
        parent=styles["Code"],
        fontName=PDF_FONT_MONO,
        fontSize=6.5,
        leading=8.5,
        textColor=colors.HexColor("#E2E8F0"),
        backColor=colors.HexColor("#0F172A"),
        leftIndent=5,
        rightIndent=5,
        borderPadding=5,
    )

    def _rl_table(tbl_spec: Dict[str, Any]) -> Table:
        headers = tbl_spec["headers"]
        rows = tbl_spec["rows"]
        col_widths = _normalize_col_widths(tbl_spec["col_weights"], 7.5 * inch)
        header_hex = "#" + str(tbl_spec.get("header_bg", "1E3A8A")).lstrip("#")
        alt_hex = "#" + str(tbl_spec.get("alt_bg", "F8FAFC")).lstrip("#")
        bold_cols = set(tbl_spec.get("bold_cols", (0,)))
        sev_col = tbl_spec.get("severity_col")

        safe_rows = list(rows) if rows else [["No records discovered in evaluated scope"] + ["—"] * (len(headers) - 1)]
        data_matrix: List[List[Any]] = [[Paragraph(_rl_markup(h), header_cell_style) for h in headers]]
        for r in safe_rows:
            row_cells: List[Any] = []
            for idx_c, val in enumerate(r):
                bounded = _truncate_cell_text(val, max_cell_chars)
                is_bold = (idx_c in bold_cols) or (sev_col == idx_c)
                row_cells.append(
                    Paragraph(
                        _rl_markup(bounded),
                        cell_bold_style if is_bold else cell_style,
                    )
                )
            data_matrix.append(row_cells)

        t = Table(
            data_matrix,
            colWidths=col_widths,
            repeatRows=1,
            splitByRow=1,
            splitInRow=1,
        )
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_hex)),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor(alt_hex), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#CBD5E1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3.0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3.0),
                    ("LEFTPADDING", (0, 0), (-1, -1), 3.5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 3.5),
                ]
            )
        )
        return t

    story: List[Any] = []
    story.append(Paragraph(_rl_markup(vm["kicker"]), kicker_style))
    story.append(Paragraph(_rl_markup(vm["title"]), title_style))
    story.append(Paragraph(_rl_markup(vm["subtitle"]), subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.4, color=colors.HexColor("#1A73E8"), spaceAfter=6))

    adv_box = Table(
        [[Paragraph(_rl_markup(vm["advisory_disclaimer"]), cell_style)]],
        colWidths=[7.5 * inch],
        splitByRow=1,
        splitInRow=1,
    )
    adv_box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#93C5FD")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(adv_box)
    story.append(Spacer(1, 6))

    if vm["coverage_warnings"]:
        cov_html = (
            f"<b>TELEMETRY COVERAGE WARNING ({vm['data_completeness_pct']:.1f}% Data Completeness):</b><br/>"
            + "<br/>".join(f"• {_rl_markup(w)}" for w in vm["coverage_warnings"])
        )
        cov_box = Table(
            [[Paragraph(cov_html, cell_style)]],
            colWidths=[7.5 * inch],
            splitByRow=1,
            splitInRow=1,
        )
        cov_box.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.9, colors.HexColor("#F59F00")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        story.append(cov_box)
        story.append(Spacer(1, 6))

    story.append(_rl_table(vm["metadata_table"]))
    story.append(Spacer(1, 6))

    for sec in vm["sections"]:
        if sec.get("page_break_before"):
            story.append(PageBreak())
        story.append(Paragraph(_rl_markup(sec["title"]), h1_style))

        if sec.get("intro"):
            story.append(Paragraph(_rl_markup(sec["intro"]), body_style))

        if sec.get("narrative_markdown"):
            for blk in _parse_markdown_blocks(sec["narrative_markdown"]):
                btype = blk["type"]
                if btype == "heading":
                    st = h2_style if int(blk.get("level", 2)) <= 2 else h3_style
                    story.append(Paragraph(_rl_inline_markdown(blk["text"]), st))
                elif btype == "bullet":
                    story.append(Paragraph(f"• {_rl_inline_markdown(blk['text'])}", bullet_style))
                elif btype == "numbered":
                    story.append(Paragraph(f"{blk['number']}. {_rl_inline_markdown(blk['text'])}", bullet_style))
                else:
                    story.append(Paragraph(_rl_inline_markdown(blk["text"]), body_style))

        if sec.get("graph_placeholder") and graph_png_path and graph_png_path.exists():
            story.append(_scaled_pdf_image(graph_png_path))
            story.append(Spacer(1, 6))

        for tbl_spec in sec.get("tables", []):
            if tbl_spec.get("title"):
                story.append(Paragraph(_rl_markup(tbl_spec["title"]), h2_style))
            if tbl_spec.get("intro"):
                story.append(Paragraph(_rl_markup(tbl_spec["intro"]), body_style))
            story.append(_rl_table(tbl_spec))
            story.append(Spacer(1, 6))
            if sec["key"] == "sec_1" and tbl_spec.get("title") is None and sec.get("notes"):
                for note in sec["notes"]:
                    story.append(Paragraph(_rl_markup(note), body_style))

        for cb in sec.get("code_blocks", []):
            story.append(Paragraph(_rl_markup(cb["title"]), h2_style))
            # Split very tall code blocks into page-safe chunks so Preformatted never raises LayoutError
            wrapped_lines = _wrap_code_lines(cb["code"], 98).splitlines() or ["# Empty module"]
            for start in range(0, len(wrapped_lines), max_code_lines_per_block):
                chunk = "\n".join(wrapped_lines[start : start + max_code_lines_per_block])
                story.append(Preformatted(chunk, code_style))
            story.append(Spacer(1, 5))

    return story


def build_executive_pdf_report(
    book: PostureAccelerationBook,
    graph_png_path: Optional[Path],
    output_path: Path,
) -> Path:
    """Builds the complete 7-section Executive PDF Report using embedded Unicode TTF fonts and LayoutError fallback."""
    _ensure_pdf_unicode_fonts()
    vm = report_view_model(book, allow_live_fetch=False)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    def _build_with_limits(max_cell_chars: int, max_code_lines: int) -> None:
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=LETTER,
            leftMargin=0.5 * inch,
            rightMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
            title="Agentic IAM Accelerator — Complete Posture, Accounts, Keys & Secrets Book",
            author="Google Cloud Security Architecture — Agentic IAM Accelerator",
        )
        story = _build_pdf_story(
            vm,
            graph_png_path,
            max_cell_chars=max_cell_chars,
            max_code_lines_per_block=max_code_lines,
        )
        doc.build(story)

    try:
        _build_with_limits(max_cell_chars=1200, max_code_lines=55)
    except LayoutError as exc:
        logger.warning("ReportLab LayoutError encountered (%s); rebuilding PDF with aggressively truncated cells.", exc)
        _build_with_limits(max_cell_chars=240, max_code_lines=35)

    return output_path


def materialize_terraform_zip_from_bundle(book: PostureAccelerationBook, out_dir: Path) -> Path:
    """Builds or refreshes `agentic_iam_terraform_remediation_bundle.zip` directly from `book.iac_bundle`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    tf_dir = out_dir / "terraform_remediation_bundle"
    tf_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / "agentic_iam_terraform_remediation_bundle.zip"
    iac = book.iac_bundle
    readme_md = (
        f"# Agentic IAM Terraform Remediation Bundle ({iac.bundle_id})\n\n"
        f"- **Evaluated Scope:** `{iac.scope}`\n"
        f"- **Generated At:** `{iac.generated_at}`\n\n"
        "## Advisory Notice\n"
        "CONSULTATIVE DRAFT, UNVALIDATED. Review every module and `MANUAL_STEPS.md` before applying.\n\n"
        "## Deployment Steps\n"
        "1. Review all HCL modules (`main.tf`, `variables.tf`, `iam.tf`, `pam_entitlements.tf`, `org_policies.tf`).\n"
        "2. Run `terraform init && terraform plan` in a staging environment first.\n"
        "3. Apply progressively across Wave 1, Wave 2, and Wave 3 change windows.\n"
    )
    files = {
        "main.tf": iac.main_tf or "# main.tf\n",
        "variables.tf": iac.variables_tf or "# variables.tf\n",
        "iam.tf": iac.iam_tf or "# iam.tf\n",
        "pam_entitlements.tf": iac.pam_entitlements_tf or "# pam_entitlements.tf\n",
        "org_policies.tf": iac.org_policies_tf or "# org_policies.tf\n",
        "MANUAL_STEPS.md": getattr(iac, "manual_steps_md", "") or "# MANUAL_STEPS.md\n\nNo manual binding removals required.\n",
        "README.md": readme_md,
    }
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            (tf_dir / fname).write_text(content, encoding="utf-8")
            zf.writestr(fname, content)
    iac.bundle_zip_path = str(zip_path)
    return zip_path


BOOK_FILENAME = "book.json"
DELIVERABLES_MANIFEST_FILENAME = "deliverables_manifest.json"
DOCX_FILENAME = "Agentic_IAM_Posture_Acceleration_Report.docx"
PDF_FILENAME = "Agentic_IAM_Posture_Acceleration_Report.pdf"
INVENTORY_JSON_FILENAME = "accounts_keys_secrets_inventory.json"
TERRAFORM_ZIP_FILENAME = "agentic_iam_terraform_remediation_bundle.zip"
GRAPH_LIGHT_FILENAME = "attack_path_graph.png"
GRAPH_DARK_FILENAME = "attack_path_graph_dark.png"

INVALIDATABLE_DELIVERABLE_FILENAMES: tuple[str, ...] = (
    DOCX_FILENAME,
    PDF_FILENAME,
    INVENTORY_JSON_FILENAME,
    TERRAFORM_ZIP_FILENAME,
    GRAPH_LIGHT_FILENAME,
    GRAPH_DARK_FILENAME,
    "posture_acceleration_book.json",
    DELIVERABLES_MANIFEST_FILENAME,
)


def scope_directory_hash(canonical_scope: str) -> str:
    """Returns a deterministic 16-char SHA-256 hex digest for a canonical GCP scope."""
    return hashlib.sha256((canonical_scope or "").strip().lower().encode("utf-8")).hexdigest()[:16]


def scoped_export_dir(scope: str = "", base_dir: Optional[Path] = None) -> Path:
    """Returns the isolated per-scope export subdirectory under the active session export dir."""
    canonical = normalize_gcp_scope(scope)
    root = base_dir if base_dir is not None else active_export_dir()
    out = root / "scopes" / scope_directory_hash(canonical)
    out.mkdir(parents=True, exist_ok=True)
    return out


def invalidate_scope_deliverables(out_dir: Path) -> None:
    """Deletes rendered DOCX, PDF, inventory JSON, ZIP, PNGs, and manifest inside a scope directory."""
    if not out_dir.exists():
        return
    for fname in INVALIDATABLE_DELIVERABLE_FILENAMES:
        try:
            (out_dir / fname).unlink(missing_ok=True)
        except OSError:
            pass


def persist_book_snapshot(
    book: PostureAccelerationBook,
    out_dir: Path,
    *,
    invalidate_deliverables: bool = True,
) -> Path:
    """Atomically persists `book.json` in `out_dir` and invalidates stale deliverables when requested."""
    out_dir.mkdir(parents=True, exist_ok=True)
    book_path = out_dir / BOOK_FILENAME
    tmp_path = out_dir / f".{BOOK_FILENAME}.{secrets.token_hex(4)}.tmp"
    tmp_path.write_text(book.model_dump_json(indent=2), encoding="utf-8")
    os.replace(tmp_path, book_path)

    if invalidate_deliverables:
        invalidate_scope_deliverables(out_dir)
    return book_path


def load_persisted_book(out_dir: Path) -> Optional[PostureAccelerationBook]:
    """Loads `book.json` from a per-scope export directory if present and valid."""
    book_path = out_dir / BOOK_FILENAME
    if not book_path.exists():
        return None
    try:
        return PostureAccelerationBook.model_validate_json(book_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def read_deliverables_manifest(out_dir: Path) -> Dict[str, Any]:
    """Reads `deliverables_manifest.json` from a per-scope export directory, or returns `{}`."""
    manifest_path = out_dir / DELIVERABLES_MANIFEST_FILENAME
    if not manifest_path.exists():
        return {}
    try:
        parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def write_deliverables_manifest(
    out_dir: Path,
    book: PostureAccelerationBook,
    artifact_filenames: Sequence[str],
    *,
    errors: Optional[Dict[str, str]] = None,
) -> Path:
    """Atomically writes `deliverables_manifest.json` recording the `book.generated_at` watermark."""
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / DELIVERABLES_MANIFEST_FILENAME
    payload: Dict[str, Any] = {
        "scope": book.scope,
        "generated_at": book.generated_at,
        "rendered_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "artifacts": {fname: book.generated_at for fname in artifact_filenames},
    }
    if errors:
        payload["errors"] = dict(errors)
    tmp_path = out_dir / f".{DELIVERABLES_MANIFEST_FILENAME}.{secrets.token_hex(4)}.tmp"
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp_path, manifest_path)
    return manifest_path


def is_deliverable_fresh(
    out_dir: Path,
    filename: str,
    book: PostureAccelerationBook,
) -> bool:
    """Returns True only if `filename` exists and its manifest `generated_at` matches `book.generated_at`."""
    if not (out_dir / filename).exists():
        return False
    manifest = read_deliverables_manifest(out_dir)
    if not manifest:
        return False
    if manifest.get("scope") != book.scope:
        return False
    if manifest.get("generated_at") != book.generated_at:
        return False
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or artifacts.get(filename) != book.generated_at:
        return False
    return True


def build_download_filename(
    artifact_type: str,
    target_scope: str,
    *,
    generated_at: str = "",
    fallback_org_id: str = "",
    dark_mode: bool = False,
) -> str:
    """Builds a scoped download filename containing the GCP Organization ID (or scope ID) and date."""
    org_id = ""
    try:
        parsed = parse_assessment_scope(target_scope)
        org_id = parsed.organization_id
    except Exception:
        org_id = ""
    if not org_id:
        org_id = (fallback_org_id or "").strip().replace("organizations/", "").strip("/")
    if not org_id and target_scope:
        tail = target_scope.strip().strip("/").split("/")[-1]
        org_id = tail.split(":")[0]
    safe_org = re.sub(r"[^a-zA-Z0-9_-]", "", org_id)[:48] or "org"

    m_date = re.match(r"^(\d{4}-\d{2}-\d{2})", (generated_at or "").strip())
    date_tag = m_date.group(1) if m_date else datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    templates = {
        "docx": f"Agentic_IAM_Posture_Acceleration_Report_{safe_org}_{date_tag}.docx",
        "pdf": f"Agentic_IAM_Posture_Acceleration_Report_{safe_org}_{date_tag}.pdf",
        "terraform-zip": f"agentic_iam_terraform_remediation_bundle_{safe_org}_{date_tag}.zip",
        "inventory-json": f"accounts_keys_secrets_inventory_{safe_org}_{date_tag}.json",
        "attack-graph-png": (
            f"attack_path_graph_dark_{safe_org}_{date_tag}.png"
            if dark_mode
            else f"attack_path_graph_{safe_org}_{date_tag}.png"
        ),
    }
    return templates.get(artifact_type, f"{artifact_type}_{safe_org}_{date_tag}")


def _render_empty_graph_png(output_path: Path, scope: str, dark_mode: bool = False) -> Path:
    """Renders an offline placeholder attack graph PNG via thread-safe OO Matplotlib (no pyplot)."""
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    output_path.parent.mkdir(parents=True, exist_ok=True)
    bg = "#1B1E26" if dark_mode else "#FFFFFF"
    fg = "#F1F5F9" if dark_mode else "#0F172A"
    fig = Figure(figsize=(10.0, 4.5), dpi=160)
    FigureCanvasAgg(fig)
    ax = fig.add_subplot(111)
    fig.patch.set_facecolor(bg)
    ax.set_facecolor(bg)
    ax.axis("off")
    ax.text(
        0.5,
        0.5,
        f"IAM Attack Path Graph — {scope}\n(No escalation nodes captured in this snapshot)",
        ha="center",
        va="center",
        fontsize=12,
        color=fg,
        parse_math=False,
    )
    fig.savefig(output_path, bbox_inches="tight", facecolor=bg)
    fig.clear()
    return output_path


def render_deliverables_from_book(
    book: PostureAccelerationBook,
    out_dir: Path,
) -> Dict[str, Any]:
    """Renders DOCX, PDF, PNGs, Inventory JSON, Terraform ZIP, and manifest strictly from `book`.

    DOCX and PDF generation run independently so an unexpected error in one format
    never blocks generation of the other format.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    target_scope = book.scope

    existing_disk_book = load_persisted_book(out_dir)
    if existing_disk_book is None or existing_disk_book.generated_at != book.generated_at:
        persist_book_snapshot(book, out_dir, invalidate_deliverables=False)

    render_book = book
    if render_book.asset_inventory is None:
        render_book = book.model_copy(
            update={"asset_inventory": AccountsKeysSecretsInventory(scope=target_scope)}
        )

    inv = _ensure_inventory(render_book, allow_live_fetch=False)
    inv_json_path = out_dir / INVENTORY_JSON_FILENAME
    inv_json_path.write_text(inv.model_dump_json(indent=2), encoding="utf-8")

    if render_book.attack_graph and render_book.attack_graph.nodes:
        graph_png = render_attack_graph_png(
            out_dir / GRAPH_LIGHT_FILENAME,
            target_scope,
            graph_summary=render_book.attack_graph,
            dark_mode=False,
        )
        graph_dark_png = render_attack_graph_png(
            out_dir / GRAPH_DARK_FILENAME,
            target_scope,
            graph_summary=render_book.attack_graph,
            dark_mode=True,
        )
    else:
        graph_png = _render_empty_graph_png(out_dir / GRAPH_LIGHT_FILENAME, target_scope, dark_mode=False)
        graph_dark_png = _render_empty_graph_png(out_dir / GRAPH_DARK_FILENAME, target_scope, dark_mode=True)

    tf_zip_path = materialize_terraform_zip_from_bundle(render_book, out_dir)

    render_errors: Dict[str, str] = {}
    rendered_artifacts: List[str] = [
        INVENTORY_JSON_FILENAME,
        TERRAFORM_ZIP_FILENAME,
        GRAPH_LIGHT_FILENAME,
        GRAPH_DARK_FILENAME,
    ]

    docx_path: Optional[Path] = None
    try:
        docx_path = build_executive_docx_report(
            book=render_book,
            graph_png_path=graph_png,
            output_path=out_dir / DOCX_FILENAME,
        )
        rendered_artifacts.append(DOCX_FILENAME)
    except Exception as exc:
        logger.exception("DOCX report generation failed; continuing with PDF generation.")
        render_errors["docx"] = str(exc)

    pdf_path: Optional[Path] = None
    try:
        pdf_path = build_executive_pdf_report(
            book=render_book,
            graph_png_path=graph_png,
            output_path=out_dir / PDF_FILENAME,
        )
        rendered_artifacts.append(PDF_FILENAME)
    except Exception as exc:
        logger.exception("PDF report generation failed; continuing with remaining deliverables.")
        render_errors["pdf"] = str(exc)

    deliverable_paths: Dict[str, str] = {
        "attack_path_graph_png": str(graph_png),
        "attack_path_graph_dark_png": str(graph_dark_png),
        "accounts_keys_secrets_inventory_json": str(inv_json_path),
        "terraform_remediation_bundle_zip": str(tf_zip_path),
        "terraform_directory": str(out_dir / "terraform_remediation_bundle"),
    }
    if docx_path is not None:
        deliverable_paths["executive_docx_report"] = str(docx_path)
    if pdf_path is not None:
        deliverable_paths["executive_pdf_report"] = str(pdf_path)

    book.deliverable_paths = dict(deliverable_paths)
    render_book.deliverable_paths = dict(deliverable_paths)

    book_manifest_path = out_dir / "posture_acceleration_book.json"
    book_manifest_path.write_text(render_book.model_dump_json(indent=2), encoding="utf-8")

    deliverables_manifest_path = write_deliverables_manifest(
        out_dir,
        book,
        rendered_artifacts,
        errors=render_errors or None,
    )

    return {
        "out_dir": out_dir,
        "book_json_path": out_dir / BOOK_FILENAME,
        "manifest_path": book_manifest_path,
        "deliverables_manifest_path": deliverables_manifest_path,
        "docx_path": docx_path,
        "pdf_path": pdf_path,
        "graph_png": graph_png,
        "graph_dark_png": graph_dark_png,
        "inv_json_path": inv_json_path,
        "tf_zip_path": tf_zip_path,
        "deliverable_paths": deliverable_paths,
        "generated_at": book.generated_at,
        "errors": render_errors,
    }


async def generate_all_executive_deliverables_async(
    scope: str = "",
    model_name: Optional[str] = None,
    force_refresh: bool = False,
    pinned_book: Optional[PostureAccelerationBook] = None,
) -> Dict[str, Any]:
    """Asynchronously builds full DOCX, PDF, PNG, Inventory JSON, and Terraform ZIP (live ADK or from pinned scan)."""
    from backend.workspace_store import save_pinned_book, save_workspace_artifact

    resolved_model = resolve_vertex_model(model_name or settings.vertex_model_id)

    if pinned_book is not None and not force_refresh:
        book = pinned_book
        target_scope = normalize_gcp_scope(book.scope or scope)
    else:
        target_scope = normalize_gcp_scope(scope)
        book = await run_posture_book_assessment(
            scope=target_scope,
            model_name=resolved_model,
            force_refresh=force_refresh,
        )

    out_dir = scoped_export_dir(target_scope)
    rendered = await asyncio.to_thread(render_deliverables_from_book, book, out_dir)

    sess = get_active_inspection_session()
    bq_status: Dict[str, Any] = {"status": "SKIPPED_PINNED_SNAPSHOT", "persisted": False}
    if pinned_book is None or (sess is not None and sess.is_live_token_valid):
        try:
            bq_status = await asyncio.to_thread(
                persist_findings_list_to_bigquery, book.triad_matrix.findings, target_scope
            )
        except Exception as exc:
            bq_status = {"status": "CUSTOMER_BIGQUERY_ERROR", "persisted": False, "detail": str(exc)[:300]}
    if sess is not None and isinstance(bq_status, dict):
        sess.last_bq_export_status = {
            k: v for k, v in bq_status.items() if k != "session_jsonl_path"
        }

    docx_path = rendered["docx_path"]
    pdf_path = rendered["pdf_path"]
    tf_zip_path = rendered["tf_zip_path"]
    graph_png = rendered["graph_png"]
    graph_dark_png = rendered["graph_dark_png"]
    inv_json_path = rendered["inv_json_path"]
    manifest_path = rendered["manifest_path"]

    # Durably persist generated deliverables + pinned book into per-user encrypted workspace store
    if sess is not None and sess.connection_mode != "local_cli_adc":
        def _persist_workspace_bundle() -> None:
            save_pinned_book(sess.session_id, sess.owner_email, target_scope, book.model_dump())
            for fpath, ctype in (
                (docx_path, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                (pdf_path, "application/pdf"),
                (tf_zip_path, "application/zip"),
                (graph_png, "image/png"),
                (graph_dark_png, "image/png"),
                (inv_json_path, "application/json"),
            ):
                if fpath is not None and fpath.exists():
                    save_workspace_artifact(
                        sess.session_id,
                        fpath.name,
                        fpath.read_bytes(),
                        content_type=ctype,
                        scope=target_scope,
                    )

        try:
            await asyncio.to_thread(_persist_workspace_bundle)
        except Exception:
            pass

    return {
        "status": "PARTIAL" if rendered.get("errors") else "GENERATED",
        "scope": target_scope,
        "requested_model": resolved_model,
        "model_version": book.telemetry.model_version if book.telemetry else resolved_model,
        "overall_posture_score": book.scorecard.overall_posture_score,
        "maturity_tier": book.scorecard.maturity_tier,
        "deliverables": book.deliverable_paths,
        "errors": rendered.get("errors") or {},
        "manifest_json": str(manifest_path),
        "deliverables_manifest_json": str(rendered["deliverables_manifest_path"]),
        "bigquery_persistence": bq_status,
        "telemetry": book.telemetry.model_dump() if book.telemetry else None,
    }


def generate_all_executive_deliverables(
    scope: str = "",
    model_name: Optional[str] = None,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """Synchronous wrapper for CLI (`scripts/generate_reports.py`), Streamlit, and ADK tool callers."""
    return run_async_from_sync(
        generate_all_executive_deliverables_async(
            scope=scope,
            model_name=model_name,
            force_refresh=force_refresh,
        )
    )
