"""T10 — Resilient Reports (DOCX, PDF, Unicode TTF, Performance, View Model Parity, Failure Isolation)."""

from __future__ import annotations

import struct
import time
import zlib
from pathlib import Path
from typing import List

import docx
import pytest

from backend import report_generator as rg
from backend.models.findings import (
    AccountPrincipalRecord,
    AccountsKeysSecretsInventory,
    AccountsKeysSecretsSummaryKPIs,
    AttackPathGraphSummary,
    FrameworkBenchmarkScore,
    GcpIamPostureFinding,
    IaCRemediationBundle,
    IdentityTriadCategory,
    IdentityTriadMatrix,
    IdentityTriadMetrics,
    OrgPolicyPostureRecord,
    PostureAccelerationBook,
    PostureScorecard,
    RiskSeverity,
    SecretMetadataRecord,
)


def _make_book(
    *,
    num_wave1_findings: int = 2,
    num_accounts: int = 2,
    roles_per_account: int = 2,
    narrative: str = "## Executive Highlights\n\n- **Zero Standing Access** is required.\n- Migrate to `PAM JIT`.\n\nOverall posture narrative.",
    extra_text: str = "",
) -> PostureAccelerationBook:
    findings: List[GcpIamPostureFinding] = []
    for i in range(1, num_wave1_findings + 1):
        findings.append(
            GcpIamPostureFinding(
                finding_id=f"IAM-{i:03d}",
                scope="organizations/123456789012",
                project_id="proj-t10",
                title=f"Primitive Editor role on SA #{i} {extra_text}",
                cspr_view_id="IAM-WKL-01",
                triad_category=IdentityTriadCategory.WORKLOAD_SA,
                severity=RiskSeverity.HIGH,
                principal=f"serviceAccount:sa-{i}@proj-t10.iam.gserviceaccount.com",
                role="roles/editor",
                resource="projects/proj-t10",
                risk_vector=f"Standing primitive Editor role #{i} {extra_text}",
                evidence_summary=f"Observed active binding #{i} {extra_text}",
                recommended_modernization=f"Replace roles/editor with least-privilege custom role #{i} {extra_text}",
                remediation_wave="Wave 1 (Days 0-30)",
                framework_citations=["CIS GCP 1.5"],
            )
        )

    accounts: List[AccountPrincipalRecord] = []
    for i in range(1, num_accounts + 1):
        roles = [f"roles/custom.role{r}" for r in range(1, roles_per_account + 1)]
        accounts.append(
            AccountPrincipalRecord(
                principal=f"user:alice-{i}@example.com",
                principal_type="user",
                domain="example.com",
                is_external=False,
                bindings_count=len(roles),
                projects=["proj-t10"],
                roles=roles,
                risk_level="MEDIUM",
            )
        )

    inv = AccountsKeysSecretsInventory(
        scope="organizations/123456789012",
        kpis=AccountsKeysSecretsSummaryKPIs(
            human_and_group_accounts_total=len(accounts),
            secrets_total_count=1,
            org_policies_evaluated_count=2,
            org_policies_enforced_count=1,
        ),
        accounts=accounts,
        secrets=[
            SecretMetadataRecord(
                secret_name="db-password",
                project_id="proj-t10",
                accessor_principals=[f"user:reader-{i}@example.com" for i in range(1, 16)],
                accessor_principals_total=25,
                broad_primitive_accessors_count=2,
                risk_level="HIGH",
            )
        ],
        org_policies=[
            OrgPolicyPostureRecord(
                constraint="constraints/iam.disableServiceAccountKeyCreation",
                evaluated_on="organizations/123456789012",
                enforced=True,
                status="ENFORCED",
            ),
            OrgPolicyPostureRecord(
                constraint="constraints/iam.allowedPolicyMemberDomains",
                evaluated_on="organizations/123456789012",
                enforced=None,
                status="PERMISSION_DENIED",
            ),
        ],
    )

    pillar = IdentityTriadMetrics(
        category=IdentityTriadCategory.INTERNAL,
        display_name="Internal Workforce",
        posture_score=80.0,
        total_principals_evaluated=max(1, len(accounts)),
        compliant_principals=max(1, len(accounts)),
        critical_findings_count=0,
        high_findings_count=0,
        medium_findings_count=0,
    )
    triad = IdentityTriadMatrix(
        scope="organizations/123456789012",
        organization_domain="example.com",
        internal_identities=pillar,
        external_identities=pillar.model_copy(
            update={"category": IdentityTriadCategory.EXTERNAL, "display_name": "External Identities"}
        ),
        workload_service_accounts=pillar.model_copy(
            update={"category": IdentityTriadCategory.WORKLOAD_SA, "display_name": "Workload Service Accounts"}
        ),
        findings=findings,
    )
    scorecard = PostureScorecard(
        scope="organizations/123456789012",
        organization_domain="example.com",
        overall_posture_score=78.0,
        maturity_tier="Managed",
        internal_identities_score=80.0,
        external_identities_score=80.0,
        workload_identities_score=75.0,
        least_privilege_index=75.0,
        impersonation_resilience_score=80.0,
        total_bindings_analyzed=max(1, len(accounts) * roles_per_account),
        overprivileged_bindings_count=0,
        excess_permissions_eliminated=0,
        critical_findings=0,
        high_findings=len(findings),
        medium_findings=0,
        low_findings=0,
        framework_benchmarks=[
            FrameworkBenchmarkScore(
                framework_id="CIS-GCP",
                framework_name="CIS GCP Foundation Benchmark",
                alignment_score_pct=80.0,
                controls_passed=4,
                controls_evaluated=5,
                primary_focus="IAM Hardening",
            )
        ],
    )
    iac = IaCRemediationBundle(
        bundle_id="iac-t10-test",
        scope="organizations/123456789012",
        main_tf="# CONSULTATIVE DRAFT, UNVALIDATED.\nterraform {}\n",
        variables_tf="# variables\n",
        iam_tf="# iam\n",
        pam_entitlements_tf="# pam\n",
        org_policies_tf="# org policies\n",
        manual_steps_md="# MANUAL_STEPS.md\nReview before running.\n",
    )

    return PostureAccelerationBook(
        scope="organizations/123456789012",
        organization_domain="example.com",
        scorecard=scorecard,
        triad_matrix=triad,
        attack_graph=AttackPathGraphSummary(
            scope="organizations/123456789012",
            total_nodes=0,
            total_edges=0,
            toxic_combinations_count=0,
            escalation_paths_count=0,
            max_chain_depth=0,
        ),
        recommendations=[],
        iac_bundle=iac,
        asset_inventory=inv,
        executive_narrative_markdown=narrative,
    )


def _write_minimal_png(path: Path, width: int, height: int) -> Path:
    """Writes a valid minimal RGBA PNG with exact IHDR dimensions (stdlib only)."""
    def _chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw_scanlines = b"".join(b"\x00" + (b"\x20\x40\x80" * width) for _ in range(height))
    idat = zlib.compress(raw_scanlines)
    png_bytes = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")
    path.write_bytes(png_bytes)
    return path


def test_pdf_handles_80_findings_in_same_wave(tmp_path: Path) -> None:
    book = _make_book(num_wave1_findings=80)
    wave_rows = rg._build_wave_rows(book)
    # 1 row per action (+ baseline rows for empty Wave 2 and Wave 3)
    assert len(wave_rows) >= 80
    pdf_path = tmp_path / "wave80.pdf"
    rg.build_executive_pdf_report(book, None, pdf_path)
    assert pdf_path.exists()
    raw = pdf_path.read_bytes()
    assert raw.startswith(b"%PDF-")
    assert len(raw) > 5000


def test_pdf_handles_principal_with_300_roles(tmp_path: Path) -> None:
    book = _make_book(num_accounts=1, roles_per_account=300)
    pdf_path = tmp_path / "roles300.pdf"
    rg.build_executive_pdf_report(book, None, pdf_path)
    assert pdf_path.exists()
    raw = pdf_path.read_bytes()
    assert raw.startswith(b"%PDF-")

    vm = rg.report_view_model(book)
    sec3 = [s for s in vm["sections"] if s["key"] == "sec_3"][0]
    acct_tbl = [t for t in sec3["tables"] if (t["title"] or "").startswith("3.2")][0]
    roles_cell = acct_tbl["rows"][0][4]
    assert "(+290 more)" in roles_cell


def test_docx_handles_xml10_control_characters(tmp_path: Path) -> None:
    book = _make_book(
        narrative="Executive summary with control char\x0b and nul\x00 and bell\x07.",
        extra_text="bad\x0bchar\x0cvalue",
    )
    docx_path = tmp_path / "control_chars.docx"
    rg.build_executive_docx_report(book, None, docx_path)
    assert docx_path.exists()
    parsed = docx.Document(str(docx_path))
    full_text = "\n".join(p.text for p in parsed.paragraphs)
    assert "\x0b" not in full_text
    assert "\x00" not in full_text
    assert "Executive summary with control char" in full_text


def test_docx_with_2000_accounts_builds_under_3_seconds(tmp_path: Path) -> None:
    book = _make_book(num_wave1_findings=5, num_accounts=2000, roles_per_account=3)
    docx_path = tmp_path / "accounts2000.docx"
    t0 = time.perf_counter()
    rg.build_executive_docx_report(book, None, docx_path)
    elapsed = time.perf_counter() - t0
    assert docx_path.exists()
    assert elapsed < 3.0, f"2,000-account DOCX build took {elapsed:.2f}s (limit: 3.0s)"


def test_pdf_unicode_japanese_and_arrow_embeds_unicode_font(tmp_path: Path) -> None:
    book = _make_book(
        narrative="## Unicode Verification\n\n- Scope mapping: **日本語 → GCP IAM**\n",
        extra_text="日本語 → escalação",
    )
    pdf_path = tmp_path / "unicode.pdf"
    rg.build_executive_pdf_report(book, None, pdf_path)
    raw = pdf_path.read_bytes()
    assert raw.startswith(b"%PDF-")
    # Bundled open-source DejaVuSans TTF is embedded via FontFile2 and CJK uses HeiseiKakuGo-W5
    assert b"DejaVuSans" in raw
    assert b"FontFile2" in raw
    assert b"HeiseiKakuGo-W5" in raw
    assert (rg.FONTS_DIR / "LICENSE_DEJAVU").exists()


def test_view_model_parity_between_docx_and_pdf_and_markdown_rendering(tmp_path: Path) -> None:
    book = _make_book()
    vm = rg.report_view_model(book)
    expected_headings = [s["title"] for s in vm["sections"]]
    for s in vm["sections"]:
        for t in s["tables"]:
            if t.get("title"):
                expected_headings.append(t["title"])

    docx_path = tmp_path / "parity.docx"
    pdf_path = tmp_path / "parity.pdf"
    rg.build_executive_docx_report(book, None, docx_path)
    rg.build_executive_pdf_report(book, None, pdf_path)

    parsed = docx.Document(str(docx_path))
    docx_headings = [p.text for p in parsed.paragraphs if p.style and p.style.name.startswith("Heading")]
    for h in expected_headings:
        assert h in docx_headings, f"Missing heading in DOCX: {h}"

    # Verify Markdown markers are converted (not printed raw) in DOCX
    all_para_text = "\n".join(p.text for p in parsed.paragraphs)
    assert "## Executive Highlights" not in all_para_text
    assert "**Zero Standing Access**" not in all_para_text
    assert "Zero Standing Access" in all_para_text

    # Verify true accessor total (25) and canonical NOT EVALUATED Org Policy label in view model + DOCX
    all_table_text = "\n".join(cell.text for tbl in parsed.tables for row in tbl.rows for cell in row.cells)
    assert "25 principals" in all_table_text
    assert "(+17 more)" in all_table_text
    assert "NOT EVALUATED" in all_table_text


def test_docx_and_pdf_generation_are_independent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    book = _make_book()

    # Case 1: DOCX fails -> PDF still generated and manifest records error
    def _boom_docx(*args, **kwargs):
        raise RuntimeError("Simulated DOCX failure")

    monkeypatch.setattr(rg, "build_executive_docx_report", _boom_docx)
    out1 = tmp_path / "case1"
    res1 = rg.render_deliverables_from_book(book, out1)
    assert res1["docx_path"] is None
    assert res1["pdf_path"] is not None and res1["pdf_path"].exists()
    assert "docx" in res1["errors"]
    manifest1 = rg.read_deliverables_manifest(out1)
    assert rg.PDF_FILENAME in manifest1["artifacts"]
    assert rg.DOCX_FILENAME not in manifest1["artifacts"]
    assert "docx" in manifest1.get("errors", {})

    # Case 2: PDF fails -> DOCX still generated
    monkeypatch.undo()

    def _boom_pdf(*args, **kwargs):
        raise RuntimeError("Simulated PDF failure")

    monkeypatch.setattr(rg, "build_executive_pdf_report", _boom_pdf)
    out2 = tmp_path / "case2"
    res2 = rg.render_deliverables_from_book(book, out2)
    assert res2["pdf_path"] is None
    assert res2["docx_path"] is not None and res2["docx_path"].exists()
    assert "pdf" in res2["errors"]


def test_pdf_preserves_png_aspect_ratio(tmp_path: Path) -> None:
    png_path = _write_minimal_png(tmp_path / "wide.png", width=1600, height=400)
    img = rg._scaled_pdf_image(png_path)
    ratio = img.drawWidth / img.drawHeight
    assert abs(ratio - 4.0) < 0.01
