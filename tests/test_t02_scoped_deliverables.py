"""Offline unit & API tests for T02 — Per-scope deliverables, invalidation, and no stale files."""

from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List

import pytest
from docx import Document as DocxDocument
from fastapi.testclient import TestClient

import backend.main as main_mod
import backend.report_generator as report_mod
import backend.session_vault as vault_mod
import backend.workspace_store as ws_mod
from backend.identity_guard import (
    IAM_SESSION_COOKIE,
    IamConsultantIdentity,
    mint_consultant_cookie,
)
from backend.models.findings import (
    AccountsKeysSecretsInventory,
    AttackPathEdge,
    AttackPathGraphSummary,
    AttackPathNode,
    IaCRemediationBundle,
    IdentityTriadCategory,
    IdentityTriadMatrix,
    IdentityTriadMetrics,
    PostureAccelerationBook,
    PostureScorecard,
    RiskSeverity,
)


def _make_book(
    scope: str,
    *,
    generated_at: str,
    marker: str,
    domain: str = "example.com",
) -> PostureAccelerationBook:
    """Builds a minimal valid `PostureAccelerationBook` for offline deliverable testing."""
    pillar_int = IdentityTriadMetrics(
        category=IdentityTriadCategory.INTERNAL,
        display_name="Internal Identities",
        posture_score=80.0,
        total_principals_evaluated=5,
        compliant_principals=4,
        critical_findings_count=0,
        high_findings_count=1,
        medium_findings_count=0,
    )
    pillar_ext = IdentityTriadMetrics(
        category=IdentityTriadCategory.EXTERNAL,
        display_name="External Identities",
        posture_score=90.0,
        total_principals_evaluated=2,
        compliant_principals=2,
        critical_findings_count=0,
        high_findings_count=0,
        medium_findings_count=0,
    )
    pillar_wkl = IdentityTriadMetrics(
        category=IdentityTriadCategory.WORKLOAD_SA,
        display_name="Workload Identities",
        posture_score=85.0,
        total_principals_evaluated=4,
        compliant_principals=3,
        critical_findings_count=0,
        high_findings_count=1,
        medium_findings_count=0,
    )
    scorecard = PostureScorecard(
        scope=scope,
        organization_domain=domain,
        overall_posture_score=85.0,
        maturity_tier="Managed",
        internal_identities_score=80.0,
        external_identities_score=90.0,
        workload_identities_score=85.0,
        least_privilege_index=82.0,
        impersonation_resilience_score=88.0,
        total_bindings_analyzed=11,
        overprivileged_bindings_count=2,
        excess_permissions_eliminated=10,
        critical_findings=0,
        high_findings=2,
        medium_findings=0,
        low_findings=0,
    )
    triad = IdentityTriadMatrix(
        scope=scope,
        internal_identities=pillar_int,
        external_identities=pillar_ext,
        workload_service_accounts=pillar_wkl,
        findings=[],
    )
    graph = AttackPathGraphSummary(
        scope=scope,
        total_nodes=2,
        total_edges=1,
        escalation_paths_count=0,
        toxic_combinations_count=0,
        max_chain_depth=1,
        nodes=[
            AttackPathNode(
                node_id=f"user:alice@{domain}",
                label=f"alice@{domain}",
                node_type="user",
                risk_level=RiskSeverity.LOW,
            ),
            AttackPathNode(
                node_id=f"resource:{scope}",
                label=scope,
                node_type="resource",
                risk_level=RiskSeverity.MEDIUM,
            ),
        ],
        edges=[
            AttackPathEdge(
                source=f"user:alice@{domain}",
                target=f"resource:{scope}",
                relationship="roles/viewer",
                permission_vector="resourcemanager.projects.get",
            )
        ],
    )
    iac = IaCRemediationBundle(
        bundle_id=f"bundle-{marker}",
        scope=scope,
        generated_at=generated_at,
        main_tf=f'# scope = "{scope}" ({marker})\n',
        iam_tf=f'# iam for {marker}\n',
        pam_entitlements_tf="# pam\n",
        org_policies_tf="# org policies\n",
        variables_tf=f'variable "scope" {{ default = "{scope}" }}\n',
    )
    inv = AccountsKeysSecretsInventory(
        scope=scope,
        collected_at=generated_at,
    )
    return PostureAccelerationBook(
        scope=scope,
        organization_domain=domain,
        generated_at=generated_at,
        scorecard=scorecard,
        triad_matrix=triad,
        attack_graph=graph,
        recommendations=[],
        iac_bundle=iac,
        asset_inventory=inv,
        executive_narrative_markdown=f"Executive narrative for {scope} — {marker}.",
    )


def _extract_docx_text(raw_bytes: bytes) -> str:
    doc = DocxDocument(io.BytesIO(raw_bytes))
    parts: List[str] = [p.text for p in doc.paragraphs]
    for tbl in doc.tables:
        for row in tbl.rows:
            for cell in row.cells:
                parts.append(cell.text)
    return "\n".join(parts)


def _extract_pdf_text(raw_bytes: bytes) -> str:
    """Decompresses ReportLab PDF streams (FlateDecode or ASCII85Decode+FlateDecode) via stdlib."""
    import base64
    import re
    import zlib

    chunks: List[str] = [raw_bytes.decode("latin-1", errors="ignore")]
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", raw_bytes, flags=re.DOTALL):
        payload = match.group(1).strip()
        try:
            decompressed = zlib.decompress(payload)
            chunks.append(decompressed.decode("latin-1", errors="ignore"))
            continue
        except zlib.error:
            pass
        if payload.endswith(b"~>"):
            try:
                decoded_a85 = base64.a85decode(payload[:-2], ignorechars=b" \t\r\n")
                decompressed = zlib.decompress(decoded_a85)
                chunks.append(decompressed.decode("latin-1", errors="ignore"))
            except Exception:
                continue
    return "\n".join(chunks)


@pytest.fixture
def isolated_deliverable_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Isolates session export dirs, workspace store, and provides an authenticated TestClient + connected session."""
    sess_root = tmp_path / "sessions"
    ws_root = tmp_path / "workspaces"
    sess_root.mkdir(parents=True, exist_ok=True)
    ws_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(vault_mod, "_SESSION_ROOT_DIR", sess_root)
    monkeypatch.setattr(ws_mod, "_LOCAL_STORE_ROOT", ws_root)
    monkeypatch.delenv("IAM_WORKSPACE_BUCKET", raising=False)
    monkeypatch.delenv("WORKSPACE_GCS_BUCKET", raising=False)

    email = "t02-tester@example.com"
    ident = IamConsultantIdentity(
        email=email,
        display_name="T02 Tester",
        domain="example.com",
        subject="t02-tester-sub",
        auth_channel="verified_google_cookie",
    )
    sid = ws_mod.derive_workspace_id(email)
    sess = vault_mod.store_inspection_session(
        session_id=sid,
        owner_email=email,
        user_access_token="offline-direct-token",
        connection_mode="direct_user",
        organization_id="111111111111",
        organization_domain="alpha.example.com",
        customer_name="Alpha Corp",
        token_expires_at=time.time() + 3600.0,
    )

    client = TestClient(main_mod.app)
    client.cookies.set(IAM_SESSION_COOKIE, mint_consultant_cookie(ident))
    try:
        yield client, sess, sess_root
    finally:
        vault_mod.wipe_inspection_session(sid, email, wipe_persistent=True)


def test_scan_scope_a_download_then_scan_scope_b_download_has_no_stale_leak(
    isolated_deliverable_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Criterion 1: Scan Scope A -> download -> Scan Scope B -> download returns Scope B (never Scope A)."""
    client, sess, _ = isolated_deliverable_env

    scope_a = "organizations/111111111111"
    scope_b = "organizations/222222222222"
    books_by_scope = {
        scope_a: _make_book(
            scope_a,
            generated_at="2026-11-18T09:00:00+00:00",
            marker="MARKER_ALPHA_SCOPE_A",
            domain="alpha.example.com",
        ),
        scope_b: _make_book(
            scope_b,
            generated_at="2026-11-19T10:30:00+00:00",
            marker="MARKER_BETA_SCOPE_B",
            domain="beta.example.com",
        ),
    }

    async def fake_run_book(scope: str = "", model_name: str | None = None, force_refresh: bool = False):
        return books_by_scope[scope]

    monkeypatch.setattr(main_mod, "run_posture_book_assessment", fake_run_book)
    monkeypatch.setattr(report_mod, "run_posture_book_assessment", fake_run_book)

    # 1. Scan Scope A and download DOCX, PDF, and inventory JSON
    r_book_a = client.post(
        "/api/v1/book",
        params={"scope": scope_a},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert r_book_a.status_code == 200

    r_docx_a = client.get("/api/v1/download/docx", params={"scope": scope_a})
    assert r_docx_a.status_code == 200
    assert r_docx_a.headers.get("cache-control") == "no-store"
    cd_a = r_docx_a.headers.get("content-disposition", "")
    assert "111111111111" in cd_a
    assert "2026-11-18" in cd_a
    text_a = _extract_docx_text(r_docx_a.content)
    assert scope_a in text_a
    assert "MARKER_ALPHA_SCOPE_A" in text_a

    r_pdf_a = client.get("/api/v1/download/pdf", params={"scope": scope_a})
    assert r_pdf_a.status_code == 200
    assert r_pdf_a.content.startswith(b"%PDF-")
    assert r_pdf_a.headers.get("cache-control") == "no-store"
    pdf_text_a = _extract_pdf_text(r_pdf_a.content)
    assert "MARKER_ALPHA_SCOPE_A" in pdf_text_a

    # 2. Scan Scope B and download DOCX, PDF, and inventory JSON
    r_book_b = client.post(
        "/api/v1/book",
        params={"scope": scope_b},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert r_book_b.status_code == 200

    r_docx_b = client.get("/api/v1/download/docx", params={"scope": scope_b})
    assert r_docx_b.status_code == 200
    assert r_docx_b.headers.get("cache-control") == "no-store"
    cd_b = r_docx_b.headers.get("content-disposition", "")
    assert "222222222222" in cd_b
    assert "2026-11-19" in cd_b
    text_b = _extract_docx_text(r_docx_b.content)
    assert scope_b in text_b
    assert "MARKER_BETA_SCOPE_B" in text_b
    assert scope_a not in text_b
    assert "MARKER_ALPHA_SCOPE_A" not in text_b

    r_pdf_b = client.get("/api/v1/download/pdf", params={"scope": scope_b})
    assert r_pdf_b.status_code == 200
    assert r_pdf_b.content.startswith(b"%PDF-")
    assert r_pdf_b.content != r_pdf_a.content
    assert "222222222222" in r_pdf_b.headers.get("content-disposition", "")
    assert "2026-11-19" in r_pdf_b.headers.get("content-disposition", "")
    pdf_text_b = _extract_pdf_text(r_pdf_b.content)
    assert "MARKER_BETA_SCOPE_B" in pdf_text_b
    assert "MARKER_ALPHA_SCOPE_A" not in pdf_text_b
    assert scope_a not in pdf_text_b

    r_inv_b = client.get("/api/v1/download/inventory-json", params={"scope": scope_b})
    assert r_inv_b.status_code == 200
    assert r_inv_b.headers.get("cache-control") == "no-store"
    assert json.loads(r_inv_b.content)["scope"] == scope_b

    # Verify files were stored in separate per-scope subdirectories under session_export_dir
    dir_a = sess.session_export_dir / "scopes" / report_mod.scope_directory_hash(scope_a)
    dir_b = sess.session_export_dir / "scopes" / report_mod.scope_directory_hash(scope_b)
    assert dir_a != dir_b
    assert (dir_a / report_mod.BOOK_FILENAME).exists()
    assert (dir_b / report_mod.BOOK_FILENAME).exists()


def test_rescan_same_scope_invalidates_and_generates_new_file(
    isolated_deliverable_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Criterion 2 & Req 3: A fresh scan of the same scope invalidates old deliverables and generates a new file."""
    client, sess, _ = isolated_deliverable_env
    scope = "organizations/111111111111"

    runs = [
        _make_book(scope, generated_at="2026-11-18T08:00:00+00:00", marker="SCAN_GENERATION_ONE"),
        _make_book(scope, generated_at="2026-11-19T14:15:00+00:00", marker="SCAN_GENERATION_TWO"),
    ]
    call_idx = {"n": 0}

    async def fake_run_book(scope: str = "", model_name: str | None = None, force_refresh: bool = False):
        idx = min(call_idx["n"], len(runs) - 1)
        call_idx["n"] += 1
        return runs[idx]

    monkeypatch.setattr(main_mod, "run_posture_book_assessment", fake_run_book)
    monkeypatch.setattr(report_mod, "run_posture_book_assessment", fake_run_book)

    scope_dir = sess.session_export_dir / "scopes" / report_mod.scope_directory_hash(scope)

    # First scan + verify book.json written and deliverables absent
    r1_book = client.post(
        "/api/v1/book",
        params={"scope": scope},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert r1_book.status_code == 200
    assert (scope_dir / report_mod.BOOK_FILENAME).exists()
    assert not (scope_dir / report_mod.DOCX_FILENAME).exists()
    assert not (scope_dir / report_mod.PDF_FILENAME).exists()
    assert not (scope_dir / report_mod.INVENTORY_JSON_FILENAME).exists()

    # Download DOCX v1
    r1_docx = client.get("/api/v1/download/docx", params={"scope": scope})
    assert r1_docx.status_code == 200
    assert "SCAN_GENERATION_ONE" in _extract_docx_text(r1_docx.content)
    assert (scope_dir / report_mod.DOCX_FILENAME).exists()
    assert (scope_dir / report_mod.PDF_FILENAME).exists()
    assert (scope_dir / report_mod.INVENTORY_JSON_FILENAME).exists()

    # Second scan (refresh=true) on the SAME scope must invalidate DOCX, PDF, and inventory
    r2_book = client.post(
        "/api/v1/book",
        params={"scope": scope, "refresh": "true"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert r2_book.status_code == 200
    assert (scope_dir / report_mod.BOOK_FILENAME).exists()
    assert not (scope_dir / report_mod.DOCX_FILENAME).exists()
    assert not (scope_dir / report_mod.PDF_FILENAME).exists()
    assert not (scope_dir / report_mod.INVENTORY_JSON_FILENAME).exists()

    # Subsequent download must render the new DOCX (v2) without re-running ADK
    r2_docx = client.get("/api/v1/download/docx", params={"scope": scope})
    assert r2_docx.status_code == 200
    assert r2_docx.headers.get("cache-control") == "no-store"
    assert "2026-11-19" in r2_docx.headers.get("content-disposition", "")
    text_v2 = _extract_docx_text(r2_docx.content)
    assert "SCAN_GENERATION_TWO" in text_v2
    assert "SCAN_GENERATION_ONE" not in text_v2
    assert call_idx["n"] == 2  # Only the two /api/v1/book scans invoked assessment


def test_manifest_generated_at_mismatch_triggers_regeneration_without_llm(
    isolated_deliverable_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Req 5: If book.json generated_at differs from deliverables_manifest.json, download regenerates without LLM."""
    client, sess, _ = isolated_deliverable_env
    scope = "organizations/111111111111"
    scope_dir = sess.session_export_dir / "scopes" / report_mod.scope_directory_hash(scope)

    book_v1 = _make_book(scope, generated_at="2026-11-17T08:00:00+00:00", marker="MANIFEST_OLD_V1")
    report_mod.render_deliverables_from_book(book_v1, scope_dir)
    assert (scope_dir / report_mod.DOCX_FILENAME).exists()

    # Overwrite ONLY book.json with a newer generated_at while leaving old DOCX & old manifest on disk
    book_v2 = _make_book(scope, generated_at="2026-11-19T18:45:00+00:00", marker="MANIFEST_NEW_V2")
    report_mod.persist_book_snapshot(book_v2, scope_dir, invalidate_deliverables=False)

    async def fail_if_called(*args: Any, **kwargs: Any):
        raise AssertionError("ADK runner / assessment must NOT be called when book.json exists")

    monkeypatch.setattr(main_mod, "run_posture_book_assessment", fail_if_called)
    monkeypatch.setattr(report_mod, "run_posture_book_assessment", fail_if_called)

    resp = client.get("/api/v1/download/docx", params={"scope": scope})
    assert resp.status_code == 200
    text = _extract_docx_text(resp.content)
    assert "MANIFEST_NEW_V2" in text
    assert "MANIFEST_OLD_V1" not in text
    manifest = report_mod.read_deliverables_manifest(scope_dir)
    assert manifest.get("generated_at") == "2026-11-19T18:45:00+00:00"


def test_store_inspection_session_clears_export_dir_and_invokes_purge_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Criterion 3 & Req 1: Re-calling store_inspection_session with the same sid empties export dir & runs hooks."""
    sess_root = tmp_path / "sessions"
    ws_root = tmp_path / "workspaces"
    monkeypatch.setattr(vault_mod, "_SESSION_ROOT_DIR", sess_root)
    monkeypatch.setattr(ws_mod, "_LOCAL_STORE_ROOT", ws_root)
    monkeypatch.delenv("IAM_WORKSPACE_BUCKET", raising=False)
    monkeypatch.delenv("WORKSPACE_GCS_BUCKET", raising=False)

    sid = "t02-reconnect-sid"
    email = "reconnect@example.com"
    purged_sids: List[str] = []

    def _hook(session_id: str) -> None:
        purged_sids.append(session_id)

    monkeypatch.setattr(vault_mod, "_CACHE_PURGE_HOOKS", list(vault_mod._CACHE_PURGE_HOOKS))
    vault_mod.register_cache_purge_hook(_hook)

    try:
        sess1 = vault_mod.store_inspection_session(
            session_id=sid,
            owner_email=email,
            user_access_token="tok-1",
            connection_mode="direct_user",
            organization_id="111111111111",
            token_expires_at=time.time() + 3600.0,
        )
        export_dir = sess1.session_export_dir
        stale_scoped = export_dir / "scopes" / "abcdef0123456789" / report_mod.DOCX_FILENAME
        stale_scoped.parent.mkdir(parents=True, exist_ok=True)
        stale_scoped.write_bytes(b"stale-docx-content")
        (export_dir / "stale_root.txt").write_text("stale", encoding="utf-8")
        assert stale_scoped.exists()

        purged_sids.clear()
        sess2 = vault_mod.store_inspection_session(
            session_id=sid,
            owner_email=email,
            user_access_token="tok-2",
            connection_mode="direct_user",
            organization_id="222222222222",
            token_expires_at=time.time() + 3600.0,
        )
        assert sess2.session_export_dir == export_dir
        assert export_dir.exists()
        assert list(export_dir.iterdir()) == []
        assert sid in purged_sids
    finally:
        vault_mod.wipe_inspection_session(sid, email, wipe_persistent=True)


def test_download_does_not_call_adk_runner_when_book_json_exists(
    isolated_deliverable_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Criterion 4 & Req 4: Downloads render strictly from persisted book.json without invoking the ADK runner."""
    from google.adk.runners import Runner

    client, sess, _ = isolated_deliverable_env
    scope = "organizations/444444444444"
    scope_dir = sess.session_export_dir / "scopes" / report_mod.scope_directory_hash(scope)
    book = _make_book(
        scope,
        generated_at="2026-11-19T11:00:00+00:00",
        marker="NO_ADK_RUNNER_MARKER",
        domain="delta.example.com",
    )
    report_mod.persist_book_snapshot(book, scope_dir, invalidate_deliverables=True)

    async def fail_assessment(*args: Any, **kwargs: Any):
        raise AssertionError("run_posture_book_assessment must NOT be called when book.json exists")

    def fail_runner_run_async(*args: Any, **kwargs: Any):
        raise AssertionError("ADK Runner.run_async must NOT be called when book.json exists")

    monkeypatch.setattr(main_mod, "run_posture_book_assessment", fail_assessment)
    monkeypatch.setattr(report_mod, "run_posture_book_assessment", fail_assessment)
    monkeypatch.setattr(Runner, "run_async", fail_runner_run_async)

    for artifact_type in ("docx", "pdf", "terraform-zip", "inventory-json", "attack-graph-png"):
        resp = client.get(f"/api/v1/download/{artifact_type}", params={"scope": scope})
        assert resp.status_code == 200, f"{artifact_type} failed: {resp.status_code} {resp.text}"
        assert resp.headers.get("cache-control") == "no-store"
        cd = resp.headers.get("content-disposition", "")
        assert "444444444444" in cd
        assert "2026-11-19" in cd
        if artifact_type == "docx":
            assert "NO_ADK_RUNNER_MARKER" in _extract_docx_text(resp.content)
        elif artifact_type == "terraform-zip":
            with zipfile.ZipFile(io.BytesIO(resp.content), "r") as zf:
                assert "NO_ADK_RUNNER_MARKER" in zf.read("main.tf").decode("utf-8")
        elif artifact_type == "inventory-json":
            assert json.loads(resp.content)["scope"] == scope


def test_download_never_runs_scan_when_no_book_exists_for_scope(
    isolated_deliverable_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T21: a GET download never runs a scan or the LLM. Without a pinned book it answers 409; refresh=true is 405."""
    client, _, _ = isolated_deliverable_env
    scope = "organizations/555555555555"
    calls = {"n": 0}

    async def fake_run_book(scope: str = "", model_name: str | None = None, force_refresh: bool = False):
        calls["n"] += 1
        return _make_book(
            scope,
            generated_at="2026-11-19T16:00:00+00:00",
            marker="FALLBACK_LIVE_SCAN",
            domain="epsilon.example.com",
        )

    monkeypatch.setattr(main_mod, "run_posture_book_assessment", fake_run_book)
    monkeypatch.setattr(report_mod, "run_posture_book_assessment", fake_run_book)

    r1 = client.get("/api/v1/download/docx", params={"scope": scope})
    assert r1.status_code == 409
    assert "Run a scan first" in r1.json()["detail"]

    r2 = client.get("/api/v1/download/pdf", params={"scope": scope, "refresh": "true"})
    assert r2.status_code == 405
    assert r2.headers.get("allow") == "POST"

    r3 = client.get("/api/v1/download/inventory-json", params={"scope": scope})
    assert r3.status_code == 409

    assert calls["n"] == 0
