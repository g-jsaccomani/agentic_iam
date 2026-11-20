"""Offline tests for T13 — Strict Scope Validation, Read-Only HTTP Guard, and Clean Role Cache (M3, M4)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend import main as main_mod
from backend.identity_guard import IAM_SESSION_COOKIE, IamConsultantIdentity, mint_consultant_cookie
from backend.tools import cai_collector, recommender_tool
from backend.validators import (
    assert_read_only_gcp_request,
    validate_bq_table_id,
    validate_folder_id,
    validate_org_id,
    validate_project_id,
    validate_sa_email,
)


# ==============================================================================
# 1. Strict Resource ID & Scope Validators
# ==============================================================================


@pytest.mark.parametrize(
    "bad_scope",
    [
        "projects/victim-proj:setIamPolicy?x=",
        "projects/victim-proj:setIamPolicy",
        "organizations/123456789012:setIamPolicy?x=",
        "organizations/abc123",
        "organizations/123456789012/extra/path",
        "folders/not-digits",
        "folders/12345/sub",
        "projects/UPPER-CASE-PROJ",
        "projects/short",
        "projects/a../etc/passwd",
        "organizations/123456789012/projects:good-proj,bad:setIamPolicy",
    ],
)
def test_malicious_and_invalid_scopes_raise_value_error(bad_scope: str) -> None:
    """Acceptance Criterion 1: `projects/victim-proj:setIamPolicy?x=` and malformed scopes raise ValueError."""
    with pytest.raises(ValueError):
        cai_collector.parse_assessment_scope(bad_scope)


def test_valid_scopes_parse_cleanly() -> None:
    p_org = cai_collector.parse_assessment_scope("organizations/123456789012")
    assert p_org.canonical_scope == "organizations/123456789012"
    assert p_org.mode == "ORG_ALL"

    p_multi = cai_collector.parse_assessment_scope("organizations/123456789012/projects:prj-alpha-01,prj-beta-02")
    assert p_multi.canonical_scope == "organizations/123456789012/projects:prj-alpha-01,prj-beta-02"
    assert p_multi.project_ids == ("prj-alpha-01", "prj-beta-02")

    p_fld = cai_collector.parse_assessment_scope("folders/987654321")
    assert p_fld.canonical_scope == "folders/987654321"
    assert p_fld.mode == "FOLDER"


def test_validators_reject_malformed_ids() -> None:
    assert validate_org_id("123456789012") == "123456789012"
    assert validate_folder_id("folders/999") == "999"
    assert validate_project_id("prj-valid-01") == "prj-valid-01"
    assert validate_sa_email("sa-iam-assessor@prj-valid-01.iam.gserviceaccount.com").endswith(".gserviceaccount.com")
    assert validate_bq_table_id("prj-valid-01.iam_ds.posture_findings") == ("prj-valid-01", "iam_ds", "posture_findings")

    with pytest.raises(ValueError):
        validate_org_id("123:setIamPolicy")
    with pytest.raises(ValueError):
        validate_project_id("victim-proj:setIamPolicy?x=")
    with pytest.raises(ValueError):
        validate_sa_email("sa@prj-valid-01.iam.gserviceaccount.com:signJwt?x=")
    with pytest.raises(ValueError):
        validate_bq_table_id("bad-proj/../../tables.ds.tbl")


def test_invalid_scope_returns_http_400_on_api_route(fake_session) -> None:
    """Invalid scope query parameter translates cleanly into HTTP 400 on FastAPI routes."""
    from backend import session_vault, workspace_store

    ident = IamConsultantIdentity(
        email=fake_session.owner_email,
        display_name="T13 Tester",
        domain="example.com",
        subject="sub-t13",
        auth_channel="verified_google_cookie",
    )
    sid = workspace_store.derive_workspace_id(fake_session.owner_email)
    session_vault.store_inspection_session(
        session_id=sid,
        owner_email=fake_session.owner_email,
        user_access_token="offline-token",
        connection_mode="direct_user",
        organization_id="123456789012",
        token_expires_at=fake_session.token_expires_at,
    )
    client = TestClient(main_mod.app)
    client.cookies.set(IAM_SESSION_COOKIE, mint_consultant_cookie(ident))

    resp = client.get("/api/v1/inventory", params={"scope": "projects/victim-proj:setIamPolicy?x="})
    assert resp.status_code == 400


# ==============================================================================
# 2. Read-Only HTTP Guard in gcp_rest_request
# ==============================================================================


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/victim-proj:setIamPolicy"),
        ("POST", "https://iam.googleapis.com/v1/projects/victim-proj/serviceAccounts/sa@p.iam.gserviceaccount.com/keys"),
        ("DELETE", "https://iam.googleapis.com/v1/projects/victim-proj/serviceAccounts/sa@p.iam.gserviceaccount.com"),
        ("PUT", "https://storage.googleapis.com/storage/v1/b/victim-bucket"),
        ("GET", "https://evil.example.com/v1/organizations/123:searchAllIamPolicies"),
        ("GET", "http://cloudasset.googleapis.com/v1/organizations/123:searchAllIamPolicies"),
        ("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/victim-proj:setIamPolicy%3Fx=:getIamPolicy"),
    ],
)
def test_gcp_rest_request_blocks_disallowed_post_and_hosts_before_network(
    fake_session,
    method: str,
    url: str,
) -> None:
    """Acceptance Criterion 2: POST outside allowlist raises PermissionError before any network call."""
    with pytest.raises(PermissionError):
        cai_collector.gcp_rest_request(method, url)


def test_read_only_guard_permits_approved_read_and_post_endpoints() -> None:
    assert_read_only_gcp_request("GET", "https://cloudasset.googleapis.com/v1/organizations/123:searchAllIamPolicies")
    assert_read_only_gcp_request("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/prj-demo-01:getIamPolicy")
    assert_read_only_gcp_request("POST", "https://cloudresourcemanager.googleapis.com/v1/organizations/123:getEffectiveOrgPolicy")
    assert_read_only_gcp_request("POST", "https://logging.googleapis.com/v2/entries:list")
    assert_read_only_gcp_request("POST", "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa%40p.iam.gserviceaccount.com:generateAccessToken")
    assert_read_only_gcp_request("POST", "https://bigquery.googleapis.com/bigquery/v2/projects/prj-demo-01/datasets/ds/tables/tbl/insertAll")


# ==============================================================================
# 3. Allowed Scope Containment for Tools
# ==============================================================================


def test_tool_called_with_different_organization_than_session_is_rejected(fake_session, fake_gcp) -> None:
    """Acceptance Criterion 3: Tool called with a different organization than the active session is rejected."""
    # fake_session belongs to organizations/123456789012
    with pytest.raises(PermissionError):
        cai_collector.collect_cai_iam_bindings("organizations/999999999999")
    with pytest.raises(PermissionError):
        recommender_tool.collect_change_impact_evidence("organizations/999999999999")
    assert fake_gcp.calls == []


def test_allowed_scope_context_blocks_out_of_scope_projects(fake_session, fake_gcp) -> None:
    """Request-bound allowed scope blocks tools targeting projects outside the allowed selection."""
    with cai_collector.bind_allowed_scope_context("organizations/123456789012/projects:prj-allowed-01"):
        # Inside allowed scope passes check
        parsed = cai_collector.assert_scope_allowed("organizations/123456789012/projects:prj-allowed-01")
        assert parsed.project_ids == ("prj-allowed-01",)

        # Escalating to ORG_ALL or a different project is rejected
        with pytest.raises(PermissionError):
            cai_collector.assert_scope_allowed("organizations/123456789012")
        with pytest.raises(PermissionError):
            cai_collector.assert_scope_allowed("organizations/123456789012/projects:prj-other-02")


# ==============================================================================
# 4. _ROLE_META_CACHE Only Caches HTTP 200 Successes
# ==============================================================================


def test_role_meta_cache_403_in_one_session_does_not_poison_another_session(fake_session, fake_gcp) -> None:
    """Acceptance Criterion 4: HTTP 403 for a role in session A must NOT poison session B's lookup."""
    recommender_tool._ROLE_META_CACHE.clear()
    fake_gcp.add_sequence(
        "GET",
        "https://iam.googleapis.com/v1/roles/viewer",
        [
            (403, {"error": {"message": "Permission denied for session A"}}),
            (
                200,
                {
                    "title": "Viewer",
                    "stage": "GA",
                    "includedPermissions": ["resourcemanager.projects.get", "storage.buckets.list"],
                },
            ),
        ],
    )

    # First call gets 403 -> must NOT be cached
    res_a = recommender_tool.get_live_role_metadata("roles/viewer")
    assert res_a["status"] == "HTTP_403"
    assert "roles/viewer" not in recommender_tool._ROLE_META_CACHE

    # Second call succeeds with 200 -> gets real permissions AND is cached
    res_b = recommender_tool.get_live_role_metadata("roles/viewer")
    assert res_b["status"] == "LIVE_IAM_ROLES_API"
    assert res_b["included_permissions_count"] == 2
    assert "roles/viewer" in recommender_tool._ROLE_META_CACHE

    # Third call serves from cache (no 3rd HTTP request)
    res_c = recommender_tool.get_live_role_metadata("roles/viewer")
    assert res_c["included_permissions_count"] == 2
    assert len(fake_gcp.calls) == 2
