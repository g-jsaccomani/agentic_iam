"""Smoke tests verifying T00 offline test infrastructure fixtures and guards."""

from __future__ import annotations

import re

import httpx
import pytest

from tests.conftest import OfflineNetworkError


def test_fake_session_binds_active_context(fake_session) -> None:
    """Verifies `fake_session` creates and binds an `InspectionSession` in ContextVar scope."""
    from backend.session_vault import (
        get_active_inspection_session,
        require_active_inspection_session,
    )

    active = get_active_inspection_session()
    assert active is fake_session
    assert require_active_inspection_session().session_id == "test-session-001"
    assert active.organization_id == "123456789012"
    assert active.is_live_token_valid is True


def test_fake_gcp_routes_in_memory_without_network(fake_session, fake_gcp) -> None:
    """Verifies `fake_gcp` replaces `cai_collector.gcp_rest_request` and sibling imports in memory."""
    from backend.tools import cai_collector, directory_collector

    iam_url = "https://cloudasset.googleapis.com/v1/organizations/123456789012:searchAllIamPolicies"
    org_policy_re = re.compile(r"orgpolicy\.googleapis\.com/.+:getEffectiveOrgPolicy$")
    dir_url = "https://admin.googleapis.com/admin/directory/v1/users"

    fake_gcp.add(
        "GET",
        iam_url,
        status=200,
        data={"results": [{"resource": "//cloudresourcemanager.googleapis.com/projects/demo-proj"}]},
    )
    fake_gcp.add("POST", org_policy_re, status=200, data={"spec": {"rules": [{"enforce": True}]}})
    fake_gcp.add("GET", dir_url, status=200, data={"users": [{"primaryEmail": "alice@example.com"}]})

    status_get, data_get = cai_collector.gcp_rest_request("GET", iam_url, params={"pageSize": 50})
    assert status_get == 200
    assert data_get["results"][0]["resource"].endswith("/projects/demo-proj")

    status_post, data_post = cai_collector.gcp_rest_request(
        "POST",
        "https://orgpolicy.googleapis.com/v2/organizations/123456789012:getEffectiveOrgPolicy",
        json_body={"constraint": "constraints/iam.allowedPolicyMemberDomains"},
    )
    assert status_post == 200
    assert data_post["spec"]["rules"][0]["enforce"] is True

    status_dir, data_dir = directory_collector.gcp_rest_request("GET", dir_url)
    assert status_dir == 200
    assert data_dir["users"][0]["primaryEmail"] == "alice@example.com"

    assert len(fake_gcp.calls) == 3
    assert fake_gcp.calls[0]["method"] == "GET"
    assert fake_gcp.calls[0]["params"] == {"pageSize": 50}
    assert fake_gcp.calls[1]["method"] == "POST"
    assert fake_gcp.calls[2]["url"] == dir_url


def test_fake_gcp_sequence_supports_pagination(fake_session, fake_gcp) -> None:
    """Verifies `fake_gcp.add_sequence` returns successive pages in order."""
    from backend.tools import cai_collector

    url = "https://cloudasset.googleapis.com/v1/organizations/123456789012:searchAllResources"
    fake_gcp.add_sequence(
        "GET",
        url,
        [
            (200, {"results": [{"name": "item-1"}], "nextPageToken": "tok-2"}),
            (200, {"results": [{"name": "item-2"}]}),
        ],
    )

    s1, d1 = cai_collector.gcp_rest_request("GET", url)
    s2, d2 = cai_collector.gcp_rest_request("GET", url, params={"pageToken": "tok-2"})
    assert (s1, d1["results"][0]["name"], d1["nextPageToken"]) == (200, "item-1", "tok-2")
    assert (s2, d2["results"][0]["name"]) == (200, "item-2")


def test_unmocked_httpx_get_fails_with_clear_message() -> None:
    """Verifies an unmocked `httpx.get` call fails immediately with a clear offline error."""
    with pytest.raises(OfflineNetworkError) as exc_info:
        httpx.get("https://example.com/should-not-hit-network")

    msg = str(exc_info.value)
    assert "Outbound network request blocked" in msg
    assert "GET" in msg
    assert "https://example.com/should-not-hit-network" in msg


def test_unmocked_cai_client_fails_without_fake_gcp(fake_session) -> None:
    """Verifies pre-initialized `cai_collector._HTTP_CLIENT` is also blocked without `fake_gcp`."""
    from backend.tools import cai_collector

    with pytest.raises(OfflineNetworkError, match="Outbound network request blocked"):
        cai_collector.gcp_rest_request(
            "GET",
            "https://cloudasset.googleapis.com/v1/organizations/123456789012:searchAllIamPolicies",
        )


@pytest.mark.asyncio
async def test_unmocked_async_httpx_fails_with_clear_message() -> None:
    """Verifies async `httpx` egress is also blocked and `pytest-asyncio` works offline."""
    async with httpx.AsyncClient() as client:
        with pytest.raises(OfflineNetworkError) as exc_info:
            await client.get("https://example.com/async-blocked")

    assert "Outbound async network request blocked" in str(exc_info.value)


def test_backend_config_and_coordinator_import_without_credentials() -> None:
    """Verifies `backend.config`, `backend.agents.coordinator`, and `backend.main` work offline without credentials."""
    import google.auth

    import backend.agents.coordinator as coordinator
    import backend.config as config
    import backend.main as main_mod
    from fastapi.testclient import TestClient
    from tests.conftest import OfflineCredentialError

    assert config.settings.project_id
    assert coordinator.root_agent is not None
    assert coordinator.root_agent.name == "iam_coordinator"

    with pytest.raises(OfflineCredentialError, match="Blocked google.auth.default"):
        google.auth.default()

    client = TestClient(main_mod.app)
    resp = client.get("/health")
    assert resp.status_code == 200
