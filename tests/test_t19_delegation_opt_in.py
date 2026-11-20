"""Tests for T19 — runtime-SA auto-renew is an explicit, deployment-gated opt-in (N1, N6)."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from backend import main as main_mod
from backend import session_vault as sv
from backend import workspace_store as ws
from backend.tools.onboarding_manager import generate_customer_onboarding_kit
from tests.round2_helpers import ORG_A, SA_A, XRW, authed_client, connect_sa, reset_state, stub_token_minting

FLAG = "IAM_ENABLE_PERSISTENT_DELEGATION"
BASE = dict(
    customer_name="ACME",
    organization_id="123456789012",
    seed_project_id="prj-sec-gov",
    impersonator_user_email="me@example.com",
)
GRANT_MARKERS = ("allow_persistent_auto_renew", "DELEGATION_SA_MEMBER", "ENABLE_PERSISTENT_AUTO_RENEW")


@pytest.fixture(autouse=True)
def _clean_state():
    reset_state()
    yield
    reset_state()


def _grants_runtime_sa(text: str) -> bool:
    """True when any line grants something to the platform runtime SA (revoke lines do not count)."""
    return any("sa-agentic-iam-engine" in ln and "remove-iam-policy-binding" not in ln for ln in text.splitlines())


def test_default_kit_grants_nothing_to_the_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FLAG, "true")  # even when the deployment offers auto-renew, the default kit omits it
    kit = generate_customer_onboarding_kit(**BASE)
    for key in ("bash_script", "terraform_hcl", "guide_markdown"):
        assert not any(marker in kit[key] for marker in GRANT_MARKERS), key
        assert not _grants_runtime_sa(kit[key]), key
    assert "sa-agentic-iam-engine" not in kit["terraform_hcl"]
    assert "receives **zero** permissions" in kit["guide_markdown"]


def test_opt_in_is_refused_when_the_deployment_did_not_enable_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    with pytest.raises(ValueError, match="not enabled on this deployment"):
        generate_customer_onboarding_kit(**BASE, enable_persistent_auto_renew=True)


def test_opt_in_kit_is_conditional_and_tells_the_customer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FLAG, "true")
    kit = generate_customer_onboarding_kit(**BASE, enable_persistent_auto_renew=True)

    tf = kit["terraform_hcl"]
    assert 'variable "enable_persistent_auto_renew"' in tf
    assert "count              = var.enable_persistent_auto_renew ? 1 : 0" in tf

    sh = kit["bash_script"]
    assert subprocess.run(["bash", "-n"], input=sh, text=True, capture_output=True).returncode == 0
    assert '"${ENABLE_PERSISTENT_AUTO_RENEW:-true}" == "true"' in sh
    assert "DELEGATION_SA_MEMBER=" in sh

    guide = kit["guide_markdown"]
    assert "Optional Persistent Auto-Renew (enabled in this kit)" in guide
    assert "Revoking the consultant's own access does NOT remove it" in guide
    assert "receives **zero** permissions" not in guide


def test_direct_user_kit_never_carries_auto_renew(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FLAG, "true")
    kit = generate_customer_onboarding_kit(**BASE, onboarding_mode="direct_user", enable_persistent_auto_renew=True)
    for key in ("bash_script", "terraform_hcl"):
        assert not any(marker in kit[key] for marker in GRANT_MARKERS), key


def test_kit_endpoint_honours_the_deployment_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    client = authed_client("t19-kit@example.com")
    refused = client.post("/api/v1/onboarding/kit", json={**BASE, "enable_persistent_auto_renew": True}, headers=XRW)
    assert refused.status_code == 400
    default = client.post("/api/v1/onboarding/kit", json=BASE, headers=XRW)
    assert default.status_code == 200
    assert not _grants_runtime_sa(default.json()["bash_script"])


def test_runtime_sa_minting_is_refused_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)

    def _must_not_load_host_credentials(*_a, **_k):
        raise AssertionError("host credentials must not be loaded when delegation is disabled")

    monkeypatch.setattr("google.auth.default", _must_not_load_host_credentials)
    with pytest.raises(PermissionError, match="disabled"):
        sv.mint_delegated_sa_token_via_runtime_sa(SA_A)
    assert sv.configured_delegation_sa_email() == ""


def test_reconnect_without_user_token_is_refused_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    calls = stub_token_minting(monkeypatch)
    email = "t19-off@example.com"
    sess = connect_sa(email, SA_A, ORG_A)
    assert calls == [("user", SA_A)]  # no silent runtime-SA probe
    assert sess.persistent_sa_delegation is False

    with pytest.raises(PermissionError):
        connect_sa(email, SA_A, ORG_A, token="")
    assert ("runtime", SA_A) not in calls


def test_reconnect_without_user_token_needs_a_delegation_verified_with_the_user_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(FLAG, "true")
    email = "t19-unverified@example.com"
    calls = stub_token_minting(monkeypatch, runtime_ok=False)
    assert connect_sa(email, SA_A, ORG_A).persistent_sa_delegation is False

    calls = stub_token_minting(monkeypatch, runtime_ok=True)  # the grant appears later: still needs the user once
    with pytest.raises(PermissionError):
        connect_sa(email, SA_A, ORG_A, token="")
    assert calls == []

    verified = connect_sa(email, SA_A, ORG_A)
    assert verified.persistent_sa_delegation is True
    again = connect_sa(email, SA_A, ORG_A, token="")
    assert again.effective_access_token == "ya29.runtime-minted"


def test_expired_token_is_not_renewed_through_the_runtime_sa_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    calls = stub_token_minting(monkeypatch)
    sess = sv.InspectionSession(
        session_id=ws.derive_workspace_id("t19-renew@example.com"),
        owner_email="t19-renew@example.com",
        connection_mode="impersonated_sa",
        base_user_access_token="",
        impersonated_sa_email=SA_A,
        effective_access_token="ya29.expired",
        token_expires_at=time.time() - 10.0,
        persistent_sa_delegation=True,
    )
    assert sv._try_renew_session_token(sess, force=True) is False
    assert calls == []


def test_dashboard_and_api_text_make_no_false_claims(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    source = Path(main_mod.__file__).read_text(encoding="utf-8")
    assert "powered 100%" not in source
    assert "powered 100%" not in main_mod.app.description

    html = authed_client("t19-ui@example.com").get("/").text
    assert "__AUTO_RENEW_DISPLAY__" not in html
    assert "__RETENTION_OPTIONS_HTML__" not in html
    assert 'const DELEGATION_SA_EMAIL = "";' in html
    assert '<option value="0">Do not persist (session only)</option>' in html
    assert '<option value="30" selected>30 days</option>' in html
