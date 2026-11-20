"""T15 — Deploy scripts hardening tests (offline, zero real gcloud execution)."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
BOOTSTRAP_SCRIPT = SCRIPTS_DIR / "01_bootstrap_gcp.sh"
DEPLOY_SCRIPT = SCRIPTS_DIR / "02_deploy_cloud_run.sh"


def _make_poison_bin_dir(tmp_path: Path) -> tuple[Path, Path]:
    """Create stub gcloud/bq/python3 binaries that record any execution and fail loudly."""
    bin_dir = tmp_path / "poison_bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    marker = tmp_path / "executed_commands.log"
    for cmd in ("gcloud", "bq", "python3"):
        stub = bin_dir / cmd
        stub.write_text(
            "#!/usr/bin/env bash\n"
            f'printf "%s %s\\n" "{cmd}" "$*" >> "{marker}"\n'
            "exit 99\n",
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir, marker


def _clean_env(bin_dir: Path, extra: dict[str, str]) -> dict[str, str]:
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(bin_dir.parent),
    }
    env.update(extra)
    return env


def test_t15_bash_syntax_check_passes_for_all_shell_scripts() -> None:
    shell_scripts = sorted(SCRIPTS_DIR.glob("*.sh"))
    assert len(shell_scripts) >= 2
    for script in shell_scripts:
        proc = subprocess.run(
            ["bash", "-n", str(script)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"bash -n failed for {script.name}: {proc.stderr}"


def test_t15_no_hardcoded_personal_defaults_or_oauth_ids_in_scripts() -> None:
    forbidden_patterns = [
        # Hardcoded OAuth client IDs or live Cloud Run service URLs
        re.compile(r"\.apps\.googleusercontent\.com", re.IGNORECASE),
        re.compile(r"https?://[a-z0-9-]+\.[a-z0-9-]+\.run\.app", re.IGNORECASE),
        # Hardcoded real corporate/personal domains (only RFC 2606 .example domains allowed in comments)
        re.compile(r"domain:(?!corp\.example\b|[a-z0-9.-]+\.example\b)[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE),
        re.compile(
            r"\b[a-z0-9._%+-]+@(?!corp\.example\b|[a-z0-9.-]+\.example\b"
            r"|[a-z0-9.-]+\.iam\.gserviceaccount\.com\b"
            r"|developer\.gserviceaccount\.com\b"
            r"|gcp-sa-[a-z0-9.-]+\.iam\.gserviceaccount\.com\b"
            r")[a-z0-9.-]+\.[a-z]{2,}",
            re.IGNORECASE,
        ),
        # Hardcoded non-placeholder 10-14 digit org/project numbers
        re.compile(r"\b(?!000000000000\b|000000000001\b|123456789012\b)[0-9]{10,14}\b"),
    ]
    for path in sorted(SCRIPTS_DIR.glob("*.sh")):
        text = path.read_text(encoding="utf-8")
        for pat in forbidden_patterns:
            assert not pat.search(text), f"Forbidden pattern {pat.pattern!r} found in {path.name}"


@pytest.mark.parametrize(
    "missing_var",
    ["ACCOUNT", "ORG_ID", "PROJECT_ID"],
)
def test_t15_bootstrap_fails_before_gcloud_when_mandatory_var_missing(
    tmp_path: Path, missing_var: str
) -> None:
    bin_dir, marker = _make_poison_bin_dir(tmp_path)
    vars_map = {
        "ACCOUNT": "admin@corp.example",
        "ORG_ID": "123456789012",
        "PROJECT_ID": "my-valid-project-1",
    }
    vars_map.pop(missing_var)
    proc = subprocess.run(
        ["bash", str(BOOTSTRAP_SCRIPT)],
        env=_clean_env(bin_dir, vars_map),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert not marker.exists(), f"gcloud/bq was executed before env validation: {marker.read_text()}"


@pytest.mark.parametrize(
    "env_override",
    [
        {"PROJECT_ID": "my-valid-project-1", "ALLOWED_IAP_DOMAINS": "corp.example", "IAP_MEMBERS": "domain:corp.example"},  # missing ACCOUNT
        {"ACCOUNT": "admin@corp.example", "ALLOWED_IAP_DOMAINS": "corp.example", "IAP_MEMBERS": "domain:corp.example"},  # missing PROJECT_ID
        {"ACCOUNT": "admin@corp.example", "PROJECT_ID": "my-valid-project-1", "IAP_MEMBERS": "domain:corp.example"},  # missing ALLOWED_IAP_DOMAINS
        {"ACCOUNT": "admin@corp.example", "PROJECT_ID": "my-valid-project-1", "ALLOWED_IAP_DOMAINS": "corp.example"},  # missing IAP_MEMBERS
        {
            "ACCOUNT": "admin@corp.example",
            "PROJECT_ID": "my-valid-project-1",
            "ALLOWED_IAP_DOMAINS": "*",
            "IAP_MEMBERS": "domain:corp.example",
        },  # wildcard without explicit opt-in
        {
            "ACCOUNT": "admin@corp.example",
            "PROJECT_ID": "my-valid-project-1",
            "ALLOWED_IAP_DOMAINS": "corp.example",
            "IAP_MEMBERS": "allAuthenticatedUsers",
        },  # allAuthenticatedUsers without opt-in
        {
            "ACCOUNT": "admin@corp.example",
            "PROJECT_ID": "my-valid-project-1",
            "ALLOWED_IAP_DOMAINS": "corp.example",
            "IAP_MEMBERS": "allUsers",
            "ALLOW_ANY_GOOGLE_ACCOUNT": "true",
        },  # allUsers always forbidden
    ],
)
def test_t15_deploy_fails_before_gcloud_on_missing_or_unsafe_vars(
    tmp_path: Path, env_override: dict[str, str]
) -> None:
    bin_dir, marker = _make_poison_bin_dir(tmp_path)
    proc = subprocess.run(
        ["bash", str(DEPLOY_SCRIPT)],
        env=_clean_env(bin_dir, env_override),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert not marker.exists(), f"gcloud was executed despite invalid env: {marker.read_text()}"


def test_t15_bootstrap_dry_run_executes_zero_commands_and_grants_minimal_roles(
    tmp_path: Path,
) -> None:
    bin_dir, marker = _make_poison_bin_dir(tmp_path)
    proc = subprocess.run(
        ["bash", str(BOOTSTRAP_SCRIPT)],
        env=_clean_env(
            bin_dir,
            {
                "DRY_RUN": "1",
                "ACCOUNT": "admin@corp.example",
                "ORG_ID": "123456789012",
                "PROJECT_ID": "agentic-iam-prod-1",
            },
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert not marker.exists(), f"DRY_RUN=1 executed commands: {marker.read_text()}"

    combined = proc.stdout + "\n" + proc.stderr
    assert "[DRY_RUN]" in combined
    # Runtime SA receives ONLY aiplatform.user and logging.logWriter
    role_matches = re.findall(r"--role=([^\s]+)", combined)
    assert sorted(role_matches) == ["roles/aiplatform.user", "roles/logging.logWriter"]

    # Legacy grant revocation commands are documented in header comments
    script_text = BOOTSTRAP_SCRIPT.read_text(encoding="utf-8")
    assert "remove-iam-policy-binding" in script_text
    assert "roles/cloudasset.viewer" in script_text
    assert "|| true" not in script_text


def test_t15_deploy_dry_run_service_scoped_iap_and_no_storage_admin(tmp_path: Path) -> None:
    bin_dir, marker = _make_poison_bin_dir(tmp_path)
    proc = subprocess.run(
        ["bash", str(DEPLOY_SCRIPT)],
        env=_clean_env(
            bin_dir,
            {
                "DRY_RUN": "1",
                "ACCOUNT": "admin@corp.example",
                "PROJECT_ID": "agentic-iam-prod-1",
                "ALLOWED_IAP_DOMAINS": "corp.example,partner.example",
                "IAP_MEMBERS": "domain:corp.example, user:auditor@partner.example",
            },
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert not marker.exists(), f"DRY_RUN=1 executed commands: {marker.read_text()}"

    combined = proc.stdout + "\n" + proc.stderr
    assert "[DRY_RUN]" in combined
    # Compute SA must NOT get roles/storage.admin
    assert "roles/storage.admin" not in combined
    # Cloud Run state & background scan flags (T08/T09)
    assert "--min-instances=1" in combined
    assert "--max-instances=1" in combined
    assert "--session-affinity" in combined
    assert "--no-cpu-throttling" in combined

    # roles/run.invoker bound strictly to the IAP service agent
    invoker_lines = [line for line in combined.splitlines() if "roles/run.invoker" in line]
    assert len(invoker_lines) == 1
    assert "serviceAccount:service-000000000000@gcp-sa-iap.iam.gserviceaccount.com" in invoker_lines[0]

    # Service-level IAP bindings for configured IAP_MEMBERS, never allAuthenticatedUsers
    iap_lines = [line for line in combined.splitlines() if "iap web add-iam-policy-binding" in line]
    assert len(iap_lines) == 2
    for line in iap_lines:
        assert "--resource-type=cloud-run" in line
        assert "--service=agentic-iam-accelerator" in line
        assert "allAuthenticatedUsers" not in line
    assert any("domain:corp.example" in line for line in iap_lines)
    assert any("user:auditor@partner.example" in line for line in iap_lines)

    # Static checks on deploy script: trap cleanup EXIT and no || true
    script_text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert "trap cleanup EXIT" in script_text
    assert "|| true" not in script_text


def test_t15_deploy_dry_run_opt_in_allow_any_google_account(tmp_path: Path) -> None:
    bin_dir, marker = _make_poison_bin_dir(tmp_path)
    proc = subprocess.run(
        ["bash", str(DEPLOY_SCRIPT)],
        env=_clean_env(
            bin_dir,
            {
                "DRY_RUN": "1",
                "ACCOUNT": "admin@corp.example",
                "PROJECT_ID": "agentic-iam-prod-1",
                "ALLOWED_IAP_DOMAINS": "*",
                "ALLOW_ANY_GOOGLE_ACCOUNT": "true",
            },
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert not marker.exists()
    combined = proc.stdout + "\n" + proc.stderr
    iap_lines = [line for line in combined.splitlines() if "iap web add-iam-policy-binding" in line]
    assert len(iap_lines) == 1
    assert "--resource-type=cloud-run" in iap_lines[0]
    assert "--member=allAuthenticatedUsers" in iap_lines[0]
