"""T16 — Repository hygiene tests (exports untracked, pinned deps & lock, CI, Dockerfile)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_PINNED_VERSIONS = {
    "google-adk": "2.14.1",
    "google-genai": "2.34.0",
    "fastapi": "0.162.0",
    "starlette": "1.10.0",
    "pydantic": "2.14.3",
    "httpx": "0.28.1",
    "google-auth": "2.62.2",
    "reportlab": "5.1.0",
    "python-docx": "1.2.0",
    "networkx": "3.7",
    "matplotlib": "3.11.2",
    "uvicorn": "0.54.0",
    "streamlit": "1.67.0",
}


def _parse_pinned_requirements(path: Path) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        assert "==" in line, f"Unpinned dependency in {path.name}: {line}"
        name_part, version = line.split("==", 1)
        # Normalize extras like uvicorn[standard] -> uvicorn
        pkg = re.sub(r"\[.*\]", "", name_part).strip().lower()
        parsed[pkg] = version.strip()
    return parsed


def test_t16_exports_untracked_in_git_and_preserved_on_disk() -> None:
    proc = subprocess.run(
        ["git", "ls-files", "exports"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.stdout.strip() == "", f"exports/ still tracked in git:\n{proc.stdout}"

    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "exports/" in gitignore

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "git filter-repo --path exports --invert-paths" in readme


def test_t16_direct_requirements_and_lockfile_are_pinned_exactly() -> None:
    req_path = REPO_ROOT / "requirements.txt"
    lock_path = REPO_ROOT / "requirements.lock"
    dev_path = REPO_ROOT / "requirements-dev.txt"

    assert req_path.is_file()
    assert lock_path.is_file()
    assert dev_path.is_file()

    direct = _parse_pinned_requirements(req_path)
    locked = _parse_pinned_requirements(lock_path)
    dev = _parse_pinned_requirements(dev_path)

    for pkg, expected_ver in EXPECTED_PINNED_VERSIONS.items():
        assert direct.get(pkg) == expected_ver, f"requirements.txt mismatch for {pkg}: {direct.get(pkg)}"
        assert locked.get(pkg) == expected_ver, f"requirements.lock mismatch for {pkg}: {locked.get(pkg)}"

    # Every direct runtime requirement must appear with the exact same version in requirements.lock
    for pkg, ver in direct.items():
        assert locked.get(pkg) == ver, f"Lockfile missing or mismatched direct dep {pkg}=={ver}"

    assert "pytest" in dev
    assert "pytest" not in locked


def test_t16_ci_workflow_runs_pytest_and_shellcheck() -> None:
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_path.is_file(), "Missing .github/workflows/ci.yml"

    data = yaml.safe_load(ci_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    raw = ci_path.read_text(encoding="utf-8")
    assert "pytest -q" in raw
    assert "shellcheck" in raw
    assert "bash -n" in raw
    assert "requirements.lock" in raw


def test_t16_dockerfile_removes_curl_and_uses_lockfile() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert not re.search(r"\bcurl\b", dockerfile), "Dockerfile must not install or invoke curl"
    assert "requirements.lock" in dockerfile
