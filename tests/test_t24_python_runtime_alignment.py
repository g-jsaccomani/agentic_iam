"""T24 — the container, CI and lockfile must agree on the Python version.

`requirements.lock` is a plain freeze of one interpreter's environment. When the Dockerfile or CI used an
older Python than the one the lock was frozen from, `pip install -r requirements.lock` failed (for example
`contourpy==1.4.0` requires Python >= 3.12), which broke both CI and the Cloud Run image build.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _lock_python() -> str:
    header = (REPO_ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines()[0]
    match = re.search(r"Python (\d+\.\d+)", header)
    assert match, "requirements.lock header must state the Python version it was frozen from"
    return match.group(1)


def test_dockerfile_uses_the_python_the_lock_was_frozen_from() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    match = re.search(r"^FROM python:(\d+\.\d+)", dockerfile, flags=re.M)
    assert match, "Dockerfile must start from an official python:<major>.<minor> image"
    assert match.group(1) == _lock_python()


def test_ci_uses_the_python_the_lock_was_frozen_from() -> None:
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    versions = re.findall(r"python-version:\s*[\"']?(\d+\.\d+)", ci)
    assert versions, "CI must pin a python-version"
    assert set(versions) == {_lock_python()}


def test_this_suite_runs_on_the_python_the_lock_was_frozen_from() -> None:
    assert f"{sys.version_info.major}.{sys.version_info.minor}" == _lock_python()
