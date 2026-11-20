"""T25: Repository sanitization & anti-leak guardrails.

Ensures no collected environment data (exports, posture books, inventories,
reports, graphs, Terraform bundles), no local credentials/secrets, no personal
workstation paths, and no live GCP project/OAuth identifiers are tracked in Git.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
from typing import List

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Well-known public gcloud CLI OAuth client ID (published by Google Cloud SDK)
PUBLIC_GCLOUD_CLIENT_ID = "32555940559.apps.googleusercontent.com"

# Synthetic RFC / test placeholders permitted in unit tests
SYNTHETIC_OAUTH_PREFIXES = ("999999999999-", "000000000000-", "123456789012-")
SYNTHETIC_RUN_APP_SUBSTRINGS = ("-123456789012.", "<PROJECT-NUM>", "${PROJECT_NUMBER}")


def _tracked_files() -> List[str]:
    out = subprocess.check_output(
        ["git", "ls-files"],
        cwd=str(REPO_ROOT),
        text=True,
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def test_no_environment_exports_or_secret_files_tracked_in_git() -> None:
    """No collected environment outputs, deliverables, workspaces, or secret files may be tracked."""
    forbidden_path_patterns = [
        re.compile(r"^exports/"),
        re.compile(r"^\.agentic_iam_workspaces/"),
        re.compile(r"^\.env(?!\.example$)(?:$|\.)"),
        re.compile(r"\.(?:pdf|docx|zip|key|pem|p12|pfx|tfstate|tfvars)(?:\.|$)", re.IGNORECASE),
        re.compile(r"(?:^|/)posture_acceleration_book[^/]*\.json$", re.IGNORECASE),
        re.compile(r"(?:^|/)iam_posture_findings[^/]*\.jsonl$", re.IGNORECASE),
        re.compile(r"(?:^|/)attack_path_graph[^/]*\.png$", re.IGNORECASE),
        re.compile(r"(?:^|/)Agentic_IAM_Posture_Acceleration_Report\.", re.IGNORECASE),
        re.compile(r"(?:^|/).*(?:credentials|service[-_]account)[^/]*\.json$", re.IGNORECASE),
    ]

    violations: List[str] = []
    for rel in _tracked_files():
        for pat in forbidden_path_patterns:
            if pat.search(rel):
                violations.append(f"{rel} (matched {pat.pattern})")
                break

    assert not violations, "Forbidden collected/sensitive files tracked in git:\n" + "\n".join(violations)


def test_no_secrets_local_paths_or_live_identifiers_in_tracked_files() -> None:
    """Tracked text files must not contain real secrets, workstation paths, live run.app URLs, or real OAuth IDs."""
    secret_patterns = [
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----")),
        ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{30,}")),
        ("oauth_client_secret", re.compile(r"GOCSPX-[0-9A-Za-z\-_]{15,}")),
        ("live_oauth_token", re.compile(r"ya29\.[0-9A-Za-z\-_]{40,}")),
        ("local_user_path", re.compile(r"(?:/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/|C:\\\\Users\\\\[A-Za-z0-9._-]+\\\\)")),
    ]
    oauth_client_rx = re.compile(r"\b[0-9]{8,}(?:-[a-z0-9]+)?\.apps\.googleusercontent\.com\b", re.IGNORECASE)
    run_app_rx = re.compile(r"https?://[^\s\"'`)]+\.run\.app\b", re.IGNORECASE)

    binary_suffixes = {".ttf", ".otf", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2"}
    violations: List[str] = []

    for rel in _tracked_files():
        path = REPO_ROOT / rel
        if not path.is_file() or path.suffix.lower() in binary_suffixes or rel == "requirements.lock":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), 1):
            for label, pat in secret_patterns:
                if pat.search(line):
                    violations.append(f"{rel}:{line_no} [{label}]")

            for m in oauth_client_rx.finditer(line):
                cid = m.group(0)
                if cid != PUBLIC_GCLOUD_CLIENT_ID and not cid.startswith(SYNTHETIC_OAUTH_PREFIXES):
                    violations.append(f"{rel}:{line_no} [non-synthetic oauth_client_id: {cid}]")

            for m in run_app_rx.finditer(line):
                url = m.group(0)
                if not any(tok in url for tok in SYNTHETIC_RUN_APP_SUBSTRINGS):
                    violations.append(f"{rel}:{line_no} [live run.app URL: {url}]")

    assert not violations, "Sanitization violations in tracked files:\n" + "\n".join(violations)


def test_env_example_uses_placeholders_only() -> None:
    """`.env.example` must not ship a real GCP project ID or target organization values."""
    env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    kv = {}
    for line in env_example.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        kv[k.strip()] = v.strip()

    assert kv.get("GOOGLE_CLOUD_PROJECT", "") in ("", "your-gcp-project-id")
    assert kv.get("GCP_ORGANIZATION_ID", "") == ""
    assert kv.get("GCP_ORGANIZATION_DOMAIN", "") == ""
    assert kv.get("GCP_ASSESSMENT_SCOPE", "") == ""
    assert kv.get("ALLOWED_IAP_DOMAINS", "").endswith(".example")


def test_gitignore_blocks_environment_collections_and_secrets() -> None:
    """Representative environment collection outputs and credential files must be ignored by git."""
    sample_paths = [
        "exports/posture_acceleration_book.json",
        "exports/Agentic_IAM_Posture_Acceleration_Report.pdf",
        "exports/Agentic_IAM_Posture_Acceleration_Report.docx",
        "exports/agentic_iam_terraform_remediation_bundle.zip",
        ".agentic_iam_workspaces/abc123/connection.json",
        ".env",
        ".env.production",
        "posture_acceleration_book.json",
        "customer_inventory.json",
        "iam_posture_findings.jsonl",
        "sa-credentials.json",
        "terraform.tfvars",
        "terraform.tfstate",
    ]
    for sample in sample_paths:
        proc = subprocess.run(
            ["git", "check-ignore", "-q", "--no-index", sample],
            cwd=str(REPO_ROOT),
            check=False,
        )
        assert proc.returncode == 0, f".gitignore must ignore '{sample}'"
