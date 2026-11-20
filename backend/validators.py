"""Strict GCP resource identifier validators and read-only HTTP request guardrails (`backend/validators.py`).

Prevents path/query/verb smuggling (`projects/victim:setIamPolicy?x=`), enforces HTTPS host and
read-only POST allowlists on all outbound GCP REST calls, and guarantees every dynamic URL segment
is strictly validated and percent-encoded via `urllib.parse.quote(segment, safe="")`.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import FrozenSet, Tuple

ORG_ID_RE = re.compile(r"^[0-9]{1,32}$")
FOLDER_ID_RE = re.compile(r"^[0-9]{1,32}$")
PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
SA_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}@[a-z0-9][a-z0-9.-]{1,126}\.gserviceaccount\.com$"
)
BQ_DATASET_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,1023}$")
BQ_TABLE_RE = re.compile(r"^[A-Za-z0-9_$-]{1,1024}$")
ROLE_NAME_RE = re.compile(
    r"^(?:roles/[a-zA-Z0-9._-]+|(?:organizations/[0-9]{1,32}|projects/[a-z][a-z0-9-]{4,28}[a-z0-9])/roles/[a-zA-Z0-9._-]+)$"
)

GCP_READ_ALLOWED_HOSTS: FrozenSet[str] = frozenset(
    {
        "admin.googleapis.com",
        "apikeys.googleapis.com",
        "bigquery.googleapis.com",
        "cloudasset.googleapis.com",
        "cloudidentity.googleapis.com",
        "cloudkms.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "iam.googleapis.com",
        "iamcredentials.googleapis.com",
        "logging.googleapis.com",
        "oauth2.googleapis.com",
        "orgpolicy.googleapis.com",
        "policyanalyzer.googleapis.com",
        "policysimulator.googleapis.com",
        "recommender.googleapis.com",
        "run.googleapis.com",
        "secretmanager.googleapis.com",
        "serviceusage.googleapis.com",
        "storage.googleapis.com",
    }
)

GCP_ALLOWED_POST_SUFFIXES: Tuple[str, ...] = (
    ":getIamPolicy",
    ":getEffectiveOrgPolicy",
    "entries:list",
    ":generateAccessToken",
    "insertAll",
)


def quote_path_segment(segment: str) -> str:
    """Percent-encodes a single URL path segment with `safe=""`."""
    return urllib.parse.quote(str(segment), safe="")


def validate_org_id(raw: str, *, allow_empty: bool = False) -> str:
    """Validates a numeric GCP Organization ID (optionally prefixed with `organizations/`)."""
    val = (raw or "").strip()
    if not val:
        if allow_empty:
            return ""
        raise ValueError("Organization ID is required and must contain digits only.")
    if val.startswith("organizations/"):
        val = val[len("organizations/") :]
    if not ORG_ID_RE.match(val):
        raise ValueError(f"Invalid GCP Organization ID '{raw}'. Expected digits only.")
    return val


def validate_folder_id(raw: str, *, allow_empty: bool = False) -> str:
    """Validates a numeric GCP Folder ID (optionally prefixed with `folders/`)."""
    val = (raw or "").strip()
    if not val:
        if allow_empty:
            return ""
        raise ValueError("Folder ID is required and must contain digits only.")
    if val.startswith("folders/"):
        val = val[len("folders/") :]
    if not FOLDER_ID_RE.match(val):
        raise ValueError(f"Invalid GCP Folder ID '{raw}'. Expected digits only.")
    return val


def validate_project_id(raw: str, *, allow_empty: bool = False) -> str:
    """Validates a GCP Project ID against `^[a-z][a-z0-9-]{4,28}[a-z0-9]$`."""
    val = (raw or "").strip()
    if not val:
        if allow_empty:
            return ""
        raise ValueError("GCP Project ID is required.")
    if val.startswith("projects/"):
        val = val[len("projects/") :]
    if not PROJECT_ID_RE.match(val):
        raise ValueError(
            f"Invalid GCP Project ID '{raw}'. Expected 6-30 lowercase letters, digits, or hyphens."
        )
    return val


def validate_sa_email(raw: str, *, allow_empty: bool = False) -> str:
    """Validates a Google Cloud Service Account email address."""
    val = (raw or "").strip()
    if val.startswith("serviceAccount:"):
        val = val[len("serviceAccount:") :].strip()
    if not val:
        if allow_empty:
            return ""
        raise ValueError("Service Account email is required.")
    if ".." in val or not SA_EMAIL_RE.match(val):
        raise ValueError(
            f"Invalid GCP Service Account email '{raw}'. Expected format: name@project-id.iam.gserviceaccount.com"
        )
    return val


def validate_bq_table_id(raw: str, *, allow_empty: bool = False) -> Tuple[str, str, str]:
    """Validates a `project.dataset.table` BigQuery identifier and returns `(project, dataset, table)`."""
    val = (raw or "").strip()
    if not val:
        if allow_empty:
            return ("", "", "")
        raise ValueError("BigQuery table ID is required (project.dataset.table).")
    parts = val.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid BigQuery table ID '{raw}'. Expected exact 'project.dataset.table' format."
        )
    proj, dataset, table = parts
    proj = validate_project_id(proj)
    if not BQ_DATASET_RE.match(dataset):
        raise ValueError(f"Invalid BigQuery dataset ID '{dataset}'.")
    if not BQ_TABLE_RE.match(table):
        raise ValueError(f"Invalid BigQuery table name '{table}'.")
    return proj, dataset, table


def validate_iam_role_name(raw: str) -> str:
    """Validates a predefined (`roles/...`) or custom (`organizations/.../roles/...`, `projects/.../roles/...`) role."""
    val = (raw or "").strip()
    if not val:
        raise ValueError("IAM role name is required.")
    if not val.startswith(("roles/", "organizations/", "projects/")):
        val = f"roles/{val}"
    if ".." in val or not ROLE_NAME_RE.match(val):
        raise ValueError(f"Invalid IAM role name '{raw}'.")
    return val


def quote_gcp_resource_path(resource_path: str) -> str:
    """Quotes each slash-delimited segment of a validated GCP resource path (e.g. `organizations/123`)."""
    clean = (resource_path or "").strip().strip("/")
    if not clean:
        raise ValueError("GCP resource path cannot be empty.")
    segments = clean.split("/")
    for seg in segments:
        if not seg or seg in (".", ".."):
            raise ValueError(f"Invalid GCP resource path '{resource_path}'.")
    return "/".join(quote_path_segment(seg) for seg in segments)


def assert_read_only_gcp_request(method: str, url: str) -> None:
    """Enforces HTTPS host allowlist and read-only method/POST-suffix allowlist before any network I/O."""
    verb = (method or "").strip().upper()
    if verb not in ("GET", "POST"):
        raise PermissionError(
            f"Blocked disallowed HTTP method '{verb}' on '{url}'. Only GET and approved read-only POST calls are permitted."
        )

    parts = urllib.parse.urlsplit(url or "")
    if parts.scheme.lower() != "https":
        raise PermissionError(f"Blocked non-HTTPS GCP request URL: '{url}'.")
    if parts.username or parts.password:
        raise PermissionError(f"Blocked GCP request URL containing credentials: '{url}'.")
    host = (parts.hostname or "").strip().lower()
    if host not in GCP_READ_ALLOWED_HOSTS:
        raise PermissionError(
            f"Blocked GCP request to non-allowlisted host '{host}' (url='{url}')."
        )

    raw_path = parts.path or ""
    decoded_path = urllib.parse.unquote(raw_path)
    if ".." in raw_path.split("/") or ".." in decoded_path.split("/"):
        raise PermissionError(f"Blocked path traversal in GCP request URL: '{url}'.")

    # Secret material is never read (metadata-only assessment): block Secret Manager payload access
    # (`.../versions/*:access`) and API Keys key string retrieval (`.../keys/*/keyString`) for every verb.
    secret_paths = (raw_path.rstrip("/"), decoded_path.rstrip("/"))
    if host == "secretmanager.googleapis.com" and any(p.endswith(":access") for p in secret_paths):
        raise PermissionError(
            f"Blocked Secret Manager secret payload access (':access') on '{url}'. Only secret metadata reads are permitted."
        )
    if host == "apikeys.googleapis.com" and any(p.endswith("/keyString") for p in secret_paths):
        raise PermissionError(
            f"Blocked API Keys key string retrieval ('/keyString') on '{url}'. Only API key metadata reads are permitted."
        )

    if verb == "POST":
        if "?" in decoded_path or "#" in decoded_path:
            raise PermissionError(f"Blocked smuggled query/fragment in POST path: '{url}'.")
        if not (
            raw_path.endswith(GCP_ALLOWED_POST_SUFFIXES)
            and decoded_path.endswith(GCP_ALLOWED_POST_SUFFIXES)
        ):
            raise PermissionError(
                f"Blocked POST request to disallowed GCP endpoint path '{raw_path}'. "
                f"Allowed POST suffixes: {', '.join(GCP_ALLOWED_POST_SUFFIXES)}."
            )
