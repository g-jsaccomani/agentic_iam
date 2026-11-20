"""Environment configuration and Vertex AI runtime management for Agentic IAM Accelerator.

Zero-Trust Multi-User Architecture:
1. AI Compute Plane (`GOOGLE_CLOUD_PROJECT`): Used strictly to run Google ADK + Vertex AI
   (`gemini-3.1-pro-preview-customtools` on `location="global"`).
2. Target Inspection Plane: Zero default Organization, Domain, or Project scope is pre-loaded.
   Every authenticated user starts with a clean console and connects/impersonates their own
   target Organization in an isolated in-memory session (`backend/session_vault.py`).
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

DEFAULT_VERTEX_LOCATION = "global"
DEFAULT_VERTEX_MODEL = "gemini-3.1-pro-preview-customtools"

REQUIRED_GCP_APIS: List[str] = [
    "cloudasset.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "orgpolicy.googleapis.com",
    "recommender.googleapis.com",
    "policyanalyzer.googleapis.com",
    "policysimulator.googleapis.com",
    "aiplatform.googleapis.com",
    "run.googleapis.com",
    "admin.googleapis.com",
    "cloudidentity.googleapis.com",
    "logging.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
]

VERTEX_MODEL_CATALOG: Dict[str, Dict[str, Any]] = {
    "gemini-3.1-pro-preview-customtools": {
        "id": "gemini-3.1-pro-preview-customtools",
        "vertex_model_id": "gemini-3.1-pro-preview-customtools",
        "label": "Gemini 3.1 Pro Preview (Custom Tools)",
        "location": "global",
        "is_default": True,
        "thinking_supported": True,
        "description": (
            "Recommended multi-agent orchestrator model purpose-built for high-precision Google ADK FunctionTool "
            "execution across Cloud Asset Inventory, Recommender, Cloud Audit Log samples, NetworkX, and advisory Terraform IaC."
        ),
    },
}

SUPPORTED_VERTEX_MODELS: Tuple[str, ...] = tuple(VERTEX_MODEL_CATALOG.keys())

VERTEX_MODEL_ALIASES: Dict[str, str] = {
    "gemini-3.1-pro": DEFAULT_VERTEX_MODEL,
}


def resolve_vertex_model(requested_model: Optional[str] = None) -> str:
    """Resolves and validates the canonical Vertex AI model (`gemini-3.1-pro-preview-customtools` on `global`)."""
    raw = (requested_model or "").strip()
    if not raw:
        raw = os.getenv("GEMINI_MODEL", DEFAULT_VERTEX_MODEL).strip() or DEFAULT_VERTEX_MODEL
    resolved = VERTEX_MODEL_ALIASES.get(raw, raw)
    if resolved not in SUPPORTED_VERTEX_MODELS:
        raise ValueError(
            f"Unsupported Vertex AI model '{requested_model}'. Standardized platform model (location='global'): {DEFAULT_VERTEX_MODEL}"
        )
    return resolved


def get_model_catalog_metadata(active_model: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns metadata for the standardized Vertex AI model (`gemini-3.1-pro-preview-customtools`)."""
    current = resolve_vertex_model(active_model)
    return [
        {
            **entry,
            "active": entry["id"] == current,
            "selected": entry["id"] == current,
        }
        for entry in VERTEX_MODEL_CATALOG.values()
    ]


def install_gcloud_adc_fallback(vertex_project_id: str) -> None:
    """Bridges local workstation ADC strictly for Vertex AI (`aiplatform.googleapis.com`) when running outside Cloud Run."""
    if os.getenv("K_SERVICE"):
        return
    try:
        import time
        import google.auth
        from google.oauth2 import credentials as oauth2_credentials

        argolis_cfg = Path.home() / ".config" / "gcloud-argolis"
        if not argolis_cfg.exists():
            return

        orig_default = google.auth.default
        if getattr(orig_default, "_agentic_iam_patched", False):
            return

        cache_state: Dict[str, Any] = {"token": "", "expires_at": 0.0, "skip_until": 0.0}

        def _patched_default(scopes=None, request=None, quota_project_id=None, default_scopes=None):
            now = time.monotonic()
            if cache_state["token"] and now < cache_state["expires_at"]:
                creds = oauth2_credentials.Credentials(
                    token=cache_state["token"],
                    quota_project_id=quota_project_id or vertex_project_id,
                )
                return creds, (quota_project_id or vertex_project_id)

            if now >= cache_state["skip_until"]:
                try:
                    env = os.environ.copy()
                    env["CLOUDSDK_CONFIG"] = str(argolis_cfg)
                    env["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"
                    for k in (
                        "CLOUDSDK_INTERNAL_USER",
                        "CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE",
                        "CLOUDSDK_CONTEXT_AWARE_USE_ECP_HTTP_PROXY",
                        "CLOUDSDK_CONTEXT_AWARE_USE_MTLS_FOR_GRPC",
                        "CLOUDSDK_CONTEXT_AWARE_CERTIFICATE_CONFIG_FILE_PATH",
                        "GOOGLE_API_CERTIFICATE_CONFIG",
                        "GOOGLE_AUTH_WEBAUTHN_PLUGIN",
                    ):
                        env.pop(k, None)
                    proc = subprocess.run(
                        ["gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)", "--quiet"],
                        env=env,
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=4,
                    )
                    acct = (proc.stdout.strip().splitlines() or [""])[0].strip()
                    cmd = ["gcloud", "auth", "print-access-token", "--quiet"]
                    if acct:
                        cmd.append(f"--account={acct}")
                    proc_tok = subprocess.run(
                        cmd,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=4,
                    )
                    tok = proc_tok.stdout.strip() if proc_tok.returncode == 0 else ""
                    if tok:
                        cache_state["token"] = tok
                        cache_state["expires_at"] = now + 300.0
                        creds = oauth2_credentials.Credentials(
                            token=tok,
                            quota_project_id=quota_project_id or vertex_project_id,
                        )
                        return creds, (quota_project_id or vertex_project_id)
                    cache_state["skip_until"] = now + 300.0
                except Exception:
                    cache_state["skip_until"] = now + 300.0

            creds, detected_proj = orig_default(
                scopes=scopes,
                request=request,
                quota_project_id=quota_project_id,
                default_scopes=default_scopes,
            )
            return creds, (detected_proj or vertex_project_id)

        _patched_default._agentic_iam_patched = True  # type: ignore[attr-defined]
        google.auth.default = _patched_default
    except Exception:
        pass


@dataclass
class AcceleratorConfig:
    """Centralized runtime configuration with Clean-Slate Multi-User defaults (zero host Org exposure)."""

    # AI Compute Plane ONLY (Vertex AI Global Engine)
    use_vertexai: bool = field(
        default_factory=lambda: os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "TRUE").upper() == "TRUE"
    )
    project_id: str = field(
        default_factory=lambda: os.getenv("GOOGLE_CLOUD_PROJECT", "")
    )
    location: str = field(
        default_factory=lambda: DEFAULT_VERTEX_LOCATION
    )
    gemini_model: str = field(
        default_factory=lambda: resolve_vertex_model(os.getenv("GEMINI_MODEL", DEFAULT_VERTEX_MODEL))
    )

    # Target Inspection Plane Defaults — Intentionally BLANK for Clean-Slate Per-User Isolation
    organization_id: str = field(
        default_factory=lambda: os.getenv("GCP_ORGANIZATION_ID", "")
    )
    organization_domain: str = field(
        default_factory=lambda: os.getenv("GCP_ORGANIZATION_DOMAIN", "")
    )
    folder_display_name: str = field(
        default_factory=lambda: os.getenv("GCP_FOLDER_DISPLAY_NAME", "")
    )
    folder_id: str = field(
        default_factory=lambda: os.getenv("GCP_FOLDER_ID", "")
    )
    assessment_scope: str = field(
        default_factory=lambda: os.getenv("GCP_ASSESSMENT_SCOPE", "")
    )

    # Cloud Identity / Workspace Customer Identifier (evaluated per user token)
    workspace_customer_id: str = field(
        default_factory=lambda: os.getenv("WORKSPACE_CUSTOMER_ID", "my_customer")
    )

    # Local CLI Export Directory Fallback (Web/API sessions use isolated /tmp/agentic_iam_sessions/<sid>)
    export_dir: Path = field(
        default_factory=lambda: BASE_DIR / os.getenv("EXPORT_DIR", "exports")
    )

    @property
    def vertex_model_id(self) -> str:
        return resolve_vertex_model(self.gemini_model)

    def set_active_model(self, model_name: str) -> str:
        """Validates and resolves the requested model without mutating process-global state."""
        return resolve_vertex_model(model_name)

    def ensure_vertex_environment(self) -> None:
        try:
            import certifi

            ca_bundle = certifi.where()
            os.environ.setdefault("SSL_CERT_FILE", ca_bundle)
            os.environ.setdefault("REQUESTS_CA_BUNDLE", ca_bundle)
        except Exception:
            pass
        self.location = DEFAULT_VERTEX_LOCATION
        self.gemini_model = resolve_vertex_model(self.gemini_model)
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE" if self.use_vertexai else "FALSE"
        os.environ["GOOGLE_CLOUD_PROJECT"] = self.project_id
        os.environ["GOOGLE_CLOUD_LOCATION"] = DEFAULT_VERTEX_LOCATION
        os.environ["GEMINI_MODEL"] = self.gemini_model
        install_gcloud_adc_fallback(self.project_id)


settings = AcceleratorConfig()
settings.ensure_vertex_environment()
