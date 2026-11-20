"""Per-User Encrypted Persistent Workspace & Pinned Scan Store (`workspace_store.py`).

Guarantees durable connection persistence and fixed scanned datasets across:
- Browser tab closes, browser restarts, and device switches
- Cloud Run container restarts and new revision deployments

Isolation, confidentiality and retention model:
1. Every verified Google user (`owner_email`) maps to a deterministic, unforgeable
   `workspace_id = HMAC-SHA256(master_secret, "agentic_iam:ws:v1:" + owner_email.lower())[:32]`.
2. EVERY persisted document (connection record, pinned book, inventory, scan index, snapshots) is
   sealed as a whole with AES-256-GCM using a per-user derived 256-bit key. The AAD binds the
   ciphertext to `owner_email`, `workspace_id`, the object path and its storage/expiry timestamps,
   so a document cannot be edited, moved to another path, or swapped into another user's workspace.
   Legacy plaintext documents are treated as untrusted: they are ignored and deleted.
3. Retention is chosen by the consultant when connecting a customer (`0` = nothing is persisted,
   otherwise `1..IAM_WORKSPACE_MAX_RETENTION_DAYS` days). Each document carries its own expiry;
   expired documents are refused on read and removed by `purge_expired_workspace_objects`.
4. On Cloud Run, objects are persisted to a dedicated GCS state bucket (`WORKSPACE_STATE_BUCKET`)
   where the runtime Service Account holds bucket-scoped `roles/storage.objectAdmin`.
5. On local workstations (when `WORKSPACE_STATE_BUCKET` is unset), objects persist identically
   to `<project_root>/.agentic_iam_workspaces/<workspace_id>/` using atomic file replacement.
6. Binary deliverables (`.docx`/`.pdf`/`.zip`/`.png`) are NOT persisted: they are always
   re-rendered from the encrypted pinned book.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LOCAL_STORE_ROOT = Path(
    os.getenv("AGENTIC_IAM_LOCAL_STORE_DIR", str(_PROJECT_ROOT / ".agentic_iam_workspaces"))
)
_STORE_LOCK = threading.RLock()
_GCS_HTTP = httpx.Client(timeout=20.0)
_GCS_TOKEN_CACHE: Dict[str, Any] = {"token": "", "expires_at": 0.0}
_MASTER_KEY_CACHE: Optional[bytes] = None

DOCUMENT_ENVELOPE_VERSION = 2
DOCUMENT_ENVELOPE_ALG = "AES-256-GCM"
# The sealed envelope always starts with these keys in this order so the retention sweeper can read
# the expiry from the first bytes of an object without the per-user key.
_ENVELOPE_HEAD_RE = re.compile(rb'^\{"v":2,"alg":"AES-256-GCM","stored_at":(\d+),"expires_at":(\d+),')
_ENVELOPE_HEAD_BYTES = 256
# Security metadata (revoked browser session ids). It holds no customer data, has its own fixed TTL,
# and survives "Disconnect & Wipe" so that a logout stays effective.
_SECURITY_PREFIX = "security/"
_REVOKED_SIDS_PATH = "security/revoked_sids.json"

_RETENTION_BY_WS: Dict[str, int] = {}
_LAST_OBJECT_SWEEP_AT = 0.0


def _gcs_bucket_name() -> str:
    return (os.getenv("WORKSPACE_STATE_BUCKET") or "").strip().removeprefix("gs://").strip("/")


def persistence_backend_label() -> str:
    return "GCS_ENCRYPTED_WORKSPACE" if _gcs_bucket_name() else "LOCAL_ENCRYPTED_WORKSPACE"


def max_retention_days() -> int:
    """Upper bound for the consultant-selected retention (`IAM_WORKSPACE_MAX_RETENTION_DAYS`, default 365)."""
    try:
        val = int(os.getenv("IAM_WORKSPACE_MAX_RETENTION_DAYS", "365"))
    except (TypeError, ValueError):
        val = 365
    return max(1, min(3650, val))


def default_retention_days() -> int:
    """Retention applied when the consultant makes no choice (`IAM_WORKSPACE_RETENTION_DAYS`, default 30)."""
    try:
        val = int(os.getenv("IAM_WORKSPACE_RETENTION_DAYS", "30"))
    except (TypeError, ValueError):
        val = 30
    return max(0, min(max_retention_days(), val))


def normalize_retention_days(raw: Any) -> int:
    """Validates a consultant-selected retention in days (`0` = do not persist anything)."""
    if raw is None or raw == "":
        return default_retention_days()
    if isinstance(raw, bool):
        raise ValueError("Workspace retention must be a whole number of days.")
    try:
        days = int(raw)
    except (TypeError, ValueError):
        raise ValueError("Workspace retention must be a whole number of days.") from None
    upper = max_retention_days()
    if days < 0 or days > upper:
        raise ValueError(f"Workspace retention must be between 0 and {upper} days.")
    return days


def get_master_secret_bytes() -> bytes:
    """Returns a stable 32-byte master key from `IAM_SESSION_SECRET` (Secret Manager) or local persistent key."""
    global _MASTER_KEY_CACHE
    configured = (os.getenv("IAM_SESSION_SECRET") or "").strip()
    if configured:
        return hashlib.sha256(configured.encode("utf-8")).digest()

    if (os.getenv("K_SERVICE") or "").strip():
        # Fail closed on Cloud Run: a key file on the ephemeral container disk would silently change on
        # every restart and would not be protected by Secret Manager.
        raise RuntimeError(
            "IAM_SESSION_SECRET is required on Cloud Run (mount it from Secret Manager); "
            "refusing to fall back to a local key file."
        )

    with _STORE_LOCK:
        if _MASTER_KEY_CACHE is not None:
            return _MASTER_KEY_CACHE
        _LOCAL_STORE_ROOT.mkdir(parents=True, exist_ok=True)
        key_file = _LOCAL_STORE_ROOT / ".local_master.key"
        raw_secret = ""
        if key_file.exists():
            try:
                raw_secret = key_file.read_text(encoding="utf-8").strip()
            except OSError:
                raw_secret = ""
        if not raw_secret:
            raw_secret = secrets.token_urlsafe(48)
            try:
                tmp = key_file.with_suffix(".key.tmp")
                tmp.write_text(raw_secret, encoding="utf-8")
                os.chmod(tmp, 0o600)
                os.replace(tmp, key_file)
            except OSError:
                pass
        _MASTER_KEY_CACHE = hashlib.sha256(raw_secret.encode("utf-8")).digest()
        return _MASTER_KEY_CACHE


def derive_workspace_id(owner_email: str) -> str:
    """Computes a deterministic, unforgeable 32-hex workspace ID strictly bound to the verified user email."""
    clean_email = (owner_email or "").strip().lower()
    if not clean_email:
        raise ValueError("owner_email is required to derive workspace_id.")
    msg = f"agentic_iam:ws:v1:{clean_email}".encode("utf-8")
    return hmac.new(get_master_secret_bytes(), msg, hashlib.sha256).hexdigest()[:32]


def _derive_user_aes_key(owner_email: str) -> bytes:
    clean_email = (owner_email or "").strip().lower()
    msg = f"agentic_iam:aes256gcm:v1:{clean_email}".encode("utf-8")
    return hmac.new(get_master_secret_bytes(), msg, hashlib.sha256).digest()


def _derive_user_document_key(owner_email: str) -> bytes:
    clean_email = (owner_email or "").strip().lower()
    msg = f"agentic_iam:doc-aes256gcm:v2:{clean_email}".encode("utf-8")
    return hmac.new(get_master_secret_bytes(), msg, hashlib.sha256).digest()


def encrypt_user_secret_payload(owner_email: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypts sensitive per-user credential fields with AES-256-GCM bound to `owner_email` AAD."""
    clean_email = (owner_email or "").strip().lower()
    aesgcm = AESGCM(_derive_user_aes_key(clean_email))
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, clean_email.encode("utf-8"))
    return {
        "v": 1,
        "alg": "AES-256-GCM",
        "nonce_b64": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ct_b64": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }


def decrypt_user_secret_payload(owner_email: str, blob: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Decrypts an AES-256-GCM per-user credential blob; returns `{}` if missing or invalid."""
    if not isinstance(blob, dict) or not blob.get("nonce_b64") or not blob.get("ct_b64"):
        return {}
    clean_email = (owner_email or "").strip().lower()
    try:
        aesgcm = AESGCM(_derive_user_aes_key(clean_email))
        nonce = base64.urlsafe_b64decode(str(blob["nonce_b64"]).encode("ascii"))
        ciphertext = base64.urlsafe_b64decode(str(blob["ct_b64"]).encode("ascii"))
        plaintext = aesgcm.decrypt(nonce, ciphertext, clean_email.encode("utf-8"))
        parsed = json.loads(plaintext.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except Exception as exc:
        logger.warning("Unable to decrypt workspace credentials for %s: %s", clean_email, type(exc).__name__)
        return {}


def _safe_ws_id(workspace_id: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]", "", (workspace_id or "").strip())[:64]
    if not cleaned:
        raise ValueError("Invalid workspace_id.")
    return cleaned


def _safe_rel_path(rel_path: str) -> str:
    parts = [p for p in (rel_path or "").replace("\\", "/").split("/") if p and p not in (".", "..")]
    if not parts:
        raise ValueError("Invalid workspace object path.")
    cleaned_parts = [re.sub(r"[^a-zA-Z0-9._-]", "_", p) for p in parts]
    return "/".join(cleaned_parts)


def _scope_hash(scope: str) -> str:
    return hashlib.sha256((scope or "").strip().lower().encode("utf-8")).hexdigest()[:16]


def set_workspace_retention_days(workspace_id: str, days: Any) -> int:
    """Records the consultant-selected retention for this workspace (applies to subsequent writes)."""
    clean = normalize_retention_days(days)
    with _STORE_LOCK:
        _RETENTION_BY_WS[_safe_ws_id(workspace_id)] = clean
    return clean


def get_workspace_retention_days(workspace_id: str) -> int:
    with _STORE_LOCK:
        known = _RETENTION_BY_WS.get(_safe_ws_id(workspace_id))
    return default_retention_days() if known is None else known


def _get_gcs_access_token() -> str:
    now = time.time()
    if _GCS_TOKEN_CACHE["token"] and now < (_GCS_TOKEN_CACHE["expires_at"] - 120):
        return str(_GCS_TOKEN_CACHE["token"])

    import google.auth
    import google.auth.transport.requests

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/devstorage.read_write"])
    if not getattr(creds, "token", None) or getattr(creds, "expired", False):
        creds.refresh(google.auth.transport.requests.Request())
    tok = str(getattr(creds, "token", "") or "")
    if not tok:
        raise RuntimeError("Unable to obtain GCS access token for runtime Service Account.")
    expiry = getattr(creds, "expiry", None)
    if expiry is not None:
        if expiry.tzinfo is None:
            exp_epoch = expiry.replace(tzinfo=datetime.timezone.utc).timestamp()
        else:
            exp_epoch = expiry.timestamp()
    else:
        exp_epoch = now + 1800.0
    _GCS_TOKEN_CACHE["token"] = tok
    _GCS_TOKEN_CACHE["expires_at"] = exp_epoch
    return tok


def _object_name(workspace_id: str, rel_path: str) -> str:
    return f"workspaces/{_safe_ws_id(workspace_id)}/{_safe_rel_path(rel_path)}"


def _local_path(workspace_id: str, rel_path: str) -> Path:
    return _LOCAL_STORE_ROOT / _safe_ws_id(workspace_id) / _safe_rel_path(rel_path)


def _gcs_object_url(bucket: str, obj_name: str) -> str:
    return (
        f"https://storage.googleapis.com/storage/v1/b/"
        f"{urllib.parse.quote(bucket, safe='')}/o/"
        f"{urllib.parse.quote(obj_name, safe='')}"
    )


def _write_bytes(workspace_id: str, rel_path: str, data: bytes, content_type: str = "application/octet-stream") -> None:
    bucket = _gcs_bucket_name()
    if bucket:
        obj_name = _object_name(workspace_id, rel_path)
        tok = _get_gcs_access_token()
        url = (
            f"https://storage.googleapis.com/upload/storage/v1/b/"
            f"{urllib.parse.quote(bucket, safe='')}/o"
            f"?uploadType=media&name={urllib.parse.quote(obj_name, safe='')}"
        )
        resp = _GCS_HTTP.post(
            url,
            content=data,
            headers={"Authorization": f"Bearer {tok}", "Content-Type": content_type},
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"GCS write failed ({resp.status_code}) for '{obj_name}': {resp.text[:240]}")
        return

    with _STORE_LOCK:
        target = _local_path(workspace_id, rel_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
        tmp.write_bytes(data)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, target)


def _read_bytes(workspace_id: str, rel_path: str, *, head_bytes: int = 0) -> Optional[bytes]:
    """Reads an object (or only its first `head_bytes` bytes when `head_bytes > 0`)."""
    bucket = _gcs_bucket_name()
    if bucket:
        obj_name = _object_name(workspace_id, rel_path)
        try:
            tok = _get_gcs_access_token()
            headers = {"Authorization": f"Bearer {tok}"}
            if head_bytes > 0:
                headers["Range"] = f"bytes=0-{head_bytes - 1}"
            resp = _GCS_HTTP.get(f"{_gcs_object_url(bucket, obj_name)}?alt=media", headers=headers)
            if resp.status_code == 404:
                return None
            if resp.status_code in (200, 206):
                return resp.content[:head_bytes] if head_bytes > 0 else resp.content
            logger.warning("GCS read HTTP %s for %s: %s", resp.status_code, obj_name, resp.text[:200])
            return None
        except Exception as exc:
            logger.warning("GCS read error for %s: %s", obj_name, exc)
            return None

    with _STORE_LOCK:
        target = _local_path(workspace_id, rel_path)
        if not target.exists():
            return None
        try:
            if head_bytes > 0:
                with target.open("rb") as fh:
                    return fh.read(head_bytes)
            return target.read_bytes()
        except OSError:
            return None


def _delete_object(workspace_id: str, rel_path: str) -> bool:
    bucket = _gcs_bucket_name()
    if bucket:
        obj_name = _object_name(workspace_id, rel_path)
        try:
            tok = _get_gcs_access_token()
            resp = _GCS_HTTP.delete(_gcs_object_url(bucket, obj_name), headers={"Authorization": f"Bearer {tok}"})
            return resp.status_code in (200, 204, 404)
        except Exception as exc:
            logger.warning("GCS delete error for %s: %s", obj_name, exc)
            return False

    with _STORE_LOCK:
        target = _local_path(workspace_id, rel_path)
        try:
            target.unlink()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        # Drop now-empty parent directories up to (and including) the workspace directory
        ws_dir = _LOCAL_STORE_ROOT / _safe_ws_id(workspace_id)
        parent = target.parent
        while parent != _LOCAL_STORE_ROOT and (parent == ws_dir or ws_dir in parent.parents):
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent
        return True


def _gcs_list_object_names(prefix: str) -> List[str]:
    bucket = _gcs_bucket_name()
    names: List[str] = []
    tok = _get_gcs_access_token()
    page_token = ""
    while True:
        params: Dict[str, Any] = {"prefix": prefix, "maxResults": 500, "fields": "items(name),nextPageToken"}
        if page_token:
            params["pageToken"] = page_token
        list_url = f"https://storage.googleapis.com/storage/v1/b/{urllib.parse.quote(bucket, safe='')}/o"
        resp = _GCS_HTTP.get(list_url, params=params, headers={"Authorization": f"Bearer {tok}"})
        if resp.status_code != 200:
            logger.warning("GCS list HTTP %s for prefix %s", resp.status_code, prefix)
            break
        payload = resp.json()
        for item in payload.get("items") or []:
            if item.get("name"):
                names.append(str(item["name"]))
        page_token = payload.get("nextPageToken") or ""
        if not page_token:
            break
    return names


def _list_workspace_objects(workspace_id: str) -> List[str]:
    """Lists the relative object paths stored for one workspace."""
    safe_id = _safe_ws_id(workspace_id)
    if _gcs_bucket_name():
        prefix = f"workspaces/{safe_id}/"
        return [n[len(prefix):] for n in _gcs_list_object_names(prefix) if n.startswith(prefix) and len(n) > len(prefix)]

    with _STORE_LOCK:
        ws_dir = _LOCAL_STORE_ROOT / safe_id
        if not ws_dir.is_dir():
            return []
        return [
            p.relative_to(ws_dir).as_posix()
            for p in ws_dir.rglob("*")
            if p.is_file() and not p.name.endswith(".tmp")
        ]


def _list_all_workspace_objects() -> List[Tuple[str, str]]:
    """Lists `(workspace_id, relative_path)` for every stored object (used by the retention sweeper)."""
    found: List[Tuple[str, str]] = []
    if _gcs_bucket_name():
        for name in _gcs_list_object_names("workspaces/"):
            parts = name.split("/", 2)
            if len(parts) == 3 and parts[0] == "workspaces" and parts[1] and parts[2]:
                found.append((parts[1], parts[2]))
        return found

    with _STORE_LOCK:
        if not _LOCAL_STORE_ROOT.is_dir():
            return []
        for ws_dir in _LOCAL_STORE_ROOT.iterdir():
            if not ws_dir.is_dir():
                continue
            for p in ws_dir.rglob("*"):
                if p.is_file() and not p.name.endswith(".tmp"):
                    found.append((ws_dir.name, p.relative_to(ws_dir).as_posix()))
    return found


def _document_aad(owner_email: str, workspace_id: str, rel_path: str, stored_at: int, expires_at: int) -> bytes:
    clean_email = (owner_email or "").strip().lower()
    return (
        f"agentic_iam:doc:v2|{clean_email}|{_safe_ws_id(workspace_id)}|{_safe_rel_path(rel_path)}"
        f"|{int(stored_at)}|{int(expires_at)}"
    ).encode("utf-8")


def _seal_document(
    owner_email: str,
    workspace_id: str,
    rel_path: str,
    plaintext: bytes,
    *,
    stored_at: int,
    expires_at: int,
) -> bytes:
    nonce = os.urandom(12)
    aad = _document_aad(owner_email, workspace_id, rel_path, stored_at, expires_at)
    ciphertext = AESGCM(_derive_user_document_key(owner_email)).encrypt(nonce, plaintext, aad)
    envelope = {
        "v": DOCUMENT_ENVELOPE_VERSION,
        "alg": DOCUMENT_ENVELOPE_ALG,
        "stored_at": int(stored_at),
        "expires_at": int(expires_at),
        "nonce_b64": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ct_b64": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def _parse_envelope(raw: bytes) -> Optional[Dict[str, Any]]:
    """Returns the sealed envelope dict, or `None` when `raw` is not a v2 sealed document (legacy/foreign)."""
    try:
        env = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if (
        not isinstance(env, dict)
        or env.get("v") != DOCUMENT_ENVELOPE_VERSION
        or env.get("alg") != DOCUMENT_ENVELOPE_ALG
        or not isinstance(env.get("stored_at"), int)
        or not isinstance(env.get("expires_at"), int)
        or not env.get("nonce_b64")
        or not env.get("ct_b64")
    ):
        return None
    return env


def _unseal_envelope(owner_email: str, workspace_id: str, rel_path: str, env: Dict[str, Any]) -> Optional[bytes]:
    try:
        nonce = base64.urlsafe_b64decode(str(env["nonce_b64"]).encode("ascii"))
        ciphertext = base64.urlsafe_b64decode(str(env["ct_b64"]).encode("ascii"))
        aad = _document_aad(owner_email, workspace_id, rel_path, env["stored_at"], env["expires_at"])
        return AESGCM(_derive_user_document_key(owner_email)).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        logger.warning(
            "Rejected workspace document '%s' (failed authentication: %s).",
            _safe_rel_path(rel_path),
            type(exc).__name__,
        )
        return None


def _write_document(
    workspace_id: str,
    owner_email: str,
    rel_path: str,
    plaintext: bytes,
    *,
    ttl_seconds: Optional[float] = None,
    stored_at: Optional[int] = None,
) -> bool:
    """Seals and persists one document. Returns `False` when the workspace retention is `0` (nothing stored)."""
    if ttl_seconds is None:
        days = get_workspace_retention_days(workspace_id)
        if days <= 0:
            return False
        ttl_seconds = days * 86400.0
    stored = int(stored_at if stored_at is not None else time.time())
    expires = stored + max(1, int(ttl_seconds))
    sealed = _seal_document(owner_email, workspace_id, rel_path, plaintext, stored_at=stored, expires_at=expires)
    _write_bytes(workspace_id, rel_path, sealed, content_type="application/json")
    return True


def _read_document(workspace_id: str, owner_email: str, rel_path: str) -> Optional[bytes]:
    """Reads, authenticates and decrypts one document; legacy plaintext and expired documents are deleted."""
    raw = _read_bytes(workspace_id, rel_path)
    if not raw:
        return None
    env = _parse_envelope(raw)
    if env is None:
        logger.warning("Discarding legacy unencrypted workspace document '%s'.", _safe_rel_path(rel_path))
        _delete_object(workspace_id, rel_path)
        return None
    if env["expires_at"] <= time.time():
        _delete_object(workspace_id, rel_path)
        return None
    # A document that fails authentication is ignored but NOT deleted: a misconfigured master secret must
    # not turn into data loss. It still disappears when its retention expires.
    return _unseal_envelope(owner_email, workspace_id, rel_path, env)


def _write_json(
    workspace_id: str,
    owner_email: str,
    rel_path: str,
    payload: Any,
    *,
    ttl_seconds: Optional[float] = None,
) -> bool:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _write_document(workspace_id, owner_email, rel_path, raw, ttl_seconds=ttl_seconds)


def _read_json(workspace_id: str, owner_email: str, rel_path: str) -> Optional[Any]:
    raw = _read_document(workspace_id, owner_email, rel_path)
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def save_workspace_connection(
    *,
    workspace_id: str,
    owner_email: str,
    record: Dict[str, Any],
    secret_tokens: Optional[Dict[str, Any]] = None,
    replace_existing: bool = False,
) -> None:
    """Persists the user's connection metadata + AES-256-GCM encrypted tokens durably.

    `replace_existing=True` starts from a clean record instead of merging into the stored one. It is used
    when a different customer is connected, so nothing from the previous customer (hierarchy, readiness,
    pin metadata) survives in the new record.
    """
    clean_owner = owner_email.strip().lower()
    existing_doc = None if replace_existing else _read_json(workspace_id, clean_owner, "connection.json")
    merged: Dict[str, Any] = {}
    if isinstance(existing_doc, dict) and existing_doc.get("owner_email") == clean_owner:
        merged.update(existing_doc)

    merged.update(record)
    merged["owner_email"] = clean_owner
    merged["workspace_id"] = _safe_ws_id(workspace_id)
    merged["updated_at_iso"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if secret_tokens is not None:
        merged["encrypted_tokens"] = encrypt_user_secret_payload(clean_owner, secret_tokens)

    _write_json(workspace_id, clean_owner, "connection.json", merged)


def update_workspace_connection_fields(
    workspace_id: str,
    owner_email: str,
    updates: Dict[str, Any],
) -> None:
    """Updates non-secret workspace fields (hierarchy, readiness, selected scope) while keeping tokens intact."""
    clean_owner = owner_email.strip().lower()
    existing_doc = _read_json(workspace_id, clean_owner, "connection.json")
    if not isinstance(existing_doc, dict) or existing_doc.get("owner_email") != clean_owner:
        return
    for k, v in updates.items():
        if k == "encrypted_tokens":
            continue
        existing_doc[k] = v
    existing_doc["updated_at_iso"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    _write_json(workspace_id, clean_owner, "connection.json", existing_doc)


def load_workspace_connection(
    workspace_id: str,
    owner_email: str,
) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Loads and validates the user's persisted connection record and decrypted token bundle."""
    clean_owner = (owner_email or "").strip().lower()
    if not workspace_id or not clean_owner:
        return None
    doc = _read_json(workspace_id, clean_owner, "connection.json")
    if not isinstance(doc, dict):
        return None
    if str(doc.get("owner_email") or "").strip().lower() != clean_owner:
        return None
    tokens = decrypt_user_secret_payload(clean_owner, doc.get("encrypted_tokens"))
    public_doc = {k: v for k, v in doc.items() if k != "encrypted_tokens"}
    return public_doc, tokens


def save_pinned_book(
    workspace_id: str,
    owner_email: str,
    scope: str,
    book_dict: Dict[str, Any],
) -> None:
    """Pins the full `PostureAccelerationBook` as latest AND per-scope snapshot + updates scan index."""
    clean_owner = owner_email.strip().lower()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    envelope = {
        "owner_email": clean_owner,
        "scope": scope,
        "pinned_at_iso": now_iso,
        "book": book_dict,
    }
    if not _write_json(workspace_id, clean_owner, "pinned_book.json", envelope):
        return  # retention is 0: nothing is persisted for this workspace
    if scope:
        _write_json(workspace_id, clean_owner, f"snapshots/{_scope_hash(scope)}/book.json", envelope)

    if isinstance(book_dict.get("asset_inventory"), dict):
        save_pinned_inventory(workspace_id, clean_owner, scope, book_dict["asset_inventory"])

    sc = book_dict.get("scorecard") or {}
    inv_kpis = ((book_dict.get("asset_inventory") or {}).get("kpis") or {})
    entry = {
        "scope": scope,
        "scope_hash": _scope_hash(scope),
        "generated_at": book_dict.get("generated_at") or now_iso,
        "pinned_at_iso": now_iso,
        "overall_posture_score": sc.get("overall_posture_score"),
        "maturity_tier": sc.get("maturity_tier"),
        "critical_findings": sc.get("critical_findings", 0),
        "high_findings": sc.get("high_findings", 0),
        "total_bindings_analyzed": sc.get("total_bindings_analyzed", 0),
        "accounts_total": inv_kpis.get("human_and_group_accounts_total"),
        "service_accounts_total": inv_kpis.get("service_accounts_total"),
        "secrets_total": inv_kpis.get("secrets_total_count"),
        "kms_keys_total": inv_kpis.get("kms_cryptokeys_total"),
    }

    idx_doc = _read_json(workspace_id, clean_owner, "scan_index.json")
    entries: List[Dict[str, Any]] = []
    if isinstance(idx_doc, dict) and idx_doc.get("owner_email") == clean_owner and isinstance(idx_doc.get("scans"), list):
        entries = [e for e in idx_doc["scans"] if isinstance(e, dict) and e.get("scope") != scope]
    entries.insert(0, entry)
    entries = entries[:25]
    _write_json(
        workspace_id,
        clean_owner,
        "scan_index.json",
        {"owner_email": clean_owner, "updated_at_iso": now_iso, "scans": entries},
    )

    update_workspace_connection_fields(
        workspace_id,
        clean_owner,
        {
            "pinned_scope": scope,
            "pinned_generated_at": book_dict.get("generated_at") or now_iso,
            "has_pinned_book": True,
        },
    )


def load_pinned_book(
    workspace_id: str,
    owner_email: str,
    scope: str = "",
) -> Optional[Dict[str, Any]]:
    """Loads a pinned `PostureAccelerationBook` for the requested scope (or latest pinned book).

    With a non-empty `scope`, a book pinned for any other scope is never returned.
    """
    clean_owner = (owner_email or "").strip().lower()
    if not workspace_id or not clean_owner:
        return None
    if scope:
        scoped_env = _read_json(workspace_id, clean_owner, f"snapshots/{_scope_hash(scope)}/book.json")
        if (
            isinstance(scoped_env, dict)
            and scoped_env.get("owner_email") == clean_owner
            and scoped_env.get("scope") == scope
            and isinstance(scoped_env.get("book"), dict)
        ):
            return scoped_env["book"]

    latest_env = _read_json(workspace_id, clean_owner, "pinned_book.json")
    if (
        isinstance(latest_env, dict)
        and latest_env.get("owner_email") == clean_owner
        and isinstance(latest_env.get("book"), dict)
    ):
        if not scope or latest_env.get("scope") == scope:
            return latest_env["book"]
    return None


def save_pinned_inventory(
    workspace_id: str,
    owner_email: str,
    scope: str,
    inv_dict: Dict[str, Any],
) -> None:
    """Pins the full `AccountsKeysSecretsInventory` as latest AND per-scope snapshot."""
    clean_owner = owner_email.strip().lower()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    envelope = {
        "owner_email": clean_owner,
        "scope": scope,
        "pinned_at_iso": now_iso,
        "inventory": inv_dict,
    }
    if not _write_json(workspace_id, clean_owner, "pinned_inventory.json", envelope):
        return  # retention is 0: nothing is persisted for this workspace
    if scope:
        _write_json(workspace_id, clean_owner, f"snapshots/{_scope_hash(scope)}/inventory.json", envelope)

    update_workspace_connection_fields(
        workspace_id,
        clean_owner,
        {
            "has_pinned_inventory": True,
            "pinned_inventory_scope": scope,
            "pinned_inventory_at": inv_dict.get("collected_at") or now_iso,
        },
    )


def load_pinned_inventory(
    workspace_id: str,
    owner_email: str,
    scope: str = "",
) -> Optional[Dict[str, Any]]:
    """Loads a pinned `AccountsKeysSecretsInventory` for the requested scope (or latest).

    With a non-empty `scope`, an inventory pinned for any other scope is never returned.
    """
    clean_owner = (owner_email or "").strip().lower()
    if not workspace_id or not clean_owner:
        return None
    if scope:
        scoped_env = _read_json(workspace_id, clean_owner, f"snapshots/{_scope_hash(scope)}/inventory.json")
        if (
            isinstance(scoped_env, dict)
            and scoped_env.get("owner_email") == clean_owner
            and scoped_env.get("scope") == scope
            and isinstance(scoped_env.get("inventory"), dict)
        ):
            return scoped_env["inventory"]

    latest_env = _read_json(workspace_id, clean_owner, "pinned_inventory.json")
    if (
        isinstance(latest_env, dict)
        and latest_env.get("owner_email") == clean_owner
        and isinstance(latest_env.get("inventory"), dict)
    ):
        if not scope or latest_env.get("scope") == scope:
            return latest_env["inventory"]
    return None


def load_scan_index(workspace_id: str, owner_email: str) -> List[Dict[str, Any]]:
    clean_owner = (owner_email or "").strip().lower()
    if not workspace_id or not clean_owner:
        return []
    doc = _read_json(workspace_id, clean_owner, "scan_index.json")
    if isinstance(doc, dict) and doc.get("owner_email") == clean_owner and isinstance(doc.get("scans"), list):
        return [s for s in doc["scans"] if isinstance(s, dict)]
    return []


def save_workspace_artifact(
    workspace_id: str,
    filename: str,
    data: bytes,
    content_type: str = "application/octet-stream",
    scope: str = "",
) -> None:
    """Intentionally persists nothing.

    Binary deliverables (`.docx`, `.pdf`, `.zip`, `.png`) used to be written to the store in plaintext and
    were never read back. They are always re-rendered from the encrypted pinned book, so keeping a second,
    unencrypted copy of customer data at rest had no benefit. The signature is kept for existing callers.
    """
    return None


def save_revoked_session_ids(
    workspace_id: str,
    owner_email: str,
    revoked: Dict[str, float],
    ttl_seconds: float,
) -> None:
    """Persists revoked browser session ids (`sid -> cookie expiry epoch`) so a logout survives restarts."""
    clean_owner = (owner_email or "").strip().lower()
    now = time.time()
    live = {str(sid): float(exp) for sid, exp in (revoked or {}).items() if float(exp) > now}
    _write_json(
        workspace_id,
        clean_owner,
        _REVOKED_SIDS_PATH,
        {"owner_email": clean_owner, "revoked": live},
        ttl_seconds=max(60.0, float(ttl_seconds)),
    )


def load_revoked_session_ids(workspace_id: str, owner_email: str) -> Dict[str, float]:
    """Loads the still-valid revoked browser session ids for this user (`{}` when none)."""
    clean_owner = (owner_email or "").strip().lower()
    if not workspace_id or not clean_owner:
        return {}
    doc = _read_json(workspace_id, clean_owner, _REVOKED_SIDS_PATH)
    if not isinstance(doc, dict) or doc.get("owner_email") != clean_owner or not isinstance(doc.get("revoked"), dict):
        return {}
    now = time.time()
    out: Dict[str, float] = {}
    for sid, exp in doc["revoked"].items():
        try:
            if float(exp) > now:
                out[str(sid)] = float(exp)
        except (TypeError, ValueError):
            continue
    return out


def apply_workspace_retention(workspace_id: str, owner_email: str, days: Any) -> Dict[str, int]:
    """Applies a newly selected retention to everything already stored for this workspace.

    `0` deletes all stored customer data. Otherwise each document's expiry is recomputed from its original
    storage time: documents already older than the new retention are deleted, the rest are re-sealed.
    """
    clean_days = set_workspace_retention_days(workspace_id, days)
    if clean_days <= 0:
        return {"deleted": wipe_workspace(workspace_id, forget_retention=False), "restamped": 0}

    clean_owner = (owner_email or "").strip().lower()
    ttl = clean_days * 86400
    now = time.time()
    deleted = 0
    restamped = 0
    for rel in _list_workspace_objects(workspace_id):
        if rel.startswith(_SECURITY_PREFIX):
            continue
        raw = _read_bytes(workspace_id, rel)
        if not raw:
            continue
        env = _parse_envelope(raw)
        if env is None or env["stored_at"] + ttl <= now:
            if _delete_object(workspace_id, rel):
                deleted += 1
            continue
        if env["expires_at"] == env["stored_at"] + ttl:
            continue
        plaintext = _unseal_envelope(clean_owner, workspace_id, rel, env)
        if plaintext is None:
            continue
        _write_document(workspace_id, clean_owner, rel, plaintext, ttl_seconds=ttl, stored_at=env["stored_at"])
        restamped += 1
    return {"deleted": deleted, "restamped": restamped}


def purge_expired_workspace_objects(*, force: bool = False) -> int:
    """Deletes expired documents and legacy plaintext objects across ALL workspaces (retention sweeper).

    Only the first bytes of each object are read, so no per-user key is needed. Throttled by
    `IAM_WORKSPACE_SWEEP_INTERVAL_SECONDS` (default 6 hours on GCS, 5 minutes on the local store).
    """
    global _LAST_OBJECT_SWEEP_AT
    default_interval = "21600" if _gcs_bucket_name() else "300"
    try:
        interval = float(os.getenv("IAM_WORKSPACE_SWEEP_INTERVAL_SECONDS", default_interval))
    except (TypeError, ValueError):
        interval = float(default_interval)
    now = time.time()
    with _STORE_LOCK:
        if not force and (now - _LAST_OBJECT_SWEEP_AT) < interval:
            return 0
        _LAST_OBJECT_SWEEP_AT = now

    deleted = 0
    try:
        for ws_id, rel in _list_all_workspace_objects():
            head = _read_bytes(ws_id, rel, head_bytes=_ENVELOPE_HEAD_BYTES)
            if head is None:
                continue
            match = _ENVELOPE_HEAD_RE.match(head)
            if match is not None and int(match.group(2)) > now:
                continue
            if _delete_object(ws_id, rel):
                deleted += 1
    except Exception as exc:
        logger.warning("Workspace retention sweep warning: %s", exc)
    if deleted:
        logger.info("Workspace retention sweep removed %d expired or legacy object(s).", deleted)
    return deleted


def wipe_workspace(workspace_id: str, *, forget_retention: bool = True) -> int:
    """Explicitly deletes ALL persisted customer data for `workspace_id` (user Disconnect & Wipe).

    The `security/` documents (revoked browser session ids, no customer data) are kept so that a logout
    performed before the wipe remains effective.
    """
    safe_id = _safe_ws_id(workspace_id)
    deleted = 0
    try:
        for rel in _list_workspace_objects(safe_id):
            if rel.startswith(_SECURITY_PREFIX):
                continue
            if _delete_object(safe_id, rel):
                deleted += 1
    except Exception as exc:
        logger.warning("wipe_workspace warning for %s: %s", safe_id, exc)
    if forget_retention:
        with _STORE_LOCK:
            _RETENTION_BY_WS.pop(safe_id, None)
    return deleted
