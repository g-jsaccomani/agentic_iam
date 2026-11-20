"""Tests for T20 — the persisted workspace is sealed, authenticated, and has a consultant-selected retention (N2)."""

from __future__ import annotations

import base64
import json
import shutil
import time
from pathlib import Path

import pytest

from backend import session_vault as sv
from backend import workspace_store as ws
from tests.round2_helpers import (
    ORG_A,
    SA_A,
    SA_B,
    SCOPE_A,
    SCOPE_B,
    book_dict,
    connect_direct,
    connect_sa,
    forget_sessions_in_memory,
    reset_state,
    stub_token_minting,
)

FLAG = "IAM_ENABLE_PERSISTENT_DELEGATION"


@pytest.fixture(autouse=True)
def _clean_state():
    reset_state()
    yield
    reset_state()


def _ws_dir(email: str) -> Path:
    return ws._LOCAL_STORE_ROOT / ws.derive_workspace_id(email)


def _files(email: str) -> list[Path]:
    root = _ws_dir(email)
    return sorted(p for p in root.rglob("*") if p.is_file()) if root.exists() else []


def _expiry(path: Path) -> tuple[int, int]:
    match = ws._ENVELOPE_HEAD_RE.match(path.read_bytes())
    assert match is not None, f"{path.name} is not a sealed v2 document"
    return int(match.group(1)), int(match.group(2))


def test_every_stored_document_is_sealed(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_token_minting(monkeypatch)
    email = "t20-sealed@example.com"
    wid = ws.derive_workspace_id(email)
    connect_sa(email, SA_A, ORG_A, customer_name="Customer A")
    ws.save_pinned_book(wid, email, SCOPE_A, {**book_dict(SCOPE_A, "CUSTOMER_A_BOOK"), "asset_inventory": {"kpis": {}}})

    names = {p.name for p in _files(email)}
    assert {"connection.json", "pinned_book.json", "pinned_inventory.json", "scan_index.json"} <= names
    for path in _files(email):
        raw = path.read_bytes()
        _expiry(path)
        for secret in (b"CUSTOMER_A_BOOK", SA_A.encode(), email.encode(), b"Customer A", ORG_A.encode()):
            assert secret not in raw, f"{secret!r} readable in {path.name}"

    assert ws.load_pinned_book(wid, email, SCOPE_A)["marker"] == "CUSTOMER_A_BOOK"


def test_tampered_or_legacy_connection_record_never_reaches_the_runtime_sa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FLAG, "true")
    calls = stub_token_minting(monkeypatch)
    email = "t20-tamper@example.com"
    wid = ws.derive_workspace_id(email)
    assert connect_sa(email, SA_A, ORG_A).persistent_sa_delegation is True
    path = _ws_dir(email) / "connection.json"
    original = path.read_text(encoding="utf-8")

    # 1. one flipped ciphertext bit
    env = json.loads(original)
    ct = bytearray(base64.urlsafe_b64decode(env["ct_b64"]))
    ct[10] ^= 0x01
    env["ct_b64"] = base64.urlsafe_b64encode(bytes(ct)).decode("ascii")
    path.write_text(json.dumps(env, separators=(",", ":")), encoding="utf-8")
    forget_sessions_in_memory()
    calls.clear()
    assert sv.get_inspection_session(wid, email) is None
    assert calls == []

    # 2. retention extended by editing the (authenticated) header
    env = json.loads(original)
    env["expires_at"] += 10**7
    path.write_text(json.dumps(env, separators=(",", ":")), encoding="utf-8")
    forget_sessions_in_memory()
    assert sv.get_inspection_session(wid, email) is None

    # 3. a legacy plaintext record pointing at another customer's SA with delegation switched on
    path.write_text(
        json.dumps(
            {
                "owner_email": email,
                "connection_mode": "impersonated_sa",
                "impersonated_sa_email": SA_B,
                "persistent_sa_delegation": True,
                "token_expires_at": time.time() - 10.0,
            }
        ),
        encoding="utf-8",
    )
    forget_sessions_in_memory()
    assert sv.get_inspection_session(wid, email) is None
    assert calls == []
    assert not path.exists(), "legacy plaintext record must be discarded"

    # the untouched original still works
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(original, encoding="utf-8")
    forget_sessions_in_memory()
    assert sv.get_inspection_session(wid, email).impersonated_sa_email == SA_A


def test_documents_cannot_be_moved_between_users_or_paths() -> None:
    owner, intruder = "t20-owner@example.com", "t20-intruder@example.com"
    connect_direct(owner, ORG_A)
    connect_direct(intruder, ORG_A)
    shutil.copyfile(_ws_dir(owner) / "connection.json", _ws_dir(intruder) / "connection.json")
    forget_sessions_in_memory()
    assert sv.get_inspection_session(ws.derive_workspace_id(intruder), intruder) is None

    wid = ws.derive_workspace_id(owner)
    ws.save_pinned_book(wid, owner, SCOPE_A, book_dict(SCOPE_A, "CUSTOMER_A_BOOK"))
    src = _ws_dir(owner) / "snapshots" / ws._scope_hash(SCOPE_A) / "book.json"
    dst = _ws_dir(owner) / "snapshots" / ws._scope_hash(SCOPE_B) / "book.json"
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    assert ws.load_pinned_book(wid, owner, SCOPE_B) is None
    assert ws.load_pinned_book(wid, owner, SCOPE_A)["marker"] == "CUSTOMER_A_BOOK"


def test_retention_zero_persists_nothing() -> None:
    email = "t20-zero@example.com"
    wid = ws.derive_workspace_id(email)
    sess = connect_direct(email, ORG_A, retention_days=0)
    ws.save_pinned_book(wid, email, SCOPE_A, book_dict(SCOPE_A, "CUSTOMER_A_BOOK"))
    ws.save_workspace_artifact(wid, "report.docx", b"plaintext report", "application/octet-stream", SCOPE_A)

    assert _files(email) == []
    assert ws.load_pinned_book(wid, email, SCOPE_A) is None
    meta = sess.to_public_metadata()
    assert meta["workspace_persisted"] is False
    assert meta["workspace_retention_days"] == 0


def test_switching_to_retention_zero_deletes_what_was_stored() -> None:
    email = "t20-tozero@example.com"
    wid = ws.derive_workspace_id(email)
    connect_direct(email, ORG_A, retention_days=30)
    ws.save_pinned_book(wid, email, SCOPE_A, book_dict(SCOPE_A, "CUSTOMER_A_BOOK"))
    assert _files(email)
    connect_direct(email, ORG_A, retention_days=0)
    assert _files(email) == []


def test_retention_sets_expiry_and_expired_documents_are_refused_and_swept(monkeypatch: pytest.MonkeyPatch) -> None:
    email = "t20-expiry@example.com"
    wid = ws.derive_workspace_id(email)
    assert connect_direct(email, ORG_A, retention_days=1).retention_days == 1
    ws.save_pinned_book(wid, email, SCOPE_A, book_dict(SCOPE_A, "CUSTOMER_A_BOOK"))
    for path in _files(email):
        stored_at, expires_at = _expiry(path)
        assert expires_at - stored_at == 86400

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 2 * 86400)
    assert ws.load_pinned_book(wid, email, SCOPE_A) is None
    assert ws.purge_expired_workspace_objects(force=True) >= 1
    assert _files(email) == []
    forget_sessions_in_memory()
    assert sv.get_inspection_session(wid, email) is None


def test_changing_retention_reseals_recent_documents_and_deletes_older_ones() -> None:
    email = "t20-change@example.com"
    wid = ws.derive_workspace_id(email)
    connect_direct(email, ORG_A, retention_days=30)
    ws.save_pinned_book(wid, email, SCOPE_A, book_dict(SCOPE_A, "CUSTOMER_A_BOOK"))
    latest = _ws_dir(email) / "pinned_book.json"
    three_days_ago = int(time.time()) - 3 * 86400
    plaintext = ws._read_document(wid, email, "pinned_book.json")
    ws._write_document(wid, email, "pinned_book.json", plaintext, ttl_seconds=30 * 86400, stored_at=three_days_ago)

    connect_direct(email, ORG_A, retention_days=7)
    assert _expiry(latest) == (three_days_ago, three_days_ago + 7 * 86400)
    assert ws.load_pinned_book(wid, email, "")["marker"] == "CUSTOMER_A_BOOK"

    connect_direct(email, ORG_A, retention_days=1)
    assert not latest.exists()
    # the snapshot written "now" is younger than one day and survives with the shorter expiry
    snapshot = _ws_dir(email) / "snapshots" / ws._scope_hash(SCOPE_A) / "book.json"
    stored_at, expires_at = _expiry(snapshot)
    assert expires_at - stored_at == 86400


def test_sweeper_removes_legacy_plaintext_objects_without_any_key() -> None:
    legacy = ws._LOCAL_STORE_ROOT / "legacyworkspace"
    (legacy / "artifacts").mkdir(parents=True)
    (legacy / "pinned_book.json").write_text('{"book": {"marker": "PLAINTEXT_BOOK"}}', encoding="utf-8")
    (legacy / "artifacts" / "report.docx").write_bytes(b"PK\x03\x04 plaintext report")
    assert ws.purge_expired_workspace_objects(force=True) == 2
    assert not legacy.exists()


def test_wipe_removes_customer_data_but_keeps_session_revocations() -> None:
    email = "t20-wipe@example.com"
    wid = ws.derive_workspace_id(email)
    connect_direct(email, ORG_A)
    ws.save_pinned_book(wid, email, SCOPE_A, book_dict(SCOPE_A, "CUSTOMER_A_BOOK"))
    ws.save_revoked_session_ids(wid, email, {"sid-1": time.time() + 600.0}, 600.0)

    assert ws.wipe_workspace(wid) >= 3
    assert [p.relative_to(_ws_dir(email)).as_posix() for p in _files(email)] == ["security/revoked_sids.json"]
    assert "sid-1" in ws.load_revoked_session_ids(wid, email)


def test_master_secret_is_mandatory_on_cloud_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("K_SERVICE", "agentic-iam")
    monkeypatch.delenv("IAM_SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="IAM_SESSION_SECRET"):
        ws.get_master_secret_bytes()


def test_retention_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_WORKSPACE_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("IAM_WORKSPACE_MAX_RETENTION_DAYS", raising=False)
    assert ws.normalize_retention_days(None) == 30
    assert ws.normalize_retention_days(0) == 0
    assert ws.normalize_retention_days("7") == 7
    assert ws.normalize_retention_days(365) == 365
    for bad in (-1, 366, "abc", True, 1.5e9):
        with pytest.raises(ValueError):
            ws.normalize_retention_days(bad)
    monkeypatch.setenv("IAM_WORKSPACE_MAX_RETENTION_DAYS", "90")
    with pytest.raises(ValueError):
        ws.normalize_retention_days(91)
