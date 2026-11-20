"""Tests for T09 — Session state, chat isolation, pending OAuth token TTL, lifespan sweeper, and safe wipe."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from backend import main, session_vault
from backend.agents import coordinator


def test_wipe_removes_chat_session_pending_tokens_and_export_dir(
    fake_session: Any,
) -> None:
    sid = fake_session.session_id
    owner = fake_session.owner_email

    # Populate chat session service, pending OAuth token, and an artifact file on disk
    chat_svc = coordinator._get_chat_session_service(sid)
    assert sid in coordinator._CHAT_SESSION_SERVICES
    assert chat_svc is not None

    session_vault.store_pending_oauth_token(sid, owner, "ya29.pending-secret", ttl_seconds=60.0)
    assert session_vault.get_pending_oauth_token(sid, owner) == "ya29.pending-secret"
    # Bound to (sid, owner): different email cannot read it
    assert session_vault.get_pending_oauth_token(sid, "other@example.com") is None

    export_dir = session_vault.session_export_dir_for_id(sid)
    export_dir.mkdir(parents=True, exist_ok=True)
    marker = export_dir / "marker.txt"
    marker.write_text("sensitive", encoding="utf-8")
    assert marker.exists()

    removed = session_vault.wipe_inspection_session(sid, owner_email=owner, wipe_persistent=False)
    assert removed is True
    assert sid not in coordinator._CHAT_SESSION_SERVICES
    assert session_vault.get_pending_oauth_token(sid, owner) is None
    assert (sid, owner) not in session_vault._PENDING_OAUTH_TOKENS
    assert not export_dir.exists()


def test_wipe_with_wrong_owner_does_not_delete_directory_caches_or_tokens(
    fake_session: Any,
) -> None:
    sid = fake_session.session_id
    owner = fake_session.owner_email
    session_vault._SESSION_VAULT[sid] = fake_session

    coordinator._get_chat_session_service(sid)
    session_vault.store_pending_oauth_token(sid, owner, "ya29.owner-token", ttl_seconds=120.0)

    export_dir = session_vault.session_export_dir_for_id(sid)
    export_dir.mkdir(parents=True, exist_ok=True)
    marker = export_dir / "protected.txt"
    marker.write_text("keep-me", encoding="utf-8")

    result = session_vault.wipe_inspection_session(
        sid,
        owner_email="attacker@example.com",
        wipe_persistent=True,
    )
    assert result is False
    assert sid in session_vault._SESSION_VAULT
    assert sid in coordinator._CHAT_SESSION_SERVICES
    assert session_vault.get_pending_oauth_token(sid, owner) == "ya29.owner-token"
    assert marker.exists(), "Wrong-owner wipe MUST NOT delete the owner's export directory!"

    # Cleanup legitimately with real owner
    assert session_vault.wipe_inspection_session(sid, owner_email=owner, wipe_persistent=False) is True


@pytest.mark.asyncio
async def test_lifespan_periodic_sweeper_purges_expired_pending_token_without_traffic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_vault.purge_pending_oauth_tokens()
    monkeypatch.setenv("IAM_SESSION_SWEEP_INTERVAL_SECONDS", "0.06")

    session_vault.store_pending_oauth_token("sid-expire-test", "alice@example.com", "ya29.short", ttl_seconds=0.05)
    assert ("sid-expire-test", "alice@example.com") in session_vault._PENDING_OAUTH_TOKENS

    async with main._app_lifespan(main.app):
        await asyncio.sleep(0.22)

    assert ("sid-expire-test", "alice@example.com") not in session_vault._PENDING_OAUTH_TOKENS


def test_purge_expired_state_sweeps_idle_session_and_its_files(
    fake_session: Any,
) -> None:
    sid = fake_session.session_id
    fake_session.last_activity_at = time.time() - 50000.0
    session_vault._SESSION_VAULT[sid] = fake_session
    coordinator._get_chat_session_service(sid)
    export_dir = session_vault.session_export_dir_for_id(sid)
    export_dir.mkdir(parents=True, exist_ok=True)
    (export_dir / "stale.txt").write_text("stale", encoding="utf-8")

    stats = session_vault.purge_expired_state(session_idle_ttl_seconds=3600.0)
    assert stats["expired_sessions_purged"] >= 1
    assert sid not in session_vault._SESSION_VAULT
    assert sid not in coordinator._CHAT_SESSION_SERVICES
    assert not export_dir.exists()
