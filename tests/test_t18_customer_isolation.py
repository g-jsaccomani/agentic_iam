"""Tests for T18 — one customer's data never appears in another customer's session (N3)."""

from __future__ import annotations

import pytest

from backend import session_vault as sv
from backend import workspace_store as ws
from tests.round2_helpers import (
    ORG_A,
    SA_A,
    SA_B,
    SCOPE_A,
    SCOPE_B,
    authed_client,
    book_dict,
    connect_direct,
    connect_sa,
    reset_state,
    stub_token_minting,
)


@pytest.fixture(autouse=True)
def _clean_state():
    reset_state()
    yield
    reset_state()


def _pin_customer_a(email: str) -> str:
    wid = ws.derive_workspace_id(email)
    ws.save_pinned_book(wid, email, SCOPE_A, book_dict(SCOPE_A, "CUSTOMER_A_BOOK"))
    sv.update_session_organization_metadata(
        wid,
        email,
        selected_scope=SCOPE_A,
        has_pinned_book=True,
        pinned_scope=SCOPE_A,
        pinned_generated_at="2026-01-01T00:00:00Z",
    )
    ws.update_workspace_connection_fields(
        wid, email, {"org_hierarchy": {"marker": "A_HIERARCHY"}, "readiness": {"marker": "A_READINESS"}}
    )
    return wid


def test_restore_never_returns_a_book_pinned_for_another_scope() -> None:
    email = "t18-restore@example.com"
    connect_direct(email, ORG_A)
    _pin_customer_a(email)
    client = authed_client(email)

    other = client.get("/api/v1/workspace/restore", params={"scope": SCOPE_B})
    assert other.status_code == 200
    assert other.json()["connected"] is True
    assert other.json()["pinned_book"] is None
    assert other.json()["pinned_inventory"] is None

    same = client.get("/api/v1/workspace/restore", params={"scope": SCOPE_A})
    assert same.json()["pinned_book"]["marker"] == "CUSTOMER_A_BOOK"

    # A deliverable requested for scope B is never rendered from customer A's book
    assert client.get("/api/v1/download/docx", params={"scope": SCOPE_B}).status_code == 409


def test_connecting_another_customer_sa_with_blank_org_inherits_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_token_minting(monkeypatch)
    email = "t18-switch@example.com"
    connect_sa(email, SA_A, ORG_A, organization_domain="customer-a.example", customer_name="Customer A")
    wid = _pin_customer_a(email)

    sess_b = connect_sa(email, SA_B, "", token="ya29.user-b")

    assert sess_b.impersonated_sa_email == SA_B
    assert sess_b.organization_id == ""
    assert sess_b.customer_name == ""
    assert sess_b.organization_domain == ""
    assert sess_b.selected_scope == ""
    assert sess_b.pinned_scope == ""
    assert sess_b.has_pinned_book is False
    assert sess_b.has_pinned_inventory is False

    record, _tokens = ws.load_workspace_connection(wid, email)
    assert record["impersonated_sa_email"] == SA_B
    assert "org_hierarchy" not in record
    assert "readiness" not in record
    assert not record.get("pinned_scope")

    body = authed_client(email).get("/api/v1/workspace/restore").json()
    assert body["connected"] is True
    assert body["pinned_book"] is None
    assert body["org_hierarchy"] is None
    assert body["readiness"] is None


def test_reconnecting_the_same_sa_and_org_keeps_pins(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_token_minting(monkeypatch)
    email = "t18-same@example.com"
    connect_sa(email, SA_A, ORG_A, organization_domain="customer-a.example", customer_name="Customer A")
    _pin_customer_a(email)

    again = connect_sa(email, SA_A, ORG_A, token="ya29.user-again")
    assert again.customer_name == "Customer A"
    assert again.pinned_scope == SCOPE_A
    assert again.has_pinned_book is True

    blank_org = connect_sa(email, SA_A, "", token="ya29.user-again")
    assert blank_org.organization_id == ORG_A
    assert blank_org.pinned_scope == SCOPE_A

    body = authed_client(email).get("/api/v1/workspace/restore").json()
    assert body["pinned_book"]["marker"] == "CUSTOMER_A_BOOK"


def test_direct_user_reconnect_only_keeps_pins_for_the_same_explicit_org() -> None:
    email = "t18-direct@example.com"
    connect_direct(email, ORG_A, customer_name="Customer A")
    _pin_customer_a(email)

    same_org = connect_direct(email, ORG_A)
    assert same_org.pinned_scope == SCOPE_A
    assert same_org.customer_name == "Customer A"

    blank_org = connect_direct(email, "")
    assert blank_org.organization_id == ""
    assert blank_org.customer_name == ""
    assert blank_org.pinned_scope == ""
    assert blank_org.has_pinned_book is False
