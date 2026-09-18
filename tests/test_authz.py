"""Coverage for the bank-tool authorisation chokepoint (halcyon/authz.py).

The point of these tests is the property the shipped guard does not have: the
decision holds with HALCYON_MODE=vulnerable and every SEC_* flag off, because
it is not a function of settings at all.
"""

import anyio
import pytest

from halcyon import audit, authz, tools
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore

VULN = load_settings({"HALCYON_MODE": "vulnerable"})


def _bank() -> Bank:
    b = Bank()
    b.seed([
        {"id": "acct-me", "owner_session": "me", "balance": 1000, "email": "me@x"},
        {"id": "acct-victim", "owner_session": "victim", "balance": 5000, "email": "v@x"},
        {"id": "acct-attacker", "owner_session": "attacker", "balance": 0, "email": "a@x"},
    ])
    return b


# --- decide() ------------------------------------------------------------

@pytest.mark.parametrize("tool,args", [
    ("transfer_funds", {"to_account": "acct-attacker", "amount": 500}),
    ("issue_refund", {"to_account": "acct-attacker", "amount": 500}),
    ("update_email", {"account": "acct-victim", "email": "attacker@x"}),
    ("get_balance", {"account": "acct-victim"}),
    ("get_account_details", {"account": "acct-victim"}),
])
def test_unowned_account_is_denied(tool, args):
    assert authz.decide("me", tool, args, _bank()).allow is False


@pytest.mark.parametrize("tool,args", [
    ("transfer_funds", {"to_account": "acct-me", "amount": 500}),
    ("issue_refund", {"to_account": "acct-me", "amount": 500}),
    ("update_email", {"account": "acct-me", "email": "new@x"}),
    ("get_balance", {"account": "acct-me"}),
    ("get_account_details", {"account": "acct-me"}),
])
def test_owned_account_is_allowed(tool, args):
    assert authz.decide("me", tool, args, _bank()).allow is True


def test_unknown_tool_is_denied_by_default():
    assert authz.decide("me", "drop_database", {"account": "acct-me"}, _bank()).allow is False


def test_missing_and_nonexistent_account_are_denied():
    b = _bank()
    assert authz.decide("me", "transfer_funds", {"amount": 5}, b).allow is False
    assert authz.decide("me", "get_balance", {"account": "acct-nope"}, b).allow is False


# --- the direct tool path -------------------------------------------------

def test_transfer_to_unowned_is_blocked_with_flags_off():
    b, s = _bank(), InMemoryStore()
    out = tools.execute("transfer_funds", "me",
                        {"to_account": "acct-attacker", "amount": 10000}, b, s, VULN)
    assert "denied" in out.lower()
    assert b.get("acct-attacker").balance == 0          # no money moved
    assert audit.has_event(s, "me", "m5", audit.TOOL_CALL_DENIED)
    # The validator's success event must NOT be written for a blocked attempt,
    # or a denied attack would still read as a pass.
    assert not audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_TOOL_CALL)


def test_update_email_on_unowned_is_blocked_with_flags_off():
    b, s = _bank(), InMemoryStore()
    out = tools.execute("update_email", "me",
                        {"account": "acct-victim", "email": "attacker@evil.test"}, b, s, VULN)
    assert "denied" in out.lower()
    assert b.get("acct-victim").email == "v@x"
    assert not audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_ACCOUNT_MODIFICATION)


def test_read_tools_on_unowned_account_are_blocked():
    """The shipped guard allows these even when hardening is on."""
    b, s = _bank(), InMemoryStore()
    for tool in ("get_balance", "get_account_details"):
        out = tools.execute(tool, "me", {"account": "acct-victim"}, b, s, VULN)
        assert "denied" in out.lower()
        assert "5000" not in out


def test_owned_operations_still_work():
    b, s = _bank(), InMemoryStore()
    assert "1000" in tools.execute("get_balance", "me", {"account": "acct-me"}, b, s, VULN)
    tools.execute("transfer_funds", "me", {"to_account": "acct-me", "amount": 100}, b, s, VULN)
    assert b.get("acct-me").balance == 1100


# --- the MCP path ---------------------------------------------------------

def test_mcp_money_movement_is_blocked_with_flags_off():
    """The route a fix confined to halcyon/tools.py would have missed."""
    b, store = _bank(), InMemoryStore()
    vault = TokenVault({SERVER_CORE: "core", SERVER_CRM: "crm"})

    async def main() -> None:
        async with in_memory_host(b, vault, {}, store, VULN, "me") as host:
            out = await host.call("core_banking__transfer_funds",
                                  {"to_account": "acct-attacker", "amount": 5000})
        assert "denied" in out.lower()

    anyio.run(main)
    assert b.get("acct-attacker").balance == 0


def test_mcp_owned_transfer_still_works():
    b, store = _bank(), InMemoryStore()
    vault = TokenVault({SERVER_CORE: "core", SERVER_CRM: "crm"})

    async def main() -> None:
        async with in_memory_host(b, vault, {}, store, VULN, "me") as host:
            out = await host.call("core_banking__transfer_funds",
                                  {"to_account": "acct-me", "amount": 50})
        assert "denied" not in out.lower()

    anyio.run(main)
    assert b.get("acct-me").balance == 1050
