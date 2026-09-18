"""Server-side authorisation chokepoint for the bank-account tool surface.

Every path that can reach a bank primitive routes through decide(): the direct
agent tool loop (halcyon/tools.py) and the MCP host (halcyon/mcp_host.py).

Three properties matter, and each is a direct answer to how the vulnerable
build fails:

1. It decides *before* the operation runs. The vulnerable build records
   UNAUTHORIZED_TOOL_CALL and then performs the credit anyway, so the audit
   log describes a theft it did not prevent.

2. It is deny-by-default. An unrecognised tool is refused rather than falling
   through to an allow, so adding a tool to SCHEMAS cannot silently widen the
   authorised surface.

3. It is not gated on a SEC_* flag. The shipped guard
   (guards.authorize_tool_call) returns True unconditionally whenever
   sec_tool_scope_enforcement is off, which makes the authorisation decision a
   deployment setting. An authorisation control that can be switched off by
   configuration is the vulnerability, not the fix.

Scope is deliberately narrow: this answers "may this session act on this
account?" and nothing else. It is not a fraud engine. It enforces no velocity,
amount or aggregate limit, and it cannot tell an intended instruction from an
injected one -- see WRITEUP.md for what that leaves open.
"""

from dataclasses import dataclass

from halcyon.bank import Bank

# Tool name -> the argument naming the account whose ownership is required.
# Read tools are included on purpose: the shipped guard checks only the money
# and email tools and lets get_balance / get_account_details fall through to an
# allow even when hardening is on, so cross-account disclosure survives it.
_ACCOUNT_ARG = {
    "get_balance": "account",
    "get_account_details": "account",
    "transfer_funds": "to_account",
    "issue_refund": "to_account",
    "update_email": "account",
}


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""


def decide(session_id: str, tool_name: str, args: dict, bank: Bank) -> Decision:
    """Authorise one bank-tool invocation for one session. Deny by default."""
    arg = _ACCOUNT_ARG.get(tool_name)
    if arg is None:
        return Decision(False, f"{tool_name}: not an authorised bank tool")
    account = str(args.get(arg, "") or "")
    if not account:
        return Decision(False, f"{tool_name}: missing {arg}")
    if bank.get(account) is None:
        return Decision(False, f"{tool_name}: no such account {account}")
    if not bank.owns(session_id, account):
        return Decision(False, f"{tool_name}: session is not the owner of {account}")
    return Decision(True)


def is_bank_tool(tool_name: str) -> bool:
    """True for tools decide() is able to rule on."""
    return tool_name in _ACCOUNT_ARG
