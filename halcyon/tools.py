from halcyon import audit, authz, guards
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.store import Store

SCHEMAS: list[dict] = [
    {"name": "get_balance", "description": "Get an account balance",
     "parameters": {"type": "object", "properties": {"account": {"type": "string"}},
                    "required": ["account"]}},
    {"name": "get_account_details", "description": "Look up an account's details",
     "parameters": {"type": "object", "properties": {"account": {"type": "string"}},
                    "required": ["account"]}},
    {"name": "transfer_funds", "description": "Transfer money to an account",
     "parameters": {"type": "object", "properties": {
         "to_account": {"type": "string"}, "amount": {"type": "integer"}},
         "required": ["to_account", "amount"]}},
    {"name": "issue_refund", "description": "Issue a refund to an account",
     "parameters": {"type": "object", "properties": {
         "to_account": {"type": "string"}, "amount": {"type": "integer"}},
         "required": ["to_account", "amount"]}},
    {"name": "update_email", "description": "Update an account's email",
     "parameters": {"type": "object", "properties": {
         "account": {"type": "string"}, "email": {"type": "string"}},
         "required": ["account", "email"]}},
]


def execute(name: str, session_id: str, args: dict, bank: Bank,
            store: Store, settings: Settings) -> str:
    audit.record(store, session_id, "m5", audit.TOOL_CALL, session_id,
                 {"tool": name, "args": args})
    # Authorisation chokepoint. This runs before any branch below, so no tool
    # body can mutate an account the session does not own. It is not gated on
    # settings: guards.authorize_tool_call still exists and still honours
    # SEC_TOOL_SCOPE_ENFORCEMENT for the lab's L1/L2 lesson, but it is no longer
    # the only thing standing between an injected instruction and the ledger.
    decision = authz.decide(session_id, name, args, bank)
    if not decision.allow:
        # Recorded under its own event type, deliberately NOT under
        # UNAUTHORIZED_TOOL_CALL. In this lab that event is the mechanism's
        # record that unauthorised money actually moved, which is why the M5
        # validator treats its presence as a successful attack. A blocked
        # attempt is a different fact and gets a different event, so detection
        # still sees the attempt without the audit log claiming a theft that
        # never happened.
        audit.record(store, session_id, "m5", audit.TOOL_CALL_DENIED, session_id,
                     {"tool": name, "args": args, "reason": decision.reason})
        return f"denied: {decision.reason}"
    if not guards.authorize_tool_call(session_id, name, args, bank, settings):
        return f"denied: {name} requires authorization / human approval"
    if name == "get_balance":
        a = bank.get(str(args.get("account", "")))
        return f"balance: {a.balance}" if a else "no such account"
    if name == "get_account_details":
        a = bank.get(str(args.get("account", "")))
        return f"account {a.id}: email={a.email} balance={a.balance}" if a else "no such account"
    if name in ("transfer_funds", "issue_refund"):
        to = str(args.get("to_account", ""))
        try:
            amount = int(args.get("amount", 0) or 0)
        except (TypeError, ValueError):
            return f"{name}: invalid amount"
        if not to:
            return f"{name}: missing to_account"
        if not bank.owns(session_id, to):
            audit.record(store, session_id, "m5", audit.UNAUTHORIZED_TOOL_CALL,
                         session_id, {"tool": name, "to_account": to, "amount": amount})
        if bank.get(to) is not None:
            bank.credit(to, amount)
        return f"{name}: moved {amount} to {to}"
    if name == "update_email":
        acct = str(args.get("account", ""))
        email = str(args.get("email", ""))
        if not acct:
            return "update_email: missing account"
        if not bank.owns(session_id, acct):
            audit.record(store, session_id, "m5", audit.UNAUTHORIZED_ACCOUNT_MODIFICATION,
                         session_id, {"account": acct, "email": email})
        if bank.get(acct) is not None:
            bank.set_email(acct, email)
        return f"update_email: {acct} -> {email}"
    return f"unknown tool: {name}"
