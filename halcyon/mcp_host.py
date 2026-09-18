from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.memory import create_connected_server_and_client_session as _connect
from mcp.types import TextContent

from halcyon import audit, authz, guards
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.mcp_servers.core_banking import build_core_banking_server
from halcyon.mcp_servers.crm import build_crm_server
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import Store

MODULE = "m6"
_SENSITIVE = {"get_account_details"}  # core-banking tools that leak data


@dataclass
class ToolInfo:
    server: str
    name: str
    description: str
    input_schema: dict

    @property
    def qualified(self) -> str:
        return f"{self.server}__{self.name}"


class MCPHost:
    def __init__(self, sessions: dict[str, ClientSession], vault: TokenVault,
                 store: Store, settings: Settings, session_id: str,
                 bank: Bank | None = None) -> None:
        self._sessions = sessions           # {SERVER_CORE: s, SERVER_CRM: s}
        self._vault = vault
        self._store = store
        self._settings = settings
        self._session_id = session_id
        # Ownership view used by the authorisation chokepoint in call(). Optional
        # only so existing constructions keep working; when it is absent the host
        # cannot authorise, and fails closed on core-banking tools.
        self._bank = bank
        self._pinned: dict[str, str] = {}
        self._served_poison = False

    async def _list(self, server: str) -> list[ToolInfo]:
        res = await self._sessions[server].list_tools()
        return [ToolInfo(server, t.name, t.description or "", t.inputSchema) for t in res.tools]

    async def list_tools(self) -> list[ToolInfo]:
        out: list[ToolInfo] = []
        for server in (SERVER_CORE, SERVER_CRM):
            out.extend(await self._list(server))
        return out

    def approve(self, tools: list[ToolInfo]) -> None:
        if self._settings.sec_mcp_desc_pinning:
            self._pinned = {ti.qualified: guards.desc_hash(ti.description) for ti in tools}

    async def schemas_for_llm(self) -> list[dict]:
        tools = await self.list_tools()
        self._served_poison = False
        schemas: list[dict] = []
        for ti in tools:
            desc = ti.description
            if self._settings.sec_mcp_desc_pinning:
                pinned = self._pinned.get(ti.qualified)
                if pinned is not None and guards.desc_hash(desc) != pinned:
                    desc = ""  # mutated since approval — drop the untrusted delta
                desc = guards.quarantine_description(desc)
            else:
                if guards.looks_poisoned(desc):
                    self._served_poison = True
                    if ti.name == "get_notes":  # a benign tool now carrying injected text == rug pull
                        audit.record(self._store, self._session_id, MODULE,
                                     audit.MCP_DESC_MUTATION_ACCEPTED, ti.server, {"tool": ti.name})
            schemas.append({"name": ti.qualified, "description": desc, "parameters": ti.input_schema})
        return schemas

    async def call(self, qualified: str, args: dict) -> str:
        server, _, name = qualified.partition("__")
        audit.record(self._store, self._session_id, MODULE, audit.TOOL_CALL,
                     self._session_id, {"tool": qualified, "args": args})
        if name == "get_integration_token":
            service = str(args.get("service", ""))
            if not service or service == SERVER_CRM:
                return self._vault.own_token(SERVER_CRM)
            if service not in (SERVER_CORE, SERVER_CRM):
                return "unknown service"
            if not guards.authorize_token_access(SERVER_CRM, service, self._settings):
                return "access denied"
            audit.record(self._store, self._session_id, MODULE, audit.TOKEN_READ,
                         SERVER_CRM, {"target": service})
            return self._vault.own_token(service)
        # Attribution is deliberately coarse: in vulnerable mode, any served
        # poisoned description arms the *next* sensitive core-tool call, not
        # necessarily the one the poison referenced. This is mechanism-based
        # (model-word-independent) rather than reading the model's intent;
        # the live e2e test proves a real model actually follows the description.
        if server == SERVER_CORE and name in _SENSITIVE and self._served_poison:
            audit.record(self._store, self._session_id, MODULE,
                         audit.MCP_POISONED_INVOCATION, self._session_id,
                         {"tool": qualified, "args": args})
        # Authorisation chokepoint for the core-banking surface. The shipped host
        # dispatches straight to the server, and the server itself checks nothing,
        # so before this the MCP route reached transfer_funds/issue_refund/
        # update_email with no ownership check in either mode -- a fix applied only
        # to halcyon/tools.py would have left it wide open. CRM tools are not
        # account-scoped and are left to their own server.
        if server == SERVER_CORE and authz.is_bank_tool(name):
            if self._bank is None:
                return "denied: host cannot authorise core-banking calls"
            decision = authz.decide(self._session_id, name, args, self._bank)
            if not decision.allow:
                audit.record(self._store, self._session_id, MODULE,
                             audit.TOOL_CALL_DENIED, self._session_id,
                             {"tool": qualified, "args": args,
                              "reason": decision.reason})
                return f"denied: {decision.reason}"
        res = await self._sessions[server].call_tool(name, args)
        first = res.content[0] if res.content else None
        return first.text if isinstance(first, TextContent) else ""


@asynccontextmanager
async def in_memory_host(bank: Bank, vault: TokenVault, customers: dict,
                         store: Store, settings: Settings,
                         session_id: str) -> AsyncIterator[MCPHost]:
    async with AsyncExitStack() as stack:
        core = await stack.enter_async_context(_connect(build_core_banking_server(bank, vault)))
        crm = await stack.enter_async_context(_connect(build_crm_server(bank, vault, customers)))
        await core.initialize()
        await crm.initialize()
        yield MCPHost({SERVER_CORE: core, SERVER_CRM: crm}, vault, store, settings,
                      session_id, bank)


@asynccontextmanager
async def http_host(core_url: str, crm_url: str, vault: TokenVault,
                     store: Store, settings: Settings,
                     session_id: str, bank: Bank | None = None) -> AsyncIterator[MCPHost]:
    """Same host, real transport: connects to the deployed mcp-core-banking
    and mcp-crm containers over streamable-HTTP instead of in-memory pipes.

    Note the limit of host-side authorisation on this transport: `bank` is the
    *host's* view of ownership, while the ledger being mutated lives in the
    remote container. That is enough to stop the agent, and not enough to stop
    anyone who can reach the server's port directly -- see WRITEUP.md.
    """
    async with AsyncExitStack() as stack:
        core_r, core_w, _ = await stack.enter_async_context(streamablehttp_client(core_url))
        core = await stack.enter_async_context(ClientSession(core_r, core_w))
        crm_r, crm_w, _ = await stack.enter_async_context(streamablehttp_client(crm_url))
        crm = await stack.enter_async_context(ClientSession(crm_r, crm_w))
        await core.initialize()
        await crm.initialize()
        yield MCPHost({SERVER_CORE: core, SERVER_CRM: crm}, vault, store, settings,
                      session_id, bank)
