"""MCP server (spec 2026-07-28, stateless Streamable HTTP) for incident investigation.

Any MCP client can investigate incidents with the same read-only tools the agent uses, get the
deterministic diagnosis, and run a remediation action. Running an action needs a person's approval
through MRTR: the server answers ``input_required`` with a form elicitation and an HMAC-signed
``requestState``; the client asks the user and retries with ``inputResponses``. The server keeps no
session state between the two calls.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections.abc import Callable
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import __version__
from .agent.remediation import Action, DryRunExecutor, plan
from .agent.tools import Toolbox, tool_specs

PROTOCOL_VERSION = "2026-07-28"
SUPPORTED = [PROTOCOL_VERSION]
HEADER_MISMATCH, UNSUPPORTED_VERSION = -32020, -32022
META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CAPS = "io.modelcontextprotocol/clientCapabilities"
APPROVAL_KEY = "approve_action"
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}


def _err(req_id: Any, code: int, message: str, status: int = 200) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}, status)


def _ok(req_id: Any, result: dict) -> JSONResponse:
    result.setdefault("resultType", "complete")
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})


def _text(text: str, *, error: bool = False, structured: dict | None = None) -> dict:
    out: dict = {"resultType": "complete", "content": [{"type": "text", "text": text}], "isError": error}
    if structured is not None:
        out["structuredContent"] = structured
    return out


class StateSigner:
    """Signs approval state so the server needs no session between the two halves of an approval."""

    def __init__(self, secret: bytes | None = None, ttl_s: int = 600):
        self.secret = secret or os.environ.get("INCIDENT_AGENT_STATE_SECRET", "").encode() or os.urandom(32)
        self.ttl_s = ttl_s
        self.used: set[str] = set()

    def issue(self, payload: dict) -> str:
        body = base64.urlsafe_b64encode(json.dumps({**payload, "exp": int(time.time()) + self.ttl_s,
                                                    "nonce": secrets.token_urlsafe(8)}).encode()).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(hmac.new(self.secret, body.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        return f"ia1.{body}.{sig}"

    def verify(self, token: str, expect: dict) -> dict:
        try:
            _, body, sig = token.split(".", 2)
        except ValueError as exc:
            raise ValueError("malformed requestState") from exc
        good = base64.urlsafe_b64encode(hmac.new(self.secret, body.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(good, sig):
            raise ValueError("requestState signature check failed")
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if data.get("exp", 0) < time.time():
            raise ValueError("requestState expired")
        if any(data.get(k) != v for k, v in expect.items()):
            raise ValueError("requestState does not match this request")
        if data["nonce"] in self.used:
            raise ValueError("requestState was already used")
        self.used.add(data["nonce"])
        return data


class IncidentMCP:
    def __init__(self, incidents: Callable[[], dict[str, str]], toolbox: Callable[[str], Toolbox], executor=None,
                 signer: StateSigner | None = None):
        self.incidents = incidents  # incident id -> snapshot path
        self.toolbox = toolbox
        self.executor = executor or DryRunExecutor()
        self.signer = signer or StateSigner()

    def tools(self) -> list[dict]:
        inc = {"incident": {"type": "string", "description": "Incident id from list_incidents"}}
        specs = tool_specs()
        tools = [{"name": "list_incidents", "description": "Incidents available to investigate, with their alerts.",
                  "inputSchema": {"type": "object", "properties": {}}, "annotations": READ_ONLY}]
        for s in specs:
            schema = json.loads(json.dumps(s.parameters))
            schema.setdefault("properties", {}).update(inc)
            schema["required"] = ["incident", *schema.get("required", [])]
            tools.append({"name": s.name, "description": s.description, "inputSchema": schema, "annotations": READ_ONLY})
        tools += [
            {"name": "diagnose", "description": "Root causes separated from symptoms, with evidence and the alerts each "
                                                "one explains. Output also in the ITBench agent_output format.",
             "inputSchema": {"type": "object", "properties": dict(inc), "required": ["incident"]}, "annotations": READ_ONLY},
            {"name": "plan_remediation", "description": "Concrete kubectl actions for the diagnosed root causes, with risk.",
             "inputSchema": {"type": "object", "properties": dict(inc), "required": ["incident"]}, "annotations": READ_ONLY},
            {"name": "run_remediation", "description": "Run one planned action. Always asks the user to approve it first.",
             "inputSchema": {"type": "object", "properties": {**inc, "action_id": {"type": "string"}},
                             "required": ["incident", "action_id"]},
             "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False,
                             "openWorldHint": True}},
        ]
        return sorted(tools, key=lambda t: t["name"])

    async def handle(self, request: Request) -> Response:
        try:
            body = json.loads(await request.body())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _err(None, -32700, "Parse error", 400)
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
            return _err(None, -32600, "Invalid Request", 400)
        if "id" not in body:
            return Response(status_code=202)
        req_id, method = body["id"], body["method"]
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        h_method = request.headers.get("mcp-method")
        if h_method is not None and h_method != method:
            return _err(req_id, HEADER_MISMATCH, "Mcp-Method header does not match the body", 400)
        if method == "tools/call" and request.headers.get("mcp-name") not in (None, params.get("name")):
            return _err(req_id, HEADER_MISMATCH, "Mcp-Name header does not match the body", 400)
        meta = params.get("_meta") or {}
        version = meta.get(META_VERSION) or request.headers.get("mcp-protocol-version")
        if version and version not in SUPPORTED:
            return _err(req_id, UNSUPPORTED_VERSION, f"Unsupported protocol version {version}; supported: {SUPPORTED}")
        if method == "server/discover":
            return _ok(req_id, {"supportedVersions": SUPPORTED, "capabilities": {"tools": {"listChanged": False}},
                                "serverInfo": {"name": "incident-agent", "version": __version__},
                                "instructions": "Investigate Kubernetes incidents: list_incidents, then list_alerts, "
                                                "find_anomalies and diagnose. Remediation needs the user's approval."})
        if method == "tools/list":
            return _ok(req_id, {"tools": self.tools(), "ttlMs": 300_000, "cacheScope": "public"})
        if method == "tools/call":
            return await self._call(req_id, params, meta)
        return _err(req_id, -32601, f"Method not found: {method}")

    async def _call(self, req_id: Any, params: dict, meta: dict) -> Response:
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in {t["name"] for t in self.tools()}:
            return _err(req_id, -32602, f"Unknown tool: {name}")
        if name == "list_incidents":
            rows = []
            for iid in sorted(self.incidents()):
                tb = await asyncio.to_thread(self.toolbox, iid)
                rows.append({"incident": iid, "alerts": len(tb.snap.firing_alerts()), "source": tb.snap.meta.get("source")})
            return _ok(req_id, _text(json.dumps(rows, indent=1), structured={"incidents": rows}))
        iid = args.get("incident")
        if iid not in self.incidents():
            return _ok(req_id, _text(f"Unknown incident '{iid}'. Call list_incidents.", error=True))
        tb = await asyncio.to_thread(self.toolbox, iid)
        args = {k: v for k, v in args.items() if k != "incident"}
        if name == "diagnose":
            d = await asyncio.to_thread(tb.engine.diagnose)
            lines = [f"Root cause: {c.entity} - {c.reason}" for c in d.root_causes]
            if d.unexplained_alerts:
                lines.append(f"Alerts not explained: {d.unexplained_alerts}")
            text = "\n".join(lines) or "No root cause found."
            return _ok(req_id, _text(text, structured={"root_causes": [c.to_dict() for c in d.root_causes],
                                                       "alerts": d.alerts, "itbench": d.to_itbench()}))
        if name in ("plan_remediation", "run_remediation"):
            d = await asyncio.to_thread(tb.engine.diagnose)
            actions = plan(tb.engine, d.root_causes)
            if name == "plan_remediation":
                return _ok(req_id, _text("\n".join(f"{a.id} [{a.risk}] {a.title}: {a.command}" for a in actions)
                                         or "No actions.", structured={"actions": [a.to_dict() for a in actions]}))
            return await self._remediate(req_id, iid, args.get("action_id"), actions, params, meta)
        text, is_error = await asyncio.to_thread(tb.call, name, args)
        return _ok(req_id, _text(text, error=is_error))

    async def _remediate(self, req_id: Any, iid: str, action_id: str | None, actions: list[Action], params: dict,
                         meta: dict) -> Response:
        action = next((a for a in actions if a.id == action_id), None)
        if action is None:
            return _ok(req_id, _text(f"No action '{action_id}' in the plan. Call plan_remediation.", error=True))
        state = params.get("requestState")
        if state:
            try:
                self.signer.verify(state, {"incident": iid, "action": action.id, "command": action.command})
            except ValueError as exc:
                return _err(req_id, -32602, str(exc))
            reply = (params.get("inputResponses") or {}).get(APPROVAL_KEY) or {}
            approved = reply.get("action") == "accept" and bool((reply.get("content") or {}).get("approve"))
            if not approved:
                return _ok(req_id, _text(f"Not run: the user declined `{action.command}`.", error=True))
            result = await asyncio.to_thread(self.executor.run, action)
            return _ok(req_id, _text(result.output, error=not result.ok, structured=result.__dict__))
        if "elicitation" not in (meta.get(META_CAPS) or {}):
            return _ok(req_id, _text("This action needs a person's approval, and this client cannot ask for it "
                                     "(no elicitation capability). Approve it in the incident console.", error=True))
        token = self.signer.issue({"incident": iid, "action": action.id, "command": action.command})
        message = (f"Approve remediation for incident {iid}?\n{action.title}\nCommand: {action.command}\n"
                   f"Risk: {action.risk}; reversible: {'yes' if action.reversible else 'no'}\nWhy: {action.rationale}")
        return _ok(req_id, {"resultType": "input_required", "requestState": token, "inputRequests": {APPROVAL_KEY: {
            "method": "elicitation/create", "params": {"mode": "form", "message": message, "requestedSchema": {
                "type": "object", "properties": {"approve": {"type": "boolean", "title": "Run this command?",
                                                             "default": False}}, "required": ["approve"]}}}}})
