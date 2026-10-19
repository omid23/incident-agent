"""Incident console: investigate, review the diagnosis and evidence, approve remediation. Also serves MCP at /mcp."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from importlib import resources
from pathlib import Path
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from .. import __version__
from ..agent.graph import _context, build_graph, register_snapshot, resume_incident, run_incident
from ..analysis.detectors import pre_existing
from ..entities import Ref
from ..mcp_server import IncidentMCP
from ..snapshot import Snapshot


class IncidentStore:
    """Incidents come from snapshot directories on disk, or from snapshots registered in memory (demo mode)."""

    def __init__(self, root: str | Path | None = None):
        self.root = Path(root) if root else None
        self.memory: dict[str, str] = {}

    def add(self, incident_id: str, snap: Snapshot) -> None:
        self.memory[incident_id] = register_snapshot(snap, f"mem://{incident_id}")

    def paths(self) -> dict[str, str]:
        out = dict(self.memory)
        if self.root and self.root.is_dir():
            for d in sorted(self.root.iterdir()):
                if d.is_dir() and ((d / "k8s" / "objects.json").exists() or any(d.glob("k8s_objects*.tsv"))):
                    out[d.name] = str(d)
        return out


def create_app(store: IncidentStore, llm=None, executor=None, state_db: str | Path = ":memory:") -> Starlette:
    conn = sqlite3.connect(str(state_db), check_same_thread=False)
    graph = build_graph(llm, executor=executor, checkpointer=SqliteSaver(conn))
    threads: dict[str, str] = {}
    lock = threading.Lock()
    mcp = IncidentMCP(store.paths, lambda iid: _context(store.paths()[iid])[2], executor=executor)
    index_html = (resources.files("incident_agent.web") / "index.html").read_text(encoding="utf-8")

    def thread_of(iid: str) -> str | None:
        return threads.get(iid)

    def state_of(iid: str) -> dict:
        tid = thread_of(iid)
        if not tid:
            return {}
        snap = graph.get_state({"configurable": {"thread_id": tid}})
        values = dict(snap.values or {})
        values.pop("messages", None)
        pending = [i.value for i in (snap.interrupts or [])]
        values["pending_approval"] = pending[0] if pending else None
        values["thread_id"] = tid
        return values

    async def home(request: Request) -> Response:
        return HTMLResponse(index_html)

    async def info(request: Request) -> Response:
        return JSONResponse({"version": __version__, "model": getattr(llm, "model", None) if llm else None,
                             "executor": getattr(executor, "name", "dry-run") if executor else "dry-run"})

    async def incidents(request: Request) -> Response:
        rows = []
        for iid, path in store.paths().items():
            snap, engine, _ = await asyncio.to_thread(_context, path)
            st = state_of(iid)
            rows.append({"id": iid, "alerts": len(snap.firing_alerts()), "source": snap.meta.get("source"),
                         "scenario": snap.meta.get("scenario"), "status": st.get("status", "new"),
                         "window_end": snap.meta.get("window_end"),
                         "top_alert": (snap.firing_alerts() or [{}])[0].get("labels", {}).get("alertname")})
        return JSONResponse(rows)

    def _get(iid: str) -> tuple[Snapshot, Any, Any] | None:
        path = store.paths().get(iid)
        return _context(path) if path else None

    async def incident(request: Request) -> Response:
        iid = request.path_params["iid"]
        ctx = await asyncio.to_thread(_get, iid)
        if ctx is None:
            return JSONResponse({"error": f"No incident '{iid}'."}, 404)
        snap, engine, tb = ctx
        alerts = [{"alertname": a["labels"].get("alertname"), "severity": a["labels"].get("severity"),
                   "entity": str(engine.ix.alert_entity(a) or ""), "activeAt": a.get("activeAt"),
                   "pre_existing": pre_existing(engine.ix, a),
                   "summary": (a.get("annotations") or {}).get("summary")} for a in snap.firing_alerts()]
        return JSONResponse({"id": iid, "meta": snap.meta, "stats": snap.stats(), "alerts": alerts,
                             "state": state_of(iid)})

    async def investigate(request: Request) -> Response:
        iid = request.path_params["iid"]
        path = store.paths().get(iid)
        if path is None:
            return JSONResponse({"error": f"No incident '{iid}'."}, 404)
        body = await _json(request)
        mode = body.get("mode") or ("llm" if llm else "rules")
        if mode == "llm" and llm is None:
            return JSONResponse({"error": "No model is configured. Start with --provider anthropic or --provider openai "
                                          "to use the LLM investigator; the rules engine works without one."}, 400)
        with lock:
            tid = f"{iid}:{int(time.time() * 1000)}"
            threads[iid] = tid
        await asyncio.to_thread(run_incident, graph, path, iid, mode, tid)
        return JSONResponse(state_of(iid))

    async def approve(request: Request) -> Response:
        iid = request.path_params["iid"]
        tid = thread_of(iid)
        st = state_of(iid)
        if not tid or not st.get("pending_approval"):
            return JSONResponse({"error": "Nothing is waiting for approval. Investigate the incident first."}, 409)
        body = await _json(request)
        decisions = body.get("decisions")
        if not isinstance(decisions, dict):
            return JSONResponse({"error": "Send {\"decisions\": {\"a1\": \"approve\" | \"reject\"}}."}, 400)
        await asyncio.to_thread(resume_incident, graph, tid, {"decisions": decisions})
        return JSONResponse(state_of(iid))

    async def topology(request: Request) -> Response:
        ctx = await asyncio.to_thread(_get, request.path_params["iid"])
        if ctx is None:
            return JSONResponse({"error": "No such incident."}, 404)
        snap, engine, _ = ctx
        st = state_of(request.path_params["iid"])
        roots = {rc["entity"] for rc in (st.get("diagnosis") or {}).get("root_causes", [])}
        alerted = {str(engine.ix.alert_entity(a)) for a in snap.firing_alerts() if not pre_existing(engine.ix, a)}
        nodes: dict[str, dict] = {}
        merged: dict[tuple[str, str], dict] = {}

        def node(ref: Ref) -> str:
            """One node per application component: a Service is drawn as the workload behind it."""
            ids = {str(ref)}
            if ref.kind == "Service":
                backends = engine.ix.service_backends.get(ref) or []
                if len(backends) == 1:
                    ids.add(str(backends[0]))
                    ref = backends[0]
            else:
                ids |= {str(s) for s in engine.ix.services_of.get(ref, [])}
            key = str(ref)
            n = nodes.setdefault(key, {"id": key, "label": ref.name, "kind": ref.kind, "namespace": ref.namespace,
                                       "missing": ref not in snap.by_ref, "root": False, "alerted": False,
                                       "members": []})
            n["members"] = sorted(set(n["members"]) | ids)
            n["root"] = n["root"] or bool(ids & roots)
            n["alerted"] = n["alerted"] or bool(ids & alerted)
            cause, symptom = engine.score(ref)
            n["cause"], n["symptom"] = round(cause, 2), round(symptom, 2)
            return key

        for (caller, callee), e in engine.ix.call_edges.items():
            if not e.calls:
                continue
            a, b = node(caller), node(callee)
            m = merged.setdefault((a, b), {"from": a, "to": b, "calls": 0, "errors": 0})
            m["calls"] += e.calls
            m["errors"] += e.errors
        edges = [{**m, "error_rate": round(m["errors"] / m["calls"], 3)} for m in merged.values()]
        for r in roots:
            try:
                node(Ref.parse(r))
            except ValueError:
                pass
        return JSONResponse({"nodes": list(nodes.values()), "edges": edges})

    async def resource(request: Request) -> Response:
        ctx = await asyncio.to_thread(_get, request.path_params["iid"])
        if ctx is None:
            return JSONResponse({"error": "No such incident."}, 404)
        entity = request.query_params.get("entity", "")
        _, _, tb = ctx
        text, err = await asyncio.to_thread(tb.call, "get_resource", {"entity": entity})
        events, _ = await asyncio.to_thread(tb.call, "get_events", {"entity": entity})
        findings, _ = await asyncio.to_thread(tb.call, "find_anomalies", {"entity": entity})
        return JSONResponse({"entity": entity, "yaml": text, "events": events, "findings": findings}, 400 if err else 200)

    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    return Starlette(routes=[
        Route("/", home), Route("/api/info", info), Route("/api/incidents", incidents),
        Route("/api/incidents/{iid}", incident), Route("/api/incidents/{iid}/investigate", investigate, methods=["POST"]),
        Route("/api/incidents/{iid}/approve", approve, methods=["POST"]),
        Route("/api/incidents/{iid}/topology", topology), Route("/api/incidents/{iid}/resource", resource),
        Route("/mcp", mcp.handle, methods=["POST"]), Route("/healthz", healthz),
    ])


async def _json(request: Request) -> dict:
    try:
        data = await request.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}
