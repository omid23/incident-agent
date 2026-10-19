"""Read-only investigation tools over an incident snapshot.

The same tools serve the LangGraph agent and the MCP server. Outputs are compact text, because
they go into a model's context: every list is capped and long values are truncated.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable
from typing import Any

import yaml

from ..analysis.detectors import template_diff
from ..analysis.index import _template
from ..analysis.rca import RCAEngine
from ..entities import Ref
from ..snapshot import Snapshot, parse_time
from .llm import ToolSpec

MAX_LINES = 60


def _cap(lines: list[str], n: int = MAX_LINES) -> str:
    extra = f"\n... {len(lines) - n} more" if len(lines) > n else ""
    return "\n".join(lines[:n]) + extra


def _strip(obj: dict) -> dict:
    """Drop noisy fields before showing an object to a model."""
    o = json.loads(json.dumps(obj))
    md = o.get("metadata", {})
    for k in ("uid", "resourceVersion", "generation"):
        md.pop(k, None)
    if "managedFields" in md:
        md["managedFields"] = [{"manager": f.get("manager"), "time": f.get("time")} for f in md["managedFields"]][-3:]
    ann = md.get("annotations") or {}
    ann.pop("kubectl.kubernetes.io/last-applied-configuration", None)
    if o.get("kind") == "Secret":
        o["data"] = {k: "<redacted>" for k in (o.get("data") or {})}
    return o


class Toolbox:
    def __init__(self, snap: Snapshot, engine: RCAEngine | None = None):
        self.snap = snap
        self.engine = engine or RCAEngine(snap)
        self.ix = self.engine.ix
        self._handlers: dict[str, Callable[[dict], str]] = {
            "list_alerts": self.list_alerts, "find_anomalies": self.find_anomalies,
            "get_resource": self.get_resource, "list_resources": self.list_resources,
            "get_events": self.get_events, "search_logs": self.search_logs,
            "trace_summary": self.trace_summary, "get_metric": self.get_metric,
            "dependencies": self.dependencies, "rollout_history": self.rollout_history,
        }

    @property
    def specs(self) -> list[ToolSpec]:
        return tool_specs()

    def call(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        handler = self._handlers.get(name)
        if handler is None:
            return f"Unknown tool '{name}'.", True
        try:
            return handler(args or {}), False
        except (KeyError, ValueError, TypeError) as exc:
            return f"Error: {exc}", True

    @staticmethod
    def _specs() -> list[ToolSpec]:
        ent = {"type": "string", "description": "Entity as namespace/Kind/name, e.g. otel-demo/Deployment/cart"}
        return [
            ToolSpec("list_alerts", "Firing alerts with the entity each one is attached to.", {"type": "object", "properties": {}}),
            ToolSpec("find_anomalies", "Evidence found by automatic checks (pod failures, recent changes, broken Services and "
                     "policies, where failed requests start, new error logs, metric shifts). Optionally filter by entity "
                     "or role (defect, change, symptom, context).",
                     {"type": "object", "properties": {"entity": ent, "role": {"type": "string"}}}),
            ToolSpec("get_resource", "A Kubernetes object as YAML (Secrets redacted).",
                     {"type": "object", "properties": {"entity": ent}, "required": ["entity"]}),
            ToolSpec("list_resources", "List objects of a kind, with a one-line status each.",
                     {"type": "object", "properties": {"kind": {"type": "string"}, "namespace": {"type": "string"}},
                      "required": ["kind"]}),
            ToolSpec("get_events", "Kubernetes events, newest last. Filter by entity, reason or type (Warning).",
                     {"type": "object", "properties": {"entity": ent, "reason": {"type": "string"},
                                                       "type": {"type": "string"}}}),
            ToolSpec("search_logs", "Application logs grouped into patterns with counts. Filter by service, severity or text.",
                     {"type": "object", "properties": {"service": {"type": "string"}, "contains": {"type": "string"},
                                                       "severity": {"type": "string"}, "since_incident": {"type": "boolean"}}}),
            ToolSpec("trace_summary", "Calls between services from distributed traces: volume, error rate and the top error "
                     "message per edge. Filter by service.",
                     {"type": "object", "properties": {"service": {"type": "string"}}}),
            ToolSpec("get_metric", "A metric's series summarised before and during the incident.",
                     {"type": "object", "properties": {"name": {"type": "string"}, "label": {"type": "string",
                                                       "description": "label value to filter on, e.g. a service name"}},
                      "required": ["name"]}),
            ToolSpec("dependencies", "What an entity depends on (callees, config, policies, node) and what depends on it.",
                     {"type": "object", "properties": {"entity": ent}, "required": ["entity"]}),
            ToolSpec("rollout_history", "ReplicaSet revisions of a workload and what changed between the last two.",
                     {"type": "object", "properties": {"entity": ent}, "required": ["entity"]}),
        ]

    # -- handlers ------------------------------------------------------------------------------------

    def list_alerts(self, args: dict) -> str:
        rows = []
        for a in self.snap.firing_alerts():
            ent = self.ix.alert_entity(a)
            lbl = {k: v for k, v in a.get("labels", {}).items() if k not in ("alertname", "severity")}
            rows.append(f"{a['labels'].get('alertname')} [{a['labels'].get('severity', '')}] {json.dumps(lbl)} -> "
                        f"{ent or 'unknown entity'} (active since {a.get('activeAt', '?')})")
        return _cap(rows) or "No alerts are firing."

    def find_anomalies(self, args: dict) -> str:
        ent = Ref.parse(args["entity"]) if args.get("entity") else None
        role = args.get("role")
        rows = []
        for f in sorted(self.engine.findings, key=lambda f: (-{"defect": 3, "change": 2, "symptom": 1}.get(f.role, 0),
                                                              -f.weight)):
            if ent and f.entity != ent and ent not in f.related:
                continue
            if role and f.role != role:
                continue
            ev = f" | {f.evidence[0][:160]}" if f.evidence else ""
            rows.append(f"[{f.role} {f.weight:.2f}] {f.entity}: {f.summary}{ev}")
        return _cap(rows, 40) or "No anomalies match."

    def get_resource(self, args: dict) -> str:
        ref = Ref.parse(args["entity"])
        obj = self.snap.get(ref)
        if obj is None:
            similar = [str(r) for r in self.snap.by_ref if r.kind == ref.kind and r.namespace == ref.namespace][:10]
            return f"{ref} does not exist in the snapshot. Existing {ref.kind}s here: {', '.join(similar) or 'none'}"
        text = yaml.safe_dump(_strip(obj), sort_keys=False, width=140)
        return text[:6000] + ("\n... truncated" if len(text) > 6000 else "")

    def list_resources(self, args: dict) -> str:
        from ..entities import canonical_kind

        kind = canonical_kind(args["kind"])
        ns = args.get("namespace")
        rows = []
        for o in self.snap.of_kind(kind, ns):
            rows.append(f"{Ref.of(o)}  {self._status_line(o)}")
        return _cap(rows) or f"No {kind} objects" + (f" in {ns}" if ns else "")

    def _status_line(self, o: dict) -> str:
        kind, st, spec = o.get("kind"), o.get("status", {}), o.get("spec", {})
        if kind == "Pod":
            cs = (st.get("containerStatuses") or [{}])[0]
            waiting = ((cs.get("state") or {}).get("waiting") or {}).get("reason")
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in st.get("conditions", []))
            return f"phase={st.get('phase')} ready={ready} restarts={cs.get('restartCount', 0)}" + \
                (f" waiting={waiting}" if waiting else "") + f" node={spec.get('nodeName', '-')}"
        if kind in ("Deployment", "StatefulSet"):
            return f"replicas={spec.get('replicas')} ready={st.get('readyReplicas', 0)} updated={st.get('updatedReplicas', 0)}"
        if kind == "Service":
            backends = self.ix.service_backends.get(Ref.of(o)) or []
            return f"selector={json.dumps(spec.get('selector'))} ports={[(p.get('port'), p.get('targetPort')) for p in spec.get('ports', [])]} backends={[b.name for b in backends]}"
        if kind == "Node":
            ready = next((c.get("status") for c in st.get("conditions", []) if c.get("type") == "Ready"), "?")
            return f"ready={ready} unschedulable={bool(spec.get('unschedulable'))}"
        md = o.get("metadata", {})
        times = [f.get("time") for f in md.get("managedFields") or []]
        return f"created={md.get('creationTimestamp')} last_modified={max(t for t in times if t) if any(times) else '-'}"

    def get_events(self, args: dict) -> str:
        ref = Ref.parse(args["entity"]) if args.get("entity") else None
        rows = []
        for e in self.snap.events:
            inv = e.get("involvedObject") or {}
            if ref:
                names = {ref.name}
                if ref.kind in ("Deployment", "StatefulSet"):
                    names |= {p["metadata"]["name"] for p in self.ix.pods_by_workload.get(ref, [])}
                    names |= {r["metadata"]["name"] for r in self.ix.replicasets(ref)}
                if inv.get("name") not in names:
                    continue
            if args.get("reason") and e.get("reason") != args["reason"]:
                continue
            if args.get("type") and e.get("type") != args["type"]:
                continue
            rows.append(f"{e.get('lastTimestamp')} {e.get('type')} {e.get('reason')} {inv.get('kind')}/{inv.get('name')} "
                        f"x{e.get('count', 1)}: {e.get('message', '')[:400]}")
        return _cap(rows[-MAX_LINES:]) or "No matching events."

    def search_logs(self, args: dict) -> str:
        from ..analysis.detectors import incident_start

        t0 = incident_start(self.ix) if args.get("since_incident", True) else float("-inf")
        svc, contains = args.get("service"), (args.get("contains") or "").lower()
        sev = (args.get("severity") or "").upper()
        groups: Counter = Counter()
        first: dict[tuple, str] = {}
        sample: dict[tuple, str] = {}
        for row in self.snap.logs:
            t = parse_time(row.get("timestamp")) or 0
            if t < t0:
                continue
            if svc and svc not in (row.get("service") or "") and svc not in (row.get("pod") or ""):
                continue
            if sev and (row.get("severity") or "").upper() != sev:
                continue
            body = str(row.get("body", ""))
            if contains and contains not in body.lower():
                continue
            key = (row.get("service"), row.get("severity"), _template(body))
            groups[key] += 1
            first.setdefault(key, row.get("timestamp", ""))
            sample.setdefault(key, body)
        rows = [f"{n}x {svc_} {sev_} (first {first[(svc_, sev_, tpl)]}): {sample[(svc_, sev_, tpl)][:260]}"
                for (svc_, sev_, tpl), n in groups.most_common(25)]
        return _cap(rows) or "No matching logs."

    def trace_summary(self, args: dict) -> str:
        svc = args.get("service")
        rows = []
        for (caller, callee), e in sorted(self.ix.call_edges.items(), key=lambda kv: -kv[1].errors):
            if not e.calls:
                continue
            if svc and svc not in (caller.name, callee.name):
                continue
            top = max(e.messages.items(), key=lambda kv: kv[1])[0] if e.messages else ""
            top = e.examples.get(top, top)
            exists = "" if callee in self.snap.by_ref else " [Service not found]"
            rows.append(f"{caller.name} -> {callee.name}{exists}: {e.calls} calls, {e.errors} errors "
                        f"({e.errors / e.calls:.0%})" + (f"; callee never answered: {top[:160]}" if top else "")
                        + (f"; {e.answered_errors} errors returned by the callee" if e.answered_errors else ""))
        return _cap(rows, 40) or "No traced calls match."

    def get_metric(self, args: dict) -> str:
        from ..analysis.detectors import incident_start

        t0 = incident_start(self.ix)
        name, label = args["name"], args.get("label")
        rows = []
        for s in self.snap.metrics:
            if s["name"] != name and not re.fullmatch(name.replace("*", ".*"), s["name"]):
                continue
            if label and label not in s.get("labels", {}).values():
                continue
            pts = s.get("points") or []
            b = [v for t, v in pts if t < t0]
            a = [v for t, v in pts if t >= t0]
            fmt = lambda xs: f"median {sorted(xs)[len(xs) // 2]:.4g}, max {max(xs):.4g}" if xs else "no data"  # noqa: E731
            rows.append(f"{s['name']} {json.dumps(s.get('labels', {}))}: before {fmt(b)} | during {fmt(a)}")
        if not rows:
            names = sorted({s["name"] for s in self.snap.metrics})
            return f"No series named {name}. Available: {', '.join(names)[:600]}"
        return _cap(rows, 30)

    def dependencies(self, args: dict) -> str:
        ref = Ref.parse(args["entity"])
        down = self.engine.deps(ref, "errors")
        up = []
        if ref.kind == "Service":
            up = [(c, "called by") for c in self.ix.callers(ref)]
        elif ref.kind in ("Deployment", "StatefulSet", "DaemonSet"):
            up = [(s, "fronted by") for s in self.ix.services_of.get(ref, [])] + \
                 [(c, "called by") for c in self.ix.callers(ref)]
        lines = [f"depends on: {r} ({rel})" for r, rel in down] + [f"used by: {r} ({rel})" for r, rel in up]
        if ref not in self.snap.by_ref:
            lines.insert(0, f"note: {ref} does not exist in the snapshot")
        return _cap(lines) or "No known dependencies."

    def rollout_history(self, args: dict) -> str:
        ref = Ref.parse(args["entity"])
        rss = self.ix.replicasets(ref)
        if not rss:
            return f"{ref} has no ReplicaSets."
        lines = [f"revision {(r['metadata'].get('annotations') or {}).get('deployment.kubernetes.io/revision')} "
                 f"{r['metadata']['name']} created {r['metadata'].get('creationTimestamp')} "
                 f"replicas={r.get('status', {}).get('replicas', 0)} ready={r.get('status', {}).get('readyReplicas', 0)}"
                 for r in rss]
        if len(rss) >= 2:
            diff = template_diff(rss[-2]["spec"]["template"], rss[-1]["spec"]["template"])
            lines.append("changes in the latest revision:")
            lines += [f"  {d[:220]}" for d in diff] or ["  (none)"]
        return _cap(lines)


def tool_specs() -> list[ToolSpec]:
    return Toolbox._specs()
