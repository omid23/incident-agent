"""The incident as a timeline: what changed, then what started failing, then which alerts fired.

On call, the first question after "what is broken" is "what changed just before". The timeline
merges changes (rollouts, edits to config, policy and Services), the first Warning event of each
kind per object, the first occurrence of each new error log pattern, the first failed call on each
service edge, and alert activations. Times are shown relative to the first alert of this incident.

Each change is then ranked as a suspect: changes that landed shortly before the first alert, on an
object the alerts can reach through the dependency graph, rank highest. This is correlation, not
proof, so the ranking is a hint for the investigator; the RCA engine does not use it.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..entities import CLUSTER_SCOPED, Ref, canonical_kind
from ..snapshot import iso, parse_time
from .detectors import incident_start, pre_existing
from .index import _template
from .rca import POD_ALERTS, TRAFFIC_LOSS_ALERTS, RCAEngine

ERROR_SEVERITIES = ("ERROR", "FATAL", "CRITICAL")
SUSPECT_WINDOW_S = 2 * 3600  # changes older than this before the first alert are background
MAX_PER_GROUP = 3  # new log patterns / warning reasons kept per workload


@dataclass
class Entry:
    time: float
    kind: str  # change | warning | error | alert | marker
    summary: str
    entity: Ref | None = None
    detail: list[str] = field(default_factory=list)
    count: int = 1
    tags: list[str] = field(default_factory=list)  # root_cause, on_alert_path, pre_existing, suspect

    def to_dict(self, t0: float | None = None) -> dict:
        out = {"time": iso(self.time), "kind": self.kind, "summary": self.summary,
               "entity": str(self.entity) if self.entity else None, "count": self.count, "tags": self.tags,
               "detail": self.detail[:4]}
        if t0 is not None:
            out["offset_s"] = round(self.time - t0)
        return out


@dataclass
class Suspect:
    entity: Ref
    time: float
    lead_s: float  # seconds before the first alert
    score: float
    summary: str
    reasons: list[str]

    def to_dict(self) -> dict:
        return {"entity": str(self.entity), "time": iso(self.time), "lead_s": round(self.lead_s),
                "score": round(self.score, 2), "summary": self.summary, "reasons": self.reasons}


@dataclass
class Timeline:
    entries: list[Entry]
    suspects: list[Suspect]
    first_alert: float | None  # first alert of this incident (pre-existing alerts excluded)
    incident_start: float
    window: tuple[float, float]

    @property
    def anchor(self) -> float:
        return self.first_alert if self.first_alert is not None else self.incident_start

    def to_dict(self) -> dict:
        return {"anchor": iso(self.anchor), "first_alert": iso(self.first_alert) if self.first_alert else None,
                "incident_start": iso(self.incident_start),
                "window": [iso(self.window[0]), iso(self.window[1])],
                "suspects": [s.to_dict() for s in self.suspects],
                "entries": [e.to_dict(self.anchor) for e in self.entries]}

    def filter(self, entity: Ref | None = None, kinds: set[str] | None = None, since: float | None = None) -> list[Entry]:
        out = []
        for e in self.entries:
            if entity is not None and e.entity != entity:
                continue
            if kinds and e.kind not in kinds:
                continue
            if since is not None and e.time < since:
                continue
            out.append(e)
        return out

    def render(self, entries: list[Entry] | None = None, limit: int = 60, suspects: int = 3) -> list[str]:
        entries = self.entries if entries is None else entries
        lines = []
        if self.first_alert is not None:
            lines.append(f"T0 = first alert of this incident, {iso(self.first_alert)}")
        else:
            lines.append(f"T0 = estimated incident start, {iso(self.incident_start)} (no new alerts)")
        if self.suspects and suspects:
            lines.append("Changes most likely to have triggered it:")
            for s in self.suspects[:suspects]:
                lines.append(f"  {_offset(s.time - self.anchor):>8}  {s.entity}: {s.summary} [{', '.join(s.reasons)}]")
        lines.append("")
        if len(entries) > limit:
            # Changes and root-cause entries first, then alerts; the long tail of downstream errors goes.
            total = len(entries)
            entries = sorted(sorted(entries, key=lambda e: (_priority(e), e.time))[:limit], key=_order)
            lines.append(f"(showing {len(entries)} of {total} entries)")
        for e in entries:
            tags = f" [{', '.join(e.tags)}]" if e.tags else ""
            count = f" x{e.count}" if e.count > 1 else ""
            lines.append(f"{_offset(e.time - self.anchor):>8}  {e.kind:<7} {e.summary}{count}{tags}")
        return lines


def _duration(seconds: float) -> str:
    s = int(round(seconds))
    if s >= 3600:
        return f"{s // 3600}h{s % 3600 // 60:02d}m"
    if s >= 60:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s}s"


def _offset(seconds: float) -> str:
    return f"T{'-' if seconds < 0 else '+'}{_duration(abs(seconds))}"


KIND_ORDER = {"marker": 0, "change": 1, "warning": 2, "error": 3, "alert": 4}


def _order(e: Entry) -> tuple:
    return e.time, KIND_ORDER.get(e.kind, 9), e.summary


def _priority(e: Entry) -> int:
    if e.kind in ("change", "marker") or "root_cause" in e.tags:
        return 0
    return {"alert": 1, "warning": 2}.get(e.kind, 3)


def build_timeline(engine: RCAEngine, roots: Iterable[Ref] | None = None) -> Timeline:
    """Roots are the diagnosed root causes to tag; by default, the rules engine's."""
    ix = engine.ix
    start, end = ix.start, ix.end
    t0 = incident_start(ix)
    roots = set(roots) if roots is not None else {c.entity for c in engine.diagnose().root_causes}
    entries: list[Entry] = [Entry(start, "marker", "snapshot window starts"),
                            Entry(t0, "marker", "estimated incident start"),
                            Entry(end, "marker", "snapshot window ends")]

    # -- alerts, and the entities each new alert can reach ------------------------------------------
    reachable: dict[Ref, int] = defaultdict(int)  # entity -> number of new alerts whose path reaches it
    first_alert = None
    for a in ix.snap.firing_alerts():
        t = parse_time(a.get("activeAt"))
        if t is None:
            continue
        ent = ix.alert_entity(a)
        name = a.get("labels", {}).get("alertname", "")
        old = pre_existing(ix, a)
        tags = ["pre_existing"] if old else []
        if ent in roots:
            tags.append("root_cause")
        entries.append(Entry(t, "alert", f"{name} fires on {ent or 'an unknown entity'}", ent,
                             [s for s in [(a.get("annotations") or {}).get("summary")] if s], tags=tags))
        if old or ent is None:
            continue
        first_alert = t if first_alert is None else min(first_alert, t)
        mode = "pod" if name in POD_ALERTS else "traffic" if name in TRAFFIC_LOSS_ALERTS else "errors"
        for ref in engine.reach(ent, mode):
            reachable[ref] += 1

    def tags_for(ref: Ref | None) -> list[str]:
        if ref is None:
            return []
        return (["root_cause"] if ref in roots else []) + (["on_alert_path"] if ref in reachable else [])

    # -- changes ------------------------------------------------------------------------------------
    changes: list[tuple[Entry, float]] = []
    timed = sorted((f for f in engine.findings if f.role == "change" and f.time is not None), key=lambda f: -f.weight)
    for f in timed:
        if any(e.entity == f.entity and abs(e.time - f.time) <= 10 for e, _ in changes):
            continue  # a rollout is also an edit of the Deployment: keep the more specific finding
        e = Entry(f.time, "change", f.summary, f.entity, list(f.evidence), tags=tags_for(f.entity))
        entries.append(e)
        changes.append((e, f.weight))
    for e in _vanished_services(ix):
        e.tags = tags_for(e.entity) + ["inferred"]
        entries.append(e)
        changes.append((e, 0.45))

    # -- first Warning event per object and reason ----------------------------------------------------
    warnings: dict[tuple[Ref, str], Entry] = {}
    for ev in ix.snap.events:
        if ev.get("type") != "Warning":
            continue
        t = parse_time(ev.get("firstTimestamp") or ev.get("eventTime") or ev.get("lastTimestamp"))
        if t is None or t < start:
            continue  # recurring since before the window: background, not this incident
        inv = ev.get("involvedObject") or ev.get("regarding") or {}
        if not inv.get("kind") or not inv.get("name"):
            continue
        kind = canonical_kind(inv["kind"])
        obj = Ref("" if kind in CLUSTER_SCOPED else inv.get("namespace") or "", kind, inv["name"])
        ref = ix.workload_of(obj)
        key = (ref, ev.get("reason", ""))
        n = int(ev.get("count") or 1)
        if key in warnings:
            w = warnings[key]
            w.count += n
            if t < w.time:
                w.time, w.detail = t, [str(ev.get("message", ""))[:300]]
            continue
        where = ref.name if ref == obj else f"{ref.name} ({obj.kind.lower()} {obj.name})"
        warnings[key] = Entry(t, "warning", f"{ev.get('reason')} on {where}", ref,
                              [str(ev.get("message", ""))[:300]], n, tags_for(ref))
    entries += _top_per_entity(warnings.values())

    # -- first occurrence of each new error log pattern ----------------------------------------------
    before: dict[tuple, int] = defaultdict(int)
    during: dict[tuple, Entry] = {}
    for row in ix.snap.logs:
        if (row.get("severity") or "").upper() not in ERROR_SEVERITIES and (row.get("severity_number") or 0) < 17:
            continue
        t = parse_time(row.get("timestamp"))
        if t is None:
            continue
        w = ix.workload_for_service_name(row.get("service", ""), row.get("namespace"))
        if w is None:
            continue
        body = str(row.get("body", ""))
        key = (w, _template(body))
        if t < t0:
            before[key] += 1
        elif key in during:
            during[key].count += 1
        else:
            during[key] = Entry(t, "error", f"{w.name} logs a new error: {body[:140]}", w, [body[:300]],
                                tags=tags_for(w))
    fresh = [e for key, e in during.items() if before[key] < max(1, e.count / 3)]
    entries += _top_per_entity(fresh)

    # -- first failed call per edge -------------------------------------------------------------------
    for (caller, callee), edge in ix.call_edges.items():
        if not edge.errors or edge.first_error is None:
            continue
        t = parse_time(edge.first_error)
        if t is None or t < t0 - 300:
            continue  # failing since before the incident
        rate = edge.errors / max(1, edge.calls)
        if edge.errors < 3 or rate < 0.05:
            continue
        missing = "" if callee in ix.snap.by_ref else " (Service not found)"
        entries.append(Entry(t, "error", f"calls {caller.name} -> {callee.name}{missing} start failing "
                                         f"({edge.errors}/{edge.calls}, {rate:.0%})", caller,
                             [f"{k}: {edge.examples.get(k, k)[:200]}" for k in list(edge.messages)[:2]],
                             edge.errors, tags_for(callee) or tags_for(caller)))

    entries.sort(key=_order)
    suspects = _suspects(changes, first_alert if first_alert is not None else t0, reachable, roots)
    for e in entries:
        if e.kind == "change" and any(s.entity == e.entity and s.time == e.time for s in suspects[:3]):
            e.tags.append("suspect")
    return Timeline(entries, suspects, first_alert, t0, (start, end))


def _vanished_services(ix) -> list[Entry]:
    """A deleted Service leaves no object behind; its callers show when it went: answered, then unresolvable."""
    missing = {callee for (_, callee), e in ix.call_edges.items()
               if e.errors and callee.kind == "Service" and callee not in ix.snap.by_ref}
    if not missing:
        return []
    calls: dict[Ref, list[tuple[float, bool]]] = defaultdict(list)  # Service -> (start, failed)
    for s in ix.snap.spans:
        attrs = s.get("attributes") or {}
        host = attrs.get("server.address") or attrs.get("peer.service")
        if s.get("kind") != "CLIENT" or not host:
            continue
        caller = ix.workload_for_service_name(s.get("service", ""), s.get("namespace"))
        t = parse_time(s.get("start"))
        if caller is None or t is None:
            continue
        callee = ix.resolve_host(str(host), caller.namespace)
        if callee in missing:
            calls[callee].append((t, s.get("status") == "ERROR"))
    out = []
    for svc, rows in calls.items():
        first_err = min((t for t, failed in rows if failed), default=None)
        last_ok = max((t for t, failed in rows if not failed and first_err is not None and t < first_err), default=None)
        if first_err is None or last_ok is None:
            continue  # never answered in the window: it may never have existed here
        out.append(Entry(first_err, "change", f"Service {svc.name} disappeared: last answered at {iso(last_ok)}, "
                                              f"calls fail from {iso(first_err)} and it is no longer in the cluster",
                         svc, [f"inferred from client spans to {svc.name}"]))
    return out


def _top_per_entity(entries) -> list[Entry]:
    """The earliest few entries per entity: a crash-looping workload should not flood the timeline."""
    by: dict[Ref | None, list[Entry]] = defaultdict(list)
    for e in entries:
        by[e.entity].append(e)
    out = []
    for group in by.values():
        out += sorted(group, key=lambda e: e.time)[:MAX_PER_GROUP]
    return out


def _suspects(changes: list[tuple[Entry, float]], anchor: float, reachable: dict[Ref, int],
              roots: set[Ref]) -> list[Suspect]:
    out = []
    for e, weight in changes:
        lead = anchor - e.time
        if lead < -60 or lead > SUSPECT_WINDOW_S:
            continue  # after the first alert (a reaction, not a trigger), or long before it
        reasons = [f"{_duration(lead)} before the first alert" if lead >= 0 else "as the first alert fired"]
        # Closer in time is more suspicious; decays to ~0.2 at the edge of the window.
        recency = 1.0 / (1.0 + max(lead, 0) / 900)
        score = 0.45 * recency + 0.35 * min(weight / 0.45, 1.0)
        if e.entity in reachable:
            score += 0.2 * min(1.0, reachable[e.entity] / 2)
            reasons.append(f"on the dependency path of {reachable[e.entity]} alert"
                           + ("s" if reachable[e.entity] != 1 else ""))
        else:
            score *= 0.5
            reasons.append("no alert's dependency path reaches it")
        if e.entity in roots:
            reasons.append("diagnosed root cause")
        out.append(Suspect(e.entity, e.time, lead, min(score, 1.0), e.summary, reasons))
    # A change no alert can reach is only a suspect when nothing on an alert's path changed.
    if any(s.entity in reachable for s in out):
        out = [s for s in out if s.entity in reachable]
    best: dict[Ref, Suspect] = {}
    for s in sorted(out, key=lambda s: (-s.score, s.lead_s)):
        best.setdefault(s.entity, s)
    return list(best.values())
