"""Read ITBench snapshots (ITBench-Lite and ITBench-AA on Hugging Face).

A scenario directory holds TSV exports written by ITBench's ClickHouse recorder
(``components/recorders/clickhouse``, Go encoding/csv with a tab delimiter) plus Prometheus alert snapshots::

    Scenario-N/
      alerts/alerts_at_<timestamp>.json   firing alerts: [{labels, annotations, state, value}]
      k8s_objects_raw.tsv                 OpenTelemetry k8sobjects rows; Body is the object JSON
      k8s_events_raw.tsv                  Kubernetes events; Body is the event JSON
      otel_logs_raw.tsv                   OpenTelemetry logs table
      otel_traces_raw.tsv                 Jaeger ``spans`` table
      metrics*/                           per-pod / per-service metric TSVs
      ground_truth.yaml

The "lite" exports (``k8s_objects.tsv``, ``otel_logs.tsv``, ``otel_traces.tsv``) are read too.
Column names are matched case-insensitively against the names the recorder's queries use. The
recorder writes Go-formatted values (``map[k:v ...]`` for ClickHouse maps), which are parsed here.

This adapter was written from the recorder source, not tested against the 31 GB dataset; run
``incident-agent itbench-check`` on a downloaded scenario to see what it reads.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from .entities import Ref
from .eval.groundtruth import GroundTruth, parse_ground_truth
from .snapshot import Snapshot, iso, parse_time

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def parse_map(value: str) -> dict[str, str]:
    """ClickHouse Map values as JSON, Python-dict text, or Go's ``map[k:v k2:v2]`` formatting."""
    v = (value or "").strip()
    if not v or v in ("{}", "map[]"):
        return {}
    if v.startswith("{"):
        try:
            return {str(k): str(x) for k, x in json.loads(v).items()}
        except json.JSONDecodeError:
            try:
                return {str(k): str(x) for k, x in json.loads(v.replace("'", '"')).items()}
            except json.JSONDecodeError:
                return {}
    if v.startswith("map[") and v.endswith("]"):
        body = v[4:-1]
        out: dict[str, str] = {}
        # Keys never contain spaces; values may. Split on " key:" boundaries.
        for m in re.finditer(r"(?:^|\s)([\w./-]+):(.*?)(?=\s[\w./-]+:|$)", body):
            out[m.group(1)] = m.group(2)
        return out
    return {}


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")  # Go encoding/csv: RFC 4180 quoting
        header = next(reader, None)
        if not header:
            return []
        keys = [h.strip() for h in header]
        return [dict(zip(keys, row, strict=False)) for row in reader if row]


def _get(row: dict[str, str], *names: str) -> str:
    lower = {k.lower(): v for k, v in row.items()}
    for n in names:
        if n.lower() in lower and lower[n.lower()] != "":
            return lower[n.lower()]
    return ""


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def _unwrap(body: Any) -> dict | None:
    """k8sobjects in watch mode wraps objects as {type, object}."""
    if isinstance(body, dict) and isinstance(body.get("object"), dict) and "kind" in body["object"]:
        return body["object"]
    return body if isinstance(body, dict) and body.get("kind") else None


def _first(root: Path, *names: str) -> Path:
    for n in names:
        for candidate in (root / n, root / "raw" / n, root / "lite" / n):
            if candidate.exists():
                return candidate
    return root / names[0]


def load_objects(root: Path) -> list[dict]:
    latest: dict[Ref, tuple[float, dict]] = {}
    deleted: dict[Ref, float] = {}
    for row in _rows(_first(root, "k8s_objects_raw.tsv", "k8s_objects.tsv")):
        body = _json(_get(row, "Body", "body"))
        obj = _unwrap(body)
        if obj is None:
            continue
        t = parse_time(_get(row, "Timestamp", "timestamp")) or 0.0
        ref = Ref.of(obj)
        if isinstance(body, dict) and body.get("type") == "DELETED":
            deleted[ref] = max(t, deleted.get(ref, 0.0))
            continue
        if ref not in latest or t >= latest[ref][0]:
            latest[ref] = (t, obj)
    return [o for ref, (t, o) in sorted(latest.items()) if deleted.get(ref, -1) < t]


def load_events(root: Path) -> list[dict]:
    out = []
    for row in _rows(_first(root, "k8s_events_raw.tsv", "k8s_events.tsv")):
        ev = _unwrap(_json(_get(row, "Body", "body"))) or _json(_get(row, "Body", "body"))
        if not isinstance(ev, dict):
            continue
        if "involvedObject" not in ev and "regarding" in ev:  # events.k8s.io/v1
            ev["involvedObject"] = ev["regarding"]
            ev.setdefault("message", ev.get("note", ""))
        ts = _get(row, "Timestamp", "timestamp")
        ev.setdefault("lastTimestamp", ev.get("eventTime") or ts)
        ev.setdefault("firstTimestamp", ev.get("lastTimestamp"))
        out.append(ev)
    return out


def load_logs(root: Path) -> list[dict]:
    out = []
    for row in _rows(_first(root, "otel_logs_raw.tsv", "otel_logs.tsv")):
        res = parse_map(_get(row, "ResourceAttributes", "resource_attributes"))
        out.append({"timestamp": _get(row, "Timestamp", "timestamp"),
                    "service": _get(row, "ServiceName", "service_name") or res.get("service.name", ""),
                    "namespace": res.get("k8s.namespace.name", ""), "pod": res.get("k8s.pod.name", ""),
                    "severity": (_get(row, "SeverityText", "severity_text") or "").upper(),
                    "severity_number": int(_get(row, "SeverityNumber", "severity_number") or 0),
                    "body": _get(row, "Body", "body"), "trace_id": _get(row, "TraceId", "trace_id")})
    return out


_KIND = {"client": "CLIENT", "server": "SERVER", "producer": "PRODUCER", "consumer": "CONSUMER", "internal": "INTERNAL"}


def load_spans(root: Path) -> list[dict]:
    rows = _rows(_first(root, "otel_traces_raw.tsv", "otel_traces.tsv"))
    durations = [float(_get(r, "duration", "Duration") or 0) for r in rows[:500]]
    scale = 1e-6 if durations and sorted(durations)[len(durations) // 2] > 1e5 else 1e-3  # ns or us -> ms
    out = []
    for r in rows:
        attrs = parse_map(_get(r, "SpanAttributes", "attributes", "span_attributes", "tags"))
        res = parse_map(_get(r, "ResourceAttributes", "resource_attributes"))
        kind = _get(r, "SpanKind", "span_kind", "kind").lower().replace("span_kind_", "")
        status = _get(r, "StatusCode", "status_code").lower()
        host = attrs.get("server.address") or attrs.get("net.peer.name") or attrs.get("peer.service") or \
            attrs.get("rpc.service", "").split(".")[-1].lower() or ""
        start = parse_time(_get(r, "Timestamp", "start_time", "timestamp")) or 0.0
        out.append({"trace_id": _get(r, "TraceId", "trace_id"), "span_id": _get(r, "SpanId", "span_id", "id"),
                    "parent_span_id": _get(r, "ParentSpanId", "parent_span_id"),
                    "service": _get(r, "ServiceName", "service_name"), "namespace": res.get("k8s.namespace.name", ""),
                    "name": _get(r, "SpanName", "span_name", "name"), "kind": _KIND.get(kind, kind.upper()),
                    "start": start, "duration_ms": float(_get(r, "Duration", "duration") or 0) * scale,
                    "status": "ERROR" if "error" in status else "OK",
                    "status_message": _get(r, "StatusMessage", "status_message"),
                    "attributes": {"server.address": host} if host else {}})
    return out


def load_alerts(root: Path) -> list[dict]:
    files = sorted((root / "alerts").glob("*.json")) if (root / "alerts").is_dir() else []
    first_seen: dict[str, str] = {}
    latest: list[dict] = []
    for f in files:
        data = _json(f.read_text(encoding="utf-8")) or []
        if isinstance(data, dict):
            data = data.get("data", {}).get("alerts", data.get("alerts", []))
        m = re.search(r"(\d{4}-\d{2}-\d{2}T[\d:.-]+Z?|\d{10,})", f.stem)
        ts = m.group(1) if m else ""
        for a in data:
            key = json.dumps(a.get("labels", {}), sort_keys=True)
            first_seen.setdefault(key, a.get("activeAt") or ts)
        latest = data
    out = []
    for a in latest:
        key = json.dumps(a.get("labels", {}), sort_keys=True)
        out.append({"labels": a.get("labels", {}), "annotations": a.get("annotations", {}),
                    "state": a.get("state") or "firing", "value": a.get("value", ""),
                    "activeAt": a.get("activeAt") or _normalise_ts(first_seen.get(key, ""))})
    return out


def _normalise_ts(ts: str) -> str:
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})(.*)", ts)
    t = parse_time(f"{m.group(1)}T{m.group(2)}:{m.group(3)}:{m.group(4)}{m.group(5)}" if m else ts)
    return iso(t) if t else ts


def load_metrics(root: Path) -> list[dict]:
    out = []
    for d in [p for p in root.iterdir() if p.is_dir() and p.name.startswith("metrics")]:
        for f in sorted(d.rglob("*.tsv")):
            subject = re.sub(r"_raw$", "", f.stem)
            label_key, _, label_val = subject.partition("_")
            series: dict[tuple, dict] = {}
            for row in _rows(f):
                name = _get(row, "metric_name", "__name__", "name", "metric")
                t = parse_time(_get(row, "timestamp", "unix_milli", "ts", "time"))
                try:
                    v = float(_get(row, "value", "val"))
                except ValueError:
                    continue
                if not name or t is None:
                    continue
                k = (name,)
                s = series.setdefault(k, {"name": name, "labels": {label_key: label_val}, "points": []})
                s["points"].append([t, v])
            out.extend(series.values())
    return out


def load_itbench_snapshot(root: str | Path) -> Snapshot:
    root = Path(root)
    objects = load_objects(root)
    events = load_events(root)
    logs, spans, alerts, metrics = load_logs(root), load_spans(root), load_alerts(root), load_metrics(root)
    times = [s["start"] for s in spans] + [parse_time(r["timestamp"]) or 0 for r in logs]
    times = [t for t in times if t]
    meta = {"source": "itbench", "path": str(root)}
    if times:
        meta.update(window_start=iso(min(times)), window_end=iso(max(times)))
    return Snapshot(root.name, objects, events, alerts, logs, spans, metrics, meta)


def load_itbench_ground_truth(root: str | Path) -> GroundTruth | None:
    path = Path(root) / "ground_truth.yaml"
    if not path.exists():
        return None
    return parse_ground_truth(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, Path(root).name)


def export_itbench(snap: Snapshot, root: str | Path) -> Path:
    """Write a snapshot in the ITBench layout (used to test the reader, and to share synthetic scenarios)."""
    root = Path(root)
    (root / "alerts").mkdir(parents=True, exist_ok=True)

    def write(name: str, header: list[str], rows: list[list[Any]]) -> None:
        with open(root / name, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, delimiter="\t", lineterminator="\n")
            w.writerow(header)
            for r in rows:
                w.writerow([str(x) for x in r])

    def gomap(d: dict) -> str:
        return "map[" + " ".join(f"{k}:{v}" for k, v in d.items()) + "]"

    end = snap.meta.get("window_end", "")
    write("k8s_objects_raw.tsv", ["Timestamp", "Body", "ResourceAttributes", "LogAttributes"],
          [[end, json.dumps(o), gomap({"k8s.namespace.name": o["metadata"].get("namespace", "")}),
            gomap({"k8s.resource.name": o.get("kind", "").lower() + "s"})] for o in snap.objects])
    write("k8s_events_raw.tsv", ["Timestamp", "Body", "ResourceAttributes"],
          [[e.get("lastTimestamp", ""), json.dumps(e), gomap({"k8s.namespace.name": e["metadata"].get("namespace", "")})]
           for e in snap.events])
    write("otel_logs_raw.tsv", ["Timestamp", "TraceId", "SpanId", "SeverityText", "SeverityNumber", "ServiceName", "Body",
                                "ResourceAttributes", "LogAttributes"],
          [[r["timestamp"], r.get("trace_id", ""), "", r["severity"], {"ERROR": 17, "WARN": 13}.get(r["severity"], 9),
            r["service"], r["body"], gomap({"k8s.namespace.name": r.get("namespace", ""), "k8s.pod.name": r.get("pod", "")}),
            "map[]"] for r in snap.logs])
    write("otel_traces_raw.tsv", ["start_time", "trace_id", "id", "parent_span_id", "name", "kind", "service_name",
                                  "duration", "status_code", "status_message", "attributes", "ResourceAttributes"],
          [[iso(s["start"]).replace("Z", "") + f".{int((s['start'] % 1) * 1e6):06d}", s["trace_id"], s["span_id"],
            s["parent_span_id"], s["name"], "SPAN_KIND_" + s["kind"], s["service"], int(s["duration_ms"] * 1e6),
            "STATUS_CODE_ERROR" if s["status"] == "ERROR" else "STATUS_CODE_UNSET", s["status_message"],
            json.dumps(s.get("attributes") or {}), gomap({"k8s.namespace.name": s.get("namespace", "")})]
           for s in snap.spans])
    # One file per evaluation time, as the Prometheus recorder writes them; alerts appear once active.
    times = sorted({a.get("activeAt", end) for a in snap.alerts} | {end})
    for ts in times:
        firing = [{k: a[k] for k in ("labels", "annotations", "state", "value")} for a in snap.alerts
                  if (parse_time(a.get("activeAt", end)) or 0) <= (parse_time(ts) or 0)]
        (root / "alerts" / f"alerts_at_{ts.replace(':', '-')}.json").write_text(json.dumps(firing), encoding="utf-8")
    return root
