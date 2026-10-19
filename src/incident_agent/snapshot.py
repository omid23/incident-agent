"""An offline incident snapshot: cluster objects, events, alerts, logs, traces and metrics.

Native layout (written by the simulator and the live collector)::

    meta.json           name, source, window_start, window_end, collected_at
    alerts.json         [{labels, annotations, state, value, activeAt}]
    k8s/objects.json    [Kubernetes objects as returned by `kubectl get -o json`]
    k8s/events.json     [core/v1 Events]
    logs.jsonl          {timestamp, service, namespace, pod, severity, body, trace_id}
    traces.jsonl        {trace_id, span_id, parent_span_id, service, name, kind, start, duration_ms,
                         status, status_message, attributes}
    metrics.jsonl       {name, labels, points: [[unix_ts, value], ...]}

ITBench snapshots (TSV exports) are read by :mod:`incident_agent.itbench`.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .entities import Ref


def parse_time(value: Any) -> float | None:
    """Seconds since the epoch from an ISO timestamp, a ClickHouse timestamp or a number."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1e9 if v > 1e14 else v / 1e3 if v > 1e11 else v
    text = str(value).strip().replace(" ", "T", 1)
    if text.replace(".", "", 1).isdigit():
        return parse_time(float(text))
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:  # trim nanoseconds to microseconds
        head, _, frac = text.partition(".")
        digits = "".join(ch for ch in frac if ch.isdigit())
        rest = frac[len(digits):]
        text = f"{head}.{digits[:6]}{rest}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Snapshot:
    name: str
    objects: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    logs: list[dict] = field(default_factory=list)
    spans: list[dict] = field(default_factory=list)
    metrics: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._by_ref: dict[Ref, dict] | None = None

    # -- lookups ----------------------------------------------------------------------------

    @property
    def by_ref(self) -> dict[Ref, dict]:
        if self._by_ref is None:
            self._by_ref = {Ref.of(o): o for o in self.objects}
        return self._by_ref

    def get(self, ref: Ref | str) -> dict | None:
        return self.by_ref.get(Ref.parse(ref) if isinstance(ref, str) else ref)

    def of_kind(self, kind: str, namespace: str | None = None) -> list[dict]:
        out = [o for r, o in self.by_ref.items() if r.kind == kind and (namespace is None or r.namespace == namespace)]
        return sorted(out, key=lambda o: Ref.of(o))

    def namespaces(self) -> list[str]:
        return sorted({r.namespace for r in self.by_ref if r.namespace})

    @property
    def window(self) -> tuple[float | None, float | None]:
        return parse_time(self.meta.get("window_start")), parse_time(self.meta.get("window_end"))

    def firing_alerts(self) -> list[dict]:
        return [a for a in self.alerts if (a.get("state") or "firing") == "firing"]

    def events_for(self, ref: Ref) -> list[dict]:
        out = []
        for e in self.events:
            inv = e.get("involvedObject") or e.get("regarding") or {}
            if inv.get("name") == ref.name and (inv.get("kind") or ref.kind) == ref.kind and \
                    (inv.get("namespace") or "") == ref.namespace:
                out.append(e)
        return out

    def series(self, name: str, **labels: str) -> list[dict]:
        return [m for m in self.metrics if m["name"] == name and all(m["labels"].get(k) == v for k, v in labels.items())]

    def stats(self) -> dict:
        kinds: dict[str, int] = defaultdict(int)
        for r in self.by_ref:
            kinds[r.kind] += 1
        return {"objects": len(self.objects), "events": len(self.events), "alerts": len(self.firing_alerts()),
                "logs": len(self.logs), "spans": len(self.spans), "metric_series": len(self.metrics),
                "kinds": dict(sorted(kinds.items()))}

    # -- persistence ------------------------------------------------------------------------

    def save(self, root: str | Path) -> Path:
        root = Path(root)
        (root / "k8s").mkdir(parents=True, exist_ok=True)
        (root / "meta.json").write_text(json.dumps({"name": self.name, **self.meta}, indent=1), encoding="utf-8")
        (root / "alerts.json").write_text(json.dumps(self.alerts, indent=1), encoding="utf-8")
        (root / "k8s" / "objects.json").write_text(json.dumps(self.objects), encoding="utf-8")
        (root / "k8s" / "events.json").write_text(json.dumps(self.events), encoding="utf-8")
        for fname, rows in (("logs.jsonl", self.logs), ("traces.jsonl", self.spans), ("metrics.jsonl", self.metrics)):
            with open(root / fname, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, separators=(",", ":")) + "\n")
        return root


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def load_snapshot(path: str | Path) -> Snapshot:
    """Load a native snapshot directory, or an ITBench snapshot (detected by its TSV files)."""
    root = Path(path)
    if not root.is_dir():
        raise FileNotFoundError(f"snapshot directory not found: {root}")
    if (root / "k8s_objects_raw.tsv").exists() or (root / "k8s_objects.tsv").exists() or \
            (root / "lite").is_dir() or (root / "raw").is_dir():
        from .itbench import load_itbench_snapshot

        return load_itbench_snapshot(root)
    if not (root / "k8s" / "objects.json").exists():
        raise ValueError(f"{root} is not a snapshot (no k8s/objects.json and no ITBench TSV files)")
    meta = json.loads((root / "meta.json").read_text(encoding="utf-8")) if (root / "meta.json").exists() else {}
    alerts = json.loads((root / "alerts.json").read_text(encoding="utf-8")) if (root / "alerts.json").exists() else []
    return Snapshot(
        name=meta.pop("name", root.name),
        objects=json.loads((root / "k8s" / "objects.json").read_text(encoding="utf-8")),
        events=json.loads((root / "k8s" / "events.json").read_text(encoding="utf-8"))
        if (root / "k8s" / "events.json").exists() else [],
        alerts=alerts, logs=_jsonl(root / "logs.jsonl"), spans=_jsonl(root / "traces.jsonl"),
        metrics=_jsonl(root / "metrics.jsonl"), meta=meta,
    )
