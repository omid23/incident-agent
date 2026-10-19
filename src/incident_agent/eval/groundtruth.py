"""ITBench ground truth in both published shapes.

* Library format (``itbench-hub/ITBench/library/scenarios/<id>/ground_truth.yaml``)::

      alerts: [{name: KubePodNotReady}]
      entities: [{apiVersion: apps/v1, kind: Deployment, name: checkout, namespace: otel-demo}]
      solutions: [...]

* Snapshot format (ITBench-Lite / ITBench-AA ``ground_truth.yaml``)::

      groups: [{id: checkout-deployment-1, kind: Deployment, namespace: otel-demo,
                filter: ["checkout\\b"], root_cause: true}, ...]
      aliases: [[checkout-deployment-1, checkout-service-1], ...]
      propagations: [{source: ..., target: ..., condition: ..., effect: ...}]
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..entities import Ref, canonical_kind


@dataclass
class GTEntity:
    id: str
    kind: str
    namespace: str | None = None
    name: str | None = None
    filters: list[str] = field(default_factory=list)
    root_cause: bool = False

    def matches(self, ref: Ref) -> bool:
        if canonical_kind(self.kind).lower() != ref.kind.lower():
            return False
        if self.namespace and ref.namespace and self.namespace != ref.namespace:
            return False
        if self.name is not None:
            return self.name == ref.name
        return any(re.search(f, ref.name) for f in self.filters) if self.filters else False

    @property
    def label(self) -> str:
        if self.name is not None:
            return str(Ref(self.namespace or "", canonical_kind(self.kind), self.name))
        return f"{self.namespace or '*'}/{canonical_kind(self.kind)}/~{'|'.join(self.filters)}"


@dataclass
class GroundTruth:
    scenario_id: str
    entities: list[GTEntity]
    alias_groups: list[list[str]] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    propagations: list[dict] = field(default_factory=list)
    solutions: list = field(default_factory=list)

    @property
    def root_causes(self) -> list[GTEntity]:
        return [e for e in self.entities if e.root_cause]

    def aliases_of(self, entity: GTEntity) -> list[GTEntity]:
        by_id = {e.id: e for e in self.entities}
        out = [entity]
        for group in self.alias_groups:
            if entity.id in group:
                out += [by_id[i] for i in group if i in by_id and by_id[i] is not entity]
        return out


def parse_ground_truth(data: dict, scenario_id: str) -> GroundTruth:
    if "groups" in data:
        ents = []
        for g in data.get("groups") or []:
            filt = g.get("filter") or []
            ents.append(GTEntity(str(g.get("id")), g.get("kind", ""), g.get("namespace"), g.get("name"),
                                 [filt] if isinstance(filt, str) else list(filt), bool(g.get("root_cause"))))
        return GroundTruth(scenario_id, ents, [list(map(str, a)) for a in data.get("aliases") or []],
                           [a.get("name") if isinstance(a, dict) else str(a) for a in data.get("alerts") or []],
                           data.get("propagations") or [], data.get("solutions") or [])
    ents = []
    for i, e in enumerate(data.get("entities") or []):
        md = e.get("metadata") or {}
        name, ns = e.get("name") or md.get("name"), e.get("namespace") or md.get("namespace") or ""
        kind = canonical_kind(e.get("kind", ""))
        ents.append(GTEntity(f"rc-{i}", kind, ns or None, name, root_cause=True))
    alerts = [a.get("name") if isinstance(a, dict) else str(a) for a in data.get("alerts") or []]
    return GroundTruth(scenario_id, ents, [], alerts, [], data.get("solutions") or [])


def load_ground_truth(path: str | Path, scenario_id: str | None = None) -> GroundTruth:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return parse_ground_truth(data, scenario_id or path.parent.name)
