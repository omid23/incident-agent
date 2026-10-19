"""ITBench-AA scoring, done deterministically.

Per run: if any ground-truth root cause is missed the run scores 0; otherwise it scores precision
(true positives / predicted entities), so every extra entity costs points. ITBench-AA's grader is an
LLM judge that maps names to ground truth and honours alias groups; here the mapping is exact.

Two matching modes:

* ``strict``     kind, namespace and name must match a root cause (or one of its listed aliases)
* ``component``  Pods, ReplicaSets, Deployments, StatefulSets and the Services in front of them count as one
                 application component, which is how the judge's "semantic grouping" treats them
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities import WORKLOAD_KINDS, Ref
from ..snapshot import Snapshot
from .groundtruth import GroundTruth, GTEntity

COMPONENT_KINDS = set(WORKLOAD_KINDS) | {"Pod", "ReplicaSet", "Service"}


@dataclass
class Score:
    recall: float
    precision: float
    itbench: float  # precision at full recall
    f1: float
    tp: int
    fp: int
    missed: list[str]
    false_positives: list[str]

    def to_dict(self) -> dict:
        return {"recall": round(self.recall, 3), "precision": round(self.precision, 3),
                "itbench": round(self.itbench, 3), "f1": round(self.f1, 3), "tp": self.tp, "fp": self.fp,
                "missed": self.missed, "false_positives": self.false_positives}


class ComponentKey:
    """Maps entities to their application component using the snapshot's ownership and Service routing."""

    def __init__(self, snap: Snapshot | None):
        self.ix = None
        if snap is not None:
            from ..analysis.index import ClusterIndex

            self.ix = ClusterIndex(snap)

    def __call__(self, ref: Ref) -> tuple[str, str] | None:
        if ref.kind not in COMPONENT_KINDS:
            return None
        if self.ix is not None:
            if ref.kind in ("Pod", "ReplicaSet"):
                w = self.ix.workload_of(ref)
                if w != ref:
                    return (w.namespace, w.name)
            if ref.kind == "Service":
                backends = self.ix.service_backends.get(ref) or []
                if len(backends) == 1:
                    return (backends[0].namespace, backends[0].name)
        name = ref.name
        if ref.kind in ("Pod", "ReplicaSet"):
            parts = name.split("-")
            name = "-".join(parts[:-2] if ref.kind == "Pod" and len(parts) > 2 else parts[:-1]) or name
        return (ref.namespace, name)


def _matches(gt: GroundTruth, ent: GTEntity, pred: Ref, mode: str, key: ComponentKey) -> bool:
    for alias in gt.aliases_of(ent):
        if alias.matches(pred):
            return True
        if mode == "component" and alias.name is not None:
            a = Ref(alias.namespace or pred.namespace, alias.kind, alias.name)
            ka, kp = key(a), key(pred)
            if ka is not None and ka == kp:
                return True
    return False


def score(predicted: list[str], gt: GroundTruth, mode: str = "strict", snap: Snapshot | None = None) -> Score:
    key = ComponentKey(snap) if mode == "component" else ComponentKey(None)
    preds: list[Ref] = []
    for p in predicted:
        try:
            r = Ref.parse(p)
        except ValueError:
            continue
        if r not in preds:
            preds.append(r)
    roots = gt.root_causes
    # Alias groups count once: drop root causes that are aliases of an earlier one.
    unique: list[GTEntity] = []
    for e in roots:
        if not any(e in gt.aliases_of(u) for u in unique):
            unique.append(e)
    matched = [e for e in unique if any(_matches(gt, e, p, mode, key) for p in preds)]
    tp_preds = [p for p in preds if any(_matches(gt, e, p, mode, key) for e in roots)]
    recall = len(matched) / len(unique) if unique else 1.0
    precision = len(tp_preds) / len(preds) if preds else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return Score(recall, precision, precision if recall == 1.0 and preds else 0.0, f1, len(tp_preds),
                 len(preds) - len(tp_preds), [e.label for e in unique if e not in matched],
                 [str(p) for p in preds if p not in tp_preds])
