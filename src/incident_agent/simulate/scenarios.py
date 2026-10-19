"""Incident snapshots for the 30 ITBench SRE scenarios in ``itbench-hub/ITBench/library/scenarios``.

The scenario definitions, fault mechanisms and ground truth are IBM's (Apache-2.0, vendored in
``data/itbench``). The cluster, traffic and telemetry are generated here, because the recorded
ITBench snapshots are distributed through Hugging Face rather than GitHub.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path

import yaml

from ..entities import Ref
from ..eval.groundtruth import GroundTruth, load_ground_truth
from ..snapshot import Snapshot
from .engine import World
from .faults import MECHANISMS, add_noise
from .topology import application


@dataclass
class ScenarioSpec:
    id: str
    applications: list[str]
    faults: list[tuple[str, Ref]]  # (fault id, target)
    autoscaling: bool
    ground_truth: GroundTruth

    @property
    def fault_ids(self) -> list[str]:
        return sorted({f for f, _ in self.faults})

    @property
    def split(self) -> str:
        """Split by fault mechanism, so test scenarios use mechanisms never seen while tuning."""
        key = "+".join(self.fault_ids)
        return "dev" if zlib.crc32(key.encode()) % 2 == 0 else "test"


def _data_dir() -> Path:
    return Path(str(resources.files("incident_agent") / "data" / "itbench"))


@lru_cache(maxsize=1)
def load_specs() -> dict[str, ScenarioSpec]:
    out: dict[str, ScenarioSpec] = {}
    for d in sorted((_data_dir() / "scenarios").iterdir(), key=lambda p: int(p.name)):
        spec = yaml.safe_load((d / "scenario.yaml").read_text(encoding="utf-8"))
        extra = d / "extra_variables.yaml"
        extra_vars = yaml.safe_load(extra.read_text(encoding="utf-8")) if extra.exists() else {}
        faults = []
        for fault in spec.get("faults") or []:
            for inj in fault.get("injections") or []:
                for tgt in inj.get("targets") or []:
                    k = tgt["kubernetes"]
                    faults.append((inj["id"], Ref.parse(f"{k.get('namespace', '')}/{k['kind']}/{k['name']}")))
        if not faults:
            continue
        out[d.name] = ScenarioSpec(
            d.name, [a["id"] for a in spec["environment"]["applications"]], faults,
            bool((extra_vars or {}).get("applications_opentelemetry_demo_kubernetes_autoscaling_enabled")),
            load_ground_truth(d / "ground_truth.yaml", d.name))
    return out


def fault_definition(fault_id: str) -> dict:
    path = _data_dir() / "faults" / f"{fault_id}.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}


def build(scenario_id: str, seed: int = 0) -> tuple[Snapshot, GroundTruth]:
    spec = load_specs()[str(scenario_id)]
    world = World([application(a) for a in spec.applications], seed=zlib.crc32(f"{scenario_id}:{seed}".encode()) % 997,
                  autoscaling=spec.autoscaling, name=f"itbench-{scenario_id}-s{seed}")
    gt_refs = [Ref(e.namespace or "", e.kind, e.name) for e in spec.ground_truth.root_causes if e.name]
    add_noise(world)
    for i, (fault_id, target) in enumerate(spec.faults):
        fn = MECHANISMS.get(fault_id)
        if fn is None:
            raise KeyError(f"no mechanism for fault {fault_id}")
        fn(world, target, gt_refs, world.t_fault + 25 * i)
    world.simulate_traffic()
    snap = world.snapshot()
    snap.meta.update({"scenario": scenario_id, "faults": spec.fault_ids, "split": spec.split,
                      "applications": spec.applications})
    return snap, spec.ground_truth


def scenario_ids(split: str = "all") -> list[str]:
    return [s.id for s in load_specs().values() if split == "all" or s.split == split]
