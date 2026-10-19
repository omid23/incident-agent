"""Evaluation: the agent and three baselines on the ITBench scenarios, scored the ITBench-AA way.

Baselines show what the problem looks like without causal reasoning:

* ``alert targets``    blame whatever the alerts fire on (what a tired on-call engineer does first)
* ``error origin``     follow traces to where failed requests start, ignore configuration
* ``every anomaly``    report every entity with evidence of a defect, without separating causes from noise
"""

from __future__ import annotations

import json
import statistics
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from ..analysis.rca import RCAEngine
from ..snapshot import Snapshot
from .groundtruth import GroundTruth
from .scoring import score


def baseline_alert_targets(snap: Snapshot) -> list[str]:
    eng = RCAEngine(snap)
    out = []
    for a in snap.firing_alerts():
        ent = eng.ix.alert_entity(a)
        if ent and str(ent) not in out:
            out.append(str(ent))
    return out


def baseline_error_origin(snap: Snapshot) -> list[str]:
    eng = RCAEngine(snap)
    origins = [f for f in eng.findings if f.signal in ("error_origin", "latency_origin")]
    if origins:
        best = max(origins, key=lambda f: f.weight)
        return [str(eng._prefer_workload(best.entity))]
    return baseline_alert_targets(snap)[:1]


def baseline_every_anomaly(snap: Snapshot) -> list[str]:
    eng = RCAEngine(snap)
    return [str(r) for r in sorted({f.entity for f in eng.findings if f.role == "defect"})]


def rules_agent(snap: Snapshot) -> list[str]:
    return RCAEngine(snap).diagnose().entities()


@dataclass
class Method:
    name: str
    predict: Callable[[Snapshot], list[str] | tuple[list[str], dict]]
    workers: int = 1


Case = tuple[str, int, Callable[[], tuple[Snapshot, GroundTruth]], str]  # (scenario, repeat, loader, split)


def run(cases: list[Case], methods: list[Method], workers: int = 1) -> dict:
    """Each snapshot is built once and given to every method."""
    def one_case(case: Case) -> list[dict]:
        sid, rep, load, split = case
        snap, gt = load()
        out = []
        for m in methods:
            t = time.perf_counter()
            res = m.predict(snap)
            pred, extra = (res if isinstance(res, tuple) else (res, {}))
            ms = (time.perf_counter() - t) * 1000
            s_strict, s_comp = score(pred, gt, "strict", snap), score(pred, gt, "component", snap)
            out.append({"method": m.name, "scenario": sid, "repeat": rep, "split": split, "predicted": pred,
                        "ground_truth": [e.label for e in gt.root_causes], "strict": s_strict.to_dict(),
                        "component": s_comp.to_dict(), "latency_ms": round(ms, 1), **extra})
        return out

    workers = max([workers] + [m.workers for m in methods])
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        rows = [r for rs in pool.map(one_case, cases) for r in rs]
    return {"rows": rows, "summary": summarize(rows)}


def summarize(rows: list[dict]) -> dict:
    out: dict = {}
    for r in rows:
        out.setdefault(r["method"], {}).setdefault(r["split"], []).append(r)
    summary: dict = {}
    for method, splits in out.items():
        summary[method] = {}
        for split, rs in sorted(splits.items()):
            summary[method][split] = _agg(rs)
        summary[method]["all"] = _agg([r for rs in splits.values() for r in rs])
    return summary


def _agg(rs: list[dict]) -> dict:
    def mean(key: str, mode: str) -> float:
        return round(statistics.mean(r[mode][key] for r in rs), 3) if rs else 0.0

    per_scenario: dict[str, list[float]] = {}
    for r in rs:
        per_scenario.setdefault(r["scenario"], []).append(r["strict"]["itbench"])
    return {"runs": len(rs), "scenarios": len(per_scenario),
            "itbench_strict": mean("itbench", "strict"), "itbench_component": mean("itbench", "component"),
            "recall_strict": mean("recall", "strict"), "precision_strict": mean("precision", "strict"),
            "full_recall_rate": round(sum(r["strict"]["recall"] == 1 for r in rs) / len(rs), 3) if rs else 0,
            "mean_entities": round(statistics.mean(len(r["predicted"]) for r in rs), 2) if rs else 0,
            "latency_p50_ms": round(statistics.median(r["latency_ms"] for r in rs), 1) if rs else 0,
            "solved_scenarios": sum(1 for v in per_scenario.values() if statistics.mean(v) == 1.0)}


def synthetic_cases(split: str = "all", repeats: int = 3) -> list[Case]:
    from ..simulate.scenarios import build, load_specs

    cases: list[Case] = []
    for sid, spec in load_specs().items():
        if split != "all" and spec.split != split:
            continue
        for rep in range(repeats):
            cases.append((sid, rep, lambda sid=sid, rep=rep: build(sid, rep), spec.split))
    return cases


def itbench_cases(root: str | Path) -> list[Case]:
    """Scenario directories of a downloaded ITBench-Lite / ITBench-AA snapshot set."""
    from ..itbench import load_itbench_ground_truth, load_itbench_snapshot

    cases: list[Case] = []
    for d in sorted(p for p in Path(root).rglob("ground_truth.yaml")):
        scen = d.parent

        def load(scen: Path = scen):
            return load_itbench_snapshot(scen), load_itbench_ground_truth(scen)

        cases.append((scen.name, 0, load, "itbench"))
    return cases


def to_markdown(report: dict, title: str, order: list[str] | None = None) -> str:
    s = report["summary"]
    methods = order or list(s)
    splits = [k for k in ("dev", "test", "itbench", "all") if any(k in s[m] for m in methods)]
    lines = [f"# {title}", "",
             "ITBench-AA scoring: a run scores 0 if any ground-truth root cause is missed, otherwise its precision. "
             "`strict` needs the exact kind and name; `component` lets a Deployment, its Pods and its Service stand for "
             "each other, as the ITBench judge's semantic grouping does.", ""]
    for split in splits:
        n = next((s[m][split]["runs"] for m in methods if split in s[m]), 0)
        sc = next((s[m][split]["scenarios"] for m in methods if split in s[m]), 0)
        lines += [f"## {split} ({sc} scenarios, {n} runs)", "",
                  "| method | ITBench score (strict) | ITBench score (component) | all root causes found | precision | "
                  "entities / run | scenarios solved | p50 latency |",
                  "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for m in methods:
            if split not in s[m]:
                continue
            a = s[m][split]
            lines.append(f"| {m} | {a['itbench_strict']:.3f} | {a['itbench_component']:.3f} | {a['full_recall_rate']:.0%} | "
                         f"{a['precision_strict']:.2f} | {a['mean_entities']} | {a['solved_scenarios']}/{a['scenarios']} | "
                         f"{a['latency_p50_ms']:.0f} ms |")
        lines.append("")
    return "\n".join(lines)


def per_scenario_markdown(report: dict, method: str) -> str:
    rows = [r for r in report["rows"] if r["method"] == method]
    by: dict[str, list[dict]] = {}
    for r in rows:
        by.setdefault(r["scenario"], []).append(r)
    lines = [f"## Per scenario: {method}", "", "| scenario | split | ground truth | prediction (first run) | strict | component |",
             "|---|---|---|---|---:|---:|"]
    for sid, rs in sorted(by.items(), key=lambda kv: (kv[1][0]["split"], int(kv[0]) if kv[0].isdigit() else 0, kv[0])):
        st = statistics.mean(r["strict"]["itbench"] for r in rs)
        co = statistics.mean(r["component"]["itbench"] for r in rs)
        lines.append(f"| {sid} | {rs[0]['split']} | {', '.join(rs[0]['ground_truth'])} | {', '.join(rs[0]['predicted'])} | "
                     f"{st:.2f} | {co:.2f} |")
    return "\n".join(lines) + "\n"


def dump(report: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(report, indent=1), encoding="utf-8")
