"""Command line: simulate, diagnose, timeline, investigate, serve, eval, collect."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def _llm(args):
    if not getattr(args, "provider", None):
        return None
    from .agent.llm import make_llm

    return make_llm(args.provider, args.model)


def _executor(args):
    from .agent.remediation import DryRunExecutor, KubectlExecutor

    if getattr(args, "execute", False):
        return KubectlExecutor(context=args.context, server_dry_run=not args.no_server_dry_run)
    return DryRunExecutor()


def cmd_scenarios(args) -> None:
    from .simulate.scenarios import load_specs

    for sid, spec in load_specs().items():
        if args.split != "all" and spec.split != args.split:
            continue
        rc = ", ".join(e.label for e in spec.ground_truth.root_causes)
        print(f"{sid:>4}  {spec.split:4}  {'+'.join(spec.fault_ids)[:60]:60}  {rc}")


def cmd_simulate(args) -> None:
    from .itbench import export_itbench
    from .simulate.scenarios import build, scenario_ids

    ids = scenario_ids(args.split) if args.scenario == "all" else [args.scenario]
    out = Path(args.out)
    for sid in ids:
        for seed in range(args.seed, args.seed + args.repeats):
            snap, gt = build(sid, seed)
            target = out / (f"scenario-{sid}" + (f"-s{seed}" if args.repeats > 1 or args.seed else ""))
            if args.itbench_format:
                export_itbench(snap, target)
                (target / "ground_truth.yaml").write_text((Path(__file__).parent / "data" / "itbench" / "scenarios" / sid
                                                           / "ground_truth.yaml").read_text(encoding="utf-8"))
            else:
                snap.save(target)
            print(f"wrote {target} ({snap.stats()['objects']} objects, {len(snap.spans)} spans, "
                  f"{len(snap.firing_alerts())} alerts)")


def cmd_diagnose(args) -> None:
    from .analysis.rca import diagnose
    from .snapshot import load_snapshot

    snap = load_snapshot(args.snapshot)
    d = diagnose(snap)
    if args.itbench_out:
        Path(args.itbench_out).write_text(json.dumps(d.to_itbench(), indent=1), encoding="utf-8")
    if args.json:
        print(json.dumps(d.to_dict(), indent=1))
        return
    print(f"{len(d.alerts)} firing alert(s)")
    for c in d.root_causes:
        print(f"\nROOT CAUSE  {c.entity}\n  {c.reason}")
        for f in c.findings[:3]:
            print(f"  - {f.summary}")
    if d.unexplained_alerts:
        print(f"\nnot explained: {[d.alerts[i]['alertname'] for i in d.unexplained_alerts]}")
    if d.chains:
        print("\npropagation: " + " -> ".join(max(d.chains, key=len)))


def cmd_timeline(args) -> None:
    from .analysis.rca import RCAEngine
    from .analysis.timeline import build_timeline
    from .entities import Ref
    from .snapshot import load_snapshot

    tl = build_timeline(RCAEngine(load_snapshot(args.snapshot)))
    if args.json:
        print(json.dumps(tl.to_dict(), indent=1))
        return
    ent = Ref.parse(args.entity) if args.entity else None
    kinds = set(args.kind.split(",")) if args.kind else None
    entries = tl.filter(ent, kinds) if ent or kinds else None
    print("\n".join(tl.render(entries, limit=args.limit, suspects=0 if entries is not None else 3)))


def cmd_investigate(args) -> None:
    from langgraph.checkpoint.sqlite import SqliteSaver

    from .agent.graph import build_graph, resume_incident, run_incident

    llm = _llm(args)
    conn = sqlite3.connect(args.state, check_same_thread=False)
    graph = build_graph(llm, executor=_executor(args), checkpointer=SqliteSaver(conn), max_steps=args.max_steps,
                        remediate=not args.no_remediation)
    iid = args.incident or Path(args.snapshot).name
    if args.resume:
        state = resume_incident(graph, iid, _answer(args, None))
    else:
        state = run_incident(graph, str(Path(args.snapshot).resolve()), iid, "llm" if llm else "rules", iid)
    while state.get("__interrupt__"):
        req = state["__interrupt__"][0].value
        print(f"\nDiagnosis: {req.get('summary')}")
        for rc in req["root_causes"]:
            print(f"  root cause: {rc['entity']}  ({rc['reason']})")
        print("\nProposed actions:")
        for a in req["actions"]:
            print(f"  {a['id']} [{a['risk']}] {a['title']}\n      {a['command']}")
        answer = _answer(args, req["actions"])
        if answer is None:
            print(f"\nPaused for approval. Resume with: incident-agent investigate {args.snapshot} --resume "
                  f"--incident {iid} --approve all|none|a1,a2")
            return
        state = resume_incident(graph, iid, answer)
    print("\n" + state.get("report", ""))


def _answer(args, actions):
    choice = args.approve
    if choice is None and actions is not None and sys.stdin.isatty():
        decisions = {}
        for a in actions:
            reply = input(f"Approve {a['id']} `{a['command']}`? [y/N] ").strip().lower()
            decisions[a["id"]] = "approve" if reply in ("y", "yes") else "reject"
        return {"decisions": decisions}
    if choice is None:
        return None
    if choice in ("all", "none"):
        return "approve" if choice == "all" else "reject"
    ids = {x.strip() for x in choice.split(",")}
    return {"decisions": {a: "approve" for a in ids}}


def cmd_serve(args) -> None:
    import uvicorn

    from .web.app import IncidentStore, create_app

    store = IncidentStore(args.snapshots)
    if args.demo:
        from .simulate.scenarios import build, scenario_ids

        for sid in (args.demo_scenarios.split(",") if args.demo_scenarios else scenario_ids()):
            snap, _ = build(sid, 0)
            store.add(f"itbench-{sid}", snap)
    app = create_app(store, _llm(args), _executor(args), args.state)
    print(f"Incident console on http://{args.host}:{args.port}  (MCP endpoint: /mcp; {len(store.paths())} incidents)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


def cmd_eval(args) -> None:
    from .eval import runner

    if args.itbench_data:
        cases = runner.itbench_cases(args.itbench_data)
        title = f"ITBench snapshots in {args.itbench_data}"
    else:
        cases = runner.synthetic_cases(args.split, args.repeats)
        title = f"ITBench scenarios (synthetic snapshots), {args.split} split, {args.repeats} runs each"
    methods = [runner.Method("alert targets (baseline)", runner.baseline_alert_targets),
               runner.Method("error origin (baseline)", runner.baseline_error_origin),
               runner.Method("every anomaly (baseline)", runner.baseline_every_anomaly),
               runner.Method("rules engine", runner.rules_agent)]
    llm = _llm(args)
    if llm is not None:
        methods.append(runner.Method(f"agent ({args.provider} {args.model or ''})".strip(), _llm_method(args),
                                     workers=args.workers))
    report = runner.run(cases, methods)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    md = runner.to_markdown(report, title, [m.name for m in methods])
    md += "\n" + runner.per_scenario_markdown(report, methods[-1].name)
    name = "itbench" if args.itbench_data else f"rca-{args.split}"
    (out / f"{name}.md").write_text(md, encoding="utf-8")
    if args.save_json:
        runner.dump(report, out / f"{name}.json")
    print(md)


def _llm_method(args):
    from .agent.graph import build_graph, register_snapshot, run_incident
    from .agent.llm import make_llm

    def predict(snap):
        graph = build_graph(make_llm(args.provider, args.model), remediate=False, max_steps=args.max_steps)
        key = register_snapshot(snap)
        state = run_incident(graph, key, snap.name, "llm")
        ents = [rc["entity"] for rc in state["diagnosis"]["root_causes"]]
        usage = state.get("usage") or {}
        return ents, {"steps": state.get("steps", 0), "input_tokens": usage.get("input_tokens", 0),
                      "output_tokens": usage.get("output_tokens", 0), "source": state["diagnosis"]["source"]}

    return predict


def cmd_collect(args) -> None:
    from .collect import collect_to

    path = collect_to(args.out, context=args.context, namespaces=args.namespace, prometheus=args.prometheus,
                      jaeger=args.jaeger, window_minutes=args.window)
    print(f"wrote {path}")


def cmd_itbench_check(args) -> None:
    from .itbench import load_itbench_ground_truth, load_itbench_snapshot

    snap = load_itbench_snapshot(args.path)
    print(json.dumps(snap.stats(), indent=1))
    gt = load_itbench_ground_truth(args.path)
    if gt:
        print("ground truth root causes:", [e.label for e in gt.root_causes])


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="incident-agent", description="Kubernetes incident root-cause analysis agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    def llm_args(sp):
        sp.add_argument("--provider", choices=["anthropic", "openai", "google"],
                        help="google: Vertex AI (Gemini, or Claude with a claude-* model)")
        sp.add_argument("--model")
        sp.add_argument("--max-steps", type=int, default=16)

    def exec_args(sp):
        sp.add_argument("--execute", action="store_true", help="run approved actions with kubectl (default: dry run)")
        sp.add_argument("--context", help="kubectl context")
        sp.add_argument("--no-server-dry-run", action="store_true", help="apply for real instead of --dry-run=server")

    s = sub.add_parser("scenarios", help="list the ITBench scenarios")
    s.add_argument("--split", default="all", choices=["dev", "test", "all"])
    s.set_defaults(func=cmd_scenarios)

    s = sub.add_parser("simulate", help="write incident snapshots for ITBench scenarios")
    s.add_argument("scenario", help="scenario id (see `scenarios`) or 'all'")
    s.add_argument("--out", default="snapshots")
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--repeats", type=int, default=1)
    s.add_argument("--split", default="all", choices=["dev", "test", "all"])
    s.add_argument("--itbench-format", action="store_true", help="write ITBench TSV files instead of the native format")
    s.set_defaults(func=cmd_simulate)

    s = sub.add_parser("diagnose", help="deterministic root-cause analysis of a snapshot")
    s.add_argument("snapshot")
    s.add_argument("--json", action="store_true")
    s.add_argument("--itbench-out", help="write agent_output.json for the ITBench judge")
    s.set_defaults(func=cmd_diagnose)

    s = sub.add_parser("timeline", help="what changed, then what failed, relative to the first alert")
    s.add_argument("snapshot")
    s.add_argument("--entity", help="only entries about this entity (namespace/Kind/name)")
    s.add_argument("--kind", help="comma-separated: change, warning, error, alert, marker")
    s.add_argument("--limit", type=int, default=60)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_timeline)

    s = sub.add_parser("investigate", help="run the full agent workflow (diagnose, plan, approve, remediate)")
    s.add_argument("snapshot")
    s.add_argument("--incident")
    s.add_argument("--state", default="incident-state.sqlite", help="LangGraph checkpoint database")
    s.add_argument("--approve", help="all | none | a1,a2 (default: ask interactively, or pause)")
    s.add_argument("--resume", action="store_true")
    s.add_argument("--no-remediation", action="store_true")
    llm_args(s)
    exec_args(s)
    s.set_defaults(func=cmd_investigate)

    s = sub.add_parser("serve", help="incident console + JSON API + MCP endpoint")
    s.add_argument("--snapshots", help="directory of snapshot directories")
    s.add_argument("--demo", action="store_true", help="load the ITBench scenarios as demo incidents")
    s.add_argument("--demo-scenarios", help="comma-separated scenario ids for --demo")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8750)
    s.add_argument("--state", default=":memory:")
    llm_args(s)
    exec_args(s)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("eval", help="score the agent and baselines the ITBench-AA way")
    s.add_argument("--split", default="test", choices=["dev", "test", "all"])
    s.add_argument("--repeats", type=int, default=3)
    s.add_argument("--itbench-data", help="directory of downloaded ITBench-Lite/ITBench-AA scenarios")
    s.add_argument("--out", default="reports")
    s.add_argument("--save-json", action="store_true")
    s.add_argument("--workers", type=int, default=4)
    llm_args(s)
    s.set_defaults(func=cmd_eval)

    s = sub.add_parser("collect", help="snapshot a live cluster (kubectl, Prometheus, Jaeger)")
    s.add_argument("--out", required=True)
    s.add_argument("--context")
    s.add_argument("--namespace", action="append")
    s.add_argument("--prometheus")
    s.add_argument("--jaeger")
    s.add_argument("--window", type=int, default=30, help="minutes of logs, metrics and traces")
    s.set_defaults(func=cmd_collect)

    s = sub.add_parser("itbench-check", help="show what the ITBench reader loads from a scenario directory")
    s.add_argument("path")
    s.set_defaults(func=cmd_itbench_check)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":  # pragma: no cover
    main()
