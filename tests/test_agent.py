from __future__ import annotations

import json
import sqlite3
import subprocess

import httpx
import pytest
from langgraph.checkpoint.sqlite import SqliteSaver

from incident_agent.agent.graph import (
    build_graph,
    check_proposal,
    register_snapshot,
    resume_incident,
    run_incident,
)
from incident_agent.agent.llm import AnthropicLLM, LLMResponse, OpenAICompatLLM, ScriptedLLM, ToolCall, ToolSpec
from incident_agent.agent.remediation import Action, DryRunExecutor, KubectlExecutor, plan
from incident_agent.agent.tools import Toolbox
from incident_agent.analysis.rca import RCAEngine


def call(name: str, i: int = 1, **args) -> ToolCall:
    return ToolCall(f"c_{name}_{i}", name, args)


# -- tools ------------------------------------------------------------------------------------------------

def test_tools(scenario):
    snap, _ = scenario("114")
    tb = Toolbox(snap)
    assert {s.name for s in tb.specs} == {"list_alerts", "find_anomalies", "get_resource", "list_resources",
                                          "get_events", "search_logs", "trace_summary", "get_metric",
                                          "dependencies", "rollout_history"}
    alerts, err = tb.call("list_alerts", {})
    assert not err and "HighRequestErrorRate" in alerts and "-> otel-demo/Deployment/frontend" in alerts
    found, _ = tb.call("find_anomalies", {"role": "defect"})
    assert found.splitlines()[0].startswith("[defect") and "otel-demo/Service/product-catalog" in found
    edges, _ = tb.call("trace_summary", {"service": "frontend"})
    assert "frontend -> product-catalog [Service not found]" in edges
    missing, _ = tb.call("get_resource", {"entity": "otel-demo/Service/product-catalog"})
    assert "does not exist" in missing and "otel-demo/Service/cart" in missing
    deps, _ = tb.call("dependencies", {"entity": "otel-demo/Deployment/frontend"})
    assert "depends on: otel-demo/Service/product-catalog (calls)" in deps
    logs, _ = tb.call("search_logs", {"service": "frontend", "contains": "product-catalog"})
    assert logs.split("x ", 1)[0].isdigit()
    metric, _ = tb.call("get_metric", {"name": "request_error_ratio", "label": "frontend"})
    assert "before median" in metric and "during" in metric
    assert "Available:" in tb.call("get_metric", {"name": "nope"})[0]
    assert tb.call("teleport", {}) == ("Unknown tool 'teleport'.", True)
    assert tb.call("get_resource", {"entity": "nonsense"})[1]
    pods, _ = tb.call("list_resources", {"kind": "po", "namespace": "otel-demo"})
    assert "otel-demo/Pod/frontend-" in pods and "phase=Running" in pods


def test_tool_outputs_redact_and_diff(scenario):
    snap, _ = scenario("63")
    tb = Toolbox(snap)
    secret, _ = tb.call("get_resource", {"entity": "otel-demo/Secret/email-service-secret"})
    assert "<redacted>" in secret and "aW52YWxpZ" not in secret
    snap20, _ = scenario("20")
    hist, _ = Toolbox(snap20).call("rollout_history", {"entity": "otel-demo/Deployment/product-catalog"})
    assert "changes in the latest revision:" in hist and "nonexistent" in hist
    ev, _ = Toolbox(snap20).call("get_events", {"entity": "otel-demo/Deployment/product-catalog", "type": "Warning"})
    assert "Failed" in ev and "not found" in ev


# -- remediation ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sid,expected", [
    ("20", "kubectl rollout undo deployment/product-catalog -n otel-demo"),
    ("58", "kubectl scale deployment/accounting -n otel-demo --replicas=1"),
    ("114", "kubectl expose deployment/product-catalog -n otel-demo --name=product-catalog --port=8080 --target-port=8080"),
    ("31", "kubectl delete networkpolicy frontend-ingress -n otel-demo"),
    ("48", "kubectl label namespace book-info istio.io/dataplane-mode=ambient --overwrite"),
    ("30", "kubectl patch service ad -n otel-demo --type=merge -p "),
])
def test_remediation_plans(scenario, sid, expected):
    snap, _ = scenario(sid)
    eng = RCAEngine(snap)
    actions = plan(eng, eng.diagnose().root_causes)
    assert any(a.command.startswith(expected) for a in actions), [a.command for a in actions]
    if sid == "30":
        patch = json.loads(next(a for a in actions if a.argv[0] == "patch").argv[-1])
        assert patch["spec"]["ports"][0]["targetPort"] == 8080
    if sid == "31":
        a = next(a for a in actions if a.argv[0] == "delete")
        assert a.risk == "high" and a.backup[:2] == ["get", "networkpolicy"]
        assert not any("restart" in x.command for x in actions)  # the policy's target needs no restart


def test_kubectl_executor_guards_and_backup(tmp_path):
    calls = []

    def runner(argv, capture_output=True, text=True, timeout=60):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "apiVersion: v1\nkind: NetworkPolicy\n" if "get" in argv else "deleted", "")

    ex = KubectlExecutor(context="prod", backup_dir=tmp_path, runner=runner)
    act = Action("a1", "Delete", "otel-demo/NetworkPolicy/x", ["delete", "networkpolicy", "x", "-n", "otel-demo"], "high",
                 True, "why", backup=["get", "networkpolicy", "x", "-n", "otel-demo", "-o", "yaml"])
    r = ex.run(act)
    assert r.ok and r.dry_run and calls[0][:3] == ["kubectl", "--context", "prod"]
    assert calls[-1][-1] == "--dry-run=server"
    assert (tmp_path / "a1-otel-demo_NetworkPolicy_x.yaml").read_text().startswith("apiVersion")
    for bad in (["delete", "pods", "--all", "-n", "x"], ["scale", "deployment/x", "--replicas=0"], ["exec", "x", "-n", "y"]):
        assert ex.run(Action("b", "t", "x", bad, "low", True, "")).output.startswith("refused")
    assert ex.run(Action("m", "manual", "x", [], "low", False, "", manual=True)).output.startswith("manual")
    assert DryRunExecutor().run(act).output.startswith("dry run")


# -- workflow ------------------------------------------------------------------------------------------------

def _graph(llm=None, **kw):
    return build_graph(llm, checkpointer=SqliteSaver(sqlite3.connect(":memory:", check_same_thread=False)), **kw)


def test_rules_workflow_with_approval(scenario):
    snap, _ = scenario("58")
    key = register_snapshot(snap)
    g = _graph()
    st = run_incident(g, key, "inc-58")
    assert st["diagnosis"]["root_causes"][0]["entity"] == "otel-demo/Deployment/accounting"
    assert st["diagnosis"]["verified"] and st["diagnosis"]["itbench"]["entities"][0]["contributing_factor"]
    pending = st["__interrupt__"][0].value
    assert pending["type"] == "approval" and pending["actions"][0]["command"].startswith("kubectl scale")
    st = resume_incident(g, "inc-58", {"decisions": {"a1": "approve"}})
    assert st["status"] == "remediated" and st["results"][0]["dry_run"]
    assert "[approve] Scale accounting back to 1" in st["report"]
    kinds = [e["kind"] for e in st["timeline"]]
    assert kinds == ["triage", "adjudicate", "plan", "approval", "remediate", "report"]


def test_rejection_and_no_remediation(scenario):
    snap, _ = scenario("36")
    key = register_snapshot(snap)
    g = _graph()
    run_incident(g, key, "inc-36")
    st = resume_incident(g, "inc-36", "reject")
    assert st["status"] == "rejected" and all(r["output"] == "rejected" for r in st["results"])
    st2 = run_incident(_graph(remediate=False), key, "inc-36b")
    assert "__interrupt__" not in st2 and st2["report"].startswith("# Incident inc-36b")


def test_approval_survives_a_restart(scenario, tmp_path):
    """The pause lives in the SQLite checkpoint: a new process can approve it."""
    snap, _ = scenario("20")
    key = register_snapshot(snap)
    db = str(tmp_path / "state.sqlite")
    g1 = build_graph(None, checkpointer=SqliteSaver(sqlite3.connect(db, check_same_thread=False)))
    st = run_incident(g1, key, "inc-20")
    assert st["__interrupt__"]
    del g1
    g2 = build_graph(None, checkpointer=SqliteSaver(sqlite3.connect(db, check_same_thread=False)))
    st = resume_incident(g2, "inc-20", "approve")
    assert st["status"] == "remediated" and "rollout undo" in st["results"][0]["command"]


def _llm_script(steps):
    return ScriptedLLM([LLMResponse("", [c]) if isinstance(c, ToolCall) else c for c in steps])


def test_llm_investigation_happy_path(scenario):
    snap, gt = scenario("114")
    key = register_snapshot(snap)
    llm = _llm_script([
        call("find_anomalies", role="defect"),
        call("trace_summary", 2, service="frontend"),
        LLMResponse("", [call("submit_diagnosis", 3, summary="The product-catalog Service was deleted.",
                              root_causes=[{"entity": "otel-demo/Service/product-catalog", "reason": "deleted"}])],
                    input_tokens=1200, output_tokens=80),
    ])
    st = run_incident(_graph(llm, remediate=False), key, "llm-114", "llm")
    assert st["diagnosis"]["source"] == "llm" and st["diagnosis"]["verified"]
    assert [r["entity"] for r in st["diagnosis"]["root_causes"]] == ["otel-demo/Service/product-catalog"]
    assert st["steps"] == 3 and st["usage"]["input_tokens"] == 1200
    first = llm.calls[0][0]["content"]
    assert "Automated analysis" in first and "otel-demo/Service/product-catalog" in first
    tool_msgs = [m for m in llm.calls[2] if m["role"] == "tool"]
    assert "[Service not found]" in tool_msgs[-1]["content"]


def test_llm_symptom_answer_is_sent_back(scenario):
    snap, _ = scenario("114")
    key = register_snapshot(snap)
    llm = _llm_script([
        call("submit_diagnosis", 1, summary="frontend is broken",
             root_causes=[{"entity": "otel-demo/Deployment/frontend", "reason": "errors"}]),
        call("submit_diagnosis", 2, summary="deleted Service",
             root_causes=[{"entity": "otel-demo/Service/product-catalog", "reason": "deleted"}]),
    ])
    st = run_incident(_graph(llm, remediate=False), key, "llm-rev", "llm")
    assert st["revisions"] == 1 and st["diagnosis"]["verified"]
    feedback = llm.calls[1][-1]
    assert feedback["role"] == "tool" and "not explained" in feedback["content"]
    assert [e["kind"] for e in st["timeline"]].count("adjudicate") == 2


def test_llm_failures_fall_back_to_rules(scenario):
    snap, _ = scenario("36")
    key = register_snapshot(snap)
    st = run_incident(_graph(ScriptedLLM([]), remediate=False), key, "llm-err", "llm")
    assert st["diagnosis"]["source"] == "rules" and st["status"] == "diagnosed"
    loop = ScriptedLLM(lambda s, m: LLMResponse("", [ToolCall("x", "list_alerts", {})]))
    st = run_incident(_graph(loop, remediate=False, max_steps=3), key, "llm-loop", "llm")
    assert len(loop.calls) == 3 and st["diagnosis"]["root_causes"][0]["entity"] == "book-info/Service/details"
    prose = ScriptedLLM([LLMResponse("The root cause is book-info/Service/details, its selector matches nothing.")])
    st = run_incident(_graph(prose, remediate=False), key, "llm-prose", "llm")
    assert st["diagnosis"]["root_causes"][0]["entity"] == "book-info/Service/details" and st["diagnosis"]["source"] == "llm"


def test_check_proposal(scenario):
    snap, _ = scenario("31")
    eng = RCAEngine(snap)
    alerts = eng.diagnose().alerts
    good = {"root_causes": [{"entity": "otel-demo/NetworkPolicy/frontend-ingress"}, {"entity": "otel-demo/Deployment/frontend"}]}
    assert check_proposal(eng, good, alerts)["passed"]
    v = check_proposal(eng, {"root_causes": [{"entity": "otel-demo/Deployment/nope"}]}, alerts)
    assert not v["passed"] and any("does not exist" in p for p in v["problems"])
    v = check_proposal(eng, {"root_causes": [{"entity": "otel-demo/Deployment/cart"}]}, alerts)
    assert any("NetworkPolicy/frontend-ingress has direct evidence" in p for p in v["problems"])
    v = check_proposal(eng, {"root_causes": [{"entity": "otel-demo/Deployment/load-generator"}]}, alerts)
    assert any("not explained" in p for p in v["problems"])
    assert not check_proposal(eng, {"root_causes": []}, alerts)["passed"]


# -- model adapters ------------------------------------------------------------------------------------------

def test_model_adapters_wire_format(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    seen = {}

    def anthropic(req: httpx.Request) -> httpx.Response:
        seen["a"] = json.loads(req.content)
        return httpx.Response(200, json={"content": [{"type": "tool_use", "id": "t", "name": "list_alerts", "input": {}}],
                                         "usage": {"input_tokens": 5, "output_tokens": 2}})

    def openai(req: httpx.Request) -> httpx.Response:
        seen["o"] = json.loads(req.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "done"}, "finish_reason": "stop"}]})

    msgs = [{"role": "user", "content": "q"},
            {"role": "assistant", "content": "", "tool_calls": [ToolCall("t1", "list_alerts", {})]},
            {"role": "tool", "tool_call_id": "t1", "name": "list_alerts", "content": "x", "is_error": False}]
    tools = [ToolSpec("list_alerts", "d", {"type": "object", "properties": {}})]
    r = AnthropicLLM(client=httpx.Client(transport=httpx.MockTransport(anthropic))).complete("sys", msgs, tools)
    assert r.tool_calls[0].name == "list_alerts" and seen["a"]["messages"][2]["content"][0]["type"] == "tool_result"
    r = OpenAICompatLLM(client=httpx.Client(transport=httpx.MockTransport(openai))).complete("sys", msgs, tools)
    assert r.text == "done" and seen["o"]["messages"][0] == {"role": "system", "content": "sys"}
