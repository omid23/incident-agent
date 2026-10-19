from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from incident_agent.agent.llm import LLMResponse, ScriptedLLM, ToolCall
from incident_agent.cli import main
from incident_agent.eval import runner
from incident_agent.mcp_server import StateSigner
from incident_agent.web.app import IncidentStore, create_app

V = "2026-07-28"


def rpc(method, params=None, req_id=1, caps=None):
    params = dict(params or {})
    meta = {"io.modelcontextprotocol/protocolVersion": V}
    if caps is not None:
        meta["io.modelcontextprotocol/clientCapabilities"] = caps
    params["_meta"] = meta
    body = {"jsonrpc": "2.0", "method": method, "params": params}
    if req_id is not None:
        body["id"] = req_id
    return body


@pytest.fixture
def store(scenario):
    s = IncidentStore()
    s.add("inc-30", scenario("30")[0])
    s.add("inc-114", scenario("114")[0])
    return s


@pytest.fixture
def client(store):
    return TestClient(create_app(store))


def tool(client, name, args, **kw):
    return client.post("/mcp", json=rpc("tools/call", {"name": name, "arguments": args}, **kw),
                       headers={"Mcp-Method": "tools/call", "Mcp-Name": name}).json()


# -- MCP -------------------------------------------------------------------------------------------------

def test_mcp_discover_list(client):
    d = client.post("/mcp", json=rpc("server/discover")).json()["result"]
    assert d["supportedVersions"] == [V] and d["serverInfo"]["name"] == "incident-agent"
    tools = client.post("/mcp", json=rpc("tools/list")).json()["result"]
    names = [t["name"] for t in tools["tools"]]
    assert names == sorted(names) and {"diagnose", "run_remediation", "find_anomalies", "list_incidents"} <= set(names)
    fa = next(t for t in tools["tools"] if t["name"] == "find_anomalies")
    assert fa["inputSchema"]["required"][0] == "incident" and fa["annotations"]["readOnlyHint"]
    rr = next(t for t in tools["tools"] if t["name"] == "run_remediation")
    assert rr["annotations"]["destructiveHint"] is True and tools["ttlMs"] == 300_000


def test_mcp_investigation_tools(client):
    inc = tool(client, "list_incidents", {})["result"]["structuredContent"]["incidents"]
    assert [i["incident"] for i in inc] == ["inc-114", "inc-30"]
    r = tool(client, "find_anomalies", {"incident": "inc-30", "role": "defect"})["result"]
    assert "service_port_mismatch" not in r["content"][0]["text"] and "Service ad targets port 8081" in r["content"][0]["text"]
    d = tool(client, "diagnose", {"incident": "inc-114"})["result"]
    assert d["structuredContent"]["itbench"]["entities"][0]["name"] == "otel-demo/Service/product-catalog"
    assert d["content"][0]["text"].startswith("Root cause: otel-demo/Service/product-catalog")
    plan = tool(client, "plan_remediation", {"incident": "inc-30"})["result"]["structuredContent"]["actions"]
    assert plan[0]["argv"][0] == "patch"
    assert tool(client, "list_alerts", {"incident": "nope"})["result"]["isError"]


def test_mcp_remediation_needs_approval(client):
    no_caps = tool(client, "run_remediation", {"incident": "inc-30", "action_id": "a1"})["result"]
    assert no_caps["isError"] and "approval" in no_caps["content"][0]["text"]
    caps = {"elicitation": {"form": {}}}
    ask = tool(client, "run_remediation", {"incident": "inc-30", "action_id": "a1"}, caps=caps)["result"]
    assert ask["resultType"] == "input_required"
    form = ask["inputRequests"]["approve_action"]
    assert form["method"] == "elicitation/create" and "kubectl patch service ad" in form["params"]["message"]

    def retry(state, accept=True, approve=True):
        params = {"name": "run_remediation", "arguments": {"incident": "inc-30", "action_id": "a1"},
                  "requestState": state,
                  "inputResponses": {"approve_action": {"action": "accept" if accept else "decline",
                                                        "content": {"approve": approve}}}}
        return client.post("/mcp", json=rpc("tools/call", params, caps=caps)).json()

    done = retry(ask["requestState"])["result"]
    assert not done["isError"] and done["structuredContent"]["dry_run"] and "would execute" in done["content"][0]["text"]
    assert "already used" in retry(ask["requestState"])["error"]["message"]  # no replay
    ask2 = tool(client, "run_remediation", {"incident": "inc-30", "action_id": "a1"}, caps=caps)["result"]
    assert retry(ask2["requestState"], accept=False)["result"]["isError"]
    tampered = ask2["requestState"][:-3] + "abc"
    assert "signature" in retry(tampered)["error"]["message"]
    other = tool(client, "run_remediation", {"incident": "inc-30", "action_id": "a9"}, caps=caps)["result"]
    assert other["isError"]


def test_mcp_protocol_errors(client):
    assert client.post("/mcp", content=b"{").status_code == 400
    r = client.post("/mcp", json=rpc("tools/list"), headers={"Mcp-Method": "tools/call"})
    assert r.json()["error"]["code"] == -32020
    old = rpc("tools/list")
    old["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "2025-06-18"
    assert client.post("/mcp", json=old).json()["error"]["code"] == -32022
    assert client.post("/mcp", json=rpc("prompts/list")).json()["error"]["code"] == -32601
    assert client.post("/mcp", json=rpc("tools/call", {"name": "rm_rf"})).json()["error"]["code"] == -32602
    assert client.post("/mcp", json=rpc("notifications/initialized", req_id=None)).status_code == 202


def test_state_signer_expiry():
    s = StateSigner(b"k", ttl_s=-1)
    tok = s.issue({"a": 1})
    with pytest.raises(ValueError, match="expired"):
        s.verify(tok, {"a": 1})
    s2 = StateSigner(b"k")
    with pytest.raises(ValueError, match="does not match"):
        s2.verify(s2.issue({"a": 1}), {"a": 2})


# -- console ------------------------------------------------------------------------------------------------

def test_console_flow(client):
    assert "<title>Incident Console</title>" in client.get("/").text
    assert client.get("/api/info").json()["executor"] == "dry-run"
    rows = client.get("/api/incidents").json()
    assert {r["id"]: r["status"] for r in rows} == {"inc-30": "new", "inc-114": "new"}
    detail = client.get("/api/incidents/inc-114").json()
    assert detail["alerts"] and detail["stats"]["spans"] > 1000 and detail["state"] == {}
    assert client.post("/api/incidents/inc-114/approve", json={"decisions": {}}).status_code == 409
    assert client.post("/api/incidents/inc-114/investigate", json={"mode": "llm"}).status_code == 400
    st = client.post("/api/incidents/inc-114/investigate", json={"mode": "rules"}).json()
    assert st["pending_approval"]["actions"][0]["command"].startswith("kubectl expose")
    assert client.post("/api/incidents/inc-114/approve", json={"decisions": "yes"}).status_code == 400
    st = client.post("/api/incidents/inc-114/approve", json={"decisions": {"a1": "approve"}}).json()
    assert st["status"] == "remediated" and st["pending_approval"] is None
    topo = client.get("/api/incidents/inc-114/topology").json()
    root = next(n for n in topo["nodes"] if n["id"] == "otel-demo/Service/product-catalog")
    assert root["root"] and root["missing"]
    assert any(e["to"] == "otel-demo/Service/product-catalog" and e["error_rate"] > 0.5 for e in topo["edges"])
    res = client.get("/api/incidents/inc-114/resource", params={"entity": "otel-demo/Deployment/frontend"}).json()
    assert "kind: Deployment" in res["yaml"] and "findings" in res
    assert client.get("/api/incidents/zzz").status_code == 404
    assert client.get("/healthz").json() == {"status": "ok"}


def test_console_with_model(store):
    llm = ScriptedLLM(lambda s, m: LLMResponse("", [ToolCall("s", "submit_diagnosis", {
        "summary": "port", "root_causes": [{"entity": "otel-demo/Service/ad", "reason": "targetPort"}]})]))
    llm.model = "scripted-1"
    c = TestClient(create_app(store, llm=llm))
    assert c.get("/api/info").json()["model"] == "scripted-1"
    st = c.post("/api/incidents/inc-30/investigate", json={}).json()
    assert st["diagnosis"]["source"] == "llm" and st["diagnosis"]["root_causes"][0]["entity"] == "otel-demo/Service/ad"


def test_store_reads_snapshot_dirs(scenario, tmp_path):
    scenario("36")[0].save(tmp_path / "bookinfo-incident")
    (tmp_path / "not-a-snapshot").mkdir()
    s = IncidentStore(tmp_path)
    assert list(s.paths()) == ["bookinfo-incident"]


# -- evaluation and CLI ---------------------------------------------------------------------------------------

def test_eval_runner():
    cases = [c for c in runner.synthetic_cases("all", 1) if c[0] in ("30", "114", "31")]
    rep = runner.run(cases, [runner.Method("alerts", runner.baseline_alert_targets),
                             runner.Method("rules", runner.rules_agent)])
    s = rep["summary"]
    assert s["rules"]["all"]["itbench_strict"] == 1.0 and s["rules"]["all"]["solved_scenarios"] == 3
    assert s["alerts"]["all"]["itbench_strict"] < 0.5
    md = runner.to_markdown(rep, "t", ["alerts", "rules"])
    assert "| rules | 1.000 | 1.000 | 100% |" in md
    per = runner.per_scenario_markdown(rep, "rules")
    assert "| 114 |" in per and "otel-demo/Service/product-catalog" in per


def test_cli_end_to_end(tmp_path, capsys):
    snaps = tmp_path / "snaps"
    main(["simulate", "31", "--out", str(snaps)])
    main(["diagnose", str(snaps / "scenario-31"), "--itbench-out", str(tmp_path / "out.json")])
    out = capsys.readouterr().out
    assert "ROOT CAUSE  otel-demo/NetworkPolicy/frontend-ingress" in out and "propagation:" in out
    assert json.loads((tmp_path / "out.json").read_text())["entities"][0]["contributing_factor"]
    main(["investigate", str(snaps / "scenario-31"), "--state", str(tmp_path / "s.sqlite"), "--approve", "a1"])
    out = capsys.readouterr().out
    assert "[approve] Delete NetworkPolicy frontend-ingress" in out
    main(["simulate", "36", "--out", str(tmp_path / "itb"), "--itbench-format"])
    main(["itbench-check", str(tmp_path / "itb" / "scenario-36")])
    assert "ground truth root causes: ['book-info/Service/details']" in capsys.readouterr().out
    main(["eval", "--itbench-data", str(tmp_path / "itb"), "--out", str(tmp_path / "rep")])
    md = (tmp_path / "rep" / "itbench.md").read_text()
    assert "| rules engine | 1.000 |" in md
