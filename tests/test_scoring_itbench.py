from __future__ import annotations

import json
import subprocess

import httpx
import pytest

from incident_agent.analysis.rca import diagnose
from incident_agent.collect import Collector, _kind_of
from incident_agent.eval.groundtruth import parse_ground_truth
from incident_agent.eval.scoring import score
from incident_agent.itbench import (
    export_itbench,
    load_itbench_ground_truth,
    load_itbench_snapshot,
    parse_map,
)

LIBRARY = {"alerts": [{"name": "KubePodNotReady"}],
           "entities": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "ad", "namespace": "otel-demo"},
                        {"apiVersion": "v1", "kind": "ResourceQuota", "name": "q", "namespace": "otel-demo"}]}
GROUPS = {"groups": [{"id": "ad-dep", "kind": "Deployment", "namespace": "otel-demo", "filter": ["^ad$"], "root_cause": True},
                     {"id": "ad-svc", "kind": "Service", "namespace": "otel-demo", "filter": ["^ad$"]},
                     {"id": "fe", "kind": "Deployment", "namespace": "otel-demo", "filter": ["frontend"]}],
          "aliases": [["ad-dep", "ad-svc"]], "propagations": [{"source": "ad-dep", "target": "fe"}]}


def test_ground_truth_formats():
    lib = parse_ground_truth(LIBRARY, "102")
    assert [e.label for e in lib.root_causes] == ["otel-demo/Deployment/ad", "otel-demo/ResourceQuota/q"]
    assert lib.alerts == ["KubePodNotReady"]
    grp = parse_ground_truth(GROUPS, "x")
    assert [e.id for e in grp.root_causes] == ["ad-dep"]
    assert [e.id for e in grp.aliases_of(grp.root_causes[0])] == ["ad-dep", "ad-svc"]


@pytest.mark.parametrize("pred,itb,recall,precision", [
    (["otel-demo/Deployment/ad", "otel-demo/ResourceQuota/q"], 1.0, 1.0, 1.0),
    (["otel-demo/ResourceQuota/q"], 0.0, 0.5, 1.0),  # a missed root cause scores zero
    (["otel-demo/Deployment/ad", "otel-demo/ResourceQuota/q", "otel-demo/Deployment/frontend"], 2 / 3, 1.0, 2 / 3),
    (["otel-demo/deploy/ad", "otel-demo/resourcequota/q", "otel-demo/Deployment/ad"], 1.0, 1.0, 1.0),  # normalised, deduped
    ([], 0.0, 0.0, 0.0), (["not an entity"], 0.0, 0.0, 0.0),
])
def test_library_scoring(pred, itb, recall, precision):
    s = score(pred, parse_ground_truth(LIBRARY, "102"))
    assert (s.itbench, s.recall, s.precision) == (pytest.approx(itb), recall, pytest.approx(precision))


def test_alias_and_filter_scoring():
    gt = parse_ground_truth(GROUPS, "x")
    assert score(["otel-demo/Service/ad"], gt).itbench == 1.0  # alias of the root cause
    assert score(["otel-demo/Deployment/adservice"], gt).itbench == 0.0  # the filter is anchored
    assert score(["otel-demo/Deployment/frontend"], gt).itbench == 0.0


def test_component_mode_uses_ownership(scenario):
    snap, gt = scenario("40")  # ground truth names the Service; a Deployment of the same app also counts in component mode
    assert score(["otel-demo/Deployment/valkey-cart"], gt, "strict", snap).itbench == 0.0
    assert score(["otel-demo/Deployment/valkey-cart"], gt, "component", snap).itbench == 1.0
    pod = next(p["metadata"]["name"] for p in snap.of_kind("Pod", "otel-demo") if p["metadata"]["name"].startswith("valkey-cart-"))
    assert score([f"otel-demo/Pod/{pod}"], gt, "component", snap).itbench == 1.0
    assert score(["otel-demo/Deployment/cart"], gt, "component", snap).itbench == 0.0


@pytest.mark.parametrize("text,expected", [
    ("map[k8s.namespace.name:otel-demo k8s.pod.name:cart-1]", {"k8s.namespace.name": "otel-demo", "k8s.pod.name": "cart-1"}),
    ("map[service.name:cart svc x:y]", {"service.name": "cart svc", "x": "y"}),
    ('{"a": "1"}', {"a": "1"}), ("{'a': 'b'}", {"a": "b"}), ("map[]", {}), ("", {}), ("{broken", {}),
])
def test_parse_map(text, expected):
    assert parse_map(text) == expected


@pytest.mark.parametrize("sid", ["31", "48", "63", "102"])
def test_itbench_layout_roundtrip(scenario, tmp_path, sid):
    snap, gt = scenario(sid)
    root = export_itbench(snap, tmp_path / sid)
    (root / "ground_truth.yaml").write_text(json.dumps(GROUPS))
    back = load_itbench_snapshot(root)
    assert len(back.objects) == len(snap.objects) and len(back.spans) == len(snap.spans)
    assert len(back.alerts) == len(snap.alerts) and len(back.logs) == len(snap.logs)
    assert diagnose(back).entities() == diagnose(snap).entities()
    assert load_itbench_ground_truth(root).root_causes[0].id == "ad-dep"


def test_itbench_reader_edge_cases(tmp_path):
    root = tmp_path / "Scenario-9"
    root.mkdir()
    dep = {"kind": "Deployment", "metadata": {"name": "a", "namespace": "n"}}
    # Go's encoding/csv quotes fields containing quotes; write one row the way it does.
    body = json.dumps({"type": "ADDED", "object": dep}).replace('"', '""')
    deleted = json.dumps({"type": "DELETED", "object": {**dep, "metadata": {"name": "b", "namespace": "n"}}}).replace('"', '""')
    added_b = json.dumps({**dep, "metadata": {"name": "b", "namespace": "n"}}).replace('"', '""')
    (root / "k8s_objects_raw.tsv").write_text("Timestamp\tBody\n"
                                              f'2026-09-01 10:00:00\t"{body}"\n'
                                              f'2026-09-01 10:00:00\t"{added_b}"\n'
                                              f'2026-09-01 10:05:00\t"{deleted}"\n')
    ev = json.dumps({"regarding": {"kind": "Pod", "name": "p", "namespace": "n"}, "note": "boom", "reason": "X"}).replace('"', '""')
    (root / "k8s_events_raw.tsv").write_text(f'Timestamp\tBody\n2026-09-01 10:01:00\t"{ev}"\n')
    (root / "alerts").mkdir()
    (root / "alerts" / "alerts_at_2026-09-01T10-02-00Z.json").write_text(json.dumps([{"labels": {"alertname": "A"}}]))
    (root / "alerts" / "alerts_at_2026-09-01T10-04-00Z.json").write_text(json.dumps([{"labels": {"alertname": "A"}}, {"labels": {"alertname": "B"}}]))
    snap = load_itbench_snapshot(root)
    assert [o["metadata"]["name"] for o in snap.objects] == ["a"]  # b was deleted later
    assert snap.events[0]["involvedObject"]["name"] == "p" and snap.events[0]["message"] == "boom"
    assert {a["labels"]["alertname"]: a["activeAt"] for a in snap.alerts} == {"A": "2026-09-01T10:02:00Z",
                                                                              "B": "2026-09-01T10:04:00Z"}


def fake_kubectl(argv, capture_output=True, text=True, timeout=120):
    args = argv[1:]
    if args[:2] == ["--context", "kind"]:
        args = args[2:]
    out = {"items": []}
    if args[0] == "get":
        kind = args[1]
        if kind.startswith("peerauthentications"):
            return subprocess.CompletedProcess(argv, 1, "", "error: the server doesn't have a resource type")
        if kind == "pods":
            out["items"] = [{"metadata": {"name": "cart-1", "namespace": "otel-demo", "labels": {"app.kubernetes.io/name": "cart"}},
                             "status": {"phase": "Running"}}]
        if kind == "secrets":
            out["items"] = [{"metadata": {"name": "s", "namespace": "otel-demo"}, "data": {"password": "c2VjcmV0"}}]
        if kind == "deployments":
            out["items"] = [{"metadata": {"name": "cart", "namespace": "otel-demo", "labels": {"app.kubernetes.io/name": "cart"}}}]
        if kind == "events":
            out["items"] = [{"reason": "BackOff", "involvedObject": {"kind": "Pod", "name": "cart-1"}}]
        return subprocess.CompletedProcess(argv, 0, json.dumps(out), "")
    if args[0] == "logs":
        return subprocess.CompletedProcess(argv, 0, "2026-09-01T10:00:00Z ERROR NOAUTH Authentication required.\n"
                                                    "2026-09-01T10:00:01Z INFO ok\n", "")
    return subprocess.CompletedProcess(argv, 1, "", "unexpected")


def test_live_collector(tmp_path):
    def prom(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/alerts"):
            return httpx.Response(200, json={"data": {"alerts": [{"labels": {"alertname": "X"}, "state": "firing"},
                                                                 {"labels": {"alertname": "Y"}, "state": "pending"}]}})
        return httpx.Response(200, json={"data": {"result": [{"metric": {"service_name": "cart"},
                                                              "values": [[1, "0.5"], [2, "NaN"]]}]}})

    c = Collector(context="kind", namespaces=["otel-demo"], prometheus="http://prom:9090", runner=fake_kubectl,
                  http=httpx.Client(transport=httpx.MockTransport(prom)))
    snap = c.collect("live-1")
    secret = next(o for o in snap.objects if o["kind"] == "Secret")
    assert secret["data"] == {"password": ""}  # secret values are never copied
    assert [a["labels"]["alertname"] for a in snap.alerts] == ["X"]
    assert snap.logs == [{"timestamp": "2026-09-01T10:00:00Z", "service": "cart", "namespace": "otel-demo",
                          "pod": "cart-1", "severity": "ERROR", "body": "ERROR NOAUTH Authentication required.",
                          "trace_id": ""}]
    assert snap.metrics[0]["points"] == [[1.0, 0.5]]
    assert snap.save(tmp_path / "live").exists()
    assert _kind_of("networkpolicies") == "NetworkPolicy" and _kind_of("pods") == "Pod"
