from __future__ import annotations

import pytest

from incident_agent.analysis.detectors import incident_start, pre_existing, template_diff
from incident_agent.analysis.index import ClusterIndex, selector_matches
from incident_agent.analysis.rca import RCAEngine, diagnose
from incident_agent.entities import Ref
from incident_agent.eval.scoring import score


def signals(engine: RCAEngine, ref: str) -> set[str]:
    return {f.signal for f in engine.by_entity.get(Ref.parse(ref), [])}


def test_refs():
    assert str(Ref.parse("otel-demo/deploy/cart")) == "otel-demo/Deployment/cart"
    assert Ref.parse("Namespace/book-info") == Ref("", "Namespace", "book-info")
    assert Ref.parse("x/Node/worker-1").namespace == ""
    with pytest.raises(ValueError):
        Ref.parse("cart")


def test_selector_matching():
    assert selector_matches({"app": "a"}, {"app": "a", "v": "1"})
    assert not selector_matches({"app": "a"}, {"app": "b"})
    assert selector_matches({"matchExpressions": [{"key": "app", "operator": "In", "values": ["a", "b"]}]}, {"app": "b"})
    assert not selector_matches({"matchExpressions": [{"key": "x", "operator": "Exists"}]}, {"app": "b"})
    assert not selector_matches({}, {"app": "a"})


def test_index_relationships(scenario):
    snap, _ = scenario("36")
    ix = ClusterIndex(snap)
    pod = next(p for p in snap.of_kind("Pod", "book-info") if p["metadata"]["name"].startswith("productpage-v1-"))
    assert ix.workload_of(Ref.of(pod)) == Ref("book-info", "Deployment", "productpage-v1")
    assert ix.service_backends[Ref("book-info", "Service", "reviews")] == [
        Ref("book-info", "Deployment", f"reviews-v{i}") for i in (1, 2, 3)]
    assert ix.service_backends[Ref("book-info", "Service", "details")] == []  # the injected selector fault
    assert ix.workload_for_service_name("productpage.book-info") == Ref("book-info", "Deployment", "productpage-v1")
    assert ix.resolve_host("details.book-info.svc.cluster.local:9080", "x") == Ref("book-info", "Service", "details")
    alert = {"labels": {"alertname": "HighRequestErrorRate", "namespace": "book-info", "destination_service_name": "details"}}
    assert ix.alert_entity(alert) == Ref("book-info", "Service", "details")
    callers = ix.callers(Ref("book-info", "Service", "details"))
    assert callers == [Ref("book-info", "Deployment", "productpage-v1")]


def test_config_and_policy_refs(scenario):
    snap, _ = scenario("59")
    ix = ClusterIndex(snap)
    refs = dict(ix.config_refs(Ref("otel-demo", "Deployment", "recommendation")))
    assert refs[Ref("otel-demo", "ConfigMap", "recommendation-config")].startswith("init container")
    snap31, _ = scenario("31")
    ix31 = ClusterIndex(snap31)
    assert Ref("otel-demo", "NetworkPolicy", "frontend-ingress") in ix31.policies_for(Ref("otel-demo", "Deployment", "frontend"))


@pytest.mark.parametrize("sid,entity,signal", [
    ("20", "otel-demo/Deployment/product-catalog", "image_pull_failure"),
    ("20", "otel-demo/Deployment/product-catalog", "rollout"),
    ("105", "otel-demo/Deployment/product-catalog", "container_start_error"),
    ("46", "otel-demo/Deployment/postgresql", "oom_killed"),
    ("45", "otel-demo/Deployment/email", "init_container_hang"),
    ("59", "otel-demo/Deployment/recommendation", "init_container_crash"),
    ("49", "otel-demo/Deployment/frontend", "readiness_probe_failing"),
    ("33", "otel-demo/Deployment/cart", "unschedulable"),
    ("42", "otel-demo/Deployment/kafka", "preempted"),
    ("58", "otel-demo/Deployment/accounting", "scaled_to_zero"),
    ("102", "otel-demo/ResourceQuota/strict-resource-quota", "quota_exhausted"),
    ("102", "otel-demo/Deployment/ad", "no_pods"),
    ("30", "otel-demo/Service/ad", "service_port_mismatch"),
    ("36", "book-info/Service/details", "service_no_endpoints"),
    ("114", "otel-demo/Service/product-catalog", "missing_service"),
    ("31", "otel-demo/NetworkPolicy/frontend-ingress", "network_policy_blocks_ingress"),
    ("38", "otel-demo/HorizontalPodAutoscaler/frontend", "hpa_maxed_out"),
    ("50", "book-info/PeerAuthentication/application", "strict_mtls_with_plaintext_workloads"),
    ("47", "book-info/AuthorizationPolicy/bookinfo-gateway-policy", "authorization_denies_all"),
    ("48", "/Namespace/book-info", "mesh_membership_changed"),
    ("43", "otel-demo/Deployment/frontend", "caller_side_failure"),
    ("40", "otel-demo/Service/valkey-cart", "runtime_reconfigured_by_job"),
    ("63", "otel-demo/Secret/email-service-secret", "credentials_changed"),
    ("116", "otel-demo/Deployment/frontend", "latency_origin"),
    ("116", "otel-demo/Deployment/frontend", "object_flood"),
])
def test_detectors_find_the_fault(scenario, sid, entity, signal):
    snap, _ = scenario(sid)
    assert signal in signals(RCAEngine(snap), entity)


def test_noise_is_not_mistaken_for_change(scenario):
    snap, _ = scenario("20")
    eng = RCAEngine(snap)
    rollouts = [f.entity.name for f in eng.findings if f.signal == "rollout"]
    assert rollouts == ["product-catalog"]  # the days-old rollout in the noise is ignored
    assert not any(f.signal == "recent_oom" for f in eng.findings)  # the OOM from hours ago is ignored
    # The long-broken workload is found, but it is not part of this incident.
    assert "image_pull_failure" in signals(eng, "otel-demo/Deployment/legacy-exporter")
    chronic = [a for a in snap.firing_alerts() if pre_existing(eng.ix, a)]
    assert len(chronic) == 1
    assert incident_start(eng.ix) > eng.ix.start


def test_template_diff():
    old = {"metadata": {"labels": {"a": "1", "pod-template-hash": "x"}},
           "spec": {"containers": [{"name": "c", "image": "i:1", "env": [{"name": "A", "value": "1"}]}]}}
    new = {"metadata": {"labels": {"a": "2", "pod-template-hash": "y"}, "annotations": {"k": "v"}},
           "spec": {"dnsPolicy": "None", "containers": [{"name": "c", "image": "i:2", "env": [{"name": "A", "value": "2"}]}]}}
    d = template_diff(old, new)
    assert 'c.image: "i:1" -> "i:2"' in d and "c.env.A: '1' -> '2'" in d and 'spec.dnsPolicy: null -> "None"' in d
    assert "labels.a: '1' -> '2'" in d and "annotations.k: None -> 'v'" in d
    assert not any("pod-template-hash" in x for x in d)


EXPECTED = {
    "20": ["otel-demo/Deployment/product-catalog"], "30": ["otel-demo/Service/ad"],
    "31": ["otel-demo/NetworkPolicy/frontend-ingress", "otel-demo/Deployment/frontend"],
    "36": ["book-info/Service/details"], "43": ["otel-demo/Deployment/frontend"], "48": ["/Namespace/book-info"],
    "58": ["otel-demo/Deployment/accounting"],
    "102": ["otel-demo/ResourceQuota/strict-resource-quota", "otel-demo/Deployment/ad"],
    "114": ["otel-demo/Service/product-catalog"], "116": ["otel-demo/Deployment/frontend"],
    "47": ["book-info/AuthorizationPolicy/bookinfo-gateway-policy", "book-info/Gateway/bookinfo-gateway"],
    "50": ["book-info/PeerAuthentication/application", "book-info/Deployment/productpage-v1"],
    "59": ["otel-demo/Deployment/recommendation", "otel-demo/ConfigMap/recommendation-config"],
}


@pytest.mark.parametrize("sid", sorted(EXPECTED))
def test_rca_separates_root_cause_from_symptoms(scenario, sid):
    snap, gt = scenario(sid)
    d = diagnose(snap)
    assert sorted(d.entities()) == sorted(EXPECTED[sid])
    assert score(d.entities(), gt).itbench == 1.0
    assert not d.unexplained_alerts


def test_diagnosis_outputs(scenario):
    snap, _ = scenario("114")
    d = diagnose(snap)
    out = d.to_itbench()
    rc = [e for e in out["entities"] if e["contributing_factor"]]
    assert [e["name"] for e in rc] == ["otel-demo/Service/product-catalog"]
    assert any(not e["contributing_factor"] for e in out["entities"])  # symptoms are listed but not blamed
    assert out["propagations"] and all({"source", "target"} <= set(p) for p in out["propagations"])
    full = d.to_dict()
    assert full["root_causes"][0]["findings"] and full["alerts"][0]["explained_by"]
    pre = [a for a in full["alerts"] if a["pre_existing"]]
    assert pre and pre[0]["explained_by"] is None


def test_known_limitation_secret_vs_deployment(scenario):
    """ITBench scenario 34 blames the Deployment; the engine blames the rotated Secret. Documented, not patched."""
    snap, gt = scenario("34")
    assert diagnose(snap).entities() == ["otel-demo/Secret/valkey-credentials"]
    assert score(diagnose(snap).entities(), gt).itbench == 0.0
