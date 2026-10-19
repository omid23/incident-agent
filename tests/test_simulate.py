from __future__ import annotations

import json

import pytest

from incident_agent.entities import Ref
from incident_agent.simulate.faults import MECHANISMS
from incident_agent.simulate.scenarios import fault_definition, load_specs, scenario_ids
from incident_agent.snapshot import Snapshot, load_snapshot, parse_time


def test_specs_cover_itbench_library():
    specs = load_specs()
    assert len(specs) == 30
    assert all(f in MECHANISMS for s in specs.values() for f in s.fault_ids)
    assert all(fault_definition(f).get("name") for s in specs.values() for f in s.fault_ids)
    dev, test = scenario_ids("dev"), scenario_ids("test")
    assert len(dev) == len(test) == 15
    # The split is by fault mechanism: no mechanism appears on both sides.
    dev_faults = {f for s in dev for f in specs[s].fault_ids}
    test_faults = {f for s in test for f in specs[s].fault_ids}
    combos = {"+".join(specs[s].fault_ids) for s in dev} & {"+".join(specs[s].fault_ids) for s in test}
    assert not combos
    assert dev_faults and test_faults


@pytest.mark.parametrize("sid", scenario_ids())
def test_every_scenario_builds_with_alerts(scenario, sid):
    snap, gt = scenario(sid)
    assert snap.firing_alerts(), f"scenario {sid} fires no alerts"
    assert gt.root_causes
    assert len(snap.spans) > 1000 and snap.events and snap.logs
    kinds = snap.stats()["kinds"]
    assert {"Deployment", "Pod", "Service", "ReplicaSet", "Node", "Namespace"} <= set(kinds)


def test_deterministic_per_seed(fresh):
    a, _ = fresh("30", 1)
    b, _ = fresh("30", 1)
    c, _ = fresh("30", 2)
    dump = lambda s: json.dumps([s.objects, s.alerts, s.spans[:200]], sort_keys=True)  # noqa: E731
    assert dump(a) == dump(b)
    assert dump(a) != dump(c)


def test_alerts_fire_on_symptoms_not_on_the_fault(scenario):
    snap, gt = scenario("114")  # deleted product-catalog Service
    assert Ref("otel-demo", "Service", "product-catalog") not in snap.by_ref
    names = {a["labels"].get("service_name") for a in snap.firing_alerts()}
    assert "frontend" in names and "product-catalog" not in {a["labels"].get("pod") for a in snap.firing_alerts()}
    msgs = [s["status_message"] for s in snap.spans if s["status"] == "ERROR"]
    assert any("no such host" in m or "Name resolution failed" in m for m in msgs)


def test_stuck_rollout_keeps_old_pods_serving(scenario):
    snap, _ = scenario("20")  # bad image on product-catalog
    pods = [p for p in snap.of_kind("Pod", "otel-demo") if p["metadata"]["name"].startswith("product-catalog-")]
    states = sorted(next(iter(p["status"]["containerStatuses"][0]["state"])) for p in pods)
    assert states == ["running", "waiting"]
    assert len({p["metadata"]["ownerReferences"][0]["name"] for p in pods}) == 2


def test_noise_is_present_and_old(scenario):
    snap, _ = scenario("30")
    start = parse_time(snap.meta["window_start"])
    chronic = [a for a in snap.firing_alerts() if parse_time(a["activeAt"]) < start]
    assert chronic and chronic[0]["labels"]["pod"].startswith("legacy-exporter-")
    assert Ref("otel-demo", "Service", "jaeger-agent") in snap.by_ref
    warn = [r for r in snap.logs if r["service"] in ("otel-collector", "load-generator", "kafka")]
    assert warn


def test_save_and_load_roundtrip(scenario, tmp_path):
    snap, _ = scenario("36")
    snap.save(tmp_path / "s")
    back = load_snapshot(tmp_path / "s")
    assert isinstance(back, Snapshot)
    assert back.stats() == snap.stats()
    assert back.meta["scenario"] == "36"
    with pytest.raises(FileNotFoundError):
        load_snapshot(tmp_path / "missing")
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError):
        load_snapshot(tmp_path / "empty")


@pytest.mark.parametrize("value,expected", [
    ("2026-09-01T10:00:00Z", 1788256800.0), ("2026-09-01 10:00:00.123456789", 1788256800.123456),
    (1788256800, 1788256800.0), (1788256800123, 1788256800.123), ("", None), ("garbage", None),
])
def test_parse_time(value, expected):
    got = parse_time(value)
    assert (got is None and expected is None) or got == pytest.approx(expected, abs=1e-3)
