from __future__ import annotations

from incident_agent.analysis.rca import RCAEngine
from incident_agent.analysis.timeline import build_timeline
from incident_agent.entities import Ref
from incident_agent.simulate.scenarios import scenario_ids
from incident_agent.snapshot import parse_time


def test_timeline_orders_changes_before_alerts(scenario):
    snap, _ = scenario("31")
    tl = build_timeline(RCAEngine(snap))
    times = [e.time for e in tl.entries]
    assert times == sorted(times)
    new_alerts = [parse_time(a["activeAt"]) for a in snap.firing_alerts() if a["labels"]["alertname"] != "KubePodNotReady"]
    assert tl.first_alert == min(new_alerts)
    policy = Ref("otel-demo", "NetworkPolicy", "frontend-ingress")
    assert tl.suspects[0].entity == policy and 0 < tl.suspects[0].lead_s < 600
    change = next(e for e in tl.entries if e.kind == "change" and e.entity == policy)
    assert {"root_cause", "on_alert_path", "suspect"} <= set(change.tags)
    old = next(e for e in tl.entries if e.kind == "alert" and "legacy-exporter" in e.summary)
    assert "pre_existing" in old.tags and old.time < tl.window[0]
    # The unrelated dashboard edit is on the timeline but no alert can reach it, so it is not a suspect.
    assert any("grafana-dashboards" in e.summary for e in tl.entries)
    assert all(s.entity.name != "grafana-dashboards" for s in tl.suspects)


def test_timeline_infers_deleted_service(scenario):
    snap, _ = scenario("114")
    tl = build_timeline(RCAEngine(snap))
    svc = Ref("otel-demo", "Service", "product-catalog")
    gone = next(e for e in tl.entries if e.kind == "change" and e.entity == svc)
    assert "disappeared" in gone.summary and "inferred" in gone.tags and gone.time < tl.first_alert
    assert tl.suspects[0].entity == svc


def test_timeline_merges_rollout_and_edit(scenario):
    snap, _ = scenario("20")
    tl = build_timeline(RCAEngine(snap))
    dep = Ref("otel-demo", "Deployment", "product-catalog")
    assert len([e for e in tl.entries if e.kind == "change" and e.entity == dep]) == 1
    assert [s.entity for s in tl.suspects] == [dep]


def test_timeline_filter_render_and_dict(scenario):
    snap, _ = scenario("59")
    tl = build_timeline(RCAEngine(snap))
    only = tl.filter(kinds={"change"})
    assert only and all(e.kind == "change" for e in only)
    lines = tl.render(limit=8)
    assert lines[0].startswith("T0 = first alert") and "(showing 8 of" in "\n".join(lines)
    assert any(" change " in ln for ln in lines)  # trimming keeps changes ahead of downstream errors
    d = tl.to_dict()
    assert d["suspects"][0]["entity"] == "otel-demo/Deployment/recommendation"
    assert all("offset_s" in e for e in d["entries"])


def test_timeline_suspects_point_at_root_causes(scenario):
    """Correlation is a hint, not the diagnosis, but on these scenarios the top change is usually right."""
    hits = total = 0
    for sid in scenario_ids():
        snap, gt = scenario(sid)
        tl = build_timeline(RCAEngine(snap))
        if tl.suspects:
            total += 1
            hits += str(tl.suspects[0].entity) in {e.label for e in gt.root_causes}
    assert total >= 25 and hits / total >= 0.75
