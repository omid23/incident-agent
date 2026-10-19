"""Separate root causes from symptoms.

Every firing alert is attached to an entity. From there the engine walks the dependency graph in
the direction the failure must have come from (downstream for errors and latency, upstream and
inbound for lost traffic, configuration and policy for pod failures) and collects entities with
evidence of a defect. It then picks the smallest set of defects that explains every alert, adds the
object a policy breaks when the policy targets it directly, and falls back to the deepest
misbehaving entity only when no defect can be found. Extra entities count against precision in
ITBench scoring, so the selection is deliberately strict.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from ..entities import WORKLOAD_KINDS, Ref
from ..snapshot import Snapshot
from .detectors import Finding, incident_start, pre_existing, run_detectors, unavailable_workloads
from .index import ClusterIndex

POD_ALERTS = {"KubePodNotReady", "KubePodCrashLooping", "KubeContainerWaiting", "KubeDeploymentReplicasMismatch",
              "KubeHpaMaxedOut", "KubeJobFailed", "KubeContainerOOMKilled"}
TRAFFIC_LOSS_ALERTS = {"NoRequestsReceived", "KafkaConsumerLagHigh"}
CO_REPORT = {"network_policy_blocks_ingress", "quota_exhausted", "strict_mtls_with_plaintext_workloads",
             "authorization_denies_all"}
CREDENTIAL_SIGNALS = {"dependency_auth_failure", "credentials_rejected"}
MAX_DEPTH = 10


@dataclass
class Candidate:
    entity: Ref
    score: float
    findings: list[Finding]
    explains: list[int] = field(default_factory=list)  # alert indexes
    reason: str = ""

    def to_dict(self) -> dict:
        return {"entity": str(self.entity), "score": round(self.score, 3), "reason": self.reason,
                "explains_alerts": self.explains, "findings": [f.to_dict() for f in self.findings]}


@dataclass
class Diagnosis:
    root_causes: list[Candidate]
    symptoms: list[Candidate]
    alerts: list[dict]
    chains: list[list[str]]
    findings: list[Finding]
    unexplained_alerts: list[int]
    incident_start: float

    def entities(self) -> list[str]:
        return [str(c.entity) for c in self.root_causes]

    def to_dict(self) -> dict:
        return {"root_causes": [c.to_dict() for c in self.root_causes],
                "symptoms": [c.to_dict() for c in self.symptoms[:10]],
                "alerts": self.alerts, "propagation": self.chains, "unexplained_alerts": self.unexplained_alerts,
                "findings": [f.to_dict() for f in self.findings]}

    def to_itbench(self) -> dict:
        """The agent output shape the ITBench judge reads (entities with contributing_factor, propagations)."""
        ents, seen = [], set()
        for c in self.root_causes:
            ents.append({"id": f"e{len(ents) + 1}", "name": str(c.entity), "contributing_factor": True,
                         "reasoning": c.reason, "evidence": "; ".join(f.summary for f in c.findings[:3])})
            seen.add(str(c.entity))
        for c in self.symptoms[:6]:
            if str(c.entity) not in seen:
                ents.append({"id": f"e{len(ents) + 1}", "name": str(c.entity), "contributing_factor": False,
                             "reasoning": c.reason, "evidence": "; ".join(f.summary for f in c.findings[:2])})
                seen.add(str(c.entity))
        props = []
        for chain in self.chains:
            for a, b in zip(chain, chain[1:], strict=False):
                p = {"source": a, "target": b, "condition": "failure", "effect": "propagated"}
                if p not in props:
                    props.append(p)
        return {"entities": ents, "propagations": props,
                "alerts_explained": [a["alertname"] for a in self.alerts if a.get("explained_by")]}


class RCAEngine:
    def __init__(self, snap: Snapshot):
        self.snap = snap
        self.ix = ClusterIndex(snap)
        self.findings = run_detectors(self.ix)
        self.by_entity: dict[Ref, list[Finding]] = defaultdict(list)
        for f in self.findings:
            self.by_entity[f.entity].append(f)
        self.unavailable = unavailable_workloads(self.ix)
        self._promote_credentials()

    # -- scoring ------------------------------------------------------------------------------------

    def _promote_credentials(self) -> None:
        """Credential errors + a Secret that changed during the incident and is used by the failing side."""
        implicated: set[Ref] = set()
        for f in self.findings:
            if f.signal in CREDENTIAL_SIGNALS:
                implicated.add(f.entity)
                for (caller, callee) in self.ix.call_edges:
                    if caller == f.entity:
                        implicated.update(self.ix.service_backends.get(callee) or [])
        for w in list(implicated):
            for ref, how in self.ix.config_refs(w):
                if ref.kind != "Secret":
                    continue
                if any(x.signal == "recent_change" for x in self.by_entity.get(ref, [])):
                    users = [u for u in self.ix.workloads if any(r == ref for r, _ in self.ix.config_refs(u))]
                    f = Finding(ref, "credentials_changed", "defect", 0.75,
                                f"Secret {ref.name} changed during the incident and {w.name} ({how}) now fails to "
                                "authenticate", [x.summary for x in self.by_entity[ref] if x.signal == "recent_change"][:1],
                                related=users)
                    self.findings.append(f)
                    self.by_entity[ref].append(f)

    def score(self, ref: Ref) -> tuple[float, float]:
        """(cause score, symptom score), combining findings with a noisy-or."""
        defect = change = symptom = 0.0
        for f in self.by_entity.get(ref, []):
            if f.role == "defect":
                defect = 1 - (1 - defect) * (1 - f.weight)
            elif f.role == "change":
                change = 1 - (1 - change) * (1 - f.weight)
            elif f.role == "symptom":
                symptom = 1 - (1 - symptom) * (1 - f.weight)
        cause = defect + 0.35 * change * (1 - defect) if defect else 0.35 * change
        return cause, symptom

    # -- dependency graph ---------------------------------------------------------------------------

    def deps(self, ref: Ref, mode: str) -> list[tuple[Ref, str]]:
        ix = self.ix
        out: list[tuple[Ref, str]] = []
        if ref.kind == "Service":
            out += [(w, "routes to") for w in ix.service_backends.get(ref, [])]
            if ref not in self.snap.by_ref:
                out += [(w, "named like") for w in ix.workloads if w.namespace == ref.namespace and w.name == ref.name]
        elif ref.kind in WORKLOAD_KINDS:
            if mode in ("errors", "traffic"):
                out += [(c, "calls") for c in ix.callees(ref)]
            out += [(r, f"uses ({how})") for r, how in ix.config_refs(ref)]
            out += [(p, "governed by") for p in ix.policies_for(ref)]
            if ref in ix.gateway_of_workload:
                gw = ix.gateway_of_workload[ref]
                out.append((gw, "implements"))
            if ref.namespace:
                out.append((Ref("", "Namespace", ref.namespace), "runs in"))
            if mode == "traffic":
                out += [(s, "fronted by") for s in ix.services_of.get(ref, [])]
                named = Ref(ref.namespace, "Service", ref.name)
                if named not in self.snap.by_ref and any(callee == named for (_c, callee) in ix.call_edges):
                    out.append((named, "fronted by"))
                out += [(c, "called by") for c in ix.callers(ref)]
        elif ref.kind == "Gateway":
            out += [(p, "governed by") for p in ix.gateway_policies(ref)]
        elif ref.kind == "HorizontalPodAutoscaler":
            tgt = (self.snap.get(ref) or {}).get("spec", {}).get("scaleTargetRef", {})
            if tgt.get("name"):
                out.append((Ref(ref.namespace, tgt.get("kind", "Deployment"), tgt["name"]), "scales"))
        return out

    def reach(self, start: Ref, mode: str) -> dict[Ref, tuple[int, Ref | None, str]]:
        """BFS from an alerted entity: entity -> (distance, parent, relation)."""
        seen: dict[Ref, tuple[int, Ref | None, str]] = {start: (0, None, "")}
        q = deque([start])
        while q:
            cur = q.popleft()
            d = seen[cur][0]
            if d >= MAX_DEPTH:
                continue
            # Traffic loss looks upstream first, then the callers' own dependencies.
            step_mode = mode
            for nxt, rel in self.deps(cur, step_mode):
                if nxt not in seen:
                    seen[nxt] = (d + 1, cur, rel)
                    q.append(nxt)
        return seen

    # -- diagnosis -----------------------------------------------------------------------------------

    def diagnose(self, max_causes: int = 4) -> Diagnosis:
        alerts = self.snap.firing_alerts()
        alert_rows, reach_sets = [], []
        for i, a in enumerate(alerts):
            ent = self.ix.alert_entity(a)
            name = a.get("labels", {}).get("alertname", "")
            mode = "pod" if name in POD_ALERTS else "traffic" if name in TRAFFIC_LOSS_ALERTS else "errors"
            old = pre_existing(self.ix, a)
            alert_rows.append({"index": i, "alertname": name, "entity": str(ent) if ent else None,
                               "labels": a.get("labels", {}), "explained_by": None, "pre_existing": old,
                               "active_at": a.get("activeAt")})
            reach_sets.append(self.reach(ent, mode) if ent and not old else {})

        cands: dict[Ref, Candidate] = {}
        for i, r in enumerate(reach_sets):
            for ref in r:
                cause, _ = self.score(ref)
                if cause >= 0.5:
                    c = cands.setdefault(ref, Candidate(ref, cause, self.by_entity.get(ref, [])))
                    c.explains.append(i)

        # Greedy set cover: most alerts explained first, then the strongest evidence, then closest to the alert.
        uncovered = {r["index"] for r in alert_rows if not r["pre_existing"]}
        chosen: list[Candidate] = []
        while uncovered and len(chosen) < max_causes:
            def rank(c: Candidate, uncovered: set[int] = uncovered) -> tuple:
                gain = len(set(c.explains) & uncovered)
                dist = min(reach_sets[i][c.entity][0] for i in c.explains)
                return (gain > 0, round(c.score, 2), gain, -dist)

            pool = [c for c in cands.values() if set(c.explains) & uncovered and c not in chosen]
            if not pool:
                break
            best = max(pool, key=rank)
            chosen.append(best)
            uncovered -= set(best.explains)

        # Alerts with no defect behind them: blame the deepest misbehaving entity.
        for i in sorted(uncovered):
            r = reach_sets[i]
            if not r:
                continue
            ranked = sorted(r.items(), key=lambda kv: (self._symptom_rank(kv[0]), kv[1][0]), reverse=True)
            ref, (dist, _, _) = ranked[0]
            if self._symptom_rank(ref) <= 0:
                ref = next(iter(r))
            ref = self._prefer_workload(ref)
            existing = next((c for c in chosen if c.entity == ref), None)
            if existing:
                existing.explains.append(i)
            else:
                cause, symptom = self.score(ref)
                chosen.append(Candidate(ref, max(cause, symptom * 0.6), self.by_entity.get(ref, []), [i],
                                        reason="no misconfiguration found; this is where the failure starts"))
            uncovered.discard(i)

        chosen = self._co_report(chosen, reach_sets)
        for c in chosen:
            if not c.reason:
                c.reason = self._explain(c)
            for i in c.explains:
                if alert_rows[i]["explained_by"] is None:
                    alert_rows[i]["explained_by"] = str(c.entity)

        chains = []
        for c in chosen:
            for i in c.explains[:3]:
                chain = self._path(reach_sets[i], c.entity)
                if chain and chain not in chains:
                    chains.append(chain)
        symptoms = []
        chosen_refs = {c.entity for c in chosen}
        for ref, fs in self.by_entity.items():
            if ref in chosen_refs:
                continue
            _, s = self.score(ref)
            if s >= 0.3:
                symptoms.append(Candidate(ref, s, fs, reason="affected by the root cause"))
        symptoms.sort(key=lambda c: -c.score)
        return Diagnosis(chosen, symptoms, alert_rows, chains, self.findings,
                         [r["index"] for r in alert_rows if r["explained_by"] is None and not r["pre_existing"]],
                         incident_start(self.ix))

    def _symptom_rank(self, ref: Ref) -> float:
        fs = self.by_entity.get(ref, [])
        origin = max((f.weight for f in fs if f.signal in ("error_origin", "latency_origin")), default=0.0)
        cause, symptom = self.score(ref)
        return origin * 2 + symptom + cause

    def _prefer_workload(self, ref: Ref) -> Ref:
        """An existing Service whose calls fail at the application level: blame the workload behind it."""
        if ref.kind == "Service" and ref in self.snap.by_ref:
            backends = self.ix.service_backends.get(ref) or []
            if len(backends) == 1 and not any(f.role == "defect" for f in self.by_entity.get(ref, [])):
                return backends[0]
        return ref

    def _co_report(self, chosen: list[Candidate], reach_sets: list[dict]) -> list[Candidate]:
        """A policy that targets a specific object breaks that object: report both."""
        out = list(chosen)
        refs = {c.entity for c in out}

        def add(ref: Ref, why: str, explains: list[int]) -> None:
            if ref not in refs and (ref in self.snap.by_ref):
                refs.add(ref)
                cause, symptom = self.score(ref)
                out.append(Candidate(ref, max(cause, 0.5), self.by_entity.get(ref, []), list(explains), reason=why))

        for c in chosen:
            for f in c.findings:
                if f.signal in CO_REPORT:
                    for r in f.related:
                        if r.kind in WORKLOAD_KINDS and f.signal == "quota_exhausted" and r not in self.unavailable:
                            continue
                        add(r, f"targeted by {c.entity.kind} {c.entity.name}: {f.summary}", c.explains)
            if c.entity.kind in WORKLOAD_KINDS:
                failing_init = any(f.signal in ("init_container_crash", "container_config_error") for f in c.findings)
                for ref, how in self.ix.config_refs(c.entity):
                    if not failing_init or "init container" not in how and "env" not in how:
                        continue
                    changed = [f for f in self.by_entity.get(ref, []) if f.signal == "recent_change"]
                    if changed or ref not in self.snap.by_ref:
                        add(ref, f"{c.entity.name} fails in its {how}, which comes from {ref.kind} {ref.name}"
                                 + (" (changed during the incident)" if changed else " (missing)"), c.explains)
                for f in c.findings:
                    if f.signal == "no_pods":
                        for r in f.related:
                            add(r, f"blocks pod creation for {c.entity.name}", c.explains)
        return out

    def _explain(self, c: Candidate) -> str:
        defects = [f for f in c.findings if f.role == "defect"]
        main = max(defects or c.findings or [Finding(c.entity, "none", "context", 0, "no direct evidence")],
                   key=lambda f: f.weight)
        return main.summary

    @staticmethod
    def _path(r: dict, target: Ref) -> list[str]:
        if target not in r:
            return []
        path = [target]
        cur = target
        while r[cur][1] is not None:
            cur = r[cur][1]
            path.append(cur)
        return [str(x) for x in path]  # root cause first, alerted entity last


def diagnose(snap: Snapshot) -> Diagnosis:
    return RCAEngine(snap).diagnose()
