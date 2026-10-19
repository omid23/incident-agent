"""Evidence detectors. Each looks at one kind of signal and reports findings about specific entities.

A finding's ``role`` says what it can prove:

* ``defect``   the entity itself is misconfigured or broken (a bad image, a deny-all policy, a missing Service)
* ``change``   the entity changed recently (suspicious, not proof)
* ``symptom``  the entity is misbehaving (errors, latency, no traffic) but that may be inherited
* ``context``  useful background that should not be reported as a root cause on its own
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ..entities import WORKLOAD_KINDS, Ref
from ..snapshot import parse_time
from .index import ClusterIndex, _template, is_ready, selector_matches


@dataclass
class Finding:
    entity: Ref
    signal: str
    role: str  # defect | change | symptom | context
    weight: float
    summary: str
    evidence: list[str] = field(default_factory=list)
    related: list[Ref] = field(default_factory=list)  # entities this finding implicates or affects
    time: float | None = None

    def to_dict(self) -> dict:
        return {"entity": str(self.entity), "signal": self.signal, "role": self.role, "weight": round(self.weight, 2),
                "summary": self.summary, "evidence": self.evidence[:4], "related": [str(r) for r in self.related]}


def incident_start(ix: ClusterIndex) -> float:
    """When the incident began: a few minutes before the first alert went active."""
    times = [parse_time(a.get("activeAt")) for a in ix.snap.firing_alerts()]
    times = [t for t in times if t and t >= ix.start - 600]  # alerts firing for days are not this incident
    if times:
        return max(ix.start, min(times) - 8 * 60)
    return ix.start + (ix.end - ix.start) / 2


def _last_modified(obj: dict) -> float | None:
    md = obj.get("metadata", {})
    times = [parse_time(f.get("time")) for f in md.get("managedFields") or []]
    times.append(parse_time(md.get("creationTimestamp")))
    times = [t for t in times if t]
    return max(times) if times else None


def _created(obj: dict) -> float | None:
    return parse_time(obj.get("metadata", {}).get("creationTimestamp"))


# -- pods and workloads -------------------------------------------------------------------------------

def pod_failures(ix: ClusterIndex) -> list[Finding]:
    out: list[Finding] = []
    for w in ix.workloads:
        pods = [p for p in ix.pods_by_workload.get(w, []) if p.get("status", {}).get("phase") not in ("Succeeded",)]
        if not pods:
            continue
        for p in pods:
            name = p["metadata"]["name"]
            st = p.get("status", {})
            ev = ix.snap.events_for(Ref.of(p))
            for cs in st.get("initContainerStatuses") or []:
                state = cs.get("state") or {}
                if (state.get("waiting") or {}).get("reason") == "CrashLoopBackOff":
                    last = (cs.get("lastState") or {}).get("terminated") or {}
                    out.append(Finding(w, "init_container_crash", "defect", 0.9,
                                       f"init container {cs['name']} of {name} is crash-looping "
                                       f"(exit {last.get('exitCode')}: {last.get('message') or last.get('reason') or 'error'})",
                                       [f"pod {name}: init container {cs['name']} CrashLoopBackOff, {cs.get('restartCount', 0)} restarts"]))
                elif "running" in state and st.get("phase") == "Pending":
                    out.append(Finding(w, "init_container_hang", "defect", 0.85,
                                       f"init container {cs['name']} of {name} never finishes; the app container cannot start",
                                       [f"pod {name}: Init:0/1, {cs['name']} running since {state['running'].get('startedAt')}"]))
            for cs in st.get("containerStatuses") or []:
                waiting = (cs.get("state") or {}).get("waiting") or {}
                reason = waiting.get("reason", "")
                last = (cs.get("lastState") or {}).get("terminated") or {}
                if reason in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName"):
                    pull = [e["message"] for e in ev if e.get("reason") == "Failed" and "pull" in e.get("message", "")]
                    out.append(Finding(w, "image_pull_failure", "defect", 0.95,
                                       f"pod {name} cannot pull image {cs.get('image')}",
                                       (pull[:1] or [waiting.get("message", reason)])))
                elif reason == "CrashLoopBackOff":
                    why = last.get("reason", "Error")
                    signal = {"OOMKilled": "oom_killed", "StartError": "container_start_error",
                              "ContainerCannotRun": "container_start_error"}.get(why, "crash_loop")
                    out.append(Finding(w, signal, "defect", 0.9,
                                       f"container {cs['name']} in {name} is crash-looping ({why}, exit {last.get('exitCode')}, "
                                       f"{cs.get('restartCount', 0)} restarts)",
                                       [last.get("message") or f"lastState.terminated.reason={why}"]))
                elif reason in ("CreateContainerConfigError", "CreateContainerError", "RunContainerError"):
                    out.append(Finding(w, "container_config_error", "defect", 0.9,
                                       f"pod {name}: {reason}", [waiting.get("message", reason)]))
                elif "running" in (cs.get("state") or {}) and not cs.get("ready") and st.get("phase") == "Running":
                    probe = [e["message"] for e in ev if e.get("reason") == "Unhealthy"]
                    if probe:
                        out.append(Finding(w, "readiness_probe_failing", "defect", 0.85,
                                           f"pod {name} is running but never becomes ready", probe[:1]))
                if last.get("reason") == "OOMKilled" and reason != "CrashLoopBackOff":
                    finished = parse_time(last.get("finishedAt"))
                    if finished and finished >= ix.start:
                        out.append(Finding(w, "recent_oom", "symptom", 0.4, f"{name} was OOM-killed recently",
                                           [f"finishedAt {last.get('finishedAt')}"]))
            if st.get("phase") == "Pending" and not st.get("containerStatuses") and not st.get("initContainerStatuses"):
                cond = next((c for c in st.get("conditions", []) if c.get("type") == "PodScheduled"), {})
                msg = cond.get("message") or next((e["message"] for e in ev if e.get("reason") == "FailedScheduling"), "")
                related: list[Ref] = []
                m = re.search(r'persistentvolumeclaim "([^"]+)" not found', msg)
                if m:
                    related.append(Ref(w.namespace, "PersistentVolumeClaim", m.group(1)))
                if "were unschedulable" in msg:
                    related += [Ref("", "Node", n["metadata"]["name"]) for n in ix.snap.of_kind("Node")
                                if n.get("spec", {}).get("unschedulable")]
                preempted = [e for e in ix.snap.events if e.get("reason") == "Preempted"
                             and ix.workload_of(Ref(e["involvedObject"].get("namespace", ""), "Pod",
                                                    e["involvedObject"]["name"])) == w]
                if preempted:
                    out.append(Finding(w, "preempted", "defect", 0.6,
                                       f"{w.name} was preempted by a higher-priority workload and cannot be rescheduled",
                                       [preempted[0]["message"]]))
                out.append(Finding(w, "unschedulable", "defect", 0.9, f"pod {name} cannot be scheduled",
                                   [msg] if msg else ["phase Pending, PodScheduled=False"], related))
    # Workloads with no pods at all
    for w in ix.workloads:
        obj = ix.snap.get(w) or {}
        spec_replicas = obj.get("spec", {}).get("replicas")
        if w.kind != "Deployment":
            continue
        pods = ix.pods_by_workload.get(w, [])
        if spec_replicas == 0:
            changed = _last_modified(obj)
            recent = changed is not None and changed >= ix.start
            scaled = [e["message"] for e in ix.snap.events_for(w) if "Scaled down" in e.get("message", "")]
            out.append(Finding(w, "scaled_to_zero", "defect" if recent or scaled else "context", 0.9 if recent else 0.3,
                               f"{w.name} is scaled to 0 replicas", scaled[:1] or ["spec.replicas=0"]))
        elif not pods and spec_replicas:
            fails = [e["message"] for e in ix.snap.events if e.get("reason") == "FailedCreate"
                     and ix.workload_of(Ref(e["involvedObject"].get("namespace", ""), "ReplicaSet",
                                            e["involvedObject"]["name"])) == w]
            related = []
            for f in fails:
                m = re.search(r"exceeded quota: ([\w.-]+)", f)
                if m:
                    related.append(Ref(w.namespace, "ResourceQuota", m.group(1)))
            out.append(Finding(w, "no_pods", "defect", 0.8,
                               f"{w.name} wants {spec_replicas} replica(s) but has no pods", fails[:1] or [], related))
    return out


def unavailable_workloads(ix: ClusterIndex) -> set[Ref]:
    """Workloads with no ready pod (as opposed to a stuck rollout where old pods still serve)."""
    out = set()
    for w in ix.workloads:
        obj = ix.snap.get(w) or {}
        if w.kind == "Job" or obj.get("spec", {}).get("replicas") == 0:
            continue
        pods = ix.pods_by_workload.get(w, [])
        if not any(is_ready(p) for p in pods):
            out.add(w)
    return out


# -- what changed ----------------------------------------------------------------------------------

_DIFF_PATHS = [
    ("image", lambda c: c.get("image")), ("command", lambda c: c.get("command")), ("args", lambda c: c.get("args")),
    ("env", lambda c: {e["name"]: e.get("value", json.dumps(e.get("valueFrom"))) for e in c.get("env") or []}),
    ("resources", lambda c: c.get("resources")), ("readinessProbe", lambda c: c.get("readinessProbe")),
    ("livenessProbe", lambda c: c.get("livenessProbe")), ("ports", lambda c: c.get("ports")),
]
_POD_PATHS = ["nodeSelector", "affinity", "dnsPolicy", "dnsConfig", "initContainers", "volumes", "tolerations",
              "priorityClassName", "serviceAccountName", "hostNetwork"]


def template_diff(old: dict, new: dict) -> list[str]:
    changes = []
    os_, ns_ = old.get("spec", {}), new.get("spec", {})
    for oc, nc in zip(os_.get("containers") or [], ns_.get("containers") or [], strict=False):
        for label, get in _DIFF_PATHS:
            a, b = get(oc), get(nc)
            if a != b:
                if label == "env" and isinstance(a, dict) and isinstance(b, dict):
                    for k in sorted(set(a) | set(b)):
                        if a.get(k) != b.get(k):
                            changes.append(f"{nc['name']}.env.{k}: {a.get(k)!r} -> {b.get(k)!r}")
                else:
                    changes.append(f"{nc['name']}.{label}: {json.dumps(a)} -> {json.dumps(b)}")
    for key in _POD_PATHS:
        if os_.get(key) != ns_.get(key):
            changes.append(f"spec.{key}: {json.dumps(os_.get(key))} -> {json.dumps(ns_.get(key))}")
    ol, nl = old.get("metadata", {}).get("labels", {}), new.get("metadata", {}).get("labels", {})
    for k in sorted(set(ol) | set(nl)):
        if k != "pod-template-hash" and ol.get(k) != nl.get(k):
            changes.append(f"labels.{k}: {ol.get(k)!r} -> {nl.get(k)!r}")
    oa, na = old.get("metadata", {}).get("annotations") or {}, new.get("metadata", {}).get("annotations") or {}
    for k in sorted(set(oa) | set(na)):
        if oa.get(k) != na.get(k):
            changes.append(f"annotations.{k}: {oa.get(k)!r} -> {na.get(k)!r}")
    return changes


def rollouts(ix: ClusterIndex) -> list[Finding]:
    out = []
    for w in ix.workloads:
        rss = ix.replicasets(w)
        if len(rss) < 2:
            continue
        new, old = rss[-1], rss[-2]
        created = _created(new)
        if created is None or created < ix.start - 3600:
            continue
        diff = template_diff(old["spec"]["template"], new["spec"]["template"])
        if not diff:
            continue
        restart_only = all(d.startswith("annotations.kubectl.kubernetes.io/restartedAt") for d in diff)
        out.append(Finding(w, "restart" if restart_only else "rollout", "change", 0.15 if restart_only else 0.45,
                           f"{w.name} was {'restarted' if restart_only else 'changed'} at {new['metadata']['creationTimestamp']} "
                           f"(revision {(new['metadata'].get('annotations') or {}).get('deployment.kubernetes.io/revision')})",
                           diff[:6], time=created))
    return out


CHANGE_KINDS = {"ConfigMap", "Secret", "Service", "NetworkPolicy", "ResourceQuota", "HorizontalPodAutoscaler",
                "Node", "Namespace", "PeerAuthentication", "AuthorizationPolicy", "PriorityClass", "Gateway",
                "HTTPRoute", "VirtualService", "Deployment", "StatefulSet", "DaemonSet", "Job", "PersistentVolumeClaim"}


def recent_changes(ix: ClusterIndex) -> list[Finding]:
    out = []
    created_by_prefix: dict[tuple[str, str, str], list[Ref]] = defaultdict(list)
    for ref, obj in ix.snap.by_ref.items():
        if ref.kind not in CHANGE_KINDS:
            continue
        t = _last_modified(obj)
        if t is None or t < ix.start:
            continue
        created = _created(obj)
        what = "created" if created and created >= ix.start else "modified"
        manager = ((obj["metadata"].get("managedFields") or [{}])[-1]).get("manager", "")
        if ref.kind == "ConfigMap" and what == "created":
            prefix = re.sub(r"[-_.]?\d+$", "", ref.name)
            created_by_prefix[(ref.namespace, ref.kind, prefix)].append(ref)
        out.append(Finding(ref, "recent_change", "change", 0.3,
                           f"{ref.kind} {ref.name} was {what} at {_iso(t)} by {manager or 'unknown'}",
                           [f"{what} {_iso(t)} ({manager})"], time=t))
    # A burst of generated objects: report the burst once, attributed to the workload its names point at.
    for (ns, kind, prefix), refs in created_by_prefix.items():
        if len(refs) < 25:
            continue
        refs_set = set(refs)
        out = [f for f in out if f.entity not in refs_set]
        owner = next((w for w in ix.workloads if w.namespace == ns and prefix.startswith(w.name + "-")), None)
        ev = [f"{len(refs)} {kind}s named {prefix}-* created during the window"]
        out.append(Finding(owner or refs[0], "object_flood", "change" if owner else "context", 0.5,
                           f"{len(refs)} {kind}s created in bulk ({prefix}-*): etcd and API server pressure", ev,
                           related=refs[:3]))
    return out


def _iso(t: float) -> str:
    from ..snapshot import iso

    return iso(t)


# -- Services, policies and references ------------------------------------------------------------------

def services(ix: ClusterIndex) -> list[Finding]:
    out = []
    for svc in ix.snap.of_kind("Service"):
        ref = Ref.of(svc)
        sel = svc.get("spec", {}).get("selector")
        if not sel:
            continue
        backends = ix.service_backends.get(ref) or []
        if not backends:
            near = [w for w in ix.workloads if w.namespace == ref.namespace and
                    (w.name == ref.name or w.name.startswith(ref.name + "-"))]
            labels = {str(w): ix.template(w).get("metadata", {}).get("labels") for w in near}
            out.append(Finding(ref, "service_no_endpoints", "defect", 0.9,
                               f"Service {ref.name} selects no pods (selector {sel})",
                               [f"selector {json.dumps(sel)}"] + [f"{k} labels {json.dumps(v)}" for k, v in labels.items()][:2],
                               related=near))
            continue
        ports = {p.get("containerPort") for w in backends for c in ix.template(w).get("spec", {}).get("containers", [])
                 for p in c.get("ports") or []}
        names = {p.get("name") for w in backends for c in ix.template(w).get("spec", {}).get("containers", [])
                 for p in c.get("ports") or []}
        for p in svc.get("spec", {}).get("ports", []):
            tp = p.get("targetPort", p.get("port"))
            if (isinstance(tp, int) and ports and tp not in ports) or (isinstance(tp, str) and names and tp not in names):
                out.append(Finding(ref, "service_port_mismatch", "defect", 0.9,
                                   f"Service {ref.name} targets port {tp}, but its pods listen on {sorted(x for x in ports if x)}",
                                   [f"port {p.get('port')} -> targetPort {tp}"], related=backends))
    # Hostnames that callers use but no Service provides.
    seen: dict[Ref, list[str]] = defaultdict(list)
    for (caller, callee), edge in ix.call_edges.items():
        if callee.kind == "Service" and callee not in ix.snap.by_ref and callee.namespace:
            seen[callee].append(f"{caller.name} calls {edge.host}" + (f" ({edge.errors}/{edge.calls} failed)" if edge.calls else ""))
    for ref, ev in seen.items():
        workload = next((w for w in ix.workloads if w.namespace == ref.namespace and w.name == ref.name), None)
        if workload is None and not any("failed" in e for e in ev):
            continue  # an external dependency, not something deleted
        out.append(Finding(ref, "missing_service", "defect", 0.9,
                           f"Service {ref.name} does not exist, but {len(ev)} workload(s) depend on it",
                           ev[:3] + ([f"Deployment {workload.name} exists with no Service in front of it"] if workload else []),
                           related=[workload] if workload else []))
    return out


def policies(ix: ClusterIndex) -> list[Finding]:
    out = []
    for np in ix.snap.of_kind("NetworkPolicy"):
        ref = Ref.of(np)
        spec = np.get("spec", {})
        if "Ingress" not in (spec.get("policyTypes") or ["Ingress"]):
            continue
        ingress = spec.get("ingress")
        targets = [w for w in ix.workloads if w.namespace == ref.namespace and
                   (spec.get("podSelector") == {} or
                    selector_matches(spec.get("podSelector"), ix.template(w).get("metadata", {}).get("labels")))]
        if not targets:
            continue
        blocked = []
        if not ingress:
            blocked = targets
        else:
            allowed = {p.get("port") for rule in ingress for p in rule.get("ports") or []}
            if allowed:
                for w in targets:
                    ports = {p.get("containerPort") for c in ix.template(w).get("spec", {}).get("containers", [])
                             for p in c.get("ports") or []}
                    if ports and not ports & allowed:
                        blocked.append(w)
        if blocked:
            out.append(Finding(ref, "network_policy_blocks_ingress", "defect", 0.9,
                               f"NetworkPolicy {ref.name} blocks all ingress to {', '.join(w.name for w in blocked)}",
                               [f"podSelector {json.dumps(spec.get('podSelector'))}, ingress {json.dumps(ingress)}"],
                               related=blocked))
    for q in ix.snap.of_kind("ResourceQuota"):
        ref = Ref.of(q)
        hard, used = q.get("status", {}).get("hard", {}), q.get("status", {}).get("used", {})
        over = [k for k in hard if _qty(used.get(k, "0")) >= _qty(hard[k])]
        denied = [e for e in ix.snap.events if e.get("reason") == "FailedCreate" and f"exceeded quota: {ref.name}" in e.get("message", "")]
        if over or denied:
            affected = sorted({ix.workload_of(Ref(e["involvedObject"].get("namespace", ""), "ReplicaSet",
                                                  e["involvedObject"]["name"])) for e in denied})
            out.append(Finding(ref, "quota_exhausted", "defect", 0.9 if denied else 0.4,
                               f"ResourceQuota {ref.name} is exhausted ({', '.join(over) or 'limits'})"
                               + (f" and blocks pod creation for {', '.join(w.name for w in affected)}" if affected else ""),
                               [denied[0]["message"]] if denied else [f"used {used} >= hard {hard}"], related=affected))
    for h in ix.snap.of_kind("HorizontalPodAutoscaler"):
        ref = Ref.of(h)
        spec, st = h.get("spec", {}), h.get("status", {})
        cur = st.get("currentReplicas")
        tgt_util = _hpa_target(spec)
        cur_util = _hpa_current(st)
        if cur is not None and cur >= spec.get("maxReplicas", 1 << 30) and cur_util is not None and tgt_util is not None \
                and cur_util > tgt_util:
            out.append(Finding(ref, "hpa_maxed_out", "defect", 0.85,
                               f"HPA {ref.name} is pinned at maxReplicas={spec.get('maxReplicas')} with CPU at {cur_util}% "
                               f"against a {tgt_util}% target",
                               [f"minReplicas {spec.get('minReplicas')}, maxReplicas {spec.get('maxReplicas')}"],
                               related=[Ref(ref.namespace, spec.get("scaleTargetRef", {}).get("kind", "Deployment"),
                                            spec.get("scaleTargetRef", {}).get("name", ""))]))
    for pa in ix.snap.of_kind("PeerAuthentication"):
        ref = Ref.of(pa)
        if (pa.get("spec", {}).get("mtls") or {}).get("mode") != "STRICT":
            continue
        outside = []
        for w in ix.workloads:
            if w.namespace != ref.namespace:
                continue
            labels = ix.template(w).get("metadata", {}).get("labels", {})
            ann = ix.template(w).get("metadata", {}).get("annotations") or {}
            if labels.get("istio.io/dataplane-mode") == "none" or ann.get("sidecar.istio.io/inject") == "false" \
                    or labels.get("sidecar.istio.io/inject") == "false":
                outside.append(w)
        if outside:
            out.append(Finding(ref, "strict_mtls_with_plaintext_workloads", "defect", 0.8,
                               f"PeerAuthentication {ref.name} requires mTLS, but {', '.join(w.name for w in outside)} "
                               "is outside the mesh and talks plaintext", [json.dumps(pa.get("spec"))], related=outside))
    for ap in ix.snap.of_kind("AuthorizationPolicy"):
        ref = Ref.of(ap)
        spec = ap.get("spec", {})
        deny_all = spec.get("action") == "DENY" and (spec.get("rules") in ([{}], None) or spec.get("rules") == [])
        allow_none = spec.get("action", "ALLOW") == "ALLOW" and not spec.get("rules")
        if deny_all or allow_none:
            targets = [Ref(ref.namespace, t.get("kind", "Gateway"), t.get("name", "")) for t in spec.get("targetRefs") or []]
            out.append(Finding(ref, "authorization_denies_all", "defect", 0.9,
                               f"AuthorizationPolicy {ref.name} denies all traffic"
                               + (f" to {', '.join(f'{t.kind} {t.name}' for t in targets)}" if targets else ""),
                               [json.dumps(spec)], related=targets))
    for ns in ix.snap.of_kind("Namespace"):
        ref = Ref.of(ns)
        t = _last_modified(ns)
        labels = ns.get("metadata", {}).get("labels", {})
        if t and t >= ix.start and "istio.io/dataplane-mode" not in labels and \
                any(o for o in ix.snap.of_kind("Gateway", ref.name)):
            out.append(Finding(ref, "mesh_membership_changed", "defect", 0.7,
                               f"Namespace {ref.name} lost its istio.io/dataplane-mode label at {_iso(t)}: "
                               "its workloads left the ambient mesh", [f"labels now {json.dumps(labels)}"],
                               related=[w for w in ix.workloads if w.namespace == ref.name]))
    for node in ix.snap.of_kind("Node"):
        ref = Ref.of(node)
        ready = next((c for c in node.get("status", {}).get("conditions", []) if c.get("type") == "Ready"), {})
        if node.get("spec", {}).get("unschedulable"):
            out.append(Finding(ref, "node_cordoned", "context", 0.4, f"node {ref.name} is cordoned", ["spec.unschedulable=true"]))
        if ready.get("status") not in (None, "True"):
            out.append(Finding(ref, "node_not_ready", "defect", 0.8, f"node {ref.name} is NotReady", [ready.get("message", "")]))
    for job in ix.snap.of_kind("Job"):
        ref = Ref.of(job)
        created = _created(job)
        if not created or created < ix.start:
            continue
        cmd = " ".join(" ".join(c.get("command") or []) + " " + " ".join(c.get("args") or [])
                       for c in job.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []))
        hosts = re.findall(r"(?:-h|--host)\s+([a-z0-9][\w.-]*)", cmd)
        for h in hosts:
            svc = ix.resolve_host(h, ref.namespace)
            out.append(Finding(svc, "runtime_reconfigured_by_job", "defect", 0.7,
                               f"Job {ref.name} reconfigured {svc.name} at runtime: {cmd.strip()[:160]}",
                               [f"Job {ref.name} completed {job.get('status', {}).get('completionTime')}"],
                               related=[ref]))
    return out


def _hpa_target(spec: dict) -> float | None:
    for m in spec.get("metrics") or []:
        t = (m.get("resource") or {}).get("target") or {}
        if "averageUtilization" in t:
            return float(t["averageUtilization"])
    return None


def _hpa_current(st: dict) -> float | None:
    for m in st.get("currentMetrics") or []:
        c = (m.get("resource") or {}).get("current") or {}
        if "averageUtilization" in c:
            return float(c["averageUtilization"])
    return None


def _qty(v: str) -> float:
    v = str(v)
    units = {"Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3, "Ti": 1024 ** 4, "m": 1e-3, "k": 1e3, "M": 1e6, "G": 1e9}
    for u, mult in units.items():
        if v.endswith(u):
            try:
                return float(v[: -len(u)]) * mult
            except ValueError:
                return 0.0
    try:
        return float(v)
    except ValueError:
        return 0.0


# -- traces, logs and metrics -----------------------------------------------------------------------

CALLER_SIDE = re.compile(r"name resolution|resolution failed|no such host|EAI_AGAIN|ENOTFOUND|getaddrinfo|"
                         r"Domain name not found|connection termination|reset before headers", re.I)


def traces(ix: ClusterIndex) -> list[Finding]:
    """Where errors start. For each failed request, the deepest failed span is its origin."""
    t0 = incident_start(ix)
    spans = [s for s in ix.snap.spans if s.get("start", 0) >= t0]
    if not spans:
        return []
    by_trace: dict[str, list[dict]] = defaultdict(list)
    for s in spans:
        by_trace[s["trace_id"]].append(s)
    origins: Counter = Counter()
    origin_msgs: dict[Ref, Counter] = defaultdict(Counter)
    example: dict[tuple[Ref, str], str] = {}
    failed_traces = 0
    for _tid, ss in by_trace.items():
        errs = [s for s in ss if s.get("status") == "ERROR"]
        if not errs:
            continue
        failed_traces += 1
        err_ids = {s["span_id"] for s in errs}
        children_err = {s["parent_span_id"] for s in errs if s.get("parent_span_id") in err_ids}
        for s in errs:
            if s["span_id"] in children_err:
                continue  # a child failed first; this span only inherited the error
            caller = ix.workload_for_service_name(s["service"], s.get("namespace"))
            if s.get("kind") == "CLIENT":
                host = (s.get("attributes") or {}).get("server.address")
                if host and caller is not None:
                    ent = ix.resolve_host(str(host), caller.namespace)
                    origins[(ent, "callee")] += 1
                    tpl = _template(s.get("status_message", ""))
                    origin_msgs[ent][tpl] += 1
                    example.setdefault((ent, tpl), s.get("status_message", ""))
                    continue
            if caller is not None:
                origins[(caller, "self")] += 1
                tpl = _template(s.get("status_message", ""))
                origin_msgs[caller][tpl] += 1
                example.setdefault((caller, tpl), s.get("status_message", ""))
    out: list[Finding] = []
    total = sum(origins.values()) or 1
    for (ent, how), n in origins.most_common(8):
        share = n / total
        if n < 3 or share < 0.05:
            continue
        msg, cnt = origin_msgs[ent].most_common(1)[0]
        out.append(Finding(ent, "error_origin", "symptom", min(0.3 + share * 0.5, 0.8),
                           f"{n} failed requests ({share:.0%}) start at {ent.kind} {ent.name}"
                           + (" (calls to it fail)" if how == "callee" else " (its own errors)"),
                           [f"{cnt}x {example.get((ent, msg), msg)[:300]}"]))
    out += _latency_origins(ix, t0)
    # A caller whose calls to many different services fail the same way is the problem itself.
    per_caller: dict[Ref, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for (caller, callee), e in ix.call_edges.items():
        for msg in e.messages:
            if CALLER_SIDE.search(msg):
                per_caller[caller][_class(msg)].add(callee)
    for caller, classes in per_caller.items():
        for cls, callees in classes.items():
            others_ok = 0
            for callee in callees:
                for (c2, t2), e2 in ix.call_edges.items():
                    if t2 == callee and c2 != caller and e2.calls and e2.errors / e2.calls < 0.2:
                        others_ok += 1
            if len(callees) >= 2 or others_ok:
                out.append(Finding(caller, "caller_side_failure", "defect", 0.75,
                                   f"{caller.name} cannot reach {len(callees)} different services ({cls}), "
                                   + ("while other callers reach them fine" if others_ok else "the fault is on its side"),
                                   [f"{caller.name} -> {', '.join(c.name for c in sorted(callees))[:120]}"]))
    return out


def _latency_origins(ix: ClusterIndex, t0: float) -> list[Finding]:
    """Where time is spent: a server span's own time (duration minus its outgoing calls), before vs during."""
    children: dict[str, float] = defaultdict(float)
    for s in ix.snap.spans:
        if s.get("kind") == "CLIENT" and s.get("parent_span_id"):
            children[s["parent_span_id"]] += s.get("duration_ms", 0.0)
    own: dict[tuple[str, str], tuple[list[float], list[float]]] = defaultdict(lambda: ([], []))
    for s in ix.snap.spans:
        if s.get("kind") != "SERVER":
            continue
        self_ms = max(s.get("duration_ms", 0.0) - children.get(s["span_id"], 0.0), 0.0)
        own[(s["service"], s.get("namespace", ""))][0 if s["start"] < t0 else 1].append(self_ms)
    out = []
    for (svc, ns), (before, after) in own.items():
        if len(before) < 5 or len(after) < 5:
            continue
        b, a = _median(before), _median(after)
        if a > 100 and a > 5 * max(b, 1.0):
            w = ix.workload_for_service_name(svc, ns)
            if w is not None:
                out.append(Finding(w, "latency_origin", "symptom", 0.6,
                                   f"{w.name} itself got slower: median own time {b:.0f}ms -> {a:.0f}ms "
                                   "(not explained by its dependencies)", [f"{len(after)} spans since the incident began"]))
    return out


def _class(msg: str) -> str:
    if re.search(r"resolution|no such host|EAI_AGAIN|ENOTFOUND|getaddrinfo|Domain name", msg, re.I):
        return "DNS resolution fails"
    if re.search(r"connection termination|reset", msg, re.I):
        return "connections are reset"
    return "calls fail"


LOG_SIGNATURES = [
    (re.compile(r"NOAUTH|WRONGPASS|AUTH failed|invalid password|authentication failed", re.I), "dependency_auth_failure",
     "authentication to a dependency fails"),
    (re.compile(r"OOM command not allowed|maxmemory", re.I), "dependency_out_of_memory",
     "the cache rejects writes: out of memory"),
    (re.compile(r"SMTPAuthenticationError|535[- ]5\.7\.8|Username and Password not accepted", re.I), "credentials_rejected",
     "credentials are rejected by an external service"),
    (re.compile(r"no such host|Name resolution failed|ENOTFOUND|EAI_AGAIN|Domain name not found", re.I), "dns_failure",
     "a hostname does not resolve"),
    (re.compile(r"connection refused|ECONNREFUSED", re.I), "connection_refused", "connections are refused"),
    (re.compile(r"could not be established|Node may not be available|Broker may not be available", re.I),
     "broker_unreachable", "the message broker is unreachable"),
]


def logs(ix: ClusterIndex) -> list[Finding]:
    """New error patterns since the incident began, with the dependency each one names."""
    t0 = incident_start(ix)
    before: Counter = Counter()
    during: dict[tuple[str, str], Counter] = defaultdict(Counter)
    example: dict[str, str] = {}
    for row in ix.snap.logs:
        if row.get("severity") not in ("ERROR", "FATAL", "WARN", "WARNING") and (row.get("severity_number") or 0) < 13:
            continue
        t = parse_time(row.get("timestamp"))
        tpl = _template(str(row.get("body", "")))
        key = (row.get("service", ""), row.get("namespace", ""))
        if t is not None and t < t0:
            before[(key, tpl)] += 1
        else:
            during[key][tpl] += 1
            example.setdefault(tpl, str(row.get("body", "")))
    out = []
    for (svc, ns), counter in during.items():
        w = ix.workload_for_service_name(svc, ns)
        if w is None:
            continue
        for tpl, n in counter.most_common(3):
            if n < 3 or before[((svc, ns), tpl)] >= n / 3:
                continue  # an old, recurring warning
            sig = next(((s, why) for rx, s, why in LOG_SIGNATURES if rx.search(tpl)), None)
            hosts = [ix.resolve_host(h, w.namespace) for h in _hosts_in(tpl)]
            out.append(Finding(w, sig[0] if sig else "new_error_logs", "symptom", 0.35,
                               f"{w.name} logs a new error {n} times" + (f": {sig[1]}" if sig else ""),
                               [f"{n}x {example.get(tpl, tpl)[:300]}"], related=hosts))
    return out


def _hosts_in(text: str) -> list[str]:
    hosts = re.findall(r"(?:lookup|target dns:|dial tcp:? lookup|to|calling|for)\s+([a-z][a-z0-9-]{2,}(?:\.[a-z0-9-]+)?)(?::\d+)?",
                       text)
    stop = {"the", "all", "remote", "node", "interval", "host", "connect", "subchannel", "addresses", "server"}
    return [h for h in hosts if h not in stop]


def metrics(ix: ClusterIndex) -> list[Finding]:
    t0 = incident_start(ix)
    out = []
    for s in ix.snap.metrics:
        pts = s.get("points") or []
        before = [v for t, v in pts if t < t0]
        after = [v for t, v in pts if t >= t0 + 120]
        if not before or not after:
            continue
        b, a = _median(before), _median(after)
        lbl = s.get("labels", {})
        name = s["name"]
        ent = None
        if lbl.get("service_name") or lbl.get("destination_service_name"):
            nm = lbl.get("service_name") or lbl.get("destination_service_name")
            ent = ix.workload_for_service_name(nm, lbl.get("namespace")) if lbl.get("service_name") else \
                Ref(lbl.get("namespace", ""), "Service", nm)
        elif lbl.get("consumergroup"):
            ent = ix.workload_for_service_name(lbl["consumergroup"], lbl.get("namespace"))
        if ent is None:
            if name.startswith(("apiserver_", "etcd_")) and b > 0 and a > 4 * b:
                out.append(Finding(Ref("", "Node", "control-plane"), "control_plane_degraded", "context", 0.4,
                                   f"{name} rose from {b:.3g} to {a:.3g}", [json.dumps(lbl)]))
            continue
        if name.endswith("duration_p95_ms") and a > max(500, 3 * b):
            out.append(Finding(ent, "latency_increase", "symptom", 0.35, f"p95 latency of {ent.name} rose from "
                               f"{b:.0f}ms to {a:.0f}ms", [f"{name} {json.dumps(lbl)}"]))
        elif name == "requests_per_second" and b > 0.02 and max(after) == 0:
            out.append(Finding(ent, "traffic_stopped", "symptom", 0.35, f"{ent.name} stopped receiving requests "
                               f"(was {b * 60:.0f}/min)", [f"{name} {json.dumps(lbl)}"]))
        elif name == "request_error_ratio" and a > max(0.05, 4 * b):
            out.append(Finding(ent, "error_rate_increase", "symptom", 0.3, f"error ratio of {ent.name} rose from "
                               f"{b:.1%} to {a:.1%}", [f"{name} {json.dumps(lbl)}"]))
        elif name == "kafka_consumergroup_lag" and a > 5 * max(b, 1):
            out.append(Finding(ent, "consumer_lag", "symptom", 0.35, f"consumer lag for {ent.name} grew from {b:.0f} "
                               f"to {a:.0f}", [json.dumps(lbl)]))
    return out


def _median(v: list[float]) -> float:
    v = sorted(v)
    return v[len(v) // 2]


DETECTORS = [pod_failures, rollouts, recent_changes, services, policies, traces, logs, metrics]


def run_detectors(ix: ClusterIndex) -> list[Finding]:
    out: list[Finding] = []
    for d in DETECTORS:
        out.extend(d(ix))
    return out


def pre_existing(ix: ClusterIndex, alert: dict) -> bool:
    """An alert that was already firing before the snapshot window: a known, older problem."""
    t = parse_time(alert.get("activeAt"))
    return t is not None and t < ix.start - 600


__all__ = ["Finding", "run_detectors", "unavailable_workloads", "incident_start", "template_diff", "pre_existing",
           "WORKLOAD_KINDS"]
