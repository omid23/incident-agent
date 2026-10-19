"""Relationships an SRE reasons over: ownership, Service routing, configuration, policy and the call graph."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from functools import cached_property

from ..entities import WORKLOAD_KINDS, Ref
from ..snapshot import Snapshot, parse_time


def selector_matches(selector: dict | None, labels: dict | None) -> bool:
    if not selector:
        return False
    labels = labels or {}
    match = selector.get("matchLabels", selector) if "matchLabels" in selector or "matchExpressions" in selector \
        else selector
    for k, v in (match or {}).items():
        if k in ("matchLabels", "matchExpressions"):
            continue
        if labels.get(k) != v:
            return False
    for expr in selector.get("matchExpressions") or []:
        key, op, vals = expr.get("key"), expr.get("operator"), expr.get("values") or []
        if op == "In" and labels.get(key) not in vals:
            return False
        if op == "NotIn" and labels.get(key) in vals:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def is_ready(pod: dict) -> bool:
    return any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod.get("status", {}).get("conditions", []))


@dataclass
class Edge:
    caller: Ref
    callee: Ref  # a Service (or workload when no Service is known)
    host: str
    calls: int = 0
    errors: int = 0
    messages: dict[str, int] = field(default_factory=dict)  # errors where the callee never answered
    first_error: float | None = None
    answered_errors: int = 0  # errors the callee returned (or passed on from its own dependencies)
    examples: dict[str, str] = field(default_factory=dict)  # message template -> one real message


class ClusterIndex:
    def __init__(self, snap: Snapshot):
        self.snap = snap
        self.start, self.end = snap.window
        if self.end is None:
            times = [parse_time(o["metadata"].get("creationTimestamp")) for o in snap.objects]
            self.end = max(t for t in times if t) if any(times) else 0.0
        if self.start is None:
            self.start = self.end - 1800

    # -- ownership ------------------------------------------------------------------------------

    @cached_property
    def owner(self) -> dict[Ref, Ref]:
        """Pod/ReplicaSet/Job -> controlling workload (Deployment, StatefulSet, DaemonSet, Job, CronJob)."""
        out: dict[Ref, Ref] = {}
        for ref, obj in self.snap.by_ref.items():
            for o in obj["metadata"].get("ownerReferences") or []:
                out[ref] = Ref(ref.namespace, o["kind"], o["name"])
        resolved: dict[Ref, Ref] = {}
        for ref in out:
            cur, seen = ref, 0
            while cur in out and seen < 4:
                cur, seen = out[cur], seen + 1
            resolved[ref] = cur
        return resolved

    def workload_of(self, ref: Ref) -> Ref:
        if ref in self.owner or ref.kind != "Pod" or ref in self.snap.by_ref:
            return self.owner.get(ref, ref)
        # A pod that no longer exists (deleted, evicted, preempted): match its name to a ReplicaSet.
        for rs in self.snap.of_kind("ReplicaSet", ref.namespace):
            if ref.name.startswith(rs["metadata"]["name"] + "-"):
                return self.owner.get(Ref.of(rs), Ref.of(rs))
        return ref

    @cached_property
    def pods_by_workload(self) -> dict[Ref, list[dict]]:
        out: dict[Ref, list[dict]] = defaultdict(list)
        for p in self.snap.of_kind("Pod"):
            out[self.workload_of(Ref.of(p))].append(p)
        return out

    @cached_property
    def workloads(self) -> list[Ref]:
        refs = {r for r in self.snap.by_ref if r.kind in WORKLOAD_KINDS}
        return sorted(refs)

    def template(self, workload: Ref) -> dict:
        obj = self.snap.get(workload) or {}
        if workload.kind == "Job":
            return obj.get("spec", {}).get("template", {})
        return obj.get("spec", {}).get("template", {})

    def replicasets(self, workload: Ref) -> list[dict]:
        rss = [o for o in self.snap.of_kind("ReplicaSet", workload.namespace)
               if self.workload_of(Ref.of(o)) == workload]
        return sorted(rss, key=lambda r: (int((r["metadata"].get("annotations") or {})
                                               .get("deployment.kubernetes.io/revision", 0)),
                                          r["metadata"].get("creationTimestamp", "")))

    # -- Services -------------------------------------------------------------------------------

    @cached_property
    def service_backends(self) -> dict[Ref, list[Ref]]:
        out: dict[Ref, list[Ref]] = {}
        for svc in self.snap.of_kind("Service"):
            ref = Ref.of(svc)
            sel = svc.get("spec", {}).get("selector")
            backends = set()
            if sel:
                for w in self.workloads:
                    if w.namespace != ref.namespace:
                        continue
                    labels = self.template(w).get("metadata", {}).get("labels", {})
                    if selector_matches(sel, labels):
                        backends.add(w)
                for p in self.snap.of_kind("Pod", ref.namespace):
                    if selector_matches(sel, p["metadata"].get("labels")):
                        backends.add(self.workload_of(Ref.of(p)))
            out[ref] = sorted(backends)
        return out

    @cached_property
    def services_of(self) -> dict[Ref, list[Ref]]:
        out: dict[Ref, list[Ref]] = defaultdict(list)
        for svc, ws in self.service_backends.items():
            for w in ws:
                out[w].append(svc)
        return out

    def resolve_host(self, host: str, namespace: str) -> Ref:
        """A hostname as callers use it -> the Service it names (which may not exist any more)."""
        host = host.split(":")[0].strip().strip('"')
        parts = host.split(".")
        name = parts[0]
        ns = parts[1] if len(parts) > 1 and parts[1] in self.snap.namespaces() else namespace
        return Ref(ns, "Service", name)

    # -- telemetry names -> workloads ----------------------------------------------------------------

    @cached_property
    def telemetry_map(self) -> dict[str, Ref]:
        out: dict[str, Ref] = {}
        for w in self.workloads:
            tpl = self.template(w)
            names = {w.name}
            for c in tpl.get("spec", {}).get("containers", []):
                for e in c.get("env") or []:
                    if e.get("name") == "OTEL_SERVICE_NAME" and e.get("value"):
                        names.add(e["value"])
            labels = tpl.get("metadata", {}).get("labels", {})
            for k in ("app.kubernetes.io/name", "app.kubernetes.io/component", "app"):
                if labels.get(k):
                    names.add(labels[k])
            for n in names:
                out.setdefault(n, w)
                out.setdefault(f"{n}.{w.namespace}", w)
        for svc, backends in self.service_backends.items():
            if len(backends) == 1:
                out.setdefault(svc.name, backends[0])
                out.setdefault(f"{svc.name}.{svc.namespace}", backends[0])
        return out

    def workload_for_service_name(self, name: str, namespace: str | None = None) -> Ref | None:
        w = self.telemetry_map.get(name)
        if w is None and "." in name:
            w = self.telemetry_map.get(name.split(".")[0])
        if w is None and namespace:
            svc = Ref(namespace, "Service", name.split(".")[0])
            backends = self.service_backends.get(svc) or []
            w = backends[0] if backends else None
        return w

    def alert_entity(self, alert: dict) -> Ref | None:
        lbl = alert.get("labels", {})
        ns = lbl.get("namespace", "")
        if lbl.get("pod"):
            return self.workload_of(Ref(ns, "Pod", lbl["pod"]))
        if lbl.get("horizontalpodautoscaler"):
            return Ref(ns, "HorizontalPodAutoscaler", lbl["horizontalpodautoscaler"])
        for k, kind in (("deployment", "Deployment"), ("statefulset", "StatefulSet"), ("daemonset", "DaemonSet"),
                        ("job_name", "Job")):
            if lbl.get(k):
                return Ref(ns, kind, lbl[k])
        if lbl.get("destination_service_name"):
            svc = Ref(ns, "Service", lbl["destination_service_name"])
            if svc in self.snap.by_ref:
                return svc
            return self.workload_for_service_name(lbl["destination_service_name"], ns) or svc
        if lbl.get("service_name") or lbl.get("service"):
            name = lbl.get("service_name") or lbl.get("service")
            return self.workload_for_service_name(name, ns) or Ref(ns, "Service", name)
        if lbl.get("node"):
            return Ref("", "Node", lbl["node"])
        return None

    # -- configuration and policy ---------------------------------------------------------------------

    def config_refs(self, workload: Ref) -> list[tuple[Ref, str]]:
        """Objects a workload's pod template depends on, with how it uses them."""
        spec = self.template(workload).get("spec", {})
        ns = workload.namespace
        out: list[tuple[Ref, str]] = []
        for v in spec.get("volumes") or []:
            if "configMap" in v:
                out.append((Ref(ns, "ConfigMap", v["configMap"]["name"]), f"volume {v['name']}"))
            if "secret" in v:
                out.append((Ref(ns, "Secret", v["secret"].get("secretName", "")), f"volume {v['name']}"))
            if "persistentVolumeClaim" in v:
                out.append((Ref(ns, "PersistentVolumeClaim", v["persistentVolumeClaim"]["claimName"]),
                            f"volume {v['name']}"))
        init_volumes = {m["name"] for c in spec.get("initContainers") or [] for m in c.get("volumeMounts") or []}
        for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
            for ef in c.get("envFrom") or []:
                if "configMapRef" in ef:
                    out.append((Ref(ns, "ConfigMap", ef["configMapRef"]["name"]), f"envFrom in {c['name']}"))
                if "secretRef" in ef:
                    out.append((Ref(ns, "Secret", ef["secretRef"]["name"]), f"envFrom in {c['name']}"))
            for e in c.get("env") or []:
                vf = e.get("valueFrom") or {}
                if "configMapKeyRef" in vf:
                    out.append((Ref(ns, "ConfigMap", vf["configMapKeyRef"]["name"]), f"env {e['name']}"))
                if "secretKeyRef" in vf:
                    out.append((Ref(ns, "Secret", vf["secretKeyRef"]["name"]), f"env {e['name']}"))
        out = [(r, ("init container " + how) if how.startswith("volume") and how.split()[-1] in init_volumes else how)
               for r, how in out]
        if spec.get("priorityClassName"):
            out.append((Ref("", "PriorityClass", spec["priorityClassName"]), "priorityClassName"))
        seen, uniq = set(), []
        for r, how in out:
            if r not in seen:
                seen.add(r)
                uniq.append((r, how))
        return uniq

    def nodes_of(self, workload: Ref) -> list[Ref]:
        return sorted({Ref("", "Node", p["spec"]["nodeName"]) for p in self.pods_by_workload.get(workload, [])
                       if p.get("spec", {}).get("nodeName")})

    def policies_for(self, workload: Ref) -> list[Ref]:
        """NetworkPolicies, quotas, autoscalers and mesh policies that apply to a workload."""
        ns = workload.namespace
        labels = self.template(workload).get("metadata", {}).get("labels", {})
        out = []
        for np in self.snap.of_kind("NetworkPolicy", ns):
            sel = np.get("spec", {}).get("podSelector")
            if sel == {} or selector_matches(sel, labels):
                out.append(Ref.of(np))
        for q in self.snap.of_kind("ResourceQuota", ns):
            out.append(Ref.of(q))
        for h in self.snap.of_kind("HorizontalPodAutoscaler", ns):
            tgt = h.get("spec", {}).get("scaleTargetRef", {})
            if tgt.get("name") == workload.name:
                out.append(Ref.of(h))
        for kind in ("PeerAuthentication", "AuthorizationPolicy"):
            for p in self.snap.of_kind(kind, ns):
                sel = (p.get("spec", {}).get("selector") or {}).get("matchLabels")
                if not sel or selector_matches(sel, labels):
                    if kind == "AuthorizationPolicy" and p.get("spec", {}).get("targetRefs"):
                        continue
                    out.append(Ref.of(p))
        return out

    @cached_property
    def gateway_of_workload(self) -> dict[Ref, Ref]:
        """Gateway API: the Deployment Istio creates for a Gateway carries its name in a label or its name."""
        out = {}
        for gw in self.snap.of_kind("Gateway"):
            ref = Ref.of(gw)
            for w in self.workloads:
                labels = self.template(w).get("metadata", {}).get("labels", {})
                if w.namespace == ref.namespace and (labels.get("gateway.networking.k8s.io/gateway-name") == ref.name
                                                     or w.name in (f"{ref.name}-istio", ref.name)):
                    out[w] = ref
        return out

    def gateway_policies(self, gateway: Ref) -> list[Ref]:
        out = []
        for p in self.snap.of_kind("AuthorizationPolicy", gateway.namespace):
            for t in p.get("spec", {}).get("targetRefs") or []:
                if t.get("kind") == "Gateway" and t.get("name") == gateway.name:
                    out.append(Ref.of(p))
        return out

    # -- call graph ------------------------------------------------------------------------------------

    @cached_property
    def call_edges(self) -> dict[tuple[Ref, Ref], Edge]:
        """caller workload -> callee Service, from client spans; plus env-declared dependencies (no stats)."""
        out: dict[tuple[Ref, Ref], Edge] = {}
        answered = {s.get("parent_span_id") for s in self.snap.spans if s.get("kind") == "SERVER"}
        for s in self.snap.spans:
            if s.get("kind") != "CLIENT":
                continue
            host = (s.get("attributes") or {}).get("server.address") or (s.get("attributes") or {}).get("peer.service")
            if not host:
                continue
            caller = self.workload_for_service_name(s["service"], s.get("namespace"))
            if caller is None:
                continue
            callee = self.resolve_host(str(host), caller.namespace)
            e = out.setdefault((caller, callee), Edge(caller, callee, str(host)))
            e.calls += 1
            if s.get("status") == "ERROR":
                e.errors += 1
                e.first_error = min(e.first_error or s["start"], s["start"])
                if s["span_id"] in answered:
                    e.answered_errors += 1
                else:
                    msg = _template(s.get("status_message", ""))
                    e.messages[msg] = e.messages.get(msg, 0) + 1
                    e.examples.setdefault(msg, s.get("status_message", ""))
        for w in self.workloads:
            for host in self.env_hosts(w):
                callee = self.resolve_host(host, w.namespace)
                if callee.name == w.name:
                    continue
                out.setdefault((w, callee), Edge(w, callee, host))
        return out

    def env_hosts(self, workload: Ref) -> list[str]:
        hosts = []
        for c in self.template(workload).get("spec", {}).get("containers", []):
            for e in c.get("env") or []:
                v = str(e.get("value") or "")
                if e.get("name", "").endswith(("_ADDR", "_HOST", "_HOSTNAME", "_URL")) or \
                        e.get("name") == "DB_CONNECTION_STRING":
                    m = re.search(r"Host=([\w.-]+)", v) or re.search(r"^(?:\w+://)?([a-z0-9][\w.-]*)(?::\d+)?", v)
                    if m and not m.group(1).replace(".", "").isdigit():
                        hosts.append(m.group(1))
        return hosts

    def callees(self, workload: Ref) -> list[Ref]:
        return sorted({callee for (caller, callee) in self.call_edges if caller == workload})

    def callers(self, target: Ref) -> list[Ref]:
        """Workloads that call a Service (or the Services fronting a workload)."""
        services = {target} if target.kind == "Service" else set(self.services_of.get(target, []))
        if target.kind != "Service":
            services.add(Ref(target.namespace, "Service", target.name))
        return sorted({caller for (caller, callee) in self.call_edges if callee in services})


def _template(message: str) -> str:
    """Collapse ids, addresses and numbers so messages from different requests group together."""
    m = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<ip>", message)
    m = re.sub(r"\b[0-9a-f]{8,}\b", "<id>", m)
    m = re.sub(r"\b\d+(?:\.\d+)?(ms|s)?\b", "<n>", m)
    return m[:240]
