"""Builds a realistic cluster, injects faults, and records the telemetry an SRE would see.

Faults change Kubernetes objects the way the ITBench mechanisms do, and the traffic model turns
the resulting breakage into what monitoring actually shows: failed client spans in callers,
error logs that name the dependency, missing server spans, latency, restarts, events and
Prometheus alerts evaluated over the generated metrics. Alerts usually fire on symptoms
(the frontend), not on the faulty object, which is what makes root-cause analysis hard.
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
from collections import defaultdict
from dataclasses import dataclass, field

from ..entities import Ref
from ..snapshot import Snapshot, iso
from .topology import Application, Component

BASE_TIME = 1788256800.0  # 2026-09-01T10:00:00Z
WINDOW = 30 * 60  # 30 minutes of telemetry; the fault lands half way
NODES = ("worker-1", "worker-2", "worker-3")


def _hash(*parts: object, n: int = 10) -> str:
    return hashlib.sha1("/".join(map(str, parts)).encode()).hexdigest()[:n]


def _suffix(*parts: object, n: int = 5) -> str:
    alphabet = "bcdfghjklmnpqrstvwxz2456789"
    h = int(_hash(*parts, n=12), 16)
    out = ""
    for _ in range(n):
        h, r = divmod(h, len(alphabet))
        out += alphabet[r]
    return out


# -- failure modes on calls --------------------------------------------------------------------------

@dataclass
class CallFailure:
    """How calls to a component fail after ``since``."""

    mode: str  # refused | dns | timeout | unavailable | reset | forbidden | app_error | slow
    message: str = ""
    rate: float = 1.0  # fraction of calls affected
    since: float = 0.0
    latency_factor: float = 1.0
    status_code: int | None = None
    ops: tuple[str, ...] = ()  # only these operations fail (empty: all)

    def applies(self, t: float, op: str) -> bool:
        return t >= self.since and (not self.ops or op in self.ops)


CLIENT_MESSAGES = {
    "go": {
        "refused": 'rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp {ip}:{port}: connect: connection refused"',
        "dns": 'rpc error: code = Unavailable desc = name resolver error: produced zero addresses; dial tcp: lookup {host} on 10.96.0.10:53: no such host',
        "timeout": "rpc error: code = DeadlineExceeded desc = context deadline exceeded",
        "unavailable": "rpc error: code = Unavailable desc = no healthy upstream",
    },
    "javascript": {
        "refused": "14 UNAVAILABLE: No connection established. Last error: connect ECONNREFUSED {ip}:{port}",
        "dns": "14 UNAVAILABLE: Name resolution failed for target dns:{host}:{port}",
        "timeout": "4 DEADLINE_EXCEEDED: Deadline exceeded after 5.001s",
        "unavailable": "14 UNAVAILABLE: no healthy upstream",
    },
    "python": {
        "refused": "failed to connect to all addresses; last error: UNKNOWN: ipv4:{ip}:{port}: Failed to connect to remote host: Connection refused",
        "dns": "DNS resolution failed for {host}:{port}: C-ares status is not ARES_SUCCESS qtype=A name={host} is_balancer=0: Domain name not found",
        "timeout": "Deadline Exceeded",
        "unavailable": "upstream connect error or disconnect/reset before headers. reset reason: connection failure",
    },
    "dotnet": {
        "refused": 'Status(StatusCode="Unavailable", Detail="Error connecting to subchannel.", DebugException="System.Net.Sockets.SocketException: Connection refused ({ip}:{port})")',
        "dns": 'Status(StatusCode="Unavailable", Detail="Error connecting to subchannel.", DebugException="System.Net.Sockets.SocketException: Name or service not known ({host}:{port})")',
        "timeout": 'Status(StatusCode="DeadlineExceeded", Detail="")',
        "unavailable": 'Status(StatusCode="Unavailable", Detail="no healthy upstream")',
    },
    "cpp": {
        "refused": "upstream connect error or disconnect/reset before headers. reset reason: remote connection failure, transport failure reason: delayed connect error: Connection refused",
        "dns": "upstream connect error or disconnect/reset before headers. reset reason: remote connection failure, transport failure reason: resolution failed for {host}",
        "timeout": "upstream request timeout",
        "unavailable": "no healthy upstream",
    },
}
for _lang in ("java", "kotlin", "ruby", "rust", "php", "c"):
    CLIENT_MESSAGES[_lang] = CLIENT_MESSAGES["javascript" if _lang in ("ruby", "php") else "go"]
GENERIC = {
    "reset": "upstream connect error or disconnect/reset before headers. reset reason: connection termination",
    "forbidden": "RBAC: access denied",
}


@dataclass
class Workload:
    comp: Component
    deployment: dict
    replicasets: list[dict] = field(default_factory=list)
    pods: list[dict] = field(default_factory=list)
    service: dict | None = None
    serving: bool = True  # at least one ready pod behind the Service


class World:
    def __init__(self, apps: list[Application], seed: int, autoscaling: bool = False, name: str = "incident"):
        self.apps = apps
        self.rng = random.Random(seed)
        self.seed = seed
        self.name = name
        self.t0 = BASE_TIME + seed * 86400
        self.t_fault = self.t0 + WINDOW / 2 + self.rng.randint(-120, 120)
        self.t_end = self.t0 + WINDOW
        self.objects: dict[Ref, dict] = {}
        self.events: list[dict] = []
        self.logs: list[dict] = []
        self.spans: list[dict] = []
        self.metrics: list[dict] = []
        self.alerts: list[dict] = []
        self.workloads: dict[str, Workload] = {}
        self.failures: dict[str, CallFailure] = {}  # by component name
        self.caller_failures: dict[str, CallFailure] = {}  # component cannot make any outbound call
        self.no_traffic: dict[str, float] = {}  # component receives no requests after time
        self.silent: dict[str, float] = {}  # namespace whose mesh telemetry stops after time
        self.chronic: dict[str, float] = {}  # pod name -> when its (pre-existing) alert started
        self.ip: dict[str, str] = {}
        self.extra_series: list[dict] = []
        self.notes: list[str] = []
        self._build(autoscaling)

    # -- object helpers ------------------------------------------------------------------------------

    def ts(self, t: float) -> str:
        return iso(t)

    def put(self, obj: dict) -> dict:
        self.objects[Ref.of(obj)] = obj
        return obj

    def remove(self, ref: Ref) -> dict | None:
        return self.objects.pop(ref, None)

    def meta(self, name: str, namespace: str | None, created: float, labels: dict | None = None,
             annotations: dict | None = None, managed_at: float | None = None, manager: str = "helm") -> dict:
        md = {"name": name, "uid": f"{_hash(namespace, name, 'uid', n=8)}-{_hash(name, n=4)}-4{_hash(name, 1, n=3)}-"
                                   f"a{_hash(name, 2, n=3)}-{_hash(namespace, name, n=12)}",
              "creationTimestamp": self.ts(created), "resourceVersion": str(int(created) % 10_000_000),
              "labels": dict(labels or {}),
              "managedFields": [{"manager": manager, "operation": "Update", "time": self.ts(managed_at or created)}]}
        if namespace:
            md["namespace"] = namespace
        if annotations:
            md["annotations"] = dict(annotations)
        return md

    def touch(self, obj: dict, t: float, manager: str = "kubectl-patch") -> None:
        """Record a modification at time t (as managedFields does)."""
        obj["metadata"].setdefault("managedFields", []).append({"manager": manager, "operation": "Update",
                                                                "time": self.ts(t)})
        obj["metadata"]["resourceVersion"] = str(int(t) % 10_000_000 + 7)

    def event(self, obj: dict, etype: str, reason: str, message: str, first: float, last: float | None = None,
              count: int = 1, source: str = "kubelet") -> None:
        ref = Ref.of(obj)
        self.events.append({
            "apiVersion": "v1", "kind": "Event", "type": etype, "reason": reason, "message": message,
            "metadata": {"name": f"{ref.name}.{_hash(ref, reason, first, n=16)}", "namespace": ref.namespace or "default",
                         "creationTimestamp": self.ts(first)},
            "involvedObject": {"kind": ref.kind, "name": ref.name, "namespace": ref.namespace,
                               "apiVersion": obj.get("apiVersion", "v1")},
            "firstTimestamp": self.ts(first), "lastTimestamp": self.ts(last or first), "count": count,
            "source": {"component": source},
        })

    def log(self, comp: Component | str, t: float, severity: str, body: str, trace_id: str = "", pod: str = "") -> None:
        c = comp if isinstance(comp, Component) else self.component(comp)
        if not pod:
            w = self.workloads.get(c.name)
            pods = [p for p in (w.pods if w else []) if p["status"].get("phase") == "Running"]
            pod = pods[0]["metadata"]["name"] if pods else ""
        self.logs.append({"timestamp": self.ts(t) if isinstance(t, float) else t, "service": c.otel_name,
                          "namespace": c.namespace, "pod": pod, "severity": severity, "body": body,
                          "trace_id": trace_id})

    def component(self, name: str) -> Component:
        for app in self.apps:
            for c in app.components:
                if c.name == name:
                    return c
        raise KeyError(name)

    def app_of(self, comp: str) -> Application:
        for app in self.apps:
            if any(c.name == comp for c in app.components):
                return app
        raise KeyError(comp)

    # -- building the healthy cluster ----------------------------------------------------------------

    def _build(self, autoscaling: bool) -> None:
        boot = self.t0 - 6 * 86400
        for i, n in enumerate(NODES + ("control-plane",)):
            labels = {"kubernetes.io/hostname": n, "kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux"}
            if n == "control-plane":
                labels["node-role.kubernetes.io/control-plane"] = ""
            self.put({"apiVersion": "v1", "kind": "Node", "metadata": self.meta(n, None, boot, labels),
                      "spec": {"taints": [{"key": "node-role.kubernetes.io/control-plane", "effect": "NoSchedule"}]}
                      if n == "control-plane" else {},
                      "status": {"conditions": [{"type": "Ready", "status": "True", "reason": "KubeletReady"},
                                                {"type": "MemoryPressure", "status": "False"},
                                                {"type": "DiskPressure", "status": "False"}],
                                 "allocatable": {"cpu": "4", "memory": "15Gi", "pods": "110"},
                                 "addresses": [{"type": "InternalIP", "address": f"10.0.0.{10 + i}"}],
                                 "nodeInfo": {"architecture": "amd64", "kubeletVersion": "v1.34.1"}}})
        for app in self.apps:
            ns_labels = {"kubernetes.io/metadata.name": app.namespace}
            if app.namespace == "book-info":
                ns_labels["istio.io/dataplane-mode"] = "ambient"
            self.put({"apiVersion": "v1", "kind": "Namespace", "metadata": self.meta(app.namespace, None, boot, ns_labels),
                      "status": {"phase": "Active"}})
            for k, comp in enumerate(app.components):
                self._workload(comp, boot + 60 * k)
            if app.namespace == "otel-demo":
                self._otel_config(boot)
            else:
                self._istio_config(boot)
        if autoscaling:
            for name in ("fraud-detection", "frontend", "image-provider"):
                self.put({"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
                          "metadata": self.meta(name, "otel-demo", boot),
                          "spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": name},
                                   "minReplicas": 1, "maxReplicas": 3,
                                   "metrics": [{"type": "Resource", "resource": {"name": "cpu", "target": {
                                       "type": "Utilization", "averageUtilization": 80}}}]},
                          "status": {"currentReplicas": 1, "desiredReplicas": 1,
                                     "currentMetrics": [{"type": "Resource", "resource": {"name": "cpu", "current": {
                                         "averageUtilization": 31}}}]}})

    def _otel_config(self, boot: float) -> None:
        ns = "otel-demo"
        flags = {"flags": {f: {"state": "ENABLED", "variants": {"on": True, "off": False}, "defaultVariant": "off"}
                           for f in ("adFailure", "cartFailure", "productCatalogFailure", "paymentFailure",
                                     "kafkaQueueProblems", "recommendationCacheFailure")}}
        self.put({"apiVersion": "v1", "kind": "ConfigMap", "metadata": self.meta("flagd-config", ns, boot),
                  "data": {"demo.flagd.json": json.dumps(flags)}})
        self.put({"apiVersion": "v1", "kind": "ConfigMap", "metadata": self.meta("grafana-dashboards", ns, boot),
                  "data": {"demo-dashboard.json": "{\"title\": \"Demo Dashboard\"}"}})
        self.put({"apiVersion": "v1", "kind": "ConfigMap", "metadata": self.meta("otel-collector", ns, boot),
                  "data": {"relay": "receivers: {otlp: {}}\nexporters: {clickhouse: {}}"}})
        self.put({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                  "metadata": self.meta("valkey-credentials", ns, boot), "data": {"valkey-password": ""}})
        self.put({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                  "metadata": self.meta("email-service-secret", ns, boot),
                  "data": {"SMTP_USERNAME": "b3RlbC1kZW1v", "SMTP_PASSWORD": "c2VjcmV0LXBhc3N3b3Jk"}})

    def _istio_config(self, boot: float) -> None:
        ns = "book-info"
        self.put({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
                  "metadata": self.meta("bookinfo-gateway", ns, boot),
                  "spec": {"gatewayClassName": "istio",
                           "listeners": [{"name": "http", "port": 80, "protocol": "HTTP",
                                          "allowedRoutes": {"namespaces": {"from": "Same"}}}]},
                  "status": {"conditions": [{"type": "Programmed", "status": "True"}]}})
        self.put({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
                  "metadata": self.meta("bookinfo", ns, boot),
                  "spec": {"parentRefs": [{"name": "bookinfo-gateway"}],
                           "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/productpage"}}],
                                      "backendRefs": [{"name": "productpage", "port": 9080}]}]}})

    def _workload(self, comp: Component, created: float) -> None:
        labels = comp.labels
        container = {"name": comp.name.removesuffix("-v1") if comp.namespace == "book-info" else comp.name,
                     "image": comp.image, "ports": [{"containerPort": comp.port, "name": "service"}],
                     "env": [{"name": k, "value": v} for k, v in comp.env.items()]
                     + [{"name": "OTEL_SERVICE_NAME", "value": comp.otel_name}],
                     "resources": {"limits": {"memory": comp.memory_limit},
                                   "requests": {"cpu": comp.cpu_request, "memory": comp.memory_limit}}}
        if comp.secrets:
            container["envFrom"] = [{"secretRef": {"name": s}} for s in comp.secrets]
        volumes = [{"name": cm, "configMap": {"name": cm}} for cm in comp.configmaps]
        if volumes:
            container["volumeMounts"] = [{"name": v["name"], "mountPath": f"/etc/{v['name']}"} for v in volumes]
        if comp.protocol in ("grpc", "http") and not comp.infra:
            container["readinessProbe"] = {"tcpSocket": {"port": comp.port}, "periodSeconds": 10}
        template = {"metadata": {"labels": dict(labels)}, "spec": {"containers": [container]}}
        if volumes:
            template["spec"]["volumes"] = volumes
        dep = {"apiVersion": "apps/v1", "kind": "Deployment",
               "metadata": self.meta(comp.name, comp.namespace, created, labels,
                                     {"deployment.kubernetes.io/revision": "1", "meta.helm.sh/release-name": "demo"}),
               "spec": {"replicas": comp.replicas, "selector": {"matchLabels": dict(labels)},
                        "strategy": {"type": comp.strategy, **({"rollingUpdate": {"maxSurge": "25%",
                                                                                  "maxUnavailable": "25%"}}
                                                               if comp.strategy == "RollingUpdate" else {})},
                        "template": template},
               "status": {}}
        self.put(dep)
        w = Workload(comp, dep)
        self.workloads[comp.name] = w
        rs = self._replicaset(w, template, created, revision=1)
        for i in range(comp.replicas):
            self._pod(w, rs, created + 30 + i, "running")
        if comp.service:
            ref = Ref(comp.namespace, "Service", comp.service)
            if ref not in self.objects:
                sel = {"app": labels["app"]} if comp.namespace == "book-info" else dict(labels)
                self.ip[comp.service] = f"10.96.{int(_hash(comp.service, n=2), 16) % 250 + 1}.{int(_hash(comp.service, 7, n=2), 16) % 250 + 2}"
                svc = {"apiVersion": "v1", "kind": "Service", "metadata": self.meta(comp.service, comp.namespace, created,
                                                                                    {"app.kubernetes.io/name": comp.service}),
                       "spec": {"type": "ClusterIP", "clusterIP": self.ip[comp.service], "selector": sel,
                                "ports": [{"name": "tcp-service", "port": comp.port, "targetPort": comp.port,
                                           "protocol": "TCP"}]}}
                self.put(svc)
            w.service = self.objects[ref]
        self._sync(w)

    def _replicaset(self, w: Workload, template: dict, created: float, revision: int) -> dict:
        h = _hash(json.dumps(template, sort_keys=True), n=10)
        tpl = copy.deepcopy(template)
        tpl["metadata"]["labels"]["pod-template-hash"] = h
        rs = {"apiVersion": "apps/v1", "kind": "ReplicaSet",
              "metadata": self.meta(f"{w.comp.name}-{h}", w.comp.namespace, created, tpl["metadata"]["labels"],
                                    {"deployment.kubernetes.io/revision": str(revision)}, manager="kube-controller-manager"),
              "spec": {"replicas": 0, "selector": {"matchLabels": tpl["metadata"]["labels"]}, "template": tpl},
              "status": {}}
        rs["metadata"]["ownerReferences"] = [{"apiVersion": "apps/v1", "kind": "Deployment", "name": w.comp.name,
                                              "controller": True}]
        self.put(rs)
        w.replicasets.append(rs)
        return rs

    def _pod(self, w: Workload, rs: dict, created: float, state: str, **kw) -> dict:
        tpl = rs["spec"]["template"]
        name = f"{rs['metadata']['name']}-{_suffix(rs['metadata']['name'], created, len(w.pods), self.seed)}"
        node = kw.pop("node", None) or NODES[int(_hash(name, n=4), 16) % len(NODES)]
        pod = {"apiVersion": "v1", "kind": "Pod",
               "metadata": self.meta(name, w.comp.namespace, created, tpl["metadata"]["labels"],
                                     manager="kube-controller-manager"),
               "spec": copy.deepcopy(tpl["spec"]), "status": {}}
        pod["metadata"]["ownerReferences"] = [{"apiVersion": "apps/v1", "kind": "ReplicaSet",
                                               "name": rs["metadata"]["name"], "controller": True}]
        if state != "pending":
            pod["spec"]["nodeName"] = node
        self.set_pod_state(pod, state, created, **kw)
        self.put(pod)
        w.pods.append(pod)
        if state != "pending":
            self.event(pod, "Normal", "Scheduled",
                       f"Successfully assigned {w.comp.namespace}/{name} to {node}", created, source="default-scheduler")
        return pod

    def set_pod_state(self, pod: dict, state: str, since: float, *, restarts: int = 0, reason: str = "",
                      message: str = "", exit_code: int = 1, last_reason: str = "", last_finished: float | None = None,
                      init: str | None = None) -> None:
        cname = pod["spec"]["containers"][0]["name"]
        image = pod["spec"]["containers"][0]["image"]
        cs: dict = {"name": cname, "image": image, "restartCount": restarts, "ready": False, "started": False}
        phase, ready = "Running", False
        conditions = [{"type": "PodScheduled", "status": "True", "lastTransitionTime": self.ts(since)}]
        if state == "running":
            cs.update(ready=True, started=True, state={"running": {"startedAt": self.ts(since + 8)}})
            ready = True
        elif state == "notready":
            cs.update(started=True, state={"running": {"startedAt": self.ts(since + 8)}})
        elif state == "crashloop":
            cs["state"] = {"waiting": {"reason": "CrashLoopBackOff",
                                       "message": f"back-off 5m0s restarting failed container={cname} pod={pod['metadata']['name']}"}}
            cs["lastState"] = {"terminated": {"reason": reason or "Error", "exitCode": exit_code, "message": message,
                                              "finishedAt": self.ts(since + 60 * max(restarts, 1))}}
        elif state == "waiting":
            cs["state"] = {"waiting": {"reason": reason, "message": message}}
        elif state == "pending":
            phase = "Pending"
            conditions = [{"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": message,
                           "lastTransitionTime": self.ts(since)}]
            cs = None
        elif state == "init":
            phase = "Pending"
            cs["state"] = {"waiting": {"reason": "PodInitializing"}}
        if last_reason and state == "running":
            cs["lastState"] = {"terminated": {"reason": last_reason, "exitCode": 137,
                                              "finishedAt": self.ts(last_finished or since)}}
        conditions += [{"type": "Ready", "status": "True" if ready else "False",
                        **({} if ready else {"reason": "ContainersNotReady",
                                             "message": f"containers with unready status: [{cname}]"})},
                       {"type": "ContainersReady", "status": "True" if ready else "False"}]
        status: dict = {"phase": phase, "conditions": conditions, "startTime": self.ts(since), "qosClass": "Burstable"}
        if cs:
            status["containerStatuses"] = [cs]
        if pod["spec"].get("nodeName"):
            status["podIP"] = f"10.244.{int(_hash(pod['metadata']['name'], n=2), 16) % 3}.{int(_hash(pod['metadata']['name'], 3, n=2), 16) % 250 + 2}"
            status["hostIP"] = "10.0.0." + str(10 + NODES.index(pod["spec"]["nodeName"])) \
                if pod["spec"]["nodeName"] in NODES else "10.0.0.99"
        if init:
            ics = pod["spec"].get("initContainers") or [{"name": "init", "image": "busybox:1.36"}]
            istate = {"crash": {"waiting": {"reason": "CrashLoopBackOff", "message": "back-off 5m0s restarting failed container"}},
                      "running": {"running": {"startedAt": self.ts(since + 5)}}}[init]
            ist = {"name": ics[0]["name"], "image": ics[0]["image"], "ready": False, "restartCount": restarts,
                   "state": istate}
            if init == "crash":
                ist["lastState"] = {"terminated": {"reason": "Error", "exitCode": exit_code, "message": message}}
            status["initContainerStatuses"] = [ist]
            status["phase"] = "Pending"
            if cs:
                cs["state"] = {"waiting": {"reason": "PodInitializing"}}
                cs["restartCount"] = 0
        pod["status"] = status

    def _sync(self, w: Workload) -> None:
        """Recompute Deployment/ReplicaSet status and Endpoints from pods."""
        alive = [p for p in w.pods if p["metadata"].get("deletionTimestamp") is None]
        ready = [p for p in alive if any(c.get("type") == "Ready" and c.get("status") == "True"
                                         for c in p["status"].get("conditions", []))]
        for rs in w.replicasets:
            mine = [p for p in alive if p["metadata"]["ownerReferences"][0]["name"] == rs["metadata"]["name"]]
            rs["spec"]["replicas"] = len(mine)
            rs["status"] = {"replicas": len(mine), "readyReplicas": len([p for p in mine if p in ready]),
                            "availableReplicas": len([p for p in mine if p in ready])}
        spec_replicas = w.deployment["spec"]["replicas"]
        cur = w.replicasets[-1]["metadata"]["name"]
        updated = [p for p in alive if p["metadata"]["ownerReferences"][0]["name"] == cur]
        cond = [{"type": "Available", "status": "True" if len(ready) >= max(spec_replicas - 0, 1) or spec_replicas == 0
                 else "False", "reason": "MinimumReplicasAvailable" if ready or spec_replicas == 0
                 else "MinimumReplicasUnavailable"},
                {"type": "Progressing", "status": "True",
                 "reason": "NewReplicaSetAvailable" if all(p in ready for p in updated) and updated
                 else "ReplicaSetUpdated"}]
        w.deployment["status"] = {"observedGeneration": int(w.deployment["metadata"].get("generation", 1)),
                                  "replicas": len(alive), "updatedReplicas": len(updated),
                                  "readyReplicas": len(ready), "availableReplicas": len(ready),
                                  "unavailableReplicas": max(spec_replicas - len(ready), 0), "conditions": cond}
        w.serving = bool(ready)
        if w.service is not None:
            self._endpoints(w.service)

    def _endpoints(self, svc: dict) -> None:
        ns, sel = svc["metadata"]["namespace"], svc["spec"].get("selector") or {}
        addrs, not_ready = [], []
        for ref, o in self.objects.items():
            if ref.kind != "Pod" or ref.namespace != ns or not sel:
                continue
            labels = o["metadata"].get("labels", {})
            if all(labels.get(k) == v for k, v in sel.items()) and o["status"].get("podIP"):
                is_ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in o["status"]["conditions"])
                (addrs if is_ready else not_ready).append({"ip": o["status"]["podIP"],
                                                           "targetRef": {"kind": "Pod", "name": ref.name}})
        subset = {"ports": [{"port": p.get("targetPort", p["port"]), "protocol": "TCP"} for p in svc["spec"]["ports"]]}
        if addrs:
            subset["addresses"] = addrs
        if not_ready:
            subset["notReadyAddresses"] = not_ready
        self.put({"apiVersion": "v1", "kind": "Endpoints",
                  "metadata": self.meta(svc["metadata"]["name"], ns, BASE_TIME, svc["metadata"].get("labels")),
                  "subsets": [subset] if (addrs or not_ready) else []})

    def resync_all(self) -> None:
        for w in self.workloads.values():
            self._sync(w)
        for ref, o in list(self.objects.items()):
            if ref.kind == "Service":
                self._endpoints(o)

    # -- fault primitives ------------------------------------------------------------------------------

    def rollout(self, comp_name: str, mutate, t: float, new_state: str, *, stuck: bool = True, **state_kw) -> dict:
        """Change the pod template (new revision). If the new pods never become ready, a RollingUpdate keeps the
        old pods serving (the rollout is stuck); a Recreate deployment, or ``stuck=False``, has no old pods left."""
        w = self.workloads[comp_name]
        tpl = copy.deepcopy(w.deployment["spec"]["template"])
        mutate(tpl)
        w.deployment["spec"]["template"] = tpl
        rev = len(w.replicasets) + 1
        w.deployment["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = str(rev)
        w.deployment["metadata"]["generation"] = rev
        self.touch(w.deployment, t)
        rs = self._replicaset(w, tpl, t, rev)
        self.event(w.deployment, "Normal", "ScalingReplicaSet",
                   f"Scaled up replica set {rs['metadata']['name']} from 0 to 1", t, source="deployment-controller")
        keep_old = stuck and w.deployment["spec"]["strategy"]["type"] == "RollingUpdate" and new_state != "running"
        if not keep_old:
            for p in list(w.pods):
                self.remove(Ref.of(p))
                w.pods.remove(p)
            for old in w.replicasets[:-1]:
                self.event(w.deployment, "Normal", "ScalingReplicaSet",
                           f"Scaled down replica set {old['metadata']['name']} from 1 to 0", t + 2,
                           source="deployment-controller")
        new = self._pod(w, rs, t + 1, new_state, **state_kw)
        if new_state in ("crashloop", "waiting", "pending") or state_kw.get("init"):
            w.deployment["status"]["conditions"] = []
        self._sync(w)
        if not w.serving:
            self.break_component(comp_name, "refused", since=t + 3)
        return new

    def restart_pods(self, comp_name: str, t: float) -> None:
        """Delete the pods; the ReplicaSet creates fresh ones with the same template."""
        w = self.workloads[comp_name]
        n = len(w.pods)
        for p in list(w.pods):
            self.event(p, "Normal", "Killing", f"Stopping container {p['spec']['containers'][0]['name']}", t)
            self.remove(Ref.of(p))
            w.pods.remove(p)
        for i in range(max(n, 1)):
            self._pod(w, w.replicasets[-1], t + 2 + i, "running")
        self._sync(w)

    def delete_pods(self, comp_name: str, t: float) -> None:
        w = self.workloads[comp_name]
        for p in list(w.pods):
            self.event(p, "Normal", "Killing", f"Stopping container {p['spec']['containers'][0]['name']}", t)
            self.remove(Ref.of(p))
            w.pods.remove(p)
        self._sync(w)
        if not w.serving:
            self.break_component(comp_name, "refused", since=t + 2)

    def break_component(self, comp_name: str, mode: str, *, since: float, message: str = "", rate: float = 1.0,
                        latency_factor: float = 1.0, status_code: int | None = None, ops: tuple[str, ...] = ()) -> None:
        self.failures[comp_name] = CallFailure(mode, message, rate, since, latency_factor, status_code, ops)

    def stop_traffic(self, comp_name: str, since: float) -> None:
        self.no_traffic[comp_name] = since

    # -- telemetry -------------------------------------------------------------------------------------

    def simulate_traffic(self, traces_per_minute: int = 30) -> None:
        for app in self.apps:
            flows, weights = app.flows, [f.weight for f in app.flows]
            n = int(traces_per_minute * WINDOW / 60 * (1 if app.namespace == "otel-demo" else 0.6))
            for i in range(n):
                t = self.t0 + (i + self.rng.random()) * WINDOW / n
                flow = self.rng.choices(flows, weights)[0]
                self._trace(app, flow, t)

    def _trace(self, app: Application, flow, t: float) -> None:
        trace_id = _hash(self.seed, app.name, t, n=32)
        entry_caller = "load-generator" if app.namespace == "otel-demo" else None
        top = flow.calls[0]
        if entry_caller:
            self._call(app, trace_id, entry_caller, None, top, t)
        else:
            self._serve(app, trace_id, None, top, t)

    def _span(self, trace_id: str, comp: Component, parent: str | None, name: str, kind: str, start: float,
              duration_ms: float, error: str | None, attrs: dict) -> str:
        sid = _hash(trace_id, comp.name, name, kind, start, n=16)
        self.spans.append({"trace_id": trace_id, "span_id": sid, "parent_span_id": parent or "",
                           "service": comp.otel_name, "namespace": comp.namespace, "name": name, "kind": kind,
                           "start": round(start, 4), "duration_ms": round(duration_ms, 2),
                           "status": "ERROR" if error else "OK", "status_message": error or "", "attributes": attrs})
        return sid

    def _call(self, app: Application, trace_id: str, caller: str, parent: str | None, call: tuple, t: float):
        """A client span from ``caller`` to the callee in ``call``; returns (duration_ms, error)."""
        callee_name, op, _critical, _children = call
        caller_c, callee_c = self.component(caller), self.component(callee_name)
        host = callee_c.service or callee_name
        attrs = {"server.address": host, "server.port": callee_c.port, "rpc.system": callee_c.protocol}
        cf = self.caller_failures.get(caller)
        if cf and t >= cf.since:
            msg = self._client_message(caller_c, cf.mode, host, callee_c.port) if not cf.message else \
                cf.message.format(host=host, port=callee_c.port)
            self._span(trace_id, caller_c, parent, op, "CLIENT", t, self.rng.uniform(1, 4), msg, attrs)
            self._maybe_log(caller_c, t, f"failed to call {host}: {msg}", trace_id)
            return 2.0, msg
        f = self.failures.get(callee_name)
        if callee_name in self.no_traffic and t >= self.no_traffic[callee_name]:
            f = f or CallFailure("timeout", since=self.no_traffic[callee_name])
        if not caller_c.instrumented:  # the broker delivers to consumers; it records no client span
            if f and f.applies(t, op) and f.mode not in ("app_error", "slow"):
                return 0.0, None  # a consumer that is down simply stops consuming; the broker sees no error
            self._serve(app, trace_id, parent, call, t + self.rng.uniform(0.01, 0.2))
            return 0.0, None
        if f and f.applies(t, op) and f.mode not in ("app_error", "slow", "deny") and self.rng.random() < f.rate:
            dur = {"timeout": self.rng.uniform(5000, 5050), "refused": self.rng.uniform(0.5, 3)}.get(f.mode,
                                                                                               self.rng.uniform(1, 8))
            msg = f.message or GENERIC.get(f.mode) or self._client_message(caller_c, f.mode, host, callee_c.port)
            msg = msg.format(host=host, port=callee_c.port, ip=self.ip.get(host, "10.96.0.1"))
            if f.status_code:
                attrs = {**attrs, "http.response.status_code": f.status_code}
            self._span(trace_id, caller_c, parent, op, "CLIENT", t, dur, msg, attrs)
            self._maybe_log(caller_c, t, f"{op} to {host} failed: {msg}", trace_id)
            return dur, msg
        cid = _hash(trace_id, caller, callee_name, op, t, n=16)
        dur, err = self._serve(app, trace_id, cid, call, t + 0.0005)
        total = dur + self.rng.uniform(0.3, 1.5)
        if err:
            err = f"{op}: {err}" if not err.startswith(op) else err
            self._maybe_log(caller_c, t, f"error calling {host} {op}: {err}", trace_id, prob=0.35)
        self.spans.append({"trace_id": trace_id, "span_id": cid, "parent_span_id": parent or "",
                           "service": caller_c.otel_name, "namespace": caller_c.namespace, "name": op,
                           "kind": "CLIENT", "start": round(t, 4), "duration_ms": round(total, 2),
                           "status": "ERROR" if err else "OK", "status_message": err or "", "attributes": attrs})
        return total, err

    def _serve(self, app: Application, trace_id: str, parent: str | None, call: tuple, t: float):
        callee_name, op, _critical, children = call
        comp = self.component(callee_name)
        f = self.failures.get(callee_name)
        own_error = None
        base = self.rng.lognormvariate(1.3, 0.5)
        if f and f.applies(t, op) and f.mode == "slow":
            base *= f.latency_factor
        if f and f.applies(t, op) and f.mode in ("app_error", "deny") and self.rng.random() < f.rate:
            own_error = f.message
            base *= f.latency_factor
            if f.mode == "deny":
                children = []
        elif self.rng.random() < 0.0025:  # baseline background errors
            own_error = "context canceled"
        elapsed = base
        child_error = None
        sid = _hash(trace_id, comp.name, op, "SERVER", t, n=16)
        for child in children:
            d, e = self._call(app, trace_id, callee_name, sid, child, t + elapsed / 1000)
            elapsed += d
            if e and child[2] and not child_error:
                child_error = e
        err = own_error or child_error
        if own_error and comp.instrumented:
            self._maybe_log(comp, t, own_error, trace_id, prob=0.6)
        if not comp.instrumented:  # databases and brokers emit no spans; the caller's client span shows the call
            return elapsed, err
        self.spans.append({"trace_id": trace_id, "span_id": sid, "parent_span_id": parent or "",
                           "service": comp.otel_name, "namespace": comp.namespace, "name": op, "kind": "SERVER",
                           "start": round(t, 4), "duration_ms": round(elapsed, 2),
                           "status": "ERROR" if err else "OK", "status_message": err or "", "attributes": {}})
        return elapsed, err

    def _client_message(self, comp: Component, mode: str, host: str, port: int) -> str:
        table = CLIENT_MESSAGES.get(comp.language, CLIENT_MESSAGES["go"])
        tmpl = table.get(mode) or GENERIC.get(mode) or mode
        return tmpl.format(host=host, port=port, ip=self.ip.get(host, "10.96.0.1"))

    def _maybe_log(self, comp: Component, t: float, body: str, trace_id: str, prob: float = 0.5) -> None:
        if self.rng.random() < prob:
            self.log(comp, t + 0.01, "ERROR", body, trace_id)

    # -- metrics and alerts ----------------------------------------------------------------------------

    def compute_metrics(self) -> None:
        minutes = int(WINDOW / 60)
        buckets: dict[tuple, dict] = defaultdict(lambda: {"n": 0, "err": 0, "dur": []})
        for s in self.spans:
            m = int((s["start"] - self.t0) // 60)
            if not 0 <= m < minutes:
                continue
            app = self._app_by_ns(s["namespace"])
            if app.metrics_by_destination:
                if s["kind"] != "CLIENT" and s["parent_span_id"]:
                    continue
                svc = s["attributes"].get("server.address") or s["service"].split(".")[0]
                key = ("dest", s["namespace"], svc, m)
            else:
                key = ("svc", s["namespace"], s["service"], m)
            b = buckets[key]
            if s["kind"] == "SERVER" or app.metrics_by_destination:
                b["n"] += 1
                b["dur"].append(s["duration_ms"])
            b["err"] += s["status"] == "ERROR"
            b.setdefault("all", 0)
            b["all"] = b["all"] + 1
        series: dict[tuple, dict] = {}
        for (typ, ns, svc, m), b in buckets.items():
            lbl_key = "destination_service_name" if typ == "dest" else "service_name"
            for metric, value in (("request_rate", b["n"] / 60),
                                  ("error_ratio", b["err"] / max(b.get("all", 1), 1)),
                                  ("errors", b["err"] / 60),
                                  ("latency_p95_ms", _p95(b["dur"]))):
                name = {"request_rate": "requests_per_second", "error_ratio": "request_error_ratio",
                        "errors": "request_errors_per_second", "latency_p95_ms": "request_duration_p95_ms"}[metric]
                k = (name, ns, svc)
                if k not in series:
                    series[k] = {"name": name, "labels": {"namespace": ns, lbl_key: svc}, "points": []}
                series[k]["points"].append([self.t0 + m * 60, round(value, 4)])
        for s in series.values():
            have = {int(p[0]) for p in s["points"]}
            for m in range(minutes):  # minutes without requests are explicit zeros
                tt = self.t0 + m * 60
                if int(tt) not in have:
                    s["points"].append([tt, 0.0])
            s["points"].sort()
        self.metrics.extend(series.values())
        self._pod_metrics()
        self.metrics.extend(self.extra_series)

    def _pod_metrics(self) -> None:
        minutes = int(WINDOW / 60)
        for ref, pod in self.objects.items():
            if ref.kind != "Pod":
                continue
            cs = (pod["status"].get("containerStatuses") or [{}])[0]
            limit = _bytes(pod["spec"]["containers"][0].get("resources", {}).get("limits", {}).get("memory", "256Mi"))
            created = _ts(pod["metadata"]["creationTimestamp"])
            running = "running" in (cs.get("state") or {})
            base_mem = limit * self.rng.uniform(0.35, 0.6)
            mem, cpu, ready, restarts = [], [], [], []
            for m in range(minutes):
                tt = self.t0 + m * 60
                if tt < created:
                    continue
                alive = running or tt < self.t_fault
                mem.append([tt, round(base_mem * self.rng.uniform(0.97, 1.03)) if alive else 0])
                cpu.append([tt, round(self.rng.uniform(0.005, 0.04), 4) if alive else 0])
                ok = any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod["status"]["conditions"])
                ready.append([tt, 1 if (ok or tt < self.t_fault and created < self.t_fault) else 0])
                rc = cs.get("restartCount", 0)
                restarts.append([tt, rc if tt >= self.t_fault or created < self.t0 else 0])
            lbl = {"namespace": ref.namespace, "pod": ref.name, "container": pod["spec"]["containers"][0]["name"]}
            for name, pts in (("container_memory_working_set_bytes", mem), ("container_cpu_usage_cores", cpu),
                              ("kube_pod_status_ready", ready), ("kube_pod_container_status_restarts_total", restarts)):
                if pts:
                    self.metrics.append({"name": name, "labels": dict(lbl), "points": pts})

    def _app_by_ns(self, ns: str) -> Application:
        for a in self.apps:
            if a.namespace == ns:
                return a
        return self.apps[0]

    def evaluate_alerts(self) -> None:
        """Prometheus-style rules over the last five minutes, compared with the pre-incident baseline."""
        end = self.t_end
        recent = end - 5 * 60
        for s in self.metrics:
            name, lbl = s["name"], s["labels"]
            pts = s["points"]
            before = [v for t, v in pts if t < self.t_fault - 60]
            last = [v for t, v in pts if t >= recent]
            if not last:
                continue
            svc_lbl = {k: v for k, v in lbl.items() if k in ("namespace", "service_name", "destination_service_name")}
            if name == "request_error_ratio":
                errors = self._series_value("request_errors_per_second", lbl, recent) * 300
                if sum(last) / len(last) > 0.05 and errors >= 4:
                    self._alert("HighRequestErrorRate", svc_lbl, sum(last) / len(last), "critical",
                                "Error rate above 5% for 5 minutes")
            elif name == "request_duration_p95_ms":
                base = sorted(before)[len(before) // 2] if before else 0
                cur = sorted(last)[len(last) // 2]
                if cur > max(500, 3 * base):
                    self._alert("HighRequestLatency", svc_lbl, cur, "warning", "p95 latency above 500ms")
            elif name == "requests_per_second":
                if before and sum(before) / len(before) >= 0.02 and max(last) == 0:
                    self._alert("NoRequestsReceived", svc_lbl, 0, "critical", "No requests received for 5 minutes")
        for ref, pod in self.objects.items():
            if ref.kind != "Pod":
                continue
            st = pod["status"]
            if _ts(pod["metadata"]["creationTimestamp"]) > end - 120:
                continue
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in st.get("conditions", []))
            for cs in st.get("containerStatuses") or []:
                waiting = (cs.get("state") or {}).get("waiting") or {}
                if waiting.get("reason") == "CrashLoopBackOff":
                    self._alert("KubePodCrashLooping", {"namespace": ref.namespace, "pod": ref.name,
                                                        "container": cs["name"]}, cs.get("restartCount", 0), "warning",
                                f"Pod {ref.namespace}/{ref.name} ({cs['name']}) is in waiting state (reason: \"CrashLoopBackOff\").")
            for ics in st.get("initContainerStatuses") or []:
                state = ics.get("state") or {}
                if "waiting" in state or "running" in state:
                    self._alert("KubeContainerWaiting", {"namespace": ref.namespace, "pod": ref.name,
                                                         "container": ics["name"]}, 1, "warning",
                                f"pod/{ref.name} in namespace {ref.namespace} on container {ics['name']} has been in waiting state for longer than 1 hour.")
            if not ready and st.get("phase") in ("Pending", "Running", "Unknown"):
                self._alert("KubePodNotReady", {"namespace": ref.namespace, "pod": ref.name}, 1, "warning",
                            f"Pod {ref.namespace}/{ref.name} has been in a non-ready state for longer than 15 minutes.",
                            active_at=self.chronic.get(ref.name))
        for ref, hpa in self.objects.items():
            if ref.kind == "HorizontalPodAutoscaler":
                stt, spec = hpa.get("status", {}), hpa["spec"]
                if stt.get("currentReplicas") == spec.get("maxReplicas") and stt.get("desiredReplicas", 0) >= spec.get("maxReplicas", 0) \
                        and stt.get("currentMetrics"):
                    cur = stt["currentMetrics"][0]["resource"]["current"]["averageUtilization"]
                    tgt = spec["metrics"][0]["resource"]["target"]["averageUtilization"]
                    if cur > tgt:
                        self._alert("KubeHpaMaxedOut", {"namespace": ref.namespace, "horizontalpodautoscaler": ref.name},
                                    stt["currentReplicas"], "warning",
                                    f"HPA {ref.namespace}/{ref.name} has been running at max replicas for longer than 15 minutes.")

    def _series_value(self, name: str, labels: dict, since: float) -> float:
        for s in self.metrics:
            if s["name"] == name and all(s["labels"].get(k) == v for k, v in labels.items()):
                vals = [v for t, v in s["points"] if t >= since]
                return sum(vals) / len(vals) if vals else 0.0
        return 0.0

    def _alert(self, name: str, labels: dict, value: float, severity: str, summary: str,
               active_at: float | None = None) -> None:
        self.alerts.append({"labels": {"alertname": name, **labels, "severity": severity},
                            "annotations": {"summary": summary, "description": summary},
                            "state": "firing", "value": str(round(value, 4)),
                            "activeAt": self.ts(active_at or self.t_fault + self.rng.randint(90, 300))})

    # -- output ----------------------------------------------------------------------------------------

    def snapshot(self) -> Snapshot:
        self.resync_all()
        for ns, since in self.silent.items():
            self.spans = [s for s in self.spans if not (s["namespace"] == ns and s["start"] >= since
                                                        and not (s["kind"] == "SERVER" and not s["parent_span_id"]))]
        self.compute_metrics()
        self.evaluate_alerts()
        self.logs.sort(key=lambda r: r["timestamp"])
        self.spans.sort(key=lambda s: s["start"])
        self.events.sort(key=lambda e: e["lastTimestamp"])
        objs = [self.objects[r] for r in sorted(self.objects)]
        return Snapshot(self.name, objs, self.events, self.alerts, self.logs, self.spans, self.metrics,
                        {"source": "simulator", "seed": self.seed, "window_start": self.ts(self.t0),
                         "window_end": self.ts(self.t_end), "collected_at": self.ts(self.t_end)})


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return round(v[min(len(v) - 1, int(0.95 * len(v)))], 2)


def _bytes(q: str) -> int:
    units = {"Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3, "K": 1000, "M": 1000 ** 2, "G": 1000 ** 3}
    for u, mult in units.items():
        if q.endswith(u):
            return int(float(q[: -len(u)]) * mult)
    return int(float(q))


def _ts(text: str) -> float:
    from ..snapshot import parse_time

    return parse_time(text) or 0.0
