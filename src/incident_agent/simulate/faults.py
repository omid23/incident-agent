"""Fault mechanisms, one per ITBench fault id, plus background noise.

Each mechanism changes cluster objects the way the ITBench injection does (see the fault
definitions in ``data/itbench/faults``) and registers how traffic breaks as a result.
Objects a fault creates take the names from the scenario's ground truth, because those names
are part of the scenario definition.
"""

from __future__ import annotations

import base64
import copy
from collections.abc import Callable

from ..entities import Ref
from .engine import NODES, CallFailure, World, _hash, _suffix

Mechanism = Callable[[World, Ref, list[Ref], float], None]
MECHANISMS: dict[str, Mechanism] = {}


def mechanism(fault_id: str):
    def wrap(fn: Mechanism) -> Mechanism:
        MECHANISMS[fault_id] = fn
        return fn
    return wrap


def _named(gt: list[Ref], kind: str, default: str) -> str:
    return next((r.name for r in gt if r.kind == kind), default)


def _container(tpl: dict) -> dict:
    return tpl["spec"]["containers"][0]


def _restart_annotation(w: World, t: float):
    def mutate(tpl: dict) -> None:
        tpl["metadata"].setdefault("annotations", {})["kubectl.kubernetes.io/restartedAt"] = w.ts(t)
    return mutate


# -- workload template faults ----------------------------------------------------------------------------

@mechanism("nonexistent-kubernetes-workload-container-image")
def bad_image(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    image = w.workloads[target.name].comp.image.rsplit(":", 1)[0] + ":2.1.3-" + target.name + "-nonexistent"

    def mutate(tpl):
        _container(tpl)["image"] = image

    pod = w.rollout(target.name, mutate, t, "waiting", reason="ImagePullBackOff", message=f'Back-off pulling image "{image}"')
    w.event(pod, "Normal", "Pulling", f'Pulling image "{image}"', t + 2, t + 600, count=7)
    w.event(pod, "Warning", "Failed", f'Failed to pull image "{image}": rpc error: code = NotFound desc = failed to pull and '
                                      f'unpack image "{image}": failed to resolve reference "{image}": {image}: not found',
            t + 3, t + 600, count=7)
    w.event(pod, "Warning", "Failed", "Error: ErrImagePull", t + 3, t + 600, count=7)
    w.event(pod, "Normal", "BackOff", f'Back-off pulling image "{image}"', t + 10, w.t_end - 20, count=40)


@mechanism("unsupported-architecture-kubernetes-workload-container-image")
def wrong_arch(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    image = w.workloads[target.name].comp.image.rsplit(":", 1)[0] + f":2.1.3-{target.name}-linux-arm64"

    def mutate(tpl):
        _container(tpl)["image"] = image

    pod = w.rollout(target.name, mutate, t, "waiting", reason="ErrImagePull",
                    message='no match for platform in manifest: not found')
    w.event(pod, "Warning", "Failed", f'Failed to pull image "{image}": rpc error: code = NotFound desc = failed to pull and '
                                      f'unpack image "{image}": no match for platform in manifest: not found',
            t + 3, w.t_end - 30, count=9)
    w.event(pod, "Normal", "BackOff", f'Back-off pulling image "{image}"', t + 10, w.t_end - 20, count=35)


@mechanism("invalid-kubernetes-workload-container-command")
def bad_command(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    binary = f"/usr/src/app/{target.name.replace('-', '')}-svc"

    def mutate(tpl):
        _container(tpl)["command"] = [binary]

    msg = (f'failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: '
           f'unable to start container process: exec: "{binary}": stat {binary}: no such file or directory: unknown')
    pod = w.rollout(target.name, mutate, t, "crashloop", restarts=7, reason="StartError", exit_code=128, message=msg)
    w.event(pod, "Warning", "Failed", f"Error: {msg}", t + 5, w.t_end - 60, count=8)
    w.event(pod, "Warning", "BackOff", "Back-off restarting failed container", t + 20, w.t_end - 10, count=60)


@mechanism("insufficient-kubernetes-workload-container-resources")
def tiny_memory(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    def mutate(tpl):
        _container(tpl)["resources"] = {"limits": {"memory": "8Mi"}, "requests": {"memory": "8Mi", "cpu": "10m"}}

    pod = w.rollout(target.name, mutate, t, "crashloop", restarts=6, reason="OOMKilled", exit_code=137)
    w.event(pod, "Warning", "BackOff", "Back-off restarting failed container", t + 30, w.t_end - 10, count=45)
    comp = w.workloads[target.name].comp
    for caller in ("accounting",) if target.name == "postgresql" else ():
        for k in range(8):
            tt = t + 30 + k * 90
            w.log(caller, tt, "ERROR", "Npgsql.NpgsqlException (0x80004005): Failed to connect to "
                                       f"{w.ip.get(comp.service or '', '10.96.0.1')}:5432 ---> System.Net.Sockets.SocketException "
                                       "(111): Connection refused")


@mechanism("hanging-kubernetes-workload-init-container")
def hanging_init(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    def mutate(tpl):
        tpl["spec"]["initContainers"] = [{"name": "wait-for-dependencies", "image": "busybox:1.36",
                                          "command": ["sh", "-c", f"until nslookup {target.name}-dependency; do sleep 2; done"]}]

    pod = w.rollout(target.name, mutate, t, "init", init="running")
    w.event(pod, "Normal", "Started", "Started container wait-for-dependencies", t + 4)


@mechanism("crashing-kubernetes-workload-init-container")
def crashing_init(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    cm_name = _named(gt, "ConfigMap", f"{target.name}-config")
    cm = w.put({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": w.meta(cm_name, target.namespace, t - 5, {"app.kubernetes.io/name": target.name},
                                   manager="kubectl-client-side-apply"),
                "data": {"init.sh": "#!/bin/sh\nset -e\necho 'warming cache'\ncurl -sf http://localhost:9999/warmup\n"}})

    def mutate(tpl):
        tpl["spec"]["initContainers"] = [{"name": "init-config", "image": "busybox:1.36", "command": ["sh", "/scripts/init.sh"],
                                          "volumeMounts": [{"name": "init-script", "mountPath": "/scripts"}]}]
        tpl["spec"].setdefault("volumes", []).append({"name": "init-script", "configMap": {"name": cm_name}})

    pod = w.rollout(target.name, mutate, t, "init", init="crash", restarts=6, exit_code=127,
                    message="sh: curl: not found")
    w.event(pod, "Warning", "BackOff", "Back-off restarting failed container init-config in pod "
                                       f"{pod['metadata']['name']}_{target.namespace}", t + 30, w.t_end - 15, count=40)
    assert cm


@mechanism("misconfigured-kubernetes-workload-container-readiness-probe")
def bad_readiness(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    port = w.workloads[target.name].comp.port

    def mutate(tpl):
        _container(tpl)["readinessProbe"] = {"httpGet": {"path": "/api/healthz-v2", "port": port}, "periodSeconds": 5,
                                             "failureThreshold": 3}

    pod = w.rollout(target.name, mutate, t, "notready")
    w.event(pod, "Warning", "Unhealthy", "Readiness probe failed: HTTP probe failed with statuscode: 404", t + 15,
            w.t_end - 5, count=170)


@mechanism("nonexistent-kubernetes-workload-node")
def missing_node(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    def mutate(tpl):
        tpl["spec"]["nodeSelector"] = {"kubernetes.io/hostname": "worker-7"}

    msg = ("0/4 nodes are available: 1 node(s) had untolerated taint {node-role.kubernetes.io/control-plane: }, "
           "3 node(s) didn't match Pod's node affinity/selector. preemption: 0/4 nodes are available: "
           "4 Preemption is not helpful for scheduling.")
    pod = w.rollout(target.name, mutate, t, "pending", message=msg)
    w.event(pod, "Warning", "FailedScheduling", msg, t + 1, w.t_end - 30, count=12, source="default-scheduler")


@mechanism("unschedulable-kubernetes-workload-pod-anti-affinity-rule")
def anti_affinity(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    def mutate(tpl):
        tpl["spec"]["affinity"] = {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{
            "labelSelector": {"matchExpressions": [{"key": "app.kubernetes.io/name", "operator": "Exists"}]},
            "topologyKey": "kubernetes.io/hostname"}]}}

    msg = ("0/4 nodes are available: 1 node(s) had untolerated taint {node-role.kubernetes.io/control-plane: }, "
           "3 node(s) didn't match pod anti-affinity rules. preemption: 0/4 nodes are available: "
           "1 Preemption is not helpful for scheduling, 3 No preemption victims found for incoming pod.")
    pod = w.rollout(target.name, mutate, t, "pending", message=msg)
    w.event(pod, "Warning", "FailedScheduling", msg, t + 1, w.t_end - 30, count=11, source="default-scheduler")


@mechanism("nonexistent-kubernetes-workload-persistent-volume-claim")
def missing_pvc(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    claim = f"{target.name}-data"

    def mutate(tpl):
        tpl["spec"].setdefault("volumes", []).append({"name": "data", "persistentVolumeClaim": {"claimName": claim}})
        _container(tpl).setdefault("volumeMounts", []).append({"name": "data", "mountPath": "/opt/data"})

    msg = f'0/4 nodes are available: persistentvolumeclaim "{claim}" not found. preemption: 0/4 nodes are available: ' \
          "4 Preemption is not helpful for scheduling."
    pod = w.rollout(target.name, mutate, t, "pending", message=msg)
    w.event(pod, "Warning", "FailedScheduling", msg, t + 1, w.t_end - 30, count=12, source="default-scheduler")


@mechanism("failing-name-resolution-kubernetes-workload-dns-policy")
def bad_dns(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    def mutate(tpl):
        tpl["spec"]["dnsPolicy"] = "None"
        tpl["spec"]["dnsConfig"] = {"nameservers": ["192.0.2.53"], "searches": ["svc.cluster.local"]}

    w.rollout(target.name, mutate, t, "running")
    w.caller_failures[target.name] = CallFailure("dns", since=t + 20)


@mechanism("valkey-workload-changed-password")
def valkey_password(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    secret = w.objects[target]
    secret["data"] = {"valkey-password": base64.b64encode(b"rotated-" + _hash(t, n=8).encode()).decode()}
    w.touch(secret, t)
    users = [c for a in w.apps for c in a.components if target.name in c.secrets]
    for comp in users:  # the scenario deletes the pods so they pick up the new password
        w.restart_pods(comp.name, t + 20)
        w.break_component(comp.name, "app_error", since=t + 35, latency_factor=60,
                          message="NOAUTH Authentication required.")
    for k in range(10):
        w.log("cart", t + 40 + k * 70, "ERROR", "StackExchange.Redis.RedisServerException: NOAUTH Authentication required. "
                                               "at Cart.Services.ValkeyCartStore.AddItemAsync")


@mechanism("valkey-workload-out-of-memory")
def valkey_oom(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    ns = target.namespace
    job_name = f"valkey-config-{_suffix(t, n=5)}"
    job = w.put({"apiVersion": "batch/v1", "kind": "Job",
                 "metadata": w.meta(job_name, ns, t, {"app.kubernetes.io/managed-by": "ITBench"},
                                    manager="kubectl-create"),
                 "spec": {"template": {"spec": {"restartPolicy": "Never", "containers": [{
                     "name": "valkey-cli", "image": "docker.io/valkey/valkey:9.1.2-alpine3.24",
                     "command": ["sh", "-c", f"valkey-cli -h {target.name} CONFIG SET maxmemory 1mb && "
                                             f"valkey-cli -h {target.name} CONFIG SET maxmemory-policy noeviction"]}]}}},
                 "status": {"succeeded": 1, "completionTime": w.ts(t + 6),
                            "conditions": [{"type": "Complete", "status": "True"}]}})
    pod_name = f"{job_name}-{_suffix(job_name, n=5)}"
    jp = w.put({"apiVersion": "v1", "kind": "Pod",
                "metadata": {**w.meta(pod_name, ns, t + 1, {"job-name": job_name}),
                             "ownerReferences": [{"apiVersion": "batch/v1", "kind": "Job", "name": job_name}]},
                "spec": job["spec"]["template"]["spec"] | {"nodeName": NODES[1]},
                "status": {"phase": "Succeeded", "conditions": [{"type": "Ready", "status": "False",
                                                                  "reason": "PodCompleted"}],
                           "containerStatuses": [{"name": "valkey-cli", "ready": False, "restartCount": 0, "state": {
                               "terminated": {"reason": "Completed", "exitCode": 0}}}]}})
    w.event(job, "Normal", "SuccessfulCreate", f"Created pod: {pod_name}", t + 1, source="job-controller")
    w.event(job, "Normal", "Completed", "Job completed", t + 6, source="job-controller")
    assert jp
    w.break_component(target.name, "app_error", since=t + 40, ops=("HSET", "DEL"),
                      message="OOM command not allowed when used memory > 'maxmemory'.")


@mechanism("priority-kubernetes-workload-priority-preemption")
def preemption(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    ns = target.namespace
    wl = w.workloads[target.name]
    node = wl.pods[0]["spec"].get("nodeName", NODES[0])
    w.put({"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass",
           "metadata": w.meta("critical-batch", None, t - 30, manager="kubectl-client-side-apply"), "value": 1000000,
           "preemptionPolicy": "PreemptLowerPriority"})
    hog = {"apiVersion": "apps/v1", "kind": "Deployment",
           "metadata": w.meta("batch-reindex", ns, t - 20, {"app.kubernetes.io/name": "batch-reindex"},
                              manager="kubectl-client-side-apply"),
           "spec": {"replicas": 3, "selector": {"matchLabels": {"app.kubernetes.io/name": "batch-reindex"}},
                    "template": {"metadata": {"labels": {"app.kubernetes.io/name": "batch-reindex"}},
                                 "spec": {"priorityClassName": "critical-batch", "containers": [{
                                     "name": "reindex", "image": "busybox:1.36", "command": ["sleep", "infinity"],
                                     "resources": {"requests": {"memory": "4Gi", "cpu": "1"}}}]}}},
           "status": {"replicas": 3, "readyReplicas": 3, "availableReplicas": 3}}
    w.put(hog)
    victim = wl.pods[0]
    w.event(victim, "Normal", "Preempted", f"Preempted by pod {_hash('hog', t, n=8)} on node {node}", t,
            source="default-scheduler")
    w.delete_pods(target.name, t)
    msg = ("0/4 nodes are available: 1 node(s) had untolerated taint {node-role.kubernetes.io/control-plane: }, "
           "3 Insufficient memory. preemption: 0/4 nodes are available: 1 Preemption is not helpful for scheduling, "
           "3 No preemption victims found for incoming pod.")
    rs = wl.replicasets[-1]
    pod = w._pod(wl, rs, t + 2, "pending", message=msg)
    w.event(pod, "Warning", "FailedScheduling", msg, t + 2, w.t_end - 40, count=10, source="default-scheduler")
    w._sync(wl)
    w.break_component(target.name, "refused", since=t + 3)
    for consumer in ("accounting", "fraud-detection"):
        for k in range(6):
            w.log(consumer, t + 30 + k * 120, "WARN",
                  f"[Consumer clientId={consumer}-1, groupId={consumer}] Connection to node 1 (kafka/"
                  f"{w.ip.get('kafka', '10.96.0.1')}:9092) could not be established. Node may not be available.")


@mechanism("cordoned-kubernetes-worker-node")
def cordoned(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    wl = w.workloads[target.name]
    node_name = wl.pods[0]["spec"]["nodeName"]
    node = w.objects[Ref("", "Node", node_name)]
    # The workload is pinned to that node (a pre-existing affinity), so it cannot move elsewhere.
    for obj in (wl.deployment["spec"]["template"], wl.replicasets[-1]["spec"]["template"]):
        obj["spec"]["affinity"] = {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
            {"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": [node_name]}]}]}}}
    node["spec"]["unschedulable"] = True
    node["spec"].setdefault("taints", []).append({"key": "node.kubernetes.io/unschedulable", "effect": "NoSchedule",
                                                  "timeAdded": w.ts(t)})
    w.touch(node, t, manager="kubectl-cordon")
    w.event(node, "Normal", "NodeNotSchedulable", f"Node {node_name} status is now: NodeNotSchedulable", t,
            source="kubelet")
    w.delete_pods(target.name, t + 5)
    msg = ("0/4 nodes are available: 1 node(s) had untolerated taint {node-role.kubernetes.io/control-plane: }, "
           "1 node(s) were unschedulable, 2 node(s) didn't match Pod's node affinity/selector. preemption: 0/4 nodes "
           "are available: 4 Preemption is not helpful for scheduling.")
    pod = w._pod(wl, wl.replicasets[-1], t + 6, "pending", message=msg)
    w.event(pod, "Warning", "FailedScheduling", msg, t + 6, w.t_end - 30, count=12, source="default-scheduler")
    w._sync(wl)


@mechanism("scaled-to-zero-kubernetes-workload")
def scaled_to_zero(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    wl = w.workloads[target.name]
    wl.deployment["spec"]["replicas"] = 0
    w.touch(wl.deployment, t, manager="kubectl-scale")
    w.event(wl.deployment, "Normal", "ScalingReplicaSet",
            f"Scaled down replica set {wl.replicasets[-1]['metadata']['name']} from 1 to 0", t,
            source="deployment-controller")
    w.delete_pods(target.name, t + 1)
    lag = []
    for m in range(30):
        tt = w.t0 + m * 60
        lag.append([tt, 3 if tt < t else round(3 + (tt - t) / 60 * 14)])
    w.extra_series.append({"name": "kafka_consumergroup_lag", "labels": {"namespace": target.namespace,
                                                                         "consumergroup": target.name,
                                                                         "topic": "orders"}, "points": lag})


@mechanism("insufficient-kubernetes-resource-quota")
def quota(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    ns = target.namespace
    name = _named(gt, "ResourceQuota", "memory")
    rq = w.put({"apiVersion": "v1", "kind": "ResourceQuota",
                "metadata": w.meta(name, ns, t - 10, manager="kubectl-client-side-apply"),
                "spec": {"hard": {"limits.memory": "2Gi", "requests.memory": "2Gi"}},
                "status": {"hard": {"limits.memory": "2Gi", "requests.memory": "2Gi"},
                           "used": {"limits.memory": "4612Mi", "requests.memory": "4612Mi"}}})
    wl = w.workloads[target.name]
    w.delete_pods(target.name, t)
    rs = wl.replicasets[-1]
    limit = wl.comp.memory_limit
    w.event(rs, "Warning", "FailedCreate",
            f'Error creating: pods "{rs["metadata"]["name"]}-{_suffix(t, n=5)}" is forbidden: exceeded quota: {name}, '
            f"requested: limits.memory={limit},requests.memory={limit}, used: limits.memory=4612Mi,requests.memory=4612Mi, "
            "limited: limits.memory=2Gi,requests.memory=2Gi", t + 1, w.t_end - 20, count=17,
            source="replicaset-controller")
    assert rq


@mechanism("degraded-etcd-database-storage")
def etcd_pressure(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    ns = target.namespace
    blob = "x" * 64
    for i in range(240):
        w.put({"apiVersion": "v1", "kind": "ConfigMap",
               "metadata": w.meta(f"{target.name}-cache-{i:04d}", ns, t + i * 0.8,
                                  {"app.kubernetes.io/component": "configuration", "app.kubernetes.io/managed-by": "ITBench"},
                                  manager="kubectl-create"),
               "data": {"payload": blob}})
    pts = []
    for m in range(30):
        tt = w.t0 + m * 60
        pts.append([tt, round(0.08 + (0.0 if tt < t else min(2.4, (tt - t) / 60 * 0.25)), 3)])
    w.extra_series.append({"name": "apiserver_request_duration_seconds_p99", "labels": {"verb": "LIST",
                                                                                         "resource": "configmaps"},
                           "points": pts})
    w.extra_series.append({"name": "etcd_mvcc_db_total_size_in_bytes", "labels": {"instance": "control-plane"},
                           "points": [[tt, 180e6 if tt < t else 180e6 + (tt - t) * 1.6e6] for tt, _ in pts]})
    w.break_component(target.name, "slow", since=t + 60, latency_factor=180)


# -- Service and policy faults ------------------------------------------------------------------------

@mechanism("deleted-kubernetes-service")
def deleted_service(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    app = w.app_of(_comp_for_service(w, target))
    w.remove(target)
    w.remove(Ref(target.namespace, "Endpoints", target.name))
    for comp in app.by_service(target.name):
        w.workloads[comp.name].service = None
        w.break_component(comp.name, "dns", since=t + 5)


@mechanism("modified-target-port-kubernetes-service")
def wrong_target_port(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    svc = w.objects[target]
    svc["spec"]["ports"][0]["targetPort"] = svc["spec"]["ports"][0]["port"] + 1
    w.touch(svc, t)
    for comp in w.app_of(_comp_for_service(w, target)).by_service(target.name):
        w.break_component(comp.name, "refused", since=t + 2)


@mechanism("invalid-kubernetes-service-selector")
def wrong_selector(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    svc = w.objects[target]
    key = next(iter(svc["spec"]["selector"]))
    svc["spec"]["selector"][key] = svc["spec"]["selector"][key] + "-v2"
    w.touch(svc, t)
    for comp in w.app_of(_comp_for_service(w, target)).by_service(target.name):
        w.break_component(comp.name, "unavailable", since=t + 2, status_code=503, message="no healthy upstream")


@mechanism("ingress-port-blocking-network-policy")
def block_ingress(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    comp = w.workloads[target.name].comp
    name = _named(gt, "NetworkPolicy", f"{target.name}-ingress")
    w.put({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
           "metadata": w.meta(name, target.namespace, t, manager="kubectl-client-side-apply"),
           "spec": {"podSelector": {"matchLabels": dict(comp.labels)}, "policyTypes": ["Ingress"], "ingress": []}})
    w.stop_traffic(target.name, t + 3)


@mechanism("traffic-denying-istio-gateway-authorization-policy")
def deny_gateway(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    name = _named(gt, "AuthorizationPolicy", f"{target.name}-policy")
    w.put({"apiVersion": "security.istio.io/v1", "kind": "AuthorizationPolicy",
           "metadata": w.meta(name, target.namespace, t, manager="kubectl-client-side-apply"),
           "spec": {"targetRefs": [{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": target.name}],
                    "action": "DENY", "rules": [{}]}})
    w.break_component("bookinfo-gateway-istio", "deny", since=t + 2, message="RBAC: access denied", status_code=403)


@mechanism("disabled-istio-ambient-mode-kubernetes-namespace")
def disable_ambient(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    ns = w.objects[target]
    ns["metadata"]["labels"].pop("istio.io/dataplane-mode", None)
    w.touch(ns, t, manager="kubectl-label")
    w.silent[target.name] = t + 5


@mechanism("strict-mutual-tls-istio-service-mesh-enforcement")
def strict_mtls(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    ns = target.namespace
    pa_name = _named(gt, "PeerAuthentication", "default")
    w.put({"apiVersion": "security.istio.io/v1", "kind": "PeerAuthentication",
           "metadata": w.meta(pa_name, ns, t, manager="kubectl-client-side-apply"),
           "spec": {"mtls": {"mode": "STRICT"}}})
    workload = next((r.name for r in gt if r.kind == "Deployment"), "productpage-v1")

    def mutate(tpl):
        tpl["metadata"]["labels"]["istio.io/dataplane-mode"] = "none"

    w.rollout(workload, mutate, t - 40, "running")
    w.caller_failures[workload] = CallFailure("reset", since=t + 5)


@mechanism("misconfigured-kubernetes-horizontal-pod-autoscaler")
def bad_hpa(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    hpa = w.objects[target]
    hpa["spec"]["maxReplicas"] = 1
    hpa["spec"]["metrics"][0]["resource"]["target"]["averageUtilization"] = 5
    hpa["status"].update(currentReplicas=1, desiredReplicas=1)
    w.touch(hpa, t)
    w.event(hpa, "Normal", "SuccessfulRescale", "New size: 1; reason: All metrics below target", t - 3600 * 5,
            source="horizontal-pod-autoscaler")


@mechanism("corrupted-kubernetes-secret-credentials")
def corrupt_secret(w: World, target: Ref, gt: list[Ref], t: float) -> None:
    secret = w.objects[target]
    secret["data"] = {k: base64.b64encode(b"invalid-" + k.encode()).decode() for k in secret["data"]}
    w.touch(secret, t)
    users = [c for c in w.apps[0].components if target.name in c.secrets]
    for comp in users:
        w.rollout(comp.name, _restart_annotation(w, t + 30), t + 30, "running")
        w.break_component(comp.name, "app_error", since=t + 40,
                          message="Net::SMTPAuthenticationError: 535-5.7.8 Username and Password not accepted")


def _comp_for_service(w: World, ref: Ref) -> str:
    for app in w.apps:
        for c in app.components:
            if c.service == ref.name and c.namespace == ref.namespace:
                return c.name
    raise KeyError(ref)


# -- background noise ---------------------------------------------------------------------------------

def add_noise(w: World) -> None:
    """Things that are always slightly wrong in a real cluster, so not every anomaly is the incident."""
    rng = w.rng
    apps = [c for a in w.apps for c in a.components if c.name in w.workloads]
    infra = [c for c in apps if c.infra] or apps
    # A pod that crashed hours ago and recovered.
    victim = rng.choice(infra + [c for c in apps if c.name in ("opensearch", "kafka", "ad", "fraud-detection")])
    pod = w.workloads[victim.name].pods[0] if w.workloads[victim.name].pods else None
    if pod and pod["status"].get("containerStatuses"):
        cs = pod["status"]["containerStatuses"][0]
        cs["restartCount"] = rng.randint(2, 5)
        cs["lastState"] = {"terminated": {"reason": "OOMKilled", "exitCode": 137,
                                          "finishedAt": w.ts(w.t0 - rng.randint(3, 9) * 3600)}}
    # An unrelated, recent configuration change.
    for ref, obj in list(w.objects.items()):
        if ref.kind == "ConfigMap" and ref.name == "grafana-dashboards":
            w.touch(obj, w.t_fault + rng.randint(-400, 400), manager="grafana-sidecar")
    # An old rollout (days ago) of a random service.
    comp = rng.choice([c for c in apps if not c.infra and c.name in w.workloads])
    wl = w.workloads[comp.name]
    if len(wl.replicasets) == 1:
        tpl = copy.deepcopy(wl.deployment["spec"]["template"])
        tpl["spec"]["containers"][0]["image"] = comp.image.replace("2.1.3", "2.1.2")
        old = w._replicaset(wl, tpl, w.t0 - 3 * 86400, 1)
        wl.replicasets.remove(old)
        wl.replicasets.insert(0, old)
        for rs in wl.replicasets[1:]:
            rs["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "2"
        wl.deployment["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "2"
    # Readiness flaps and HPA metric hiccups that resolve on their own.
    flap = rng.choice(infra)
    if w.workloads[flap.name].pods:
        w.event(w.workloads[flap.name].pods[0], "Warning", "Unhealthy",
                "Readiness probe failed: Get \"http://10.244.1.17:9200/\": context deadline exceeded",
                w.t0 + rng.randint(60, 600), count=2)
    for ref, obj in list(w.objects.items()):
        if ref.kind == "HorizontalPodAutoscaler":
            w.event(obj, "Warning", "FailedGetResourceMetric", "failed to get cpu utilization: unable to get metrics "
                    "for resource cpu: no metrics returned from resource metrics API", w.t0 + rng.randint(0, 900),
                    count=3, source="horizontal-pod-autoscaler")
    # Long-standing breakage nobody has fixed: a workload stuck for days, and a Service with no backends.
    chronic_broken_workload(w)
    orphan_service(w)
    # Chatty warnings from the telemetry pipeline and the broker.
    names = {c.name for c in apps}
    for _k in range(rng.randint(3, 7)):
        if "otel-collector" in names:
            w.log("otel-collector", w.t0 + rng.uniform(0, 1800), "WARN",
                  "Exporting failed. Will retry the request after interval. {\"kind\": \"exporter\", \"name\": "
                  "\"opensearch\", \"error\": \"context deadline exceeded\", \"interval\": \"5.2s\"}")
        if "load-generator" in names:
            w.log("load-generator", w.t0 + rng.uniform(0, 1800), "WARN",
                  "Response time 2104 ms exceeded threshold for GET /api/products")
    if "kafka" in names:
        w.log("kafka", w.t0 + rng.uniform(0, 1800), "WARN",
              "[GroupCoordinator 1]: Member fraud-detection-1 in group fraud-detection has failed, removing it from the group")


def chronic_broken_workload(w: World) -> None:
    from .topology import Component

    app = w.apps[0]
    name = "legacy-exporter" if app.namespace == "otel-demo" else "ratings-v2-canary"
    image = f"registry.internal.example/{name}:0.9.1"
    since = w.t0 - w.rng.randint(2, 5) * 86400
    comp = Component(name, app.namespace, None, 9100, image, "go", "http", infra=True)
    w._workload(comp, since)
    wl = w.workloads[name]
    pod = wl.pods[0]
    w.set_pod_state(pod, "waiting", since + 30, reason="ImagePullBackOff", message=f'Back-off pulling image "{image}"')
    w.event(pod, "Warning", "Failed", f'Failed to pull image "{image}": rpc error: code = Unknown desc = failed to pull '
                                      f'and unpack image "{image}": failed to resolve reference: unexpected status '
                                      "from HEAD request: 401 Unauthorized", since + 40, w.t_end - 50, count=1900)
    w.event(pod, "Normal", "BackOff", f'Back-off pulling image "{image}"', since + 60, w.t_end - 20, count=9000)
    w._sync(wl)
    w.chronic[pod["metadata"]["name"]] = since + 600


def orphan_service(w: World) -> None:
    app = w.apps[0]
    name = "jaeger-agent" if app.namespace == "otel-demo" else "reviews-canary"
    w.put({"apiVersion": "v1", "kind": "Service",
           "metadata": w.meta(name, app.namespace, w.t0 - 30 * 86400, {"app.kubernetes.io/name": name}),
           "spec": {"type": "ClusterIP", "selector": {"app.kubernetes.io/name": name},
                    "ports": [{"name": "agent", "port": 6831, "targetPort": 6831, "protocol": "UDP"}]}})
