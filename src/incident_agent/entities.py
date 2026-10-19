"""Entity references in the form ITBench uses: ``namespace/Kind/name``.

Cluster-scoped objects (Node, Namespace) have an empty namespace: ``/Namespace/book-info``.
"""

from __future__ import annotations

from dataclasses import dataclass

KINDS = {
    k.lower(): k
    for k in (
        "Pod", "ReplicaSet", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Service", "Endpoints",
        "ConfigMap", "Secret", "PersistentVolumeClaim", "Node", "Namespace", "NetworkPolicy", "ResourceQuota",
        "HorizontalPodAutoscaler", "Ingress", "Gateway", "VirtualService", "AuthorizationPolicy", "PeerAuthentication",
        "PriorityClass", "Schedule", "NetworkChaos", "PodChaos", "StressChaos", "Event",
    )
}
ALIASES = {"deploy": "Deployment", "svc": "Service", "cm": "ConfigMap", "rs": "ReplicaSet", "po": "Pod",
           "pvc": "PersistentVolumeClaim", "hpa": "HorizontalPodAutoscaler", "netpol": "NetworkPolicy",
           "ns": "Namespace", "sts": "StatefulSet", "ds": "DaemonSet", "quota": "ResourceQuota",
           "deployments": "Deployment", "services": "Service", "pods": "Pod", "configmaps": "ConfigMap"}

CLUSTER_SCOPED = {"Node", "Namespace", "PriorityClass", "PersistentVolume", "ClusterRole"}
WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Job")


def canonical_kind(kind: str) -> str:
    k = kind.strip()
    return KINDS.get(k.lower()) or ALIASES.get(k.lower()) or k


@dataclass(frozen=True, order=True)
class Ref:
    namespace: str
    kind: str
    name: str

    def __str__(self) -> str:
        return f"{self.namespace}/{self.kind}/{self.name}"

    @classmethod
    def parse(cls, text: str) -> Ref:
        """Parse ``ns/Kind/name``, ``Kind/name`` (cluster-scoped) or ``kind/name -n ns`` style refs."""
        text = text.strip().strip("`'\"")
        parts = text.split("/")
        if len(parts) == 3:
            ns, kind, name = parts
        elif len(parts) == 2:
            ns, (kind, name) = "", parts
        else:
            raise ValueError(f"not an entity reference: {text!r} (expected namespace/Kind/name)")
        kind = canonical_kind(kind)
        if kind in CLUSTER_SCOPED:
            ns = ""
        if not kind or not name:
            raise ValueError(f"not an entity reference: {text!r}")
        return cls(ns, kind, name)

    @classmethod
    def of(cls, obj: dict) -> Ref:
        md = obj.get("metadata") or {}
        kind = canonical_kind(obj.get("kind", ""))
        return cls("" if kind in CLUSTER_SCOPED else md.get("namespace", ""), kind, md.get("name", ""))
