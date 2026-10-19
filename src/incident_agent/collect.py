"""Collect a snapshot from a live cluster: kubectl for objects, events and logs; Prometheus for alerts and
metrics; Jaeger (optional) for traces. The result is the same format the simulator writes, so the
agent works the same way on a real incident.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import httpx

from .snapshot import Snapshot, iso

KINDS = ["deployments", "replicasets", "statefulsets", "daemonsets", "jobs", "pods", "services", "endpoints",
         "configmaps", "secrets", "persistentvolumeclaims", "networkpolicies", "resourcequotas",
         "horizontalpodautoscalers"]
CLUSTER_KINDS = ["nodes", "namespaces", "priorityclasses"]
OPTIONAL_KINDS = ["gateways.gateway.networking.k8s.io", "httproutes.gateway.networking.k8s.io",
                  "peerauthentications.security.istio.io", "authorizationpolicies.security.istio.io"]
METRIC_QUERIES = {
    "requests_per_second": 'sum by (namespace, service_name) (rate(traces_span_metrics_calls_total{span_kind="SPAN_KIND_SERVER"}[1m]))',
    "request_error_ratio": 'sum by (namespace, service_name) (rate(traces_span_metrics_calls_total{status_code="STATUS_CODE_ERROR"}[1m])) / '
                           'sum by (namespace, service_name) (rate(traces_span_metrics_calls_total[1m]))',
    "request_duration_p95_ms": 'histogram_quantile(0.95, sum by (le, namespace, service_name) '
                               '(rate(traces_span_metrics_duration_milliseconds_bucket[1m])))',
    "kube_pod_container_status_restarts_total": "kube_pod_container_status_restarts_total",
}


class Collector:
    def __init__(self, context: str | None = None, namespaces: list[str] | None = None, prometheus: str | None = None,
                 jaeger: str | None = None, window_minutes: int = 30, runner=subprocess.run,
                 http: httpx.Client | None = None):
        self.context, self.namespaces = context, namespaces or []
        self.prometheus, self.jaeger = prometheus, jaeger
        self.window = window_minutes * 60
        self.runner = runner
        self.http = http or httpx.Client(timeout=30)

    def kubectl(self, *args: str) -> dict | str:
        argv = ["kubectl"] + (["--context", self.context] if self.context else []) + list(args)
        res = self.runner(argv, capture_output=True, text=True, timeout=120)
        if res.returncode != 0:
            raise RuntimeError(f"{' '.join(argv)}: {res.stderr.strip()[:300]}")
        if "-o" in args and "json" in args:
            return json.loads(res.stdout or "{}")
        return res.stdout

    def _scope(self) -> list[list[str]]:
        return [["-n", ns] for ns in self.namespaces] or [["-A"]]

    def objects(self) -> list[dict]:
        out: list[dict] = []
        for kind in KINDS + OPTIONAL_KINDS:
            for scope in self._scope():
                try:
                    data = self.kubectl("get", kind, *scope, "-o", "json")
                except RuntimeError:
                    continue  # CRD not installed
                for item in data.get("items", []):
                    item.setdefault("kind", _kind_of(kind))
                    if item["kind"] == "Secret":
                        item["data"] = {k: "" for k in item.get("data") or {}}  # never copy secret values
                    out.append(item)
        for kind in CLUSTER_KINDS:
            try:
                data = self.kubectl("get", kind, "-o", "json")
            except RuntimeError:
                continue
            for item in data.get("items", []):
                item.setdefault("kind", _kind_of(kind))
                out.append(item)
        return out

    def events(self) -> list[dict]:
        out = []
        for scope in self._scope():
            out += self.kubectl("get", "events", *scope, "-o", "json").get("items", [])
        return out

    def logs(self, objects: list[dict], limit: int = 300) -> list[dict]:
        rows = []
        for pod in [o for o in objects if o.get("kind") == "Pod" and o.get("status", {}).get("phase") == "Running"]:
            md = pod["metadata"]
            try:
                text = self.kubectl("logs", md["name"], "-n", md["namespace"], "--all-containers", "--timestamps",
                                    f"--since={self.window}s", f"--tail={limit}")
            except RuntimeError:
                continue
            svc = (md.get("labels") or {}).get("app.kubernetes.io/name") or (md.get("labels") or {}).get("app") or md["name"]
            for line in str(text).splitlines():
                ts, _, body = line.partition(" ")
                sev = "ERROR" if any(w in body.upper() for w in ("ERROR", "FATAL", "EXCEPTION")) else \
                    "WARN" if "WARN" in body.upper() else "INFO"
                if sev != "INFO":
                    rows.append({"timestamp": ts, "service": svc, "namespace": md["namespace"], "pod": md["name"],
                                 "severity": sev, "body": body[:2000], "trace_id": ""})
        return rows

    def alerts(self) -> list[dict]:
        if not self.prometheus:
            return []
        r = self.http.get(f"{self.prometheus.rstrip('/')}/api/v1/alerts")
        r.raise_for_status()
        return [a for a in r.json().get("data", {}).get("alerts", []) if a.get("state") == "firing"]

    def metrics(self, end: float) -> list[dict]:
        if not self.prometheus:
            return []
        out = []
        for name, q in METRIC_QUERIES.items():
            r = self.http.get(f"{self.prometheus.rstrip('/')}/api/v1/query_range",
                              params={"query": q, "start": end - self.window, "end": end, "step": 60})
            if r.status_code != 200:
                continue
            for res in r.json().get("data", {}).get("result", []):
                pts = [[float(t), float(v)] for t, v in res.get("values", []) if v not in ("NaN", "+Inf", "-Inf")]
                out.append({"name": name, "labels": res.get("metric", {}), "points": pts})
        return out

    def spans(self, end: float, services: list[str]) -> list[dict]:
        if not self.jaeger:
            return []
        out = []
        for svc in services:
            r = self.http.get(f"{self.jaeger.rstrip('/')}/api/traces",
                              params={"service": svc, "start": int((end - self.window) * 1e6), "end": int(end * 1e6),
                                      "limit": 200})
            if r.status_code != 200:
                continue
            for tr in r.json().get("data", []):
                procs = tr.get("processes", {})
                for s in tr.get("spans", []):
                    tags = {t["key"]: t.get("value") for t in s.get("tags", [])}
                    parent = next((ref["spanID"] for ref in s.get("references", []) if ref.get("refType") == "CHILD_OF"), "")
                    out.append({"trace_id": s["traceID"], "span_id": s["spanID"], "parent_span_id": parent,
                                "service": procs.get(s.get("processID"), {}).get("serviceName", svc), "namespace": "",
                                "name": s.get("operationName", ""), "kind": str(tags.get("span.kind", "")).upper(),
                                "start": s["startTime"] / 1e6, "duration_ms": s["duration"] / 1e3,
                                "status": "ERROR" if tags.get("error") in (True, "true") or tags.get("otel.status_code") == "ERROR" else "OK",
                                "status_message": str(tags.get("otel.status_description", "")),
                                "attributes": {"server.address": tags.get("server.address") or tags.get("net.peer.name") or tags.get("peer.service")}
                                if (tags.get("server.address") or tags.get("net.peer.name") or tags.get("peer.service")) else {}})
        return out

    def collect(self, name: str = "live") -> Snapshot:
        end = time.time()
        objects = self.objects()
        services = sorted({(o["metadata"].get("labels") or {}).get("app.kubernetes.io/name", "") for o in objects
                           if o.get("kind") == "Deployment"} - {""})
        return Snapshot(name, objects, self.events(), self.alerts(), self.logs(objects), self.spans(end, services),
                        self.metrics(end), {"source": "live", "context": self.context or "", "window_start": iso(end - self.window),
                                            "window_end": iso(end), "collected_at": iso(end)})


def _kind_of(resource: str) -> str:
    base = resource.split(".")[0]
    special = {"endpoints": "Endpoints", "networkpolicies": "NetworkPolicy", "resourcequotas": "ResourceQuota",
               "horizontalpodautoscalers": "HorizontalPodAutoscaler", "persistentvolumeclaims": "PersistentVolumeClaim",
               "priorityclasses": "PriorityClass", "peerauthentications": "PeerAuthentication",
               "authorizationpolicies": "AuthorizationPolicy", "httproutes": "HTTPRoute", "replicasets": "ReplicaSet",
               "statefulsets": "StatefulSet", "daemonsets": "DaemonSet", "configmaps": "ConfigMap"}
    return special.get(base, base[:-1].capitalize() if base.endswith("s") else base.capitalize())


def collect_to(path: str | Path, **kw) -> Path:
    return Collector(**kw).collect(Path(path).name).save(path)
