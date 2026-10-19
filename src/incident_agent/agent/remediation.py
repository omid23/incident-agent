"""Remediation: a plan of concrete kubectl actions per root cause, and executors that run approved actions.

Nothing mutates a cluster without a human approving that specific action. The kubectl executor
runs argument lists (never a shell), only for allowlisted verbs, always namespaced, and makes a
backup of anything it deletes or patches.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..analysis.detectors import Finding
from ..analysis.rca import Candidate, RCAEngine
from ..entities import Ref

READ_ONLY_VERBS = {"get", "describe", "logs"}
MUTATING_VERBS = {"patch", "scale", "rollout", "label", "delete", "expose", "set", "annotate", "run", "uncordon"}


@dataclass
class Action:
    id: str
    title: str
    target: str
    argv: list[str]  # kubectl arguments, without the binary; empty for manual steps
    risk: str  # low | medium | high
    reversible: bool
    rationale: str
    manual: bool = False
    backup: list[str] = field(default_factory=list)  # kubectl args whose output is saved before running

    @property
    def command(self) -> str:
        return "kubectl " + shlex.join(self.argv) if self.argv else "(manual) " + self.title

    def to_dict(self) -> dict:
        return {**asdict(self), "command": self.command}


def _n(ref: Ref) -> list[str]:
    return ["-n", ref.namespace] if ref.namespace else []


def plan(engine: RCAEngine, causes: list[Candidate]) -> list[Action]:
    actions: list[Action] = []

    def add(title: str, target: Ref, argv: list[str], risk: str, reversible: bool, why: str, manual: bool = False,
            backup: list[str] | None = None) -> None:
        if any(a.argv == argv and argv for a in actions):
            return
        actions.append(Action(f"a{len(actions) + 1}", title, str(target), argv, risk, reversible, why, manual,
                              backup or []))

    for c in causes:
        ref = c.entity
        signals = {f.signal: f for f in c.findings}
        res = f"{ref.kind.lower()}/{ref.name}"
        rollout_changed = "rollout" in signals
        if ref.kind in ("Deployment", "StatefulSet", "DaemonSet"):
            pod_defects = {"image_pull_failure", "container_start_error", "crash_loop", "init_container_crash",
                           "init_container_hang", "readiness_probe_failing", "unschedulable", "container_config_error",
                           "oom_killed"}
            if rollout_changed and pod_defects & set(signals):
                diff = "; ".join(signals["rollout"].evidence[:2])
                add(f"Roll {ref.name} back to the previous revision", ref, ["rollout", "undo", res, *_n(ref)], "medium",
                    True, f"The latest revision broke the pods ({diff}). Rolling back restores the last working template.")
            elif "oom_killed" in signals:
                add(f"Raise the memory limit of {ref.name}", ref,
                    ["set", "resources", res, *_n(ref), "--limits=memory=512Mi", "--requests=memory=256Mi"], "medium", True,
                    "Containers are OOM-killed at the current limit.")
            elif "scaled_to_zero" in signals:
                replicas = _previous_replicas(engine, ref)
                add(f"Scale {ref.name} back to {replicas}", ref, ["scale", res, *_n(ref), f"--replicas={replicas}"], "low",
                    True, signals["scaled_to_zero"].summary)
            elif "preempted" in signals:
                add(f"Free capacity for {ref.name}", ref, [], "medium", False,
                    "A higher-priority workload took its node's memory. Lower that workload's priority, scale it down, "
                    "or add capacity; then the pod schedules on its own.", manual=True)
            elif "caller_side_failure" in signals and rollout_changed:
                add(f"Roll {ref.name} back to the previous revision", ref, ["rollout", "undo", res, *_n(ref)], "medium",
                    True, f"{signals['caller_side_failure'].summary}; the change that caused it: "
                    + "; ".join(signals["rollout"].evidence[:2]))
            elif rollout_changed:
                add(f"Roll {ref.name} back to the previous revision", ref, ["rollout", "undo", res, *_n(ref)], "medium",
                    True, "The latest revision is the change that coincides with the failure: "
                    + "; ".join(signals.get("rollout", Finding(ref, "", "", 0, "")).evidence[:2]))
            elif "no_pods" in signals:
                add(f"Recreate pods for {ref.name} once creation is unblocked", ref,
                    ["rollout", "restart", res, *_n(ref)], "low", True, signals["no_pods"].summary)
            elif not c.reason.startswith("targeted by"):
                add(f"Restart {ref.name}", ref, ["rollout", "restart", res, *_n(ref)], "low", True,
                    "No configuration defect was found; a restart is a low-risk first step while investigating.")
        elif ref.kind == "Service":
            if "service_no_endpoints" in signals:
                f = signals["service_no_endpoints"]
                labels = engine.ix.template(f.related[0]).get("metadata", {}).get("labels", {}) if f.related else {}
                sel = {k: v for k, v in labels.items() if k in ("app", "app.kubernetes.io/name")} or labels
                add(f"Point Service {ref.name} at its pods", ref,
                    ["patch", "service", ref.name, *_n(ref), "--type=merge", "-p", json.dumps({"spec": {"selector": sel}})],
                    "medium", True, f.summary, backup=["get", "service", ref.name, *_n(ref), "-o", "yaml"])
            elif "service_port_mismatch" in signals:
                port = _container_port(engine, signals["service_port_mismatch"].related)
                svc = engine.snap.get(ref) or {}
                p0 = (svc.get("spec", {}).get("ports") or [{}])[0]
                patch = {"spec": {"ports": [{"name": p0.get("name", "tcp"), "port": p0.get("port"), "targetPort": port}]}}
                add(f"Fix the targetPort of Service {ref.name}", ref,
                    ["patch", "service", ref.name, *_n(ref), "--type=merge", "-p", json.dumps(patch)], "medium", True,
                    signals["service_port_mismatch"].summary, backup=["get", "service", ref.name, *_n(ref), "-o", "yaml"])
            elif "missing_service" in signals:
                f = signals["missing_service"]
                w = f.related[0] if f.related else None
                port = _container_port(engine, [w] if w else [])
                if w:
                    add(f"Recreate Service {ref.name}", ref,
                        ["expose", f"{w.kind.lower()}/{w.name}", *_n(ref), f"--name={ref.name}", f"--port={port}",
                         f"--target-port={port}"], "low", True, f.summary + ". Restore it from source control if it had "
                                                                         "custom settings.")
            elif "runtime_reconfigured_by_job" in signals:
                f = signals["runtime_reconfigured_by_job"]
                add(f"Undo the runtime change to {ref.name}", ref, [], "medium", False,
                    f.summary + ". Revert the setting (e.g. CONFIG SET maxmemory 0) and remove the Job.", manual=True)
            else:
                add(f"Inspect Service {ref.name}", ref, ["describe", "service", ref.name, *_n(ref)], "low", True,
                    "Calls to this Service fail; check its backends.")
        elif ref.kind == "NetworkPolicy":
            add(f"Delete NetworkPolicy {ref.name}", ref, ["delete", "networkpolicy", ref.name, *_n(ref)], "high", True,
                signals.get("network_policy_blocks_ingress", c.findings[0] if c.findings else Finding(ref, "", "", 0, "")).summary
                + ". The YAML is backed up first so it can be re-applied with a corrected rule.",
                backup=["get", "networkpolicy", ref.name, *_n(ref), "-o", "yaml"])
        elif ref.kind == "ResourceQuota":
            q = engine.snap.get(ref) or {}
            used = q.get("status", {}).get("used", {})
            hard = {k: _scale(v, 1.5) for k, v in used.items()}
            add(f"Raise ResourceQuota {ref.name} above current usage", ref,
                ["patch", "resourcequota", ref.name, *_n(ref), "--type=merge", "-p", json.dumps({"spec": {"hard": hard}})],
                "medium", True, signals.get("quota_exhausted", Finding(ref, "", "", 0, "quota exhausted")).summary,
                backup=["get", "resourcequota", ref.name, *_n(ref), "-o", "yaml"])
        elif ref.kind == "HorizontalPodAutoscaler":
            add(f"Restore sane limits on HPA {ref.name}", ref,
                ["patch", "hpa", ref.name, *_n(ref), "--type=merge", "-p",
                 json.dumps({"spec": {"maxReplicas": 3, "metrics": [{"type": "Resource", "resource": {
                     "name": "cpu", "target": {"type": "Utilization", "averageUtilization": 80}}}]}})],
                "medium", True, signals.get("hpa_maxed_out", Finding(ref, "", "", 0, "HPA maxed out")).summary,
                backup=["get", "hpa", ref.name, *_n(ref), "-o", "yaml"])
        elif ref.kind == "PeerAuthentication":
            add(f"Set PeerAuthentication {ref.name} to PERMISSIVE", ref,
                ["patch", "peerauthentication", ref.name, *_n(ref), "--type=merge", "-p",
                 json.dumps({"spec": {"mtls": {"mode": "PERMISSIVE"}}})], "medium", True,
                "Plaintext workloads are rejected under STRICT mTLS; PERMISSIVE accepts both while they rejoin the mesh.",
                backup=["get", "peerauthentication", ref.name, *_n(ref), "-o", "yaml"])
        elif ref.kind == "AuthorizationPolicy":
            add(f"Delete AuthorizationPolicy {ref.name}", ref, ["delete", "authorizationpolicy", ref.name, *_n(ref)],
                "high", True, signals.get("authorization_denies_all", Finding(ref, "", "", 0, "denies all")).summary,
                backup=["get", "authorizationpolicy", ref.name, *_n(ref), "-o", "yaml"])
        elif ref.kind == "Namespace":
            add(f"Put namespace {ref.name} back in the ambient mesh", ref,
                ["label", "namespace", ref.name, "istio.io/dataplane-mode=ambient", "--overwrite"], "low", True,
                signals.get("mesh_membership_changed", Finding(ref, "", "", 0, "mesh label removed")).summary)
        elif ref.kind == "Secret":
            users = [r for f in c.findings for r in f.related]
            add(f"Restore Secret {ref.name} from the source of truth", ref, [], "high", False,
                "The Secret changed during the incident and its users fail to authenticate. Restore the previous value "
                "from your secret manager, then restart: " + ", ".join(u.name for u in users), manual=True)
            for u in users:
                add(f"Restart {u.name} to load the restored Secret", u, ["rollout", "restart", f"{u.kind.lower()}/{u.name}",
                                                                         *_n(u)], "low", True,
                    "Pods read the Secret at start-up.")
        elif ref.kind == "ConfigMap":
            add(f"Fix ConfigMap {ref.name}", ref, [], "medium", False,
                c.reason + ". Correct the script/config (or roll back the workload that started using it).", manual=True)
        elif ref.kind == "Gateway":
            add(f"Review policies attached to Gateway {ref.name}", ref,
                ["get", "authorizationpolicy", *_n(ref), "-o", "wide"], "low", True, c.reason)
        else:
            add(f"Investigate {ref}", ref, [], "low", False, c.reason, manual=True)
    return actions


def _previous_replicas(engine: RCAEngine, ref: Ref) -> int:
    for rs in reversed(engine.ix.replicasets(ref)):
        n = (rs.get("status") or {}).get("replicas") or 0
        if n:
            return n
    return 1


def _container_port(engine: RCAEngine, workloads: list) -> int:
    for w in workloads:
        if w is None:
            continue
        for c in engine.ix.template(w).get("spec", {}).get("containers", []):
            for p in c.get("ports") or []:
                if p.get("containerPort"):
                    return int(p["containerPort"])
    return 8080


def _scale(q: str, factor: float) -> str:
    from ..analysis.detectors import _qty

    v = _qty(q) * factor
    return f"{int(v / 1024 ** 2)}Mi" if v > 1024 ** 2 else str(round(v, 3))


# -- executors ---------------------------------------------------------------------------------------

@dataclass
class ExecResult:
    action_id: str
    command: str
    ok: bool
    output: str
    dry_run: bool


class DryRunExecutor:
    """Records what would run. The default, and what offline snapshots always use."""

    name = "dry-run"

    def run(self, action: Action) -> ExecResult:
        if action.manual or not action.argv:
            return ExecResult(action.id, action.command, True, "manual step: hand off to an operator", True)
        return ExecResult(action.id, action.command, True, f"dry run: would execute `{action.command}`", True)


class KubectlExecutor:
    """Runs approved actions with kubectl. ``server_dry_run`` sends them with --dry-run=server first."""

    name = "kubectl"

    def __init__(self, context: str | None = None, server_dry_run: bool = True, backup_dir: str | Path = "backups",
                 runner=subprocess.run, timeout: int = 60):
        self.context, self.server_dry_run = context, server_dry_run
        self.backup_dir, self.runner, self.timeout = Path(backup_dir), runner, timeout

    def _argv(self, args: list[str]) -> list[str]:
        base = ["kubectl"] + (["--context", self.context] if self.context else [])
        return base + args

    def check(self, action: Action) -> None:
        if not action.argv:
            raise ValueError("manual action")
        verb = action.argv[0]
        if verb not in MUTATING_VERBS | READ_ONLY_VERBS:
            raise ValueError(f"verb '{verb}' is not allowed")
        if verb in MUTATING_VERBS and "-n" not in action.argv and not (verb == "label" and action.argv[1] == "namespace"):
            raise ValueError("mutating actions must be namespaced")
        if verb == "delete" and any(a in ("--all", "-A", "--all-namespaces") for a in action.argv):
            raise ValueError("bulk deletes are not allowed")

    def run(self, action: Action) -> ExecResult:
        if action.manual or not action.argv:
            return ExecResult(action.id, action.command, True, "manual step: hand off to an operator", False)
        try:
            self.check(action)
        except ValueError as exc:
            return ExecResult(action.id, action.command, False, f"refused: {exc}", False)
        if action.backup:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            res = self.runner(self._argv(action.backup), capture_output=True, text=True, timeout=self.timeout)
            if res.returncode != 0:
                return ExecResult(action.id, action.command, False, f"backup failed: {res.stderr.strip()}", False)
            (self.backup_dir / f"{action.id}-{action.target.replace('/', '_')}.yaml").write_text(res.stdout)
        args = list(action.argv)
        if self.server_dry_run and args[0] in MUTATING_VERBS - {"rollout", "run"}:
            args.append("--dry-run=server")
        res = self.runner(self._argv(args), capture_output=True, text=True, timeout=self.timeout)
        out = (res.stdout + res.stderr).strip()
        return ExecResult(action.id, "kubectl " + shlex.join(args), res.returncode == 0, out[:2000],
                          self.server_dry_run)
