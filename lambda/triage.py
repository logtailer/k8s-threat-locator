from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

from kubernetes import client

logger = logging.getLogger(__name__)


class Action(str, Enum):
    ALERT_ONLY = "alert_only"
    ANNOTATE = "annotate"
    QUARANTINE = "quarantine"


@dataclass
class PodContext:
    pod_name: str
    namespace: str
    # Pod spec flags
    has_privileged_container: bool = False
    has_host_network: bool = False
    has_host_pid: bool = False
    has_dangerous_caps: bool = False
    runs_as_root: bool = False
    # Exposure
    service_type: str = "None"   # ClusterIP | NodePort | LoadBalancer | None
    # RBAC
    service_account: str = "default"
    has_cluster_admin: bool = False
    cluster_role_names: list[str] = field(default_factory=list)
    # Namespace
    namespace_env: str = ""      # value of label environment=
    is_system_namespace: bool = False
    # Owner workload — populated when pod is still alive at enrichment time
    owner_kind: str = ""         # Deployment | StatefulSet | DaemonSet | ReplicaSet | ""
    owner_name: str = ""


@dataclass
class TriageResult:
    score: int                   # 0–100
    severity: str                # low | medium | high | critical
    action: Action
    reason: str
    context: PodContext


_DANGEROUS_CAPS = frozenset({"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"})
_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "falco", "calico-system"}

# Quarantine is never applied to these namespaces — isolating infrastructure pods (coredns,
# kube-proxy, falco) would cascade into cluster-wide outages worse than the alert itself.
_QUARANTINE_BLOCKED_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease",
    "falco", "calico-system", "calico-apiserver", "tigera-operator",
})

# Falco rules that indicate active compromise — always quarantine regardless of pod risk score.
_FORCE_QUARANTINE_RULES = frozenset({
    "shell_in_container",
    "write_to_etc",
    "Terminal shell in container",
    "Write below etc",
})


def enrich(
    core_v1: client.CoreV1Api,
    rbac_v1: client.RbacAuthorizationV1Api,
    pod_name: str,
    namespace: str,
    apps_v1: client.AppsV1Api | None = None,
) -> PodContext:
    ctx = PodContext(pod_name=pod_name, namespace=namespace)
    ctx.is_system_namespace = namespace in _SYSTEM_NAMESPACES
    logger.info("Enriching pod context: pod=%s/%s", namespace, pod_name)

    try:
        pod = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        _enrich_pod_spec(ctx, pod)
        _enrich_service_exposure(ctx, core_v1, pod, namespace)
        _enrich_rbac(ctx, rbac_v1, namespace)
        _enrich_namespace(ctx, core_v1, namespace)
        if apps_v1 is not None:
            _enrich_owner(ctx, apps_v1, pod, namespace)
    except client.ApiException as exc:
        logger.warning("Could not fully enrich pod context for %s/%s: status=%s — using partial context", namespace, pod_name, exc.status)

    return ctx


def _enrich_pod_spec(ctx: PodContext, pod: client.V1Pod) -> None:
    spec = pod.spec or client.V1PodSpec(containers=[])
    ctx.has_host_network = bool(spec.host_network)
    ctx.has_host_pid = bool(spec.host_pid)

    pod_sc = spec.security_context or client.V1PodSecurityContext()
    # Treat as root if explicitly uid=0, if runAsNonRoot is explicitly False,
    # or if neither runAsUser nor runAsNonRoot is set (no enforcement = root risk).
    pod_enforces_nonroot = pod_sc.run_as_non_root is True or (
        pod_sc.run_as_user is not None and pod_sc.run_as_user != 0
    )
    if not pod_enforces_nonroot:
        ctx.runs_as_root = True

    for container in (spec.containers or []) + (spec.init_containers or []):
        sc = container.security_context or client.V1SecurityContext()
        if sc.privileged:
            ctx.has_privileged_container = True
        # Container-level override: explicit non-root enforcement clears pod-level flag.
        if sc.run_as_non_root is True or (sc.run_as_user is not None and sc.run_as_user != 0):
            ctx.runs_as_root = False
        elif sc.run_as_user == 0 or sc.run_as_non_root is False:
            ctx.runs_as_root = True
        caps = sc.capabilities
        if caps and caps.add:
            if any(c in _DANGEROUS_CAPS for c in (caps.add or [])):
                ctx.has_dangerous_caps = True

    ctx.service_account = spec.service_account_name or "default"
    logger.debug("Pod spec enriched: privileged=%s host_network=%s root=%s sa=%s",
                 ctx.has_privileged_container, ctx.has_host_network, ctx.runs_as_root, ctx.service_account)


def _enrich_service_exposure(
    ctx: PodContext,
    core_v1: client.CoreV1Api,
    pod: client.V1Pod,
    namespace: str,
) -> None:
    pod_labels = (pod.metadata.labels or {}) if pod.metadata else {}
    if not pod_labels:
        return
    services = core_v1.list_namespaced_service(namespace=namespace)
    for svc in services.items:
        selector = (svc.spec.selector or {}) if svc.spec else {}
        if selector and all(pod_labels.get(k) == v for k, v in selector.items()):
            svc_type = svc.spec.type if svc.spec else "ClusterIP"
            if svc_type in ("LoadBalancer", "NodePort"):
                ctx.service_type = svc_type
                return
            ctx.service_type = svc_type or "ClusterIP"


def _enrich_rbac(
    ctx: PodContext,
    rbac_v1: client.RbacAuthorizationV1Api,
    namespace: str,
) -> None:
    try:
        bindings = rbac_v1.list_namespaced_role_binding(namespace=namespace)
        for rb in bindings.items:
            for subject in (rb.subjects or []):
                if subject.name == ctx.service_account and subject.kind == "ServiceAccount":
                    ref = rb.role_ref.name if rb.role_ref else ""
                    ctx.cluster_role_names.append(ref)
                    if ref == "cluster-admin":
                        ctx.has_cluster_admin = True

        cont = None
        while True:
            page = rbac_v1.list_cluster_role_binding(limit=200, _continue=cont)
            for crb in page.items:
                for subject in (crb.subjects or []):
                    if (
                        subject.name == ctx.service_account
                        and subject.kind == "ServiceAccount"
                        and subject.namespace == namespace
                    ):
                        ref = crb.role_ref.name if crb.role_ref else ""
                        ctx.cluster_role_names.append(ref)
                        if ref == "cluster-admin":
                            ctx.has_cluster_admin = True
            cont = page.metadata._continue
            if not cont:
                break
    except client.ApiException:
        logger.warning("RBAC lookup failed — skipping RBAC enrichment")


def _enrich_namespace(
    ctx: PodContext,
    core_v1: client.CoreV1Api,
    namespace: str,
) -> None:
    try:
        ns = core_v1.read_namespace(name=namespace)
        labels = (ns.metadata.labels or {}) if ns.metadata else {}
        ctx.namespace_env = labels.get("environment", labels.get("env", ""))
    except client.ApiException:
        pass


def _enrich_owner(
    ctx: PodContext,
    apps_v1: client.AppsV1Api,
    pod: client.V1Pod,
    namespace: str,
) -> None:
    owners = (pod.metadata.owner_references or []) if pod.metadata else []
    for owner in owners:
        if owner.kind == "ReplicaSet":
            try:
                rs = apps_v1.read_namespaced_replica_set(name=owner.name, namespace=namespace)
                rs_owners = (rs.metadata.owner_references or []) if rs.metadata else []
                for rs_owner in rs_owners:
                    if rs_owner.kind == "Deployment":
                        ctx.owner_kind = "Deployment"
                        ctx.owner_name = rs_owner.name
                        return
            except client.ApiException:
                pass
            ctx.owner_kind = "ReplicaSet"
            ctx.owner_name = owner.name
            return
        elif owner.kind in ("StatefulSet", "DaemonSet"):
            ctx.owner_kind = owner.kind
            ctx.owner_name = owner.name
            return
    logger.debug("Pod %s/%s has no recognised workload owner", namespace, ctx.pod_name)


def score(ctx: PodContext, alert_rule: str = "", alert_tags: list[str] | None = None) -> TriageResult:
    if ctx.namespace in _QUARANTINE_BLOCKED_NAMESPACES:
        logger.warning(
            "Triage: pod=%s/%s rule=%s — namespace is protected, downgrading to alert-only",
            ctx.namespace, ctx.pod_name, alert_rule,
        )
        return TriageResult(
            score=0,
            severity="low",
            action=Action.ALERT_ONLY,
            reason=f"namespace {ctx.namespace!r} is protected from automated quarantine",
            context=ctx,
        )

    # Tag-based check is the preferred path; rule name fallback covers older Falco deployments
    # that predate the force_quarantine tag being added to rules.
    force_quarantine = (
        (alert_tags is not None and "force_quarantine" in alert_tags)
        or alert_rule in _FORCE_QUARANTINE_RULES
    )
    if force_quarantine:
        logger.info(
            "Triage: pod=%s/%s rule=%s forced quarantine (active-compromise rule)",
            ctx.namespace, ctx.pod_name, alert_rule,
        )
        return TriageResult(
            score=100,
            severity="critical",
            action=Action.QUARANTINE,
            reason=f"active-compromise rule triggered: {alert_rule}",
            context=ctx,
        )

    points = 0
    reasons = []

    if ctx.has_privileged_container:
        points += 70
        reasons.append("privileged container")
    if ctx.has_cluster_admin:
        points += 70
        reasons.append("cluster-admin service account")
    elif ctx.cluster_role_names:
        points += 5
        reasons.append(f"non-default role bindings: {', '.join(ctx.cluster_role_names[:3])}")
    if ctx.service_type == "LoadBalancer":
        points += 40
        reasons.append("LoadBalancer service (internet-exposed)")
    elif ctx.service_type == "NodePort":
        points += 15
        reasons.append("NodePort service")
    if ctx.has_host_network:
        points += 40
        reasons.append("hostNetwork=true")
    if ctx.has_host_pid:
        points += 30
        reasons.append("hostPID=true")
    if ctx.has_dangerous_caps:
        points += 20
        reasons.append("dangerous Linux capabilities")
    if ctx.runs_as_root:
        points += 10
        reasons.append("runs as root")
    if ctx.is_system_namespace:
        points += 25
        reasons.append("system namespace")
    if ctx.namespace_env in ("prod", "production"):
        points += 10
        reasons.append("production namespace")
    elif ctx.namespace_env in ("dev", "development", "demo"):
        points -= 10
        reasons.append(f"non-production namespace ({ctx.namespace_env}) -10")
    elif ctx.namespace_env == "staging":
        points += 5
        reasons.append("staging namespace")

    points = max(0, min(100, points))

    if points >= 70:
        severity, action = "critical", Action.QUARANTINE
    elif points >= 40:
        severity, action = "high", Action.QUARANTINE
    elif points >= 20:
        severity, action = "medium", Action.ANNOTATE
    else:
        severity, action = "low", Action.ALERT_ONLY

    reason = ", ".join(reasons) if reasons else "no elevated risk factors"
    logger.info(
        "Triage: pod=%s/%s rule=%s score=%d severity=%s action=%s reason=[%s]",
        ctx.namespace, ctx.pod_name, alert_rule, points, severity, action.value, reason,
    )
    return TriageResult(score=points, severity=severity, action=action, reason=reason, context=ctx)
