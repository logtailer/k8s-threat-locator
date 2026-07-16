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
    service_type: str = "None"  # ClusterIP | NodePort | LoadBalancer | None
    # RBAC
    service_account: str = "default"
    has_cluster_admin: bool = False
    cluster_role_names: list[str] = field(default_factory=list)
    # Namespace
    namespace_env: str = ""  # value of label environment=
    is_system_namespace: bool = False
    # Owner workload — populated when pod is still alive at enrichment time
    owner_kind: str = ""  # Deployment | StatefulSet | DaemonSet | ReplicaSet | ""
    owner_name: str = ""


@dataclass
class AlertEvidence:
    """Syscall-level fields carried by a Falco alert's output_fields.

    Distinct from PodContext (which is live cluster posture) — this is what the
    kernel actually observed at the moment the rule fired. All optional so an
    alert missing a field degrades gracefully.
    """

    proc_name: str = ""  # process that triggered the rule
    proc_pname: str = ""  # its parent — separates app-RCE (parent=app) from human exec
    proc_cmdline: str = ""  # full command line — intent signal
    user_uid: str = ""
    fd_name: str = ""  # file path for filesystem rules
    fd_rip: str = ""  # remote IP for network rules
    fd_rport: str = ""  # remote port for network rules
    pod_uid: str = ""  # k8s.pod.uid — stable identity beyond the pod name


@dataclass
class TriageResult:
    score: int  # 0–100
    severity: str  # low | medium | high | critical
    action: Action
    reason: str
    context: PodContext


_DANGEROUS_CAPS = frozenset(
    {"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"}
)
_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "falco", "calico-system"}

# Quarantine is never applied to these namespaces — isolating infrastructure pods (coredns,
# kube-proxy, falco) would cascade into cluster-wide outages worse than the alert itself.
_QUARANTINE_BLOCKED_NAMESPACES = frozenset(
    {
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "falco",
        "calico-system",
        "calico-apiserver",
        "tigera-operator",
    }
)

# Fallback for Falco deployments that do not yet carry the force_quarantine tag on their rules.
# Preferred path: Falco rule carries tags: [..., force_quarantine] and alert_tags is checked in score().
# This frozenset must be kept in sync with any Falco rule that should trigger immediate quarantine
# but cannot be redeployed to add the tag (e.g. built-in upstream rules used without modification).
_FORCE_QUARANTINE_RULES = frozenset(
    {
        "shell_in_container",
        "write_to_etc",
        "imds_access_from_container",
        "Terminal shell in container",
        "Write below etc",
    }
)

# Parent-process names that indicate the application runtime itself spawned the
# offending process — i.e. application RCE, not a human operator's `kubectl exec`
# (which descends from a container-runtime/shell with a tty). Used only to
# annotate the quarantine reason; it never changes the action.
_APP_RUNTIME_PARENTS = frozenset(
    {"python", "python3", "node", "gunicorn", "uwsgi", "java", "ruby", "flask"}
)


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
        logger.warning(
            "Could not fully enrich pod context for %s/%s: status=%s — using partial context",
            namespace,
            pod_name,
            exc.status,
        )

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
        if sc.run_as_non_root is True or (
            sc.run_as_user is not None and sc.run_as_user != 0
        ):
            ctx.runs_as_root = False
        elif sc.run_as_user == 0 or sc.run_as_non_root is False:
            ctx.runs_as_root = True
        caps = sc.capabilities
        if caps and caps.add:
            if any(c in _DANGEROUS_CAPS for c in (caps.add or [])):
                ctx.has_dangerous_caps = True

    ctx.service_account = spec.service_account_name or "default"
    logger.debug(
        "Pod spec enriched: privileged=%s host_network=%s root=%s sa=%s",
        ctx.has_privileged_container,
        ctx.has_host_network,
        ctx.runs_as_root,
        ctx.service_account,
    )


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
            for subject in rb.subjects or []:
                if (
                    subject.name == ctx.service_account
                    and subject.kind == "ServiceAccount"
                ):
                    ref = rb.role_ref.name if rb.role_ref else ""
                    ctx.cluster_role_names.append(ref)
                    if ref == "cluster-admin":
                        ctx.has_cluster_admin = True

        cont = None
        while True:
            page = rbac_v1.list_cluster_role_binding(limit=200, _continue=cont)
            for crb in page.items:
                for subject in crb.subjects or []:
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
                rs = apps_v1.read_namespaced_replica_set(
                    name=owner.name, namespace=namespace
                )
                rs_owners = (rs.metadata.owner_references or []) if rs.metadata else []
                for rs_owner in rs_owners:
                    if rs_owner.kind == "Deployment":
                        ctx.owner_kind = "Deployment"
                        ctx.owner_name = rs_owner.name
                        logger.info(
                            "Owner resolved: pod=%s/%s owner_kind=Deployment owner_name=%s",
                            namespace,
                            ctx.pod_name,
                            rs_owner.name,
                        )
                        return
            except client.ApiException:
                pass
            ctx.owner_kind = "ReplicaSet"
            ctx.owner_name = owner.name
            logger.info(
                "Owner resolved: pod=%s/%s owner_kind=ReplicaSet owner_name=%s",
                namespace,
                ctx.pod_name,
                owner.name,
            )
            return
        elif owner.kind in ("StatefulSet", "DaemonSet"):
            ctx.owner_kind = owner.kind
            ctx.owner_name = owner.name
            logger.info(
                "Owner resolved: pod=%s/%s owner_kind=%s owner_name=%s",
                namespace,
                ctx.pod_name,
                owner.kind,
                owner.name,
            )
            return
    logger.debug("Pod %s/%s has no recognised workload owner", namespace, ctx.pod_name)


def _force_quarantine_reason(
    alert_rule: str, evidence: AlertEvidence | None
) -> str:
    """Annotate a force-quarantine with WHY, using the parent process.

    The action is always QUARANTINE (safety first); this only helps a responder
    tell application RCE from an operator's interactive exec at a glance.
    """
    base = f"active-compromise rule triggered: {alert_rule}"
    if evidence is None or not evidence.proc_pname:
        return base
    if evidence.proc_pname in _APP_RUNTIME_PARENTS:
        return (
            f"{base} — application RCE "
            f"(process spawned by app runtime '{evidence.proc_pname}')"
        )
    return (
        f"{base} — likely interactive exec "
        f"(parent '{evidence.proc_pname}'), review"
    )


def score(
    ctx: PodContext,
    alert_rule: str = "",
    alert_tags: list[str] | None = None,
    evidence: AlertEvidence | None = None,
) -> TriageResult:
    if evidence is not None:
        logger.info(
            "Triage evidence: pod=%s/%s proc=%s parent=%s uid=%s cmd=%s",
            ctx.namespace,
            ctx.pod_name,
            evidence.proc_name,
            evidence.proc_pname,
            evidence.user_uid,
            evidence.proc_cmdline,
        )
    if ctx.namespace in _QUARANTINE_BLOCKED_NAMESPACES:
        logger.warning(
            "Triage: pod=%s/%s rule=%s — namespace is protected, downgrading to alert-only",
            ctx.namespace,
            ctx.pod_name,
            alert_rule,
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
        alert_tags is not None and "force_quarantine" in alert_tags
    ) or alert_rule in _FORCE_QUARANTINE_RULES
    if force_quarantine:
        reason = _force_quarantine_reason(alert_rule, evidence)
        logger.info(
            "Triage: pod=%s/%s rule=%s forced quarantine (%s)",
            ctx.namespace,
            ctx.pod_name,
            alert_rule,
            reason,
        )
        return TriageResult(
            score=100,
            severity="critical",
            action=Action.QUARANTINE,
            reason=reason,
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
        reasons.append(
            f"non-default role bindings: {', '.join(ctx.cluster_role_names[:3])}"
        )
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
        ctx.namespace,
        ctx.pod_name,
        alert_rule,
        points,
        severity,
        action.value,
        reason,
    )
    return TriageResult(
        score=points, severity=severity, action=action, reason=reason, context=ctx
    )
