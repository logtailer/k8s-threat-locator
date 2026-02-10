"""
Runtime context enrichment and triage scoring for Falco alerts.

Before quarantining a pod, the handler calls enrich() to gather context from
the Kubernetes API, then score() maps that context to a TriageResult that
determines the response action.
"""
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


@dataclass
class TriageResult:
    score: int                   # 0–100
    severity: str                # low | medium | high | critical
    action: Action
    reason: str
    context: PodContext


_DANGEROUS_CAPS = {"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"}
_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "falco", "calico-system"}
