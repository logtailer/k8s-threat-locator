"""Unit tests for lambda/triage.py — all k8s and AWS calls are mocked."""
from unittest.mock import MagicMock, patch

import pytest

from triage import Action, PodContext, TriageResult, enrich, score


def _ctx(**kwargs) -> PodContext:
    defaults = dict(pod_name="test-pod", namespace="threat-demo")
    defaults.update(kwargs)
    return PodContext(**defaults)


# ---------------------------------------------------------------------------
# score() — unit tests for the scoring logic
# ---------------------------------------------------------------------------

class TestScore:
    def test_privileged_container_is_critical(self):
        result = score(_ctx(has_privileged_container=True))
        assert result.severity == "critical"
        assert result.action == Action.QUARANTINE

    def test_cluster_admin_binding_is_critical(self):
        result = score(_ctx(has_cluster_admin=True))
        assert result.severity == "critical"
        assert result.action == Action.QUARANTINE

    def test_loadbalancer_plus_root_is_high(self):
        result = score(_ctx(service_type="LoadBalancer", runs_as_root=True))
        assert result.severity in ("high", "critical")
        assert result.action == Action.QUARANTINE

    def test_host_network_is_high(self):
        result = score(_ctx(has_host_network=True))
        assert result.severity in ("high", "critical")
        assert result.action == Action.QUARANTINE

    def test_system_namespace_raises_score(self):
        base = score(_ctx())
        elevated = score(_ctx(is_system_namespace=True))
        assert elevated.score > base.score

    def test_medium_score_annotates(self):
        result = score(_ctx(runs_as_root=True, service_type="ClusterIP"))
        assert result.action == Action.ANNOTATE
        assert result.severity == "medium"

    def test_dev_namespace_lowers_score(self):
        without = score(_ctx(runs_as_root=True))
        with_dev = score(_ctx(runs_as_root=True, namespace_env="dev"))
        assert with_dev.score < without.score

    def test_no_risk_factors_is_alert_only(self):
        result = score(_ctx())
        assert result.action == Action.ALERT_ONLY
        assert result.severity == "low"

    def test_score_clamped_to_100(self):
        result = score(_ctx(
            has_privileged_container=True,
            has_cluster_admin=True,
            service_type="LoadBalancer",
            has_host_network=True,
            has_host_pid=True,
            has_dangerous_caps=True,
            runs_as_root=True,
            is_system_namespace=True,
            namespace_env="prod",
        ))
        assert result.score <= 100

    def test_reason_included_in_result(self):
        result = score(_ctx(has_privileged_container=True))
        assert "privileged" in result.reason

    def test_production_namespace_raises_score(self):
        base = score(_ctx(runs_as_root=True))
        prod = score(_ctx(runs_as_root=True, namespace_env="prod"))
        assert prod.score > base.score

    def test_staging_raises_score_more_than_dev(self):
        dev = score(_ctx(runs_as_root=True, namespace_env="dev"))
        staging = score(_ctx(runs_as_root=True, namespace_env="staging"))
        assert staging.score > dev.score

    def test_dangerous_caps_detected(self):
        result = score(_ctx(has_dangerous_caps=True))
        assert result.score >= 15


# ---------------------------------------------------------------------------
# enrich() — integration-style tests with mocked k8s clients
# ---------------------------------------------------------------------------

class TestEnrich:
    def _make_pod(self, **spec_kwargs):
        pod = MagicMock()
        pod.metadata.labels = {"app": "items-api"}
        pod.spec.host_network = spec_kwargs.get("host_network", False)
        pod.spec.host_pid = spec_kwargs.get("host_pid", False)
        pod.spec.security_context.run_as_user = spec_kwargs.get("run_as_user", 1000)
        pod.spec.security_context.run_as_non_root = spec_kwargs.get("run_as_non_root", True)
        pod.spec.service_account_name = spec_kwargs.get("service_account", "app-sa")
        container = MagicMock()
        container.security_context.privileged = spec_kwargs.get("privileged", False)
        container.security_context.run_as_user = spec_kwargs.get("container_run_as_user", 1000)
        container.security_context.capabilities.add = spec_kwargs.get("caps", [])
        pod.spec.containers = [container]
        return pod

    def test_privileged_container_detected(self):
        core_v1 = MagicMock()
        rbac_v1 = MagicMock()
        core_v1.read_namespaced_pod.return_value = self._make_pod(privileged=True)
        core_v1.list_namespaced_service.return_value.items = []
        rbac_v1.list_namespaced_role_binding.return_value.items = []
        rbac_v1.list_cluster_role_binding.return_value.items = []
        core_v1.read_namespace.return_value.metadata.labels = {}

        ctx = enrich(core_v1, rbac_v1, "test-pod", "threat-demo")
        assert ctx.has_privileged_container is True

    def test_loadbalancer_service_detected(self):
        core_v1 = MagicMock()
        rbac_v1 = MagicMock()
        core_v1.read_namespaced_pod.return_value = self._make_pod()
        svc = MagicMock()
        svc.spec.type = "LoadBalancer"
        svc.spec.selector = {"app": "items-api"}
        core_v1.list_namespaced_service.return_value.items = [svc]
        rbac_v1.list_namespaced_role_binding.return_value.items = []
        rbac_v1.list_cluster_role_binding.return_value.items = []
        core_v1.read_namespace.return_value.metadata.labels = {}

        ctx = enrich(core_v1, rbac_v1, "test-pod", "threat-demo")
        assert ctx.service_type == "LoadBalancer"

    def test_cluster_admin_binding_detected(self):
        from kubernetes import client as k8s_client
        core_v1 = MagicMock()
        rbac_v1 = MagicMock()
        core_v1.read_namespaced_pod.return_value = self._make_pod(service_account="app-sa")
        core_v1.list_namespaced_service.return_value.items = []
        core_v1.read_namespace.return_value.metadata.labels = {}
        rbac_v1.list_namespaced_role_binding.return_value.items = []

        crb = MagicMock()
        subject = MagicMock()
        subject.name = "app-sa"
        subject.kind = "ServiceAccount"
        subject.namespace = "threat-demo"
        crb.subjects = [subject]
        crb.role_ref.name = "cluster-admin"
        rbac_v1.list_cluster_role_binding.return_value.items = [crb]

        ctx = enrich(core_v1, rbac_v1, "test-pod", "threat-demo")
        assert ctx.has_cluster_admin is True

    def test_pod_not_found_returns_partial_context(self):
        from kubernetes import client as k8s_client
        core_v1 = MagicMock()
        rbac_v1 = MagicMock()
        core_v1.read_namespaced_pod.side_effect = k8s_client.ApiException(status=404)

        ctx = enrich(core_v1, rbac_v1, "missing-pod", "threat-demo")
        assert ctx.pod_name == "missing-pod"
        assert ctx.has_privileged_container is False

    def test_init_container_privileged_detected(self):
        core_v1 = MagicMock()
        rbac_v1 = MagicMock()
        pod = self._make_pod()
        init_container = MagicMock()
        init_container.security_context.privileged = True
        init_container.security_context.run_as_user = 1000
        init_container.security_context.capabilities.add = []
        pod.spec.init_containers = [init_container]
        core_v1.read_namespaced_pod.return_value = pod
        core_v1.list_namespaced_service.return_value.items = []
        rbac_v1.list_namespaced_role_binding.return_value.items = []
        rbac_v1.list_cluster_role_binding.return_value.items = []
        core_v1.read_namespace.return_value.metadata.labels = {}

        ctx = enrich(core_v1, rbac_v1, "test-pod", "threat-demo")
        assert ctx.has_privileged_container is True

    def test_rbac_permission_denied_does_not_raise(self):
        from kubernetes import client as k8s_client
        core_v1 = MagicMock()
        rbac_v1 = MagicMock()
        core_v1.read_namespaced_pod.return_value = self._make_pod()
        core_v1.list_namespaced_service.return_value.items = []
        core_v1.read_namespace.return_value.metadata.labels = {}
        rbac_v1.list_namespaced_role_binding.side_effect = k8s_client.ApiException(status=403)
        rbac_v1.list_cluster_role_binding.side_effect = k8s_client.ApiException(status=403)

        ctx = enrich(core_v1, rbac_v1, "test-pod", "threat-demo")
        assert ctx.has_cluster_admin is False
