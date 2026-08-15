"""Unit tests for lambda/handler.py — all k8s and AWS calls are mocked."""
import json
from unittest.mock import MagicMock, patch

from kubernetes import client as k8s_client

import handler


# ---------------------------------------------------------------------------
# _parse_alert() — SNS envelope handling
# ---------------------------------------------------------------------------

class TestParseAlert:
    def test_subscription_confirmation_is_ignored(self):
        record = {"Sns": {"Type": "SubscriptionConfirmation", "Message": "{}"}}
        assert handler._parse_alert(record) is None

    def test_invalid_json_returns_none(self):
        record = {"Sns": {"Message": "this is not json"}}
        assert handler._parse_alert(record) is None

    def test_valid_message_is_parsed(self):
        payload = {"rule": "shell_in_container", "output_fields": {"k8s.pod.name": "p"}}
        record = {"Sns": {"Message": json.dumps(payload)}}
        parsed = handler._parse_alert(record)
        assert parsed == payload


# ---------------------------------------------------------------------------
# _policy_name() / _workload_policy_name() — NetworkPolicy names must be a
# valid DNS-1123 label (<=63 chars, no trailing '-')
# ---------------------------------------------------------------------------

class TestPolicyName:
    def test_short_name_is_prefixed(self):
        assert handler._policy_name("items-api-abc") == "quarantine-items-api-abc"

    def test_long_name_truncated_to_63(self):
        name = handler._policy_name("p" * 100)
        assert len(name) <= 63

    def test_no_trailing_hyphen_after_truncation(self):
        # Craft a name whose 63-char cut would land on a '-'.
        pod = "a" * 51 + "-bbbbbbbbbbbb"
        name = handler._policy_name(pod)
        assert len(name) <= 63
        assert not name.endswith("-")

    def test_workload_name_prefixed_and_bounded(self):
        name = handler._workload_policy_name("d" * 100)
        assert name.startswith("quarantine-workload-")
        assert len(name) <= 63
        assert not name.endswith("-")


# ---------------------------------------------------------------------------
# _build_quarantine_policy() — must produce a deny-all NetworkPolicy
# ---------------------------------------------------------------------------

class TestBuildQuarantinePolicy:
    def test_deny_all_ingress_and_egress(self):
        policy = handler._build_quarantine_policy(
            "quarantine-p", "threat-demo", {"quarantine": "true"}
        )
        assert policy.spec.policy_types == ["Ingress", "Egress"]
        # Empty rule lists = deny-all in both directions.
        assert policy.spec.ingress == []
        assert policy.spec.egress == []

    def test_selector_matches_supplied_labels(self):
        labels = {"app": "items-api"}
        policy = handler._build_quarantine_policy("q", "ns", labels)
        assert policy.spec.pod_selector.match_labels == labels
        assert policy.metadata.labels["managed-by"] == "k8s-threat-locator"


# ---------------------------------------------------------------------------
# _quarantine_pod() — label the pod, then apply a deny-all NetworkPolicy
# ---------------------------------------------------------------------------

@patch("handler._emit_quarantine_metric")
class TestQuarantinePod:
    def test_labels_pod_and_creates_policy(self, _metric):
        core_v1, net_v1, apps_v1 = MagicMock(), MagicMock(), MagicMock()
        handler._quarantine_pod(core_v1, net_v1, apps_v1, "pod-x", "threat-demo", "shell_in_container")
        core_v1.patch_namespaced_pod.assert_called_once()
        net_v1.create_namespaced_network_policy.assert_called_once()

    def test_existing_policy_409_is_swallowed(self, _metric):
        core_v1, net_v1, apps_v1 = MagicMock(), MagicMock(), MagicMock()
        net_v1.create_namespaced_network_policy.side_effect = k8s_client.ApiException(status=409)
        # Must not raise — quarantine is idempotent.
        handler._quarantine_pod(core_v1, net_v1, apps_v1, "pod-x", "threat-demo", "write_to_etc")
        core_v1.patch_namespaced_pod.assert_called_once()

    def test_pod_gone_404_falls_back_to_workload(self, _metric):
        core_v1, net_v1, apps_v1 = MagicMock(), MagicMock(), MagicMock()
        core_v1.patch_namespaced_pod.side_effect = k8s_client.ApiException(status=404)
        # Deployment lookup returns a selector so a workload policy can be built.
        deploy = MagicMock()
        deploy.spec.selector.match_labels = {"app": "items-api"}
        apps_v1.read_namespaced_deployment.return_value = deploy

        handler._quarantine_pod(
            core_v1, net_v1, apps_v1, "pod-x", "threat-demo", "shell_in_container",
            ctx_owner_kind="Deployment", ctx_owner_name="items-api",
        )
        apps_v1.read_namespaced_deployment.assert_called_once()
        net_v1.create_namespaced_network_policy.assert_called_once()

    def test_pod_gone_404_without_owner_skips(self, _metric):
        core_v1, net_v1, apps_v1 = MagicMock(), MagicMock(), MagicMock()
        core_v1.patch_namespaced_pod.side_effect = k8s_client.ApiException(status=404)
        # No owner context -> nothing to fall back to, must not raise.
        handler._quarantine_pod(core_v1, net_v1, apps_v1, "pod-x", "threat-demo", "shell_in_container")
        net_v1.create_namespaced_network_policy.assert_not_called()


# ---------------------------------------------------------------------------
# handler() — action dispatch based on the triage result
# ---------------------------------------------------------------------------

def _event(rule="shell_in_container", pod="pod-x", ns="threat-demo"):
    message = {
        "rule": rule,
        "priority": "ERROR",
        "tags": ["force_quarantine"],
        "output_fields": {"k8s.pod.name": pod, "k8s.ns.name": ns},
    }
    return {"Records": [{"Sns": {"Message": json.dumps(message)}}]}


def _triage(action, severity="critical", reason="r", score_=100):
    result = MagicMock()
    result.action = action
    result.severity = severity
    result.reason = reason
    result.score = score_
    return result


class TestHandlerDispatch:
    def _patches(self):
        """Patch the boundaries so handler() runs without AWS or a cluster."""
        clients = (MagicMock(), MagicMock(), MagicMock(), MagicMock(), "/tmp/no-such-ca.crt")
        ctx = MagicMock(owner_kind="Deployment", owner_name="items-api")
        return (
            patch("handler._download_kubeconfig"),
            patch("handler._get_k8s_clients", return_value=clients),
            patch("handler.enrich", return_value=ctx),
            patch("handler._emit_triage_metric"),
            clients,
        )

    def test_quarantine_action_isolates_pod(self):
        p_dl, p_clients, p_enrich, p_metric, _clients = self._patches()
        with p_dl, p_clients, p_enrich, p_metric, \
                patch("handler.score", return_value=_triage(handler.Action.QUARANTINE)), \
                patch("handler._quarantine_pod") as quarantine:
            handler.handler(_event(), None)
        quarantine.assert_called_once()

    def test_quarantine_notifies_ops(self):
        # Quarantine is disruptive — it must page ops directly, not rely on the
        # wave alarm. Regression guard for the "silent isolation" gap.
        p_dl, p_clients, p_enrich, p_metric, _clients = self._patches()
        with p_dl, p_clients, p_enrich, p_metric, \
                patch("handler.score", return_value=_triage(handler.Action.QUARANTINE)), \
                patch("handler._quarantine_pod"), \
                patch("handler._notify_ops") as notify:
            handler.handler(_event(), None)
        notify.assert_called_once()

    def test_annotate_action_annotates_and_notifies(self):
        p_dl, p_clients, p_enrich, p_metric, clients = self._patches()
        core_v1 = clients[0]
        with p_dl, p_clients, p_enrich, p_metric, \
                patch("handler.score", return_value=_triage(handler.Action.ANNOTATE, "medium", "r", 25)), \
                patch("handler._notify_ops") as notify:
            handler.handler(_event(), None)
        core_v1.patch_namespaced_pod.assert_called_once()
        notify.assert_called_once()

    def test_alert_only_takes_no_action(self):
        p_dl, p_clients, p_enrich, p_metric, clients = self._patches()
        core_v1 = clients[0]
        with p_dl, p_clients, p_enrich, p_metric, \
                patch("handler.score", return_value=_triage(handler.Action.ALERT_ONLY, "low", "r", 0)), \
                patch("handler._quarantine_pod") as quarantine:
            handler.handler(_event(), None)
        quarantine.assert_not_called()
        core_v1.patch_namespaced_pod.assert_not_called()

    def test_syscall_evidence_reaches_score(self):
        # output_fields' syscall keys must arrive at score() as AlertEvidence.
        p_dl, p_clients, p_enrich, p_metric, _clients = self._patches()
        message = {
            "rule": "shell_in_container",
            "priority": "ERROR",
            "tags": ["force_quarantine"],
            "output_fields": {
                "k8s.pod.name": "pod-x",
                "k8s.ns.name": "threat-demo",
                "proc.name": "sh",
                "proc.pname": "python",
                "proc.cmdline": "sh -c id",
                "k8s.pod.uid": "uid-123",
            },
        }
        event = {"Records": [{"Sns": {"Message": json.dumps(message)}}]}
        with p_dl, p_clients, p_enrich, p_metric, \
                patch("handler.score", return_value=_triage(handler.Action.ALERT_ONLY, "low", "r", 0)) as score_mock, \
                patch("handler._quarantine_pod"):
            handler.handler(event, None)
        ev = score_mock.call_args.kwargs["evidence"]
        assert ev.proc_pname == "python"
        assert ev.proc_cmdline == "sh -c id"
        assert ev.pod_uid == "uid-123"


class TestMetricsAreNonFatal:
    """Telemetry must never block the security response."""

    def test_triage_metric_swallows_backend_error(self):
        with patch("handler._aws_client") as mk:
            mk.return_value.put_metric_data.side_effect = RuntimeError("cw down")
            handler._emit_triage_metric("pod-x", "threat-demo", "critical")  # no raise

    def test_quarantine_metric_swallows_backend_error(self):
        with patch("handler._aws_client") as mk:
            mk.return_value.put_metric_data.side_effect = RuntimeError("cw down")
            handler._emit_quarantine_metric("pod-x", "threat-demo", "write_to_etc")  # no raise
