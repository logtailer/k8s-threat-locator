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
