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
