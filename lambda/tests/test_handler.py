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
