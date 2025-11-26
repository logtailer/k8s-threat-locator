import json
import logging
import os

import boto3
from kubernetes import client, config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

KUBECONFIG_BUCKET = os.environ.get("KUBECONFIG_BUCKET", "")
KUBECONFIG_KEY = os.environ.get("KUBECONFIG_KEY", "kubeconfig")
KUBECONFIG_PATH = "/tmp/kubeconfig"


def _get_k8s_clients():
    config.load_kube_config(config_file=KUBECONFIG_PATH)
    return client.CoreV1Api(), client.NetworkingV1Api()


def _build_quarantine_policy(pod_name: str, namespace: str) -> client.V1NetworkPolicy:
    return client.V1NetworkPolicy(
        api_version="networking.k8s.io/v1",
        kind="NetworkPolicy",
        metadata=client.V1ObjectMeta(
            name=f"quarantine-{pod_name}",
            namespace=namespace,
            labels={"quarantine": "true", "managed-by": "k8s-threat-locator"},
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(
                match_labels={"quarantine": "true"}
            ),
            policy_types=["Ingress", "Egress"],
            ingress=[],
            egress=[],
        ),
    )


def _download_kubeconfig():
    s3 = boto3.client("s3")
    s3.download_file(KUBECONFIG_BUCKET, KUBECONFIG_KEY, KUBECONFIG_PATH)
    logger.info("Downloaded kubeconfig from s3://%s/%s", KUBECONFIG_BUCKET, KUBECONFIG_KEY)


def handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    for record in event.get("Records", []):
        sns_message = record.get("Sns", {}).get("Message", "{}")
        try:
            alert = json.loads(sns_message)
        except json.JSONDecodeError:
            logger.warning("Could not parse SNS message as JSON: %s", sns_message)
            continue

        output_fields = alert.get("output_fields", {})
        pod_name = output_fields.get("k8s.pod.name")
        namespace = output_fields.get("k8s.ns.name")

        if not pod_name or not namespace:
            logger.warning("Alert missing pod/namespace fields — skipping. fields=%s", output_fields)
            continue

        logger.info("Falco alert: rule=%s priority=%s pod=%s ns=%s",
                    alert.get("rule"), alert.get("priority"), pod_name, namespace)

    return {"statusCode": 200, "body": "ok"}
