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

        if not pod_name or not namespace:
            logger.warning("Cannot quarantine — pod_name=%r namespace=%r", pod_name, namespace)
            continue

        try:
            _download_kubeconfig()
            core_v1, networking_v1 = _get_k8s_clients()


            # Label the pod so the quarantine NetworkPolicy selector can target it
            core_v1.patch_namespaced_pod(
                name=pod_name,
                namespace=namespace,
                body={"metadata": {"labels": {"quarantine": "true"}}},
            )
            logger.info("Labelled pod %s/%s with quarantine=true", namespace, pod_name)

            policy = _build_quarantine_policy(pod_name, namespace)
            try:
                networking_v1.create_namespaced_network_policy(
                    namespace=namespace,
                    body=policy,
                )
                logger.info("Quarantine NetworkPolicy applied for pod %s/%s", namespace, pod_name)
            except client.ApiException as exc:
                if exc.status == 409:
                    logger.info("Quarantine policy already exists for pod %s/%s — pod is already isolated", namespace, pod_name)
                else:
                    raise
        finally:
            if os.path.exists(KUBECONFIG_PATH):
                os.remove(KUBECONFIG_PATH)

    return {"statusCode": 200, "body": "ok"}
