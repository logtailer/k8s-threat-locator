import json
import logging
import os

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import ClientError
from kubernetes import client, config

from triage import Action, enrich, score

logger = logging.getLogger()
logger.setLevel(logging.INFO)

KUBECONFIG_BUCKET = os.environ.get("KUBECONFIG_BUCKET", "")
KUBECONFIG_KEY = os.environ.get("KUBECONFIG_KEY", "kubeconfig")
KUBECONFIG_PATH = "/tmp/kubeconfig"
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

if not KUBECONFIG_BUCKET:
    logger.warning("KUBECONFIG_BUCKET is not set — S3 download will fail at runtime")


def _emit_triage_metric(pod_name: str, namespace: str, severity: str) -> None:
    cw = boto3.client("cloudwatch", region_name=AWS_REGION)
    cw.put_metric_data(
        Namespace="k8s-threat-locator",
        MetricData=[{
            "MetricName": "TriageScore",
            "Dimensions": [
                {"Name": "Namespace", "Value": namespace},
                {"Name": "Pod", "Value": pod_name},
                {"Name": "Severity", "Value": severity},
            ],
            "Value": 1,
            "Unit": "Count",
        }],
    )


def _emit_quarantine_metric(pod_name: str, namespace: str, rule: str = "") -> None:
    cw = boto3.client("cloudwatch", region_name=AWS_REGION)
    cw.put_metric_data(
        Namespace="k8s-threat-locator",
        MetricData=[
            {
                "MetricName": "QuarantineApplied",
                "Dimensions": [
                    {"Name": "Namespace", "Value": namespace},
                    {"Name": "Pod", "Value": pod_name},
                    {"Name": "Rule", "Value": rule or "unknown"},
                ],
                "Value": 1,
                "Unit": "Count",
            }
        ],
    )
    logger.info("Emitted QuarantineApplied metric for pod %s/%s rule=%s", namespace, pod_name, rule)


def _get_k8s_clients() -> tuple:
    config.load_kube_config(config_file=KUBECONFIG_PATH)
    k8s_client = client.ApiClient(
        configuration=client.Configuration(connection_pool_maxsize=4)
    )
    return (
        client.CoreV1Api(k8s_client),
        client.NetworkingV1Api(k8s_client),
        client.RbacAuthorizationV1Api(k8s_client),
    )


def _policy_name(pod_name: str) -> str:
    name = f"quarantine-{pod_name}"
    return name[:63].rstrip("-")


def _build_quarantine_policy(pod_name: str, namespace: str) -> client.V1NetworkPolicy:
    return client.V1NetworkPolicy(
        api_version="networking.k8s.io/v1",
        kind="NetworkPolicy",
        metadata=client.V1ObjectMeta(
            name=_policy_name(pod_name),
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


def _download_kubeconfig() -> None:
    s3 = boto3.client(
        "s3",
        region_name=AWS_REGION,
        config=BotocoreConfig(
            connect_timeout=5,
            read_timeout=10,
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )
    try:
        s3.download_file(KUBECONFIG_BUCKET, KUBECONFIG_KEY, KUBECONFIG_PATH)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        logger.error("S3 download failed (bucket=%s key=%s): %s", KUBECONFIG_BUCKET, KUBECONFIG_KEY, code)
        raise
    logger.info("Downloaded kubeconfig from s3://%s/%s", KUBECONFIG_BUCKET, KUBECONFIG_KEY)


def _quarantine_pod(
    core_v1: client.CoreV1Api,
    networking_v1: client.NetworkingV1Api,
    pod_name: str,
    namespace: str,
    rule: str,
) -> None:
    core_v1.patch_namespaced_pod(
        name=pod_name,
        namespace=namespace,
        body={"metadata": {"labels": {"quarantine": "true"}}},
    )
    logger.info("Labelled pod %s/%s with quarantine=true", namespace, pod_name)

    policy = _build_quarantine_policy(pod_name, namespace)
    try:
        networking_v1.create_namespaced_network_policy(namespace=namespace, body=policy)
        logger.info("Quarantine NetworkPolicy applied for pod %s/%s", namespace, pod_name)
        _emit_quarantine_metric(pod_name, namespace, rule=rule)
    except client.ApiException as exc:
        if exc.status == 409:
            logger.info("Quarantine policy already exists for pod %s/%s rule=%s — skipping", namespace, pod_name, rule)
        else:
            raise


def _parse_alert(record: dict) -> dict | None:
    sns_payload = record.get("Sns", {})
    if sns_payload.get("Type") == "SubscriptionConfirmation":
        logger.info("Ignoring SNS subscription confirmation message")
        return None
    try:
        return json.loads(sns_payload.get("Message", "{}"))
    except json.JSONDecodeError:
        logger.warning("Could not parse SNS message as JSON: %s", sns_payload.get("Message"))
        return None


def handler(event, context):
    logger.info("Received event with %d records", len(event.get("Records", [])))

    for record in event.get("Records", []):
        alert = _parse_alert(record)
        if alert is None:
            continue

        output_fields = alert.get("output_fields", {})
        pod_name = output_fields.get("k8s.pod.name")
        namespace = output_fields.get("k8s.ns.name")
        rule = alert.get("rule", "unknown")
        priority = alert.get("priority", "unknown")

        if not pod_name or not namespace:
            logger.warning("Alert missing pod/namespace fields — skipping. rule=%s fields=%s", rule, output_fields)
            continue

        logger.info("Falco alert: rule=%s priority=%s pod=%s ns=%s time=%s",
                    rule, priority, pod_name, namespace, alert.get("time"))

        try:
            _download_kubeconfig()
            core_v1, networking_v1, rbac_v1 = _get_k8s_clients()
            logger.info("Kubernetes clients initialised for pod %s/%s", namespace, pod_name)

            ctx = enrich(core_v1, rbac_v1, pod_name, namespace)
            result = score(ctx)
            _emit_triage_metric(pod_name, namespace, result.severity)

            if result.action == Action.QUARANTINE:
                _quarantine_pod(core_v1, networking_v1, pod_name, namespace, rule)
            elif result.action == Action.ANNOTATE:
                core_v1.patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body={"metadata": {"annotations": {"triage-severity": result.severity, "triage-reason": result.reason}}},
                )
                logger.info("Annotated pod %s/%s severity=%s reason=%s", namespace, pod_name, result.severity, result.reason)
            else:
                logger.info("Alert-only for pod %s/%s score=%d reason=%s", namespace, pod_name, result.score, result.reason)
        except Exception:
            logger.exception("Unhandled error while processing alert for pod %s/%s", namespace, pod_name)
            raise
        finally:
            if os.path.exists(KUBECONFIG_PATH):
                os.remove(KUBECONFIG_PATH)
                logger.info("Cleaned up kubeconfig from %s", KUBECONFIG_PATH)

    return {"statusCode": 200, "body": "ok"}
