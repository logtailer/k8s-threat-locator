import base64
import json
import logging
import os
import re
import tempfile

import boto3
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import ClientError
import yaml
from kubernetes import client

from triage import Action, enrich, score

logger = logging.getLogger()
logger.setLevel(logging.INFO)

KUBECONFIG_BUCKET = os.environ.get("KUBECONFIG_BUCKET", "")
KUBECONFIG_KEY = os.environ.get("KUBECONFIG_KEY", "kubeconfig")
KUBECONFIG_PATH = "/tmp/kubeconfig"
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
OPS_ALERTS_TOPIC_ARN = os.environ.get("OPS_ALERTS_TOPIC_ARN", "")

if not KUBECONFIG_BUCKET:
    logger.warning("KUBECONFIG_BUCKET is not set — S3 download will fail at runtime")


def _notify_ops(
    pod_name: str,
    namespace: str,
    severity: str,
    reason: str,
    rule: str = "",
    priority: str = "",
    score: int = 0,
) -> None:
    if not OPS_ALERTS_TOPIC_ARN:
        logger.debug("OPS_ALERTS_TOPIC_ARN not set — skipping ops notification")
        return
    sns = boto3.client("sns", region_name=AWS_REGION)
    message = (
        f"k8s-threat-locator: pod {namespace}/{pod_name} flagged at severity={severity}\n"
        f"rule: {rule or 'unknown'}  priority: {priority or 'unknown'}  score: {score}\n"
        f"reason: {reason}"
    )
    sns.publish(
        TopicArn=OPS_ALERTS_TOPIC_ARN,
        Subject=f"[k8s-threat-locator] {severity.upper()} — {namespace}/{pod_name}",
        Message=message,
    )
    logger.info("Ops notification sent for pod %s/%s severity=%s", namespace, pod_name, severity)


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


def _generate_eks_token(cluster_name: str, region: str) -> str:
    """Generate a bearer token for EKS equivalent to `aws eks get-token`."""
    session = boto3.session.Session()
    creds = session.get_credentials().get_frozen_credentials()
    signer = SigV4QueryAuth(creds, "sts", region, expires=900)
    url = f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
    request = AWSRequest(method="GET", url=url, headers={"x-k8s-aws-id": cluster_name})
    signer.add_auth(request)
    presigned = request.url
    token = "k8s-aws-v1." + re.sub(r"=+$", "", base64.urlsafe_b64encode(presigned.encode()).decode())
    return token


def _get_k8s_clients() -> tuple:
    with open(KUBECONFIG_PATH) as f:
        kube_cfg = yaml.safe_load(f)

    cluster_info = kube_cfg["clusters"][0]["cluster"]
    server = cluster_info["server"]
    ca_b64 = cluster_info["certificate-authority-data"]

    # Derive cluster name and region from context ARN
    context_name = kube_cfg.get("current-context", "")
    # ARN format: arn:aws:eks:<region>:<account>:cluster/<name>
    parts = context_name.split(":")
    cluster_name = parts[-1].split("/")[-1] if "/" in parts[-1] else "k8s-threat-locator"
    region = parts[3] if len(parts) > 3 else AWS_REGION

    token = _generate_eks_token(cluster_name, region)

    with tempfile.NamedTemporaryFile(suffix=".crt", delete=False) as ca_file:
        ca_file.write(base64.b64decode(ca_b64))
        ca_cert_path = ca_file.name

    k8s_config = client.Configuration()
    k8s_config.host = server
    k8s_config.ssl_ca_cert = ca_cert_path
    k8s_config.verify_ssl = True
    k8s_config.api_key = {"authorization": token}
    k8s_config.api_key_prefix = {"authorization": "Bearer"}

    k8s_client = client.ApiClient(configuration=k8s_config)
    return (
        client.CoreV1Api(k8s_client),
        client.NetworkingV1Api(k8s_client),
        client.RbacAuthorizationV1Api(k8s_client),
        client.AppsV1Api(k8s_client),
        ca_cert_path,
    )


def _policy_name(pod_name: str) -> str:
    name = f"quarantine-{pod_name}"
    return name[:63].rstrip("-")


def _workload_policy_name(owner_name: str) -> str:
    name = f"quarantine-workload-{owner_name}"
    return name[:63].rstrip("-")


def _build_quarantine_policy(name: str, namespace: str, match_labels: dict) -> client.V1NetworkPolicy:
    return client.V1NetworkPolicy(
        api_version="networking.k8s.io/v1",
        kind="NetworkPolicy",
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels={"quarantine": "true", "managed-by": "k8s-threat-locator"},
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(
                match_labels=match_labels,
            ),
            policy_types=["Ingress", "Egress"],
            ingress=[],
            egress=[],
        ),
    )


def _quarantine_workload(
    apps_v1: client.AppsV1Api,
    networking_v1: client.NetworkingV1Api,
    owner_kind: str,
    owner_name: str,
    namespace: str,
    rule: str,
) -> None:
    try:
        if owner_kind == "Deployment":
            obj = apps_v1.read_namespaced_deployment(name=owner_name, namespace=namespace)
        elif owner_kind == "StatefulSet":
            obj = apps_v1.read_namespaced_stateful_set(name=owner_name, namespace=namespace)
        elif owner_kind == "DaemonSet":
            obj = apps_v1.read_namespaced_daemon_set(name=owner_name, namespace=namespace)
        elif owner_kind == "ReplicaSet":
            obj = apps_v1.read_namespaced_replica_set(name=owner_name, namespace=namespace)
        else:
            logger.warning("Unknown owner kind %s — cannot quarantine workload", owner_kind)
            return
    except client.ApiException as exc:
        logger.error("Could not fetch %s %s/%s for workload quarantine: status=%s", owner_kind, namespace, owner_name, exc.status)
        return

    match_labels = (obj.spec.selector.match_labels or {}) if obj.spec and obj.spec.selector else {}
    if not match_labels:
        logger.warning("%s %s/%s has no pod selector — skipping workload quarantine", owner_kind, namespace, owner_name)
        return

    policy = _build_quarantine_policy(_workload_policy_name(owner_name), namespace, match_labels)
    try:
        networking_v1.create_namespaced_network_policy(namespace=namespace, body=policy)
        logger.info("Workload quarantine NetworkPolicy applied for %s %s/%s rule=%s", owner_kind, namespace, owner_name, rule)
        _emit_quarantine_metric(owner_name, namespace, rule=rule)
    except client.ApiException as exc:
        if exc.status == 409:
            logger.info("Workload quarantine policy already exists for %s %s/%s — skipping", owner_kind, namespace, owner_name)
        else:
            raise


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
    apps_v1: client.AppsV1Api,
    pod_name: str,
    namespace: str,
    rule: str,
    ctx_owner_kind: str = "",
    ctx_owner_name: str = "",
) -> None:
    try:
        core_v1.patch_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body={"metadata": {"labels": {"quarantine": "true"}}},
        )
        logger.info("Labelled pod %s/%s with quarantine=true", namespace, pod_name)
    except client.ApiException as exc:
        if exc.status == 404:
            logger.warning("Pod %s/%s no longer exists — attempting workload quarantine instead", namespace, pod_name)
            if ctx_owner_kind and ctx_owner_name:
                _quarantine_workload(apps_v1, networking_v1, ctx_owner_kind, ctx_owner_name, namespace, rule)
            else:
                logger.error("Pod %s/%s is gone and no owner info available — quarantine skipped", namespace, pod_name)
            return
        raise

    policy = _build_quarantine_policy(_policy_name(pod_name), namespace, {"quarantine": "true"})
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
        alert_tags = alert.get("tags") or []

        if not pod_name or not namespace:
            logger.warning("Alert missing pod/namespace fields — skipping. rule=%s fields=%s", rule, output_fields)
            continue

        logger.info("Falco alert: rule=%s priority=%s pod=%s ns=%s time=%s",
                    rule, priority, pod_name, namespace, alert.get("time"))

        ca_cert_path = None
        try:
            _download_kubeconfig()
            core_v1, networking_v1, rbac_v1, apps_v1, ca_cert_path = _get_k8s_clients()
            logger.info("Kubernetes clients initialised for pod %s/%s", namespace, pod_name)

            ctx = enrich(core_v1, rbac_v1, pod_name, namespace, apps_v1=apps_v1)
            result = score(ctx, alert_rule=rule, alert_tags=alert_tags)
            _emit_triage_metric(pod_name, namespace, result.severity)

            if result.action == Action.QUARANTINE:
                _quarantine_pod(
                    core_v1, networking_v1, apps_v1, pod_name, namespace, rule,
                    ctx_owner_kind=ctx.owner_kind, ctx_owner_name=ctx.owner_name,
                )
            elif result.action == Action.ANNOTATE:
                core_v1.patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body={"metadata": {"annotations": {"triage-severity": result.severity, "triage-reason": result.reason}}},
                )
                logger.info("Annotated pod %s/%s severity=%s reason=%s", namespace, pod_name, result.severity, result.reason)
                _notify_ops(pod_name, namespace, result.severity, result.reason,
                            rule=rule, priority=priority, score=result.score)
            else:
                logger.info("Alert-only for pod %s/%s score=%d reason=%s", namespace, pod_name, result.score, result.reason)
        except Exception:
            logger.exception("Unhandled error while processing alert for pod %s/%s", namespace, pod_name)
            raise
        finally:
            if os.path.exists(KUBECONFIG_PATH):
                os.remove(KUBECONFIG_PATH)
                logger.info("Cleaned up kubeconfig from %s", KUBECONFIG_PATH)
            if ca_cert_path and os.path.exists(ca_cert_path):
                os.remove(ca_cert_path)

    return {"statusCode": 200, "body": "ok"}
