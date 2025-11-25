import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

KUBECONFIG_BUCKET = os.environ.get("KUBECONFIG_BUCKET", "")
KUBECONFIG_KEY = os.environ.get("KUBECONFIG_KEY", "kubeconfig")
KUBECONFIG_PATH = "/tmp/kubeconfig"


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

        logger.info("Falco alert: rule=%s priority=%s",
                    alert.get("rule"), alert.get("priority"))

    return {"statusCode": 200, "body": "ok"}
