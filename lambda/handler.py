import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)


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
