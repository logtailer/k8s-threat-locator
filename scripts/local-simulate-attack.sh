#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env.localtest}"
NAMESPACE="${1:-threat-demo}"
TIMEOUT=60

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing env file: $ENV_FILE" >&2
  echo "Run scripts/local-bootstrap.sh first." >&2
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

POD=$(kubectl get pod -n "$NAMESPACE" -l app=items-api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "$POD" ]]; then
  echo "No items-api pod found in namespace $NAMESPACE" >&2
  exit 1
fi

cat > /tmp/local-falco-alert.json <<EOF
{
  "rule": "write_to_etc",
  "priority": "ERROR",
  "tags": ["force_quarantine"],
  "output_fields": {
    "k8s.pod.name": "$POD",
    "k8s.ns.name": "$NAMESPACE",
    "proc.name": "sh",
    "proc.pname": "python",
    "proc.cmdline": "echo pwned > /etc/localtest"
  }
}
EOF

echo "==> Publishing synthetic Falco alert to LocalStack SNS"
aws \
  --endpoint-url "$AWS_ENDPOINT_URL" \
  sns publish \
  --topic-arn "$FALCO_ALERTS_TOPIC_ARN" \
  --message "$(cat /tmp/local-falco-alert.json)" >/dev/null

echo "==> Waiting up to ${TIMEOUT}s for quarantine policy"
POLICY_NAME="quarantine-$POD"
ELAPSED=0
while [[ $ELAPSED -lt $TIMEOUT ]]; do
  if kubectl get networkpolicy "$POLICY_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "Quarantine policy applied in ~${ELAPSED}s"
    kubectl get networkpolicy "$POLICY_NAME" -n "$NAMESPACE"
    kubectl get pod "$POD" -n "$NAMESPACE" --show-labels | grep quarantine || true
    rm -f /tmp/local-falco-alert.json
    exit 0
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done

rm -f /tmp/local-falco-alert.json
echo "Timeout waiting for quarantine policy. Is local responder running?"
exit 1
