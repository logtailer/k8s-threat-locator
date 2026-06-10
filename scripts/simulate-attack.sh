#!/usr/bin/env bash
# simulate-attack.sh — trigger the full Falco → SNS → Lambda → quarantine pipeline
# Usage: ./scripts/simulate-attack.sh [namespace]

set -euo pipefail

NAMESPACE="${1:-threat-demo}"
TIMEOUT=60

echo "==> Finding items-api pod in namespace '${NAMESPACE}'..."
POD=$(kubectl get pod -n "${NAMESPACE}" -l app=items-api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${POD}" ]]; then
  echo "ERROR: No items-api pod found in namespace '${NAMESPACE}'. Is the deployment running?"
  exit 1
fi

echo "==> Target pod: ${POD}"
echo "==> Triggering write_to_etc Falco rule (ERROR priority)..."
kubectl exec -n "${NAMESPACE}" "${POD}" -- sh -c "echo pwned > /etc/simulate-attack-$(date +%s)" 2>/dev/null || true

echo "==> Waiting up to ${TIMEOUT}s for quarantine NetworkPolicy to appear..."
POLICY_NAME="quarantine-${POD}"
ELAPSED=0
while [[ ${ELAPSED} -lt ${TIMEOUT} ]]; do
  if kubectl get networkpolicy "${POLICY_NAME}" -n "${NAMESPACE}" &>/dev/null; then
    echo ""
    echo "✓ Quarantine applied in ~${ELAPSED}s"
    echo ""
    kubectl get networkpolicy "${POLICY_NAME}" -n "${NAMESPACE}"
    echo ""
    echo "==> Verifying pod is labelled..."
    kubectl get pod "${POD}" -n "${NAMESPACE}" --show-labels | grep quarantine || true
    echo ""
    echo "==> Triage annotations (if annotate action was taken):"
    kubectl get pod "${POD}" -n "${NAMESPACE}" -o jsonpath='{.metadata.annotations}' 2>/dev/null | python3 -m json.tool 2>/dev/null || true
    echo ""
    echo "==> Cleanup: remove quarantine label and NetworkPolicy"
    echo "    kubectl label pod ${POD} -n ${NAMESPACE} quarantine-"
    echo "    kubectl delete networkpolicy ${POLICY_NAME} -n ${NAMESPACE}"
    exit 0
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
  printf "."
done

echo ""
echo "TIMEOUT: quarantine NetworkPolicy did not appear within ${TIMEOUT}s."
echo "Check CloudWatch Logs at /aws/lambda/k8s-threat-locator-responder"
exit 1
