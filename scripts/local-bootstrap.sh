#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AWS_REGION="${AWS_REGION:-us-east-1}"
LOCALSTACK_ENDPOINT="${LOCALSTACK_ENDPOINT:-http://localhost:4566}"
KIND_CLUSTER="${KIND_CLUSTER:-ktl-local}"
NAMESPACE="${NAMESPACE:-threat-demo}"
APP_IMAGE="${APP_IMAGE:-k8s-threat-locator-app:local}"
KUBECONFIG_BUCKET="${KUBECONFIG_BUCKET:-k8s-threat-locator-local-kubeconfig}"
FALCO_TOPIC_NAME="${FALCO_TOPIC_NAME:-falco-alerts-local}"
OPS_TOPIC_NAME="${OPS_TOPIC_NAME:-k8s-threat-locator-ops-alerts-local}"
RESPONDER_QUEUE_NAME="${RESPONDER_QUEUE_NAME:-k8s-threat-locator-responder-events-local}"

for cmd in docker kind kubectl aws python3; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "Missing required command: $cmd" >&2
    exit 1
  }
done

export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="$AWS_REGION"

echo "==> Starting LocalStack"
docker compose -f "$ROOT_DIR/docker-compose.localstack.yml" up -d localstack

echo "==> Waiting for LocalStack health endpoint"
for _ in {1..30}; do
  if curl -s "$LOCALSTACK_ENDPOINT/_localstack/health" >/dev/null; then
    break
  fi
  sleep 1
done

echo "==> Ensuring kind cluster exists"
if ! kind get clusters | grep -qx "$KIND_CLUSTER"; then
  kind create cluster --name "$KIND_CLUSTER"
fi
kubectl config use-context "kind-$KIND_CLUSTER" >/dev/null

# kind nodes carry no topology labels, but the deployment's
# topologySpreadConstraints require topology.kubernetes.io/zone
# (whenUnsatisfiable: DoNotSchedule) — without it both replicas stay Pending.
# Give the single node a synthetic zone/region so the constraint is satisfied.
kubectl label nodes --all \
  topology.kubernetes.io/zone=local topology.kubernetes.io/region=local --overwrite >/dev/null

echo "==> Building app image (native arch) and loading into kind"
# Build for the host/kind arch (NOT linux/amd64 — that's for ECR/EKS) and
# disable buildx attestations. Load via a saved archive: `kind load
# docker-image` can leave the image untagged in the CRI view kubelet uses
# (buildx/OCI quirk), which surfaces as ImagePullBackOff. `docker save` +
# `kind load image-archive` preserves the tag.
docker build --provenance=false -t "$APP_IMAGE" "$ROOT_DIR/app"
IMG_TAR="$(mktemp)"
docker save "$APP_IMAGE" -o "$IMG_TAR"
kind load image-archive "$IMG_TAR" --name "$KIND_CLUSTER"
rm -f "$IMG_TAR"

echo "==> Applying Kubernetes manifests"
kubectl apply -f "$ROOT_DIR/k8s/namespace.yaml"
kubectl apply -f "$ROOT_DIR/k8s/resourcequota.yaml"
kubectl apply -f "$ROOT_DIR/k8s/limitrange.yaml"

# Strip the AWS-only IRSA annotation for local clusters.
sed '/eks.amazonaws.com\/role-arn/d' "$ROOT_DIR/k8s/serviceaccount.yaml" | kubectl apply -f -

# The baseline network policies are Calico CRDs (crd.projectcalico.org/v1).
# A stock kind cluster runs kindnet and has no Calico CRDs, so applying them
# would fail and abort this script. Apply only when Calico is present; a
# kindnet cluster does not enforce NetworkPolicies anyway, so the local stack
# validates the detect -> quarantine CONTROL FLOW, not network enforcement.
# (Install Calico on kind if you need real enforcement locally.)
if kubectl get crd networkpolicies.crd.projectcalico.org >/dev/null 2>&1; then
  kubectl apply -f "$ROOT_DIR/k8s/network-policies/allow-dns.yaml"
  kubectl apply -f "$ROOT_DIR/k8s/network-policies/allow-ingress-app.yaml"
  kubectl apply -f "$ROOT_DIR/k8s/network-policies/allow-egress-app.yaml"
  kubectl apply -f "$ROOT_DIR/k8s/network-policies/default-deny.yaml"
else
  echo "==> Skipping Calico baseline network policies (no Calico CRDs on this cluster)"
fi

sed \
  -e "s|<ECR_REPO_URL>/k8s-threat-locator:<IMAGE_TAG>|$APP_IMAGE|g" \
  -e "s|imagePullPolicy: Always|imagePullPolicy: IfNotPresent|g" \
  "$ROOT_DIR/k8s/deployment.yaml" | kubectl apply -f -

kubectl apply -f "$ROOT_DIR/k8s/service.yaml"
kubectl apply -f "$ROOT_DIR/k8s/pdb.yaml"
kubectl apply -f "$ROOT_DIR/k8s/lambda-rbac.yaml"
# 240s (not 120s): the cold local path (image build+load, two replicas each
# with a startupProbe of up to ~50s) can exceed 120s even when the pods are
# healthy and climbing — 120s was expiring at "1 of 2 available".
kubectl rollout status deployment/items-api -n "$NAMESPACE" --timeout=240s

echo "==> Creating LocalStack resources (S3/SNS/SQS/CloudWatch)"
if [[ "$AWS_REGION" == "us-east-1" ]]; then
  aws --endpoint-url "$LOCALSTACK_ENDPOINT" s3api create-bucket --bucket "$KUBECONFIG_BUCKET" >/dev/null 2>&1 || true
else
  aws --endpoint-url "$LOCALSTACK_ENDPOINT" s3api create-bucket \
    --bucket "$KUBECONFIG_BUCKET" \
    --create-bucket-configuration "LocationConstraint=$AWS_REGION" >/dev/null 2>&1 || true
fi

FALCO_ALERTS_TOPIC_ARN="$(aws --endpoint-url "$LOCALSTACK_ENDPOINT" sns create-topic --name "$FALCO_TOPIC_NAME" --query TopicArn --output text)"
OPS_ALERTS_TOPIC_ARN="$(aws --endpoint-url "$LOCALSTACK_ENDPOINT" sns create-topic --name "$OPS_TOPIC_NAME" --query TopicArn --output text)"
RESPONDER_QUEUE_URL="$(aws --endpoint-url "$LOCALSTACK_ENDPOINT" sqs create-queue --queue-name "$RESPONDER_QUEUE_NAME" --query QueueUrl --output text)"
RESPONDER_QUEUE_ARN="$(aws --endpoint-url "$LOCALSTACK_ENDPOINT" sqs get-queue-attributes --queue-url "$RESPONDER_QUEUE_URL" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)"

aws --endpoint-url "$LOCALSTACK_ENDPOINT" sns subscribe \
  --topic-arn "$FALCO_ALERTS_TOPIC_ARN" \
  --protocol sqs \
  --notification-endpoint "$RESPONDER_QUEUE_ARN" >/dev/null

QUEUE_POLICY=$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSnsToSend",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "$RESPONDER_QUEUE_ARN",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "$FALCO_ALERTS_TOPIC_ARN"
        }
      }
    }
  ]
}
JSON
)
aws --endpoint-url "$LOCALSTACK_ENDPOINT" sqs set-queue-attributes \
  --queue-url "$RESPONDER_QUEUE_URL" \
  --attributes "Policy=$QUEUE_POLICY" >/dev/null

TMP_KUBECONFIG="$(mktemp)"
kind get kubeconfig --name "$KIND_CLUSTER" > "$TMP_KUBECONFIG"
aws --endpoint-url "$LOCALSTACK_ENDPOINT" s3 cp "$TMP_KUBECONFIG" "s3://$KUBECONFIG_BUCKET/kubeconfig" >/dev/null
rm -f "$TMP_KUBECONFIG"

cat > "$ROOT_DIR/.env.localtest" <<EOF
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
AWS_DEFAULT_REGION=$AWS_REGION
AWS_ENDPOINT_URL=$LOCALSTACK_ENDPOINT
KUBECONFIG_BUCKET=$KUBECONFIG_BUCKET
KUBECONFIG_KEY=kubeconfig
K8S_AUTH_MODE=kubeconfig
FALCO_ALERTS_TOPIC_ARN=$FALCO_ALERTS_TOPIC_ARN
OPS_ALERTS_TOPIC_ARN=$OPS_ALERTS_TOPIC_ARN
RESPONDER_QUEUE_URL=$RESPONDER_QUEUE_URL
EOF

echo ""
echo "Local stack is ready."
echo "Environment file: $ROOT_DIR/.env.localtest"
echo "Next steps:"
echo "  1) make local-responder"
echo "  2) make local-simulate-attack"
