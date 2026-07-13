#!/usr/bin/env bash
# bootstrap.sh — one-shot post-terraform setup for k8s-threat-locator
#
# Run after `terraform apply` to wire up every component:
#   kubeconfig upload, EKS access entry, k8s manifests, Falco helm install.
#
# Usage:
#   ./scripts/bootstrap.sh [--image-tag <tag>] [--region <region>] [--namespace <ns>]
#
# Flags:
#   --image-tag   ECR image tag to deploy (default: latest)
#   --region      AWS region (default: us-east-1)
#   --namespace   App namespace (default: threat-demo)
#   --skip-falco  Skip Falco helm install (useful when re-running manifests only)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Defaults
IMAGE_TAG="latest"
AWS_REGION="us-east-1"
NAMESPACE="threat-demo"
SKIP_FALCO=false
FALCO_CHART_VERSION="4.3.0"

# Parse flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image-tag)  IMAGE_TAG="$2";  shift 2 ;;
    --region)     AWS_REGION="$2"; shift 2 ;;
    --namespace)  NAMESPACE="$2";  shift 2 ;;
    --skip-falco) SKIP_FALCO=true; shift   ;;
    *) echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
done

# ── Colours ─────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}==>${NC} ${BOLD}$*${NC}"; }
warn() { echo -e "${YELLOW}WARN:${NC} $*"; }
die()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
step() { echo -e "\n${BOLD}[$1]${NC} $2"; }

# ── 0. Prerequisites ─────────────────────────────────────────────────────────
step "0/7" "Checking prerequisites"
for cmd in aws terraform kubectl helm; do
  command -v "$cmd" &>/dev/null || die "Required tool not found: $cmd — install it and re-run"
done
aws sts get-caller-identity --query Account --output text &>/dev/null \
  || die "AWS credentials not configured — run 'aws configure' or set AWS_PROFILE"
log "Prerequisites OK"

# ── 1. Terraform outputs ─────────────────────────────────────────────────────
step "1/7" "Reading Terraform outputs"
cd "$ROOT_DIR/terraform"

_tf() { terraform output -raw "$1" 2>/dev/null || die "terraform output '$1' failed — did you run terraform apply?"; }

CLUSTER_NAME=$(_tf cluster_name)
ECR_URL=$(_tf ecr_repository_url)
IRSA_ROLE_ARN=$(_tf irsa_role_arn)
KUBECONFIG_BUCKET=$(_tf kubeconfig_bucket_name)
KUBECONFIG_KMS_KEY_ARN=$(_tf kubeconfig_kms_key_arn)
FALCOSIDEKICK_ROLE_ARN=$(_tf falcosidekick_role_arn)
FALCO_ALERTS_TOPIC_ARN=$(_tf falco_alerts_topic_arn)
LAMBDA_ROLE_ARN=$(_tf lambda_role_arn)
NODE_ROLE_ARN=$(_tf node_group_role_arn)
NODE_ROLE_NAME="${NODE_ROLE_ARN##*/}"

cd "$ROOT_DIR"

log "Cluster : $CLUSTER_NAME"
log "ECR     : $ECR_URL:$IMAGE_TAG"
log "Region  : $AWS_REGION"
log "NS      : $NAMESPACE"

# ── 2. kubeconfig ────────────────────────────────────────────────────────────
step "2/7" "kubeconfig"
log "Updating local kubeconfig..."
aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION"

log "Verifying cluster nodes are Ready..."
READY=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready" || true)
[[ "$READY" -gt 0 ]] || die "No nodes in Ready state — check cluster health before continuing"
log "$READY node(s) Ready"

log "Uploading kubeconfig to S3 (SSE-KMS)..."
aws s3 cp ~/.kube/config "s3://$KUBECONFIG_BUCKET/kubeconfig" \
  --sse aws:kms \
  --sse-kms-key-id "$KUBECONFIG_KMS_KEY_ARN" \
  --region "$AWS_REGION"
log "Kubeconfig uploaded to s3://$KUBECONFIG_BUCKET/kubeconfig"

# ── 3. EKS Access Entry for Lambda ──────────────────────────────────────────
step "3/7" "EKS Access Entry"
if aws eks describe-access-entry \
    --cluster-name "$CLUSTER_NAME" \
    --principal-arn "$LAMBDA_ROLE_ARN" \
    --region "$AWS_REGION" &>/dev/null; then
  warn "Access entry for Lambda role already exists — skipping"
else
  aws eks create-access-entry \
    --cluster-name "$CLUSTER_NAME" \
    --principal-arn "$LAMBDA_ROLE_ARN" \
    --kubernetes-groups k8s-threat-locator-responders \
    --region "$AWS_REGION"
  log "Access entry created for Lambda role"
fi

# ── 4. Kubernetes manifests ──────────────────────────────────────────────────
step "4/7" "Kubernetes manifests"

log "Applying namespace and quotas..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/resourcequota.yaml
kubectl apply -f k8s/limitrange.yaml

log "Applying ServiceAccount..."
kubectl apply -f k8s/serviceaccount.yaml
kubectl annotate serviceaccount app-sa \
  -n "$NAMESPACE" \
  "eks.amazonaws.com/role-arn=$IRSA_ROLE_ARN" \
  --overwrite

log "Applying network policies (allow rules first, then default-deny)..."
kubectl apply -f k8s/network-policies/allow-dns.yaml
kubectl apply -f k8s/network-policies/allow-ingress-app.yaml
kubectl apply -f k8s/network-policies/allow-egress-app.yaml
kubectl apply -f k8s/network-policies/default-deny.yaml

log "Applying deployment with image $ECR_URL:$IMAGE_TAG..."
# deployment.yaml uses <ECR_REPO_URL>/k8s-threat-locator:<IMAGE_TAG> as a placeholder;
# substitute at apply time so the source file stays clean in git.
sed "s|<ECR_REPO_URL>/k8s-threat-locator:<IMAGE_TAG>|$ECR_URL:$IMAGE_TAG|g" \
  k8s/deployment.yaml | kubectl apply -f -

kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/pdb.yaml
kubectl apply -f k8s/lambda-rbac.yaml

log "Waiting for deployment rollout (up to 2 min)..."
kubectl rollout status deployment/items-api -n "$NAMESPACE" --timeout=120s

# ── 5. Falcosidekick SNS IAM ─────────────────────────────────────────────────
step "5/7" "Falcosidekick SNS IAM"
if aws iam get-role-policy \
    --role-name "$NODE_ROLE_NAME" \
    --policy-name FalcosidekickSNSPublish \
    &>/dev/null; then
  warn "FalcosidekickSNSPublish policy already on node role — skipping"
else
  aws iam put-role-policy \
    --role-name "$NODE_ROLE_NAME" \
    --policy-name FalcosidekickSNSPublish \
    --policy-document "{
      \"Version\": \"2012-10-17\",
      \"Statement\": [{
        \"Effect\": \"Allow\",
        \"Action\": \"sns:Publish\",
        \"Resource\": \"$FALCO_ALERTS_TOPIC_ARN\"
      }]
    }"
  log "SNS publish policy attached to node role $NODE_ROLE_NAME"
fi

# ── 6. Falco ─────────────────────────────────────────────────────────────────
step "6/7" "Falco"
if [[ "$SKIP_FALCO" == "true" ]]; then
  warn "--skip-falco set — skipping Helm install"
else
  log "Adding falcosecurity Helm repo..."
  helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update >/dev/null
  helm repo update falcosecurity >/dev/null

  log "Installing Falco $FALCO_CHART_VERSION (helm upgrade --install)..."
  helm upgrade --install falco falcosecurity/falco \
    --namespace falco --create-namespace \
    --version "$FALCO_CHART_VERSION" \
    -f falco/values.yaml \
    --set "falcosidekick.config.aws.rolearn=$FALCOSIDEKICK_ROLE_ARN" \
    --set "falcosidekick.config.aws.sns.topicarn=$FALCO_ALERTS_TOPIC_ARN" \
    --wait --timeout 3m

  log "Falco installed. Verifying pods..."
  kubectl get pods -n falco
fi

# ── 7. Smoke test ────────────────────────────────────────────────────────────
step "7/7" "Smoke test"
POD=$(kubectl get pod -n "$NAMESPACE" -l app=items-api \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "$POD" ]]; then
  warn "No items-api pod found — skipping smoke test"
else
  log "Testing /health on pod $POD..."
  HEALTH=$(kubectl exec -n "$NAMESPACE" "$POD" -- curl -s localhost:5000/health 2>/dev/null || true)
  if echo "$HEALTH" | grep -q '"ok"'; then
    log "Health check passed: $HEALTH"
  else
    warn "Unexpected health response: ${HEALTH:-<empty>}"
  fi

  log "Verifying IRSA (should show IRSA role, not node role)..."
  kubectl exec -n "$NAMESPACE" "$POD" -- \
    aws sts get-caller-identity --region "$AWS_REGION" 2>/dev/null \
    | grep -o '"Arn": "[^"]*"' || warn "IRSA check failed — ServiceAccount annotation may not have propagated yet"
fi

echo ""
echo -e "${GREEN}${BOLD}Bootstrap complete.${NC}"
echo ""
echo "  Run the attack simulation:  make simulate-attack"
echo "  Tail Lambda logs:           aws logs tail /aws/lambda/k8s-threat-locator-responder --follow"
echo "  Reset after simulation:     see RUNBOOK.md § Step 7"
echo ""
