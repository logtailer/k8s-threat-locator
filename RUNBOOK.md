# Deployment & Test Runbook

End-to-end guide for provisioning the sandbox cluster, deploying every component, and running the full attack simulation.

---

## Prerequisites

```bash
aws sts get-caller-identity          # confirms AWS CLI is auth'd
terraform version                    # >= 1.6
kubectl version --client             # match your target EKS version
helm version                         # >= 3.x
docker info                          # daemon running
sam --version                        # AWS SAM CLI
python3 --version                    # >= 3.13 (Lambda runtime)
```

You need AWS permissions for: EKS, VPC, IAM, ECR, SNS, Lambda, CloudWatch, S3, SQS.

---

## Step 1 — Terraform: provision infrastructure

```bash
cd terraform

# One-time: create S3 bucket + DynamoDB table for remote state
aws s3 mb s3://k8s-threat-locator-tfstate --region us-east-1
aws dynamodb create-table \
  --table-name k8s-threat-locator-tflock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1

terraform init
terraform plan   # review before applying
terraform apply  # ~20 min
```

**Capture outputs** — you'll need these throughout:

```bash
terraform output          # print all
export CLUSTER_NAME=$(terraform output -raw cluster_name)
export ECR_URL=$(terraform output -raw ecr_repository_url)
export IRSA_ROLE_ARN=$(terraform output -raw irsa_role_arn)
export KUBECONFIG_BUCKET=$(terraform output -raw kubeconfig_bucket_name)
export KUBECONFIG_KMS_KEY_ARN=$(terraform output -raw kubeconfig_kms_key_arn)
export FALCOSIDEKICK_ROLE_ARN=$(terraform output -raw falcosidekick_role_arn)
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

**Verify:**

```bash
aws eks describe-cluster --name "$CLUSTER_NAME" --query 'cluster.status'
# expect: "ACTIVE"
```

---

## Step 2 — kubeconfig

```bash
aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION"
kubectl get nodes    # should show 2 nodes in Ready state
```

---

## Step 3 — Push Docker image to ECR

> CI is intentionally blocked by Trivy (Flask==1.0.0 CVEs). Push manually.

```bash
cd ../app

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ECR_URL"

docker build --platform linux/amd64 -t k8s-threat-locator:latest .
docker tag k8s-threat-locator:latest "$ECR_URL:latest"
docker push "$ECR_URL:latest"
```

**Verify:**

```bash
aws ecr list-images --repository-name k8s-threat-locator --region "$AWS_REGION"
# expect: imageTag "latest" in the list
```

---

## Step 4 — Kubernetes manifests

Apply in this order — allow rules must exist before the default-deny catches up.

```bash
cd ..

kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/resourcequota.yaml
kubectl apply -f k8s/serviceaccount.yaml

# Annotate the ServiceAccount with the IRSA role
kubectl annotate serviceaccount app-sa \
  -n threat-demo \
  eks.amazonaws.com/role-arn="$IRSA_ROLE_ARN" \
  --overwrite

# Network policies — allow rules first
kubectl apply -f k8s/network-policies/allow-dns.yaml
kubectl apply -f k8s/network-policies/allow-ingress-app.yaml
kubectl apply -f k8s/network-policies/allow-egress-app.yaml
kubectl apply -f k8s/network-policies/default-deny.yaml

# Update deployment to use the real ECR image, then apply
# Replace the image field in k8s/deployment.yaml with $ECR_URL:latest
sed -i.bak "s|image:.*|image: $ECR_URL:latest|" k8s/deployment.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

**Verify:**

```bash
kubectl get pods -n threat-demo          # STATUS: Running
kubectl get svc -n threat-demo           # service visible
kubectl get networkpolicy -n threat-demo # 3 allow policies + default-deny
```

**Smoke test the app:**

```bash
POD=$(kubectl get pod -n threat-demo -l app=items-api \
  -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n threat-demo "$POD" -- curl -s localhost:5000/health
# expect: {"status": "ok"}
```

**Verify IRSA:**

```bash
kubectl exec -n threat-demo "$POD" -- \
  aws sts get-caller-identity --region "$AWS_REGION"
# expect: Arn contains the IRSA role, not the node instance role
```

**Verify Calico blocks external traffic:**

```bash
kubectl exec -n threat-demo "$POD" -- \
  curl -m 5 https://example.com || echo "BLOCKED — Calico working"
```

---

## Step 5 — Falco

> **Note:** The `falco-alerts` SNS topic is created by Terraform (`module.lambda`) in Step 1 — it already exists by the time you reach this step. Steps 5b–5d use `$SNS_TOPIC_ARN` captured from `terraform output` (see Step 6c).

### 5a. Grant Falcosidekick permission to publish

Falcosidekick runs as a pod, so it needs an IAM policy. The simplest approach for a sandbox is to attach a policy to the node group role:

```bash
NODE_ROLE_ARN=$(cd terraform && terraform output -raw node_group_role_arn)
NODE_ROLE_NAME=$(echo "$NODE_ROLE_ARN" | cut -d'/' -f2)

aws iam put-role-policy \
  --role-name "$NODE_ROLE_NAME" \
  --policy-name FalcosidekickSNSPublish \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Action\": \"sns:Publish\",
      \"Resource\": \"$SNS_TOPIC_ARN\"
    }]
  }"
```

### 5c. Set the topic ARN in values.yaml

```bash
# Edit falco/values.yaml — replace the empty topicarn value
sed -i.bak "s|topicarn: \"\"|topicarn: \"$SNS_TOPIC_ARN\"|" falco/values.yaml
# Also set the correct region if not us-east-1
```

### 5d. Install Falco

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --version 4.3.0 \
  -f falco/values.yaml \
  --set-file falco.rules_file[0]=falco/rules/custom-rules.yaml
```

**Verify:**

```bash
kubectl get pods -n falco
# expect: falco-xxxxx Running (one per node), falco-falcosidekick-xxxxx Running (x2)

# Tail Falco logs on one node
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20

# Tail Falcosidekick logs
kubectl logs -n falco -l app=falco-falcosidekick --tail=20
```

**Quick rule test** — should fire the `shell_in_container` rule:

```bash
kubectl exec -n threat-demo "$POD" -- sh -c "echo test"
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=5 | grep shell_in_container
```

---

## Step 6 — Lambda triage responder

Lambda, the SNS topics, DLQ, IAM role, and CloudWatch alarms are all deployed by Terraform (`module.lambda`). The Terraform apply in Step 1 already provisioned them. The `null_resource` inside the module built the Linux/amd64 package via Docker and uploaded it to S3 automatically.

> The responder is capped at 10 concurrent executions (`reserved_concurrent_executions`) so an alert wave can't overwhelm the Kubernetes API with simultaneous quarantine writes. Tune with the root variable `lambda_reserved_concurrency`.

### 6a. Upload kubeconfig

The kubeconfig bucket (`$KUBECONFIG_BUCKET`) was created by Terraform. Upload the kubeconfig with SSE-KMS:

```bash
aws s3 cp ~/.kube/config "s3://$KUBECONFIG_BUCKET/kubeconfig" \
  --sse aws:kms \
  --sse-kms-key-id "$KUBECONFIG_KMS_KEY_ARN"

# Confirm the server endpoint in the uploaded kubeconfig
aws s3 cp "s3://$KUBECONFIG_BUCKET/kubeconfig" - | grep server:
# expect: https://<cluster-id>.gr7.us-east-1.eks.amazonaws.com
```

### 6b. Grant Lambda access to the EKS cluster

The cluster uses `authentication_mode = "API"` — `aws-auth` ConfigMap is disabled. Use the EKS Access Entries API:

```bash
export LAMBDA_ROLE_ARN=$(terraform -chdir=terraform output -raw lambda_role_arn)

aws eks create-access-entry \
  --cluster-name "$CLUSTER_NAME" \
  --principal-arn "$LAMBDA_ROLE_ARN" \
  --kubernetes-groups k8s-threat-locator-responders \
  --region "$AWS_REGION"

# Verify
aws eks describe-access-entry \
  --cluster-name "$CLUSTER_NAME" \
  --principal-arn "$LAMBDA_ROLE_ARN" \
  --region "$AWS_REGION" \
  --query 'accessEntry.kubernetesGroups'
# expect: ["k8s-threat-locator-responders"]
```

Apply the RBAC ClusterRole + ClusterRoleBinding:

```bash
kubectl apply -f k8s/lambda-rbac.yaml
kubectl auth can-i patch pods --as-group=k8s-threat-locator-responders -n threat-demo
```

### 6c. Capture SNS topic ARN for Falco

```bash
export SNS_TOPIC_ARN=$(terraform -chdir=terraform output -raw falco_alerts_topic_arn)
echo "SNS_TOPIC_ARN=$SNS_TOPIC_ARN"
```

### 6d. Subscribe to ops alerts

The responder pages a human on **every quarantine and annotate** via the
`k8s-threat-locator-ops-alerts` topic. Subscribe an endpoint so those
notifications reach someone (without a subscriber they are silently dropped):

```bash
export OPS_ALERTS_TOPIC_ARN=$(terraform -chdir=terraform output -raw ops_alerts_topic_arn)

# Email (confirm via the link AWS emails you), or wire to PagerDuty/Slack.
aws sns subscribe \
  --topic-arn "$OPS_ALERTS_TOPIC_ARN" \
  --protocol email \
  --notification-endpoint you@example.com \
  --region "$AWS_REGION"
```

**Verify Lambda:**

```bash
aws lambda get-function \
  --function-name k8s-threat-locator-responder \
  --region "$AWS_REGION" \
  --query 'Configuration.State'
# expect: "Active"
```

---

## Step 7 — Full attack simulation

Everything is wired up. Run the simulation:

```bash
cd ..
./scripts/simulate-attack.sh threat-demo
```

**Expected output:**

```
==> Finding items-api pod in namespace 'threat-demo'...
==> Target pod: items-api-xxxx-yyyy
==> Triggering write_to_etc Falco rule (ERROR priority)...
==> Waiting up to 60s for quarantine NetworkPolicy to appear...
..........
✓ Quarantine applied in ~12s

NAME                          POD-SELECTOR
quarantine-items-api-xxxx-yyyy   quarantine=true

==> Verifying pod is labelled...
items-api-xxxx-yyyy   app=items-api,quarantine=true
```

**Manual verification steps after simulation:**

```bash
# 1. Quarantine NetworkPolicy exists
kubectl get networkpolicy -n threat-demo

# 2. Pod is labelled
kubectl get pod -n threat-demo --show-labels | grep quarantine

# 3. Lambda logs show the triage score
aws logs tail /aws/lambda/k8s-threat-locator-responder \
  --since 5m --region "$AWS_REGION"
# look for: "score=X severity=Y action=quarantine"

# 4. CloudWatch metric was emitted
aws cloudwatch get-metric-statistics \
  --namespace k8s-threat-locator \
  --metric-name QuarantineApplied \
  --start-time $(date -u -v-5M +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 300 \
  --statistics Sum \
  --region "$AWS_REGION"
# expect: Sum >= 1
```

**Reset after simulation:**

```bash
POD=$(kubectl get pod -n threat-demo -l app=items-api \
  -o jsonpath='{.items[0].metadata.name}')

kubectl label pod "$POD" -n threat-demo quarantine-
kubectl delete networkpolicy "quarantine-$POD" -n threat-demo
```

---

## Troubleshooting

**Pod stuck in Pending**
- Check resource quota: `kubectl describe resourcequota -n threat-demo`
- Check node capacity: `kubectl describe nodes | grep -A5 Allocated`

**Falco not firing**
- Confirm Falco DaemonSet is running on the node the pod is on: `kubectl get pods -n falco -o wide`
- Check kernel module loaded: `kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "kernel module"`
- If on Bottlerocket or custom AMI nodes, switch to eBPF: set `driver.kind: ebpf` in `falco/values.yaml` and `helm upgrade`

**Falcosidekick not reaching SNS**
- `kubectl logs -n falco -l app=falco-falcosidekick` — look for SNS publish errors
- Verify node IAM role has `sns:Publish` on the topic ARN
- Confirm `topicarn` in `falco/values.yaml` is set correctly

**Lambda not quarantining**
- `aws logs tail /aws/lambda/k8s-threat-locator-responder --since 10m`
- Check Lambda can reach the EKS API: Lambda must be in the same VPC or the cluster must have a public endpoint
- Check the EKS Access Entry exists: `aws eks describe-access-entry --cluster-name "$CLUSTER_NAME" --principal-arn "$LAMBDA_ROLE_ARN" --region "$AWS_REGION"`
- Check RBAC: `kubectl auth can-i patch pods --as-group=k8s-threat-locator-responders -n threat-demo`

**DLQ has messages**
- A message in the DLQ means Lambda errored after retries
- `aws sqs receive-message --queue-url <dlq-url> --region "$AWS_REGION"` to inspect the failed payload
- Fix the root cause (usually kubeconfig or RBAC), then reprocess: delete the message and re-trigger the simulation

**Lambda can't reach EKS API**
- The cluster uses a private endpoint — Lambda must be in the VPC
- Add `VpcConfig` to the SAM template pointing to the private subnets and a security group that allows egress to port 443
- Or enable the public endpoint temporarily for testing: `aws eks update-cluster-config --name "$CLUSTER_NAME" --resources-vpc-config endpointPublicAccess=true`

---

## Teardown

```bash
# Remove Falco
helm uninstall falco -n falco

# Remove Kubernetes resources
kubectl delete namespace threat-demo
kubectl delete namespace falco

# Remove SNS topics — handled by CloudFormation stack deletion above

# Remove kubeconfig file (bucket and KMS key are Terraform-managed — terraform destroy handles them)
aws s3 rm "s3://$KUBECONFIG_BUCKET/kubeconfig"

# Destroy Terraform infrastructure (~10 min)
cd terraform
terraform destroy
```

> EKS control plane + NAT Gateway cost ~$5–10/day. Run `terraform destroy` when done.
