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
python3 --version                    # >= 3.11 (Lambda runtime)
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

docker build -t k8s-threat-locator:latest .
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

### 5a. Create SNS topic for Falcosidekick → Lambda

```bash
SNS_TOPIC_ARN=$(aws sns create-topic \
  --name k8s-threat-locator-falco \
  --region "$AWS_REGION" \
  --query TopicArn --output text)

echo "SNS_TOPIC_ARN=$SNS_TOPIC_ARN"
```

### 5b. Grant Falcosidekick permission to publish

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

### 6a. Create S3 bucket for kubeconfig

```bash
KUBECONFIG_BUCKET="k8s-threat-locator-kubeconfig-$AWS_ACCOUNT_ID"
aws s3 mb "s3://$KUBECONFIG_BUCKET" --region "$AWS_REGION"

# Block public access
aws s3api put-public-access-block \
  --bucket "$KUBECONFIG_BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### 6b. Upload kubeconfig

The kubeconfig must use the private EKS endpoint. Verify the `server:` field points to the cluster endpoint returned by Terraform.

```bash
aws s3 cp ~/.kube/config "s3://$KUBECONFIG_BUCKET/kubeconfig"

# Confirm the server endpoint in the uploaded kubeconfig
aws s3 cp "s3://$KUBECONFIG_BUCKET/kubeconfig" - | grep server:
# expect: https://<cluster-id>.gr7.us-east-1.eks.amazonaws.com
```

### 6c. Grant Lambda access to the EKS cluster

Lambda uses the kubeconfig to call the Kubernetes API. The Lambda IAM role must be added to the EKS `aws-auth` ConfigMap:

```bash
LAMBDA_ROLE_ARN="arn:aws:iam::$AWS_ACCOUNT_ID:role/k8s-threat-locator-lambda-role"

# Edit the aws-auth ConfigMap
kubectl edit configmap aws-auth -n kube-system
```

Add under `mapRoles:`:

```yaml
- rolearn: arn:aws:iam::<ACCOUNT_ID>:role/k8s-threat-locator-lambda-role
  username: lambda-quarantine
  groups:
    - k8s-threat-locator-responders
```

Then create the RBAC ClusterRole + ClusterRoleBinding:

```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k8s-threat-locator-responder
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "patch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "create"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["rolebindings", "clusterrolebindings"]
  verbs: ["list"]
- apiGroups: [""]
  resources: ["services", "namespaces"]
  verbs: ["list", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: k8s-threat-locator-responder
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-threat-locator-responder
subjects:
- kind: User
  name: lambda-quarantine
  apiGroup: rbac.authorization.k8s.io
EOF
```

### 6d. Deploy Lambda

```bash
cd lambda

sam build --template template.yaml

sam deploy \
  --stack-name k8s-threat-locator-lambda \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$AWS_REGION" \
  --parameter-overrides \
    SnsTopicArn="$SNS_TOPIC_ARN" \
    KubeconfigBucket="$KUBECONFIG_BUCKET"
```

**Verify:**

```bash
aws lambda get-function \
  --function-name k8s-threat-locator-responder \
  --region "$AWS_REGION" \
  --query 'Configuration.State'
# expect: "Active"

# Confirm SNS subscription exists
aws sns list-subscriptions-by-topic \
  --topic-arn "$SNS_TOPIC_ARN" \
  --region "$AWS_REGION"
# expect: Protocol "lambda", Endpoint is the Lambda ARN
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
- Check `aws-auth` ConfigMap has the Lambda role: `kubectl get configmap aws-auth -n kube-system -o yaml`
- Check RBAC: `kubectl auth can-i patch pods --as=lambda-quarantine -n threat-demo`

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
# Remove Lambda stack
sam delete --stack-name k8s-threat-locator-lambda --region "$AWS_REGION"

# Remove Falco
helm uninstall falco -n falco

# Remove Kubernetes resources
kubectl delete namespace threat-demo
kubectl delete namespace falco

# Remove SNS topic
aws sns delete-topic --topic-arn "$SNS_TOPIC_ARN" --region "$AWS_REGION"

# Remove kubeconfig bucket
aws s3 rm "s3://$KUBECONFIG_BUCKET" --recursive
aws s3 rb "s3://$KUBECONFIG_BUCKET"

# Destroy Terraform infrastructure (~10 min)
cd terraform
terraform destroy
```

> EKS control plane + NAT Gateway cost ~$5–10/day. Run `terraform destroy` when done.
