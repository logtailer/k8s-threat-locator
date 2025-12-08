# k8s-threat-locator

A security-focused Kubernetes project demonstrating layered cloud-native security controls:

- **Shift-left security** — CI pipeline with Trivy image scanning that fails on critical CVEs
- **Network segmentation** — Calico default-deny network policies with explicit allow rules
- **Pod identity** — AWS IRSA for least-privilege IAM access from Kubernetes pods
- **Runtime threat detection** — Falco DaemonSet watching for malicious activity in containers
- **Automated incident response** — Lambda function that quarantines compromised pods via Kubernetes NetworkPolicy

## Architecture

```
Developer → GitHub → CI (Trivy scans image → fails on critical CVEs)
                              ↓ (if CVEs fixed, would push to)
                             ECR → EKS Cluster
                                    ├── Calico (default-deny network policies)
                                    ├── Flask app (victim/test app, runs as root)
                                    └── Falco (threat detection DaemonSet)
                                           ↓ (alert on shell exec into pod)
                                          SNS → Lambda
                                                   ↓
                                        Quarantine NetworkPolicy applied to pod
```

## Components

| Component | Purpose |
|-----------|---------|
| `app/` | Python Flask API — intentionally vulnerable test subject |
| `terraform/` | AWS EKS cluster, VPC, ECR, and IRSA provisioning |
| `k8s/` | Kubernetes manifests and Calico network policies |
| `falco/` | Falco Helm values and custom detection rules |
| `lambda/` | Python Lambda for automated pod quarantine |
| `.github/workflows/` | CI pipeline with Trivy vulnerability gate |

## Runtime Threat Detection (Falco)

Falco runs as a DaemonSet on every worker node and streams kernel syscall events to detect malicious activity inside running containers.

### Installation

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

kubectl create namespace falco

helm install falco falcosecurity/falco \
  --namespace falco \
  --version 4.3.0 \
  -f falco/values.yaml \
  --set-file falco.rules_file[0]=falco/rules/custom-rules.yaml
```

### Custom Rules

| Rule | Trigger | Priority |
|------|---------|---------|
| `shell_in_container` | Shell binary spawned in container (e.g. `kubectl exec ... -- sh`) | WARNING |
| `write_to_etc` | Any file opened for write under `/etc/` inside a container | ERROR |
| `unexpected_outbound_connection` | Outbound connection from `items-api` on port other than 443/53/5000 | WARNING |

### Testing Rules

```bash
# trigger shell_in_container
kubectl exec -it -n threat-demo deploy/items-api -- /bin/sh

# trigger write_to_etc
kubectl exec -n threat-demo deploy/items-api -- sh -c "echo test > /etc/pwned"
```

Falco logs are JSON-formatted and forwarded to SNS via Falcosidekick when `falcosidekick.config.aws.sns.topicarn` is set.

> **Note:** Falco requires privileged access to the host kernel. The DaemonSet pods run with elevated permissions by design. The `falco` namespace should have strict RBAC to limit who can read Falco alerts.
>
> Create the namespace before running Helm: `kubectl create namespace falco`

## Network Security (Calico)

The cluster uses Calico as the CNI plugin. All pods in the `threat-demo` namespace are subject to a default-deny posture enforced by a Calico `NetworkPolicy` with `order: 1000`. Explicit allow policies with lower order values are then layered on top:

| Policy | Order | Purpose |
|--------|-------|---------|
| `default-deny` | 1000 | Block all ingress and egress unless explicitly allowed |
| `allow-dns-egress` | 100 | Allow UDP/TCP port 53 to kube-dns |
| `allow-ingress-items-api` | 200 | Allow port 5000 ingress from `role=frontend` pods |
| `allow-egress-items-api` | 200 | Allow HTTPS (443) egress to AWS STS/S3 for IRSA |

Apply policies in this order to avoid a connectivity outage during initial deployment (allow rules must be in place before the deny catches up):

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/network-policies/allow-dns.yaml
kubectl apply -f k8s/network-policies/allow-ingress-app.yaml
kubectl apply -f k8s/network-policies/allow-egress-app.yaml
kubectl apply -f k8s/network-policies/default-deny.yaml  # apply deny last
```

> **Requires Calico** installed as the cluster CNI. The `crd.projectcalico.org/v1` API version is Calico-specific and will not work with the standard `networking.k8s.io/v1` NetworkPolicy.

## IRSA (IAM Roles for Service Accounts)

Pods in the `threat-demo` namespace are granted AWS credentials through IRSA rather than instance profiles. The flow:

1. EKS creates a projected OIDC token for each pod and mounts it at `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`.
2. The AWS SDK exchanges this token with STS (`AssumeRoleWithWebIdentity`).
3. STS validates the token against the cluster OIDC provider and checks that both `aud = sts.amazonaws.com` and `sub = system:serviceaccount:threat-demo:app-sa` match.
4. STS returns short-lived credentials scoped to the `irsa-app` IAM role.
5. The role only has `s3:GetObject` and `s3:ListBucket` on the specific app bucket.

After `terraform apply`, annotate the ServiceAccount:

```bash
ROLE_ARN=$(terraform -chdir=terraform output -raw irsa_role_arn)
kubectl annotate serviceaccount app-sa \
  -n threat-demo \
  eks.amazonaws.com/role-arn=$ROLE_ARN
```

## Terraform

All AWS infrastructure is provisioned via Terraform. The root module composes four child modules: `vpc`, `eks`, `ecr`, and `irsa`.

```bash
cd terraform

# create the S3 bucket and DynamoDB table for state first (one-time)
aws s3 mb s3://k8s-threat-locator-tfstate
aws dynamodb create-table \
  --table-name k8s-threat-locator-tflock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

> **Warning:** `terraform destroy` will delete the EKS cluster, node groups, VPC, and all associated resources. This is irreversible. Drain and delete all workloads first and ensure the S3 state bucket is backed up.

## Automated Incident Response (Lambda)

When Falco fires an `ERROR` or `CRITICAL` alert, Falcosidekick forwards the JSON payload to an SNS topic. A Lambda function subscribed to that topic:

1. Parses the Falco alert and extracts `k8s.pod.name` and `k8s.ns.name` from `output_fields`
2. Downloads a kubeconfig from S3 to `/tmp/kubeconfig`
3. Labels the offending pod with `quarantine: "true"`
4. Creates a `NetworkPolicy` that denies all ingress and egress for pods with that label
5. Emits a `QuarantineApplied` CloudWatch metric
6. Cleans up the kubeconfig from `/tmp` regardless of success or failure

The SNS subscription uses a `FilterPolicy` so only `ERROR` and `CRITICAL` priority alerts invoke the Lambda — `WARNING` alerts (e.g. `shell_in_container`) are logged by Falco but do not trigger automatic isolation.

## Lambda Deployment (SAM)

The `lambda/` directory is a SAM application. Deploy it after the EKS cluster and SNS topic exist.

```bash
# Package and deploy
sam build --template lambda/template.yaml

sam deploy \
  --template lambda/template.yaml \
  --stack-name k8s-threat-locator-lambda \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    SnsTopicArn=<falcosidekick-sns-topic-arn> \
    KubeconfigBucket=<your-kubeconfig-bucket> \
    KubeconfigKey=kubeconfig
```

Upload the kubeconfig before deploying so the Lambda can reach the cluster:

```bash
aws s3 cp ~/.kube/config s3://<your-kubeconfig-bucket>/kubeconfig
```

> **Security note:** The kubeconfig grants cluster access. Restrict the S3 bucket to the Lambda execution role only and enable S3 server-side encryption.

## Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform >= 1.6.0
- kubectl
- Helm >= 3.x
- Docker
- AWS SAM CLI

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check — returns `{"status": "ok"}` |
| `GET` | `/items` | List all items |
| `POST` | `/items` | Create an item — body: `{"name": "<string>"}` |

## Getting Started

See each component's section in this README for setup instructions.

## Architecture Overview

```
┌─────────────┐    push     ┌──────────────────────────────────────────┐
│  Developer  │────────────▶│  GitHub Actions CI                       │
└─────────────┘             │  1. build  → docker build (no push)      │
                            │  2. scan   → Trivy CRITICAL gate          │
                            │  3. push   → ECR (blocked by step 2)     │
                            └──────────────────────────────────────────┘
                                              ↓ (if scan passes)
                             ┌────────────────────────────────────────┐
                             │  AWS EKS Cluster                       │
                             │  ┌──────────────┐  ┌───────────────┐  │
                             │  │  Calico CNI  │  │  Flask app    │  │
                             │  │  default-deny│  │  (victim pod) │  │
                             │  └──────────────┘  └───────────────┘  │
                             │  ┌──────────────────────────────────┐  │
                             │  │  Falco DaemonSet                 │  │
                             │  │  detects: shell, /etc writes,    │  │
                             │  │  unexpected outbound connections  │  │
                             │  └──────────────────────────────────┘  │
                             └────────────────────────────────────────┘
                                              ↓ alert
                             ┌────────────────────────────────────────┐
                             │  AWS SNS → Lambda                      │
                             │  applies quarantine NetworkPolicy       │
                             │  to isolate the compromised pod        │
                             └────────────────────────────────────────┘
```

## End-to-End Attack Simulation

Follow these steps to exercise the full detection-and-response pipeline on a running cluster.

### 1. Trigger the Falco `write_to_etc` rule (ERROR priority → quarantine)

```bash
# Exec into the running pod
POD=$(kubectl get pod -n threat-demo -l app=items-api -o jsonpath='{.items[0].metadata.name}')

# Write to /etc/ — triggers write_to_etc rule at ERROR priority
kubectl exec -n threat-demo "$POD" -- sh -c "echo pwned > /etc/pwned"
```

Within a few seconds Falco logs the alert, Falcosidekick pushes it to SNS, and Lambda quarantines the pod.

### 2. Verify the quarantine

```bash
# Pod should now be labelled
kubectl get pod "$POD" -n threat-demo --show-labels | grep quarantine

# NetworkPolicy should exist
kubectl get networkpolicy -n threat-demo quarantine-"$POD"

# Pod can no longer reach other pods or external endpoints
kubectl exec -n threat-demo "$POD" -- curl -m 3 https://example.com  # should timeout
```

### 3. Verify the CloudWatch metric

```bash
aws cloudwatch get-metric-statistics \
  --namespace k8s-threat-locator \
  --metric-name QuarantineApplied \
  --dimensions Name=Namespace,Value=threat-demo \
  --start-time "$(date -u -v-5M +%FT%TZ)" \
  --end-time "$(date -u +%FT%TZ)" \
  --period 300 \
  --statistics Sum
```

### 4. Trigger the `shell_in_container` rule (WARNING — logged but does not quarantine)

```bash
# WARNING priority is filtered out of the SNS subscription
kubectl exec -it -n threat-demo "$POD" -- /bin/sh
```

Falco fires the alert, but the SNS filter policy blocks it from reaching Lambda because the priority is `WARNING`, not `ERROR` or `CRITICAL`.

### Cleanup

```bash
# Remove the quarantine label and NetworkPolicy to restore connectivity
kubectl label pod "$POD" -n threat-demo quarantine-
kubectl delete networkpolicy "quarantine-$POD" -n threat-demo
```

## Intentional Vulnerabilities

The `app/requirements.txt` pins old, CVE-laden versions of Flask and its dependencies. This is deliberate — the project exists to show that Trivy catches these before any image reaches the registry. In a real project you would pin to the latest patched versions. Here, leaving them unfixed keeps the Trivy gate visibly red so the shift-left control is easy to demonstrate.

> **Note:** The `push` job in CI will never succeed while these vulnerable versions remain pinned. That is intentional — it proves the gate works.

## CI Pipeline

The pipeline runs on every push to `main` and every pull request targeting `main`. It has three sequential jobs:

1. **build** — builds the Docker image locally (no push yet)
2. **trivy-scan** — scans the image for vulnerabilities; uploads results to the GitHub Security tab as SARIF, then runs a hard gate that exits non-zero if any **CRITICAL** CVEs are found. The pipeline stops here.
3. **push** — pushes to ECR with both `<sha>` and `latest` tags. This job only runs after the scan passes and only on pushes to `main`. Because the `app/requirements.txt` pins intentionally vulnerable Flask versions, this job will never actually run — which is the point.

## Running Locally

```bash
cd app
docker build -t k8s-threat-locator-app .
docker run -p 5000:5000 k8s-threat-locator-app
```

Test the API:

```bash
curl http://localhost:5000/health
curl http://localhost:5000/items
curl -X POST http://localhost:5000/items -H "Content-Type: application/json" -d '{"name":"widget"}'
```
