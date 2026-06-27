# k8s-threat-locator

[![CI](https://github.com/anandsumit2000/k8s-threat-locator/actions/workflows/ci.yml/badge.svg)](https://github.com/anandsumit2000/k8s-threat-locator/actions/workflows/ci.yml)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![Terraform](https://img.shields.io/badge/terraform-%3E%3D1.6-623CE4.svg)](https://www.terraform.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Most security tools tell you something happened. This project builds the layer that decides what to do about it.

`k8s-threat-locator` is a runtime security system for Kubernetes that:

1. **Detects** threats at the kernel level using Falco custom rules
2. **Enriches** each alert with live cluster context — pod spec, service exposure, RBAC bindings
3. **Scores** the finding (0–100) based on actual blast radius, not just the syscall pattern
4. **Acts** proportionally — quarantine critical pods, annotate medium ones, log low-risk events

The result: automated incident response that doesn't blindly quarantine every `kubectl exec` from a dev debugging a staging pod.

---

## The Problem With Detect-and-Respond

A shell exec inside a container is suspicious. But how suspicious depends on context:

| Scenario | Risk |
|----------|------|
| `kubectl exec` into a `debug` pod in `namespace=dev` | Low |
| Shell in a pod with a `ClusterIP` service, non-root, no special RBAC | Medium |
| Shell in a pod with a `LoadBalancer` service and `cluster-admin` binding | Critical |

Without context, you quarantine all three the same way. With context, you quarantine only the third — and annotate the second for review.

---

## How the Pipeline Works

```
Developer → GitHub Actions → Trivy CVE gate → ECR → EKS
                                                       │
                                              ┌────────┴────────┐
                                              │   threat-demo   │
                                              │   namespace     │
                                              │                 │
                                              │  Calico         │
                                              │  default-deny   │
                                              │       +         │
                                              │  items-api pod  │
                                              │  (runs as root) │
                                              └────────┬────────┘
                                                       │ syscall event
                                                       ▼
                                              Falco DaemonSet
                                              (kernel-level)
                                                       │ ERROR alert
                                                       ▼
                                              Falcosidekick → SNS
                                                       │
                                                       ▼
                                              Lambda: _parse_alert()
                                                       │
                                                       ▼
                                              triage.enrich()
                                              ┌─────────────────────┐
                                              │ • pod spec flags     │
                                              │ • service type       │
                                              │ • RBAC bindings      │
                                              │ • namespace env      │
                                              └─────────┬───────────┘
                                                        │
                                                        ▼
                                              triage.score() → 0–100
                                                        │
                                          ┌─────────────┼─────────────┐
                                          ▼             ▼             ▼
                                       score<20      20≤score<70   score≥70
                                       alert_only    annotate      quarantine
                                                         │             │
                                                    patch pod     NetworkPolicy
                                                    annotation    + label pod
                                                                  + CW metric
```

### Triage Scoring

| Factor | Points |
|--------|--------|
| Privileged container | +40 |
| `cluster-admin` service account | +35 |
| `LoadBalancer` service (internet-exposed) | +25 |
| System namespace (`kube-system`, `falco`) | +20 |
| `hostNetwork: true` | +20 |
| `hostPID: true` | +20 |
| NodePort service | +15 |
| Dangerous Linux capabilities | +15 |
| Runs as root | +10 |
| Production namespace label | +10 |
| Staging namespace label | +5 |
| Non-default role bindings | +5 |
| Dev/demo namespace label | −10 |

**Actions:**
- `score < 20` → `alert_only` — log + `TriageScore` metric, no Kubernetes changes
- `20 ≤ score < 70` → `annotate` — patch pod with `triage-severity` and `triage-reason` annotations
- `score ≥ 70` → `quarantine` — label pod `quarantine=true`, apply deny-all NetworkPolicy, emit `QuarantineApplied` metric

---

## Key Design Decisions

**Why the `kubernetes` Python client and not `kubectl`?**
Bundling a `kubectl` binary in a Lambda deployment package is fragile — version drift, binary compatibility issues, and subprocess error handling. The Python client handles kubeconfig parsing, API server TLS, and retry logic natively.

**Why IRSA and not instance profiles?**
Instance profiles grant the same permissions to every pod on the node. IRSA issues short-lived OIDC tokens scoped to a specific service account — a compromised pod cannot use the credentials of any other pod on the same node.

**Why Calico's `crd.projectcalico.org/v1` and not standard `networking.k8s.io/v1`?**
Standard NetworkPolicy has no `order` field. Calico's CRD supports `order`, which makes policy priority explicit and deterministic — critical when layering a default-deny at `order: 1000` over allow rules at `order: 100–200`.

**Why intentional CVEs in the Flask app?**
The CI Trivy gate exists to prove it works. Fixing the CVEs would make the gate pass silently — leaving nothing to demonstrate. The pipeline stays visibly red by design.

**Why triage before quarantine?**
Blind quarantine is operationally expensive and trains responders to ignore alerts. Context-aware scoring means the quarantine signal carries weight — when it fires, it means something genuinely high-risk was detected, not just any anomalous syscall.

---

## Repository Layout

```
k8s-threat-locator/
├── app/                    Python Flask API (intentionally vulnerable victim app)
├── terraform/              EKS, VPC, ECR, IRSA — all infra in one apply
│   └── modules/            vpc / eks / ecr / irsa
├── k8s/                    Kubernetes manifests + Calico network policies
├── falco/                  Helm values + custom Falco rules
├── lambda/                 Triage engine + quarantine responder (Python + SAM)
│   ├── handler.py          Entry point — parse → enrich → score → act
│   ├── triage.py           Context enrichment and scoring logic
│   ├── template.yaml       SAM template — Lambda, DLQ, CloudWatch alarms
│   └── tests/              pytest unit tests for triage scoring
├── scripts/
│   └── simulate-attack.sh  End-to-end attack simulation
└── .github/workflows/      CI pipeline with Trivy vulnerability gate
```

---

## Security Controls at a Glance

| Stage | Control | Proof |
|-------|---------|-------|
| Build | Trivy CVE gate | CI pipeline is permanently red on `Flask==1.0.0` |
| Deploy | Calico default-deny | `kubectl run test -- ping 8.8.8.8` times out |
| Runtime | IRSA | `aws sts get-caller-identity` returns scoped role ARN |
| Runtime | Falco | Alert fires within seconds of `kubectl exec` |
| Response | Triage + quarantine | `kubectl get netpol` shows quarantine policy; CW metric emitted |

---

## Quick Start

### 1. Provision infrastructure

```bash
cd terraform

# One-time: create S3 bucket + DynamoDB table for Terraform state
aws s3 mb s3://k8s-threat-locator-tfstate
aws dynamodb create-table \
  --table-name k8s-threat-locator-tflock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

terraform init && terraform apply
```

### 2. Apply Kubernetes manifests

```bash
# Apply in this order — allow rules before the deny catches up
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/resourcequota.yaml
kubectl apply -f k8s/network-policies/allow-dns.yaml
kubectl apply -f k8s/network-policies/allow-ingress-app.yaml
kubectl apply -f k8s/network-policies/allow-egress-app.yaml
kubectl apply -f k8s/network-policies/default-deny.yaml
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

### 3. Deploy Falco

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update

helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --version 4.3.0 \
  -f falco/values.yaml \
  --set-file falco.rules_file[0]=falco/rules/custom-rules.yaml
```

Set `falcosidekick.config.aws.sns.topicarn` in `falco/values.yaml` to the SNS topic ARN before installing.

### 4. Deploy the Lambda triage responder

```bash
# Upload kubeconfig so Lambda can reach the cluster
aws s3 cp ~/.kube/config s3://<your-kubeconfig-bucket>/kubeconfig

sam build --template lambda/template.yaml

sam deploy \
  --stack-name k8s-threat-locator-lambda \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    SnsTopicArn=<sns-topic-arn> \
    KubeconfigBucket=<your-kubeconfig-bucket>
```

### 5. Simulate an attack

```bash
make simulate-attack
# or directly:
./scripts/simulate-attack.sh
```

The script triggers the `write_to_etc` Falco rule, polls for the quarantine NetworkPolicy, and prints the result with timing.

---

## Falco Custom Rules

| Rule | Trigger | Priority | Response |
|------|---------|----------|----------|
| `shell_in_container` | Shell binary spawned in container | ERROR | Triage → quarantine if score ≥ 70 |
| `write_to_etc` | File write under `/etc/` inside container | ERROR | Triage → quarantine if score ≥ 70 |
| `unexpected_outbound_connection` | Outbound from `items-api` on non-standard port | WARNING | Triage → annotate or alert_only |

All rules output: `container.id`, `container.name`, `k8s.pod.name`, `k8s.ns.name`, `k8s.pod.uid`, `container.image.repository`, `container.image.tag`.

---

## IRSA (IAM Roles for Service Accounts)

Pods get AWS credentials through IRSA rather than instance profiles:

1. EKS projects an OIDC token into the pod at `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`
2. The AWS SDK calls `sts:AssumeRoleWithWebIdentity` with that token
3. STS validates both `aud = sts.amazonaws.com` **and** `sub = system:serviceaccount:threat-demo:app-sa`
4. STS returns short-lived credentials scoped to `s3:GetObject` on the specific app bucket — nothing else

```bash
ROLE_ARN=$(terraform -chdir=terraform output -raw irsa_role_arn)
kubectl annotate serviceaccount app-sa -n threat-demo \
  eks.amazonaws.com/role-arn=$ROLE_ARN
```

---

## Running Tests

```bash
make lambda-test
# equivalent to:
cd lambda && python -m pytest tests/ -v
```

Tests cover all triage scoring branches and enrichment paths (privileged containers, LoadBalancer exposure, cluster-admin bindings, pod-not-found fallback, RBAC permission denied) with fully mocked Kubernetes and AWS clients.

---

## Troubleshooting

**Falco alerts not reaching Lambda**
- Set `falcosidekick.config.aws.sns.topicarn` in `falco/values.yaml`
- Check Falcosidekick logs: `kubectl logs -n falco -l app=falco-falcosidekick`
- Verify Falcosidekick IAM permission to `sns:Publish` on the topic

**Lambda not applying quarantine**
- Check CloudWatch Logs at `/aws/lambda/k8s-threat-locator-responder`
- Verify kubeconfig is in S3 and Lambda role has `s3:GetObject` on the exact key ARN
- Ensure `server:` in kubeconfig points to the private EKS endpoint and is reachable from the Lambda VPC
- Enable EKS audit logging: `aws eks update-cluster-config --name <cluster> --logging '{"clusterLogging":[{"types":["api","audit"],"enabled":true}]}'`

**DLQ has messages**
- A message in `k8s-threat-locator-dlq` means a quarantine attempt failed after retries
- Check the Lambda CloudWatch Logs for the corresponding error
- The `DLQDepthAlarm` CloudWatch alarm fires as soon as one message lands

**Score is lower than expected**
- Check the `TriageScore` CloudWatch metric dimensions for `Severity`
- Add `environment=prod` label to the namespace to raise the score for production workloads
- Review `triage.py:score()` — the full scoring table is in this README

**NetworkPolicy not blocking traffic**
- Calico must be the CNI: `kubectl get daemonset -n kube-system -l k8s-app=calico-node`
- Quarantine NetworkPolicy targets pods with label `quarantine=true` — confirm the pod was labelled

**Kernel module fails on nodes**
- Switch to `driver.kind: ebpf` in `falco/values.yaml` for Bottlerocket or custom AMI nodes

---

## Prerequisites

- AWS CLI with permissions for EKS, VPC, IAM, ECR, SNS, Lambda, CloudWatch, S3, SQS
- Terraform >= 1.6
- kubectl matching the EKS cluster version
- Helm >= 3.x
- Docker (local builds)
- AWS SAM CLI (Lambda deployment)
- Python 3.11+ (`make lambda-test`)

---

## Component Versions

| Component | Version |
|-----------|---------|
| Python (Lambda) | 3.11 |
| Python (app) | 3.9.18 |
| Flask | 1.0.0 (intentionally vulnerable) |
| kubernetes Python client | 30.1.0 |
| Terraform | >= 1.6.0 |
| AWS provider | ~> 5.0 |
| Falco Helm chart | 4.3.0 |
| Calico | via EKS managed add-on |
| Trivy action | v0.20.0 |
| ruff | v0.3.0 |

---

## Changelog

### v0.2.0 (2026-06-27)
- **Triage layer** — `lambda/triage.py` enriches each Falco alert with live pod context (spec flags, service exposure, RBAC bindings, namespace environment) and produces a 0–100 risk score
- **Proportional response** — three action levels (`alert_only` / `annotate` / `quarantine`) replace the previous unconditional quarantine
- **`TriageScore` CloudWatch metric** — emitted on every alert with `Severity` dimension for dashboarding
- **Dead letter queue** — failed quarantine invocations land in SQS DLQ with 14-day retention
- **CloudWatch alarms** — quarantine rate alarm (>5 in 5 min) and DLQ depth alarm (≥1 message)
- **`scripts/simulate-attack.sh`** — end-to-end attack simulation with polling and timing output
- **`make lambda-test`** — 16 pytest unit tests covering all scoring branches and enrichment paths
- Production signals: MIT license, `SECURITY.md`, `Makefile`, PR template, `CODEOWNERS`

### v0.1.0 (2025-12-28)
- Initial release — Flask victim app, Trivy CI gate, Terraform EKS/VPC/ECR/IRSA, Calico network policies, Falco custom rules, Lambda quarantine responder
