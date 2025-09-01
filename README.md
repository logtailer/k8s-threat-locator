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

## Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform >= 1.6.0
- kubectl
- Helm >= 3.x
- Docker

## Getting Started

See each component's section in this README for setup instructions.
