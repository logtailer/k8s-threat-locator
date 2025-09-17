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

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check — returns `{"status": "ok"}` |
| `GET` | `/items` | List all items |
| `POST` | `/items` | Create an item — body: `{"name": "<string>"}` |

## Getting Started

See each component's section in this README for setup instructions.

## Intentional Vulnerabilities

The `app/requirements.txt` pins old, CVE-laden versions of Flask and its dependencies. This is deliberate — the project exists to show that Trivy catches these before any image reaches the registry. In a real project you would pin to the latest patched versions. Here, leaving them unfixed keeps the Trivy gate visibly red so the shift-left control is easy to demonstrate.

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
