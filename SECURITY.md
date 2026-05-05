# Security Policy

## Supported Versions

This is a demonstration project. Only the `main` branch is actively maintained.

## Reporting a Vulnerability

If you find a security issue in this project (e.g. a logic flaw in the triage scoring, an IAM policy that is broader than intended, or a bypass in the quarantine NetworkPolicy), please report it privately:

1. **Do not open a public GitHub issue.**
2. Email `anandsumit2000@gmail.com` with the subject line `[k8s-threat-locator] Security Report`.
3. Include a description of the issue, steps to reproduce, and your assessment of the impact.

You can expect an acknowledgement within 48 hours and a resolution or mitigation plan within 7 days for issues that affect the demonstration's integrity.

## Intentional Vulnerabilities

Several components in this project are **deliberately insecure** for demonstration purposes:

- `app/requirements.txt` pins `Flask==1.0.0` and other CVE-laden dependencies — this is intentional to prove the Trivy CI gate works.
- The `items-api` deployment runs as root (`USER` is not set in the Dockerfile) — this is intentional so Falco can detect privileged shell executions.

These are not bugs. Do not report them as vulnerabilities.
