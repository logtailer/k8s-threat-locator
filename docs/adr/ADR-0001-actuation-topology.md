# ADR-0001: Actuation topology for the threat responder

**Status:** Proposed
**Date:** 2026-07-18
**Deciders:** Repo owner

## Context

The system's job is: detect a runtime threat (Falco/eBPF, in-cluster) → decide (score) → **actuate** (label the pod, apply a deny-all NetworkPolicy). Today the *decide + actuate* stage runs **outside** the cluster as an AWS Lambda:

```
Falco (DaemonSet) → Falcosidekick → SNS(falco-alerts) → Lambda responder
                                                          ├─ download kubeconfig from S3 (per invocation)
                                                          ├─ mint EKS bearer token (SigV4 → STS)
                                                          ├─ build K8s API clients
                                                          ├─ enrich() : GET pod, services, RBAC, namespace
                                                          ├─ score()  : triage
                                                          └─ act      : PATCH pod + CREATE NetworkPolicy  ← reaches back INTO the cluster
```

The architectural tension: **a component whose only side effect is mutating cluster state lives outside the cluster and has to tunnel back in.** That inversion is the source of most incidental complexity — the S3-hosted kubeconfig, the hand-rolled EKS token generator (`lambda/handler.py:_generate_eks_token`), the EKS access-entry mapping, and the requirement that the API server be reachable from Lambda (a *public* endpoint, or Lambda-in-VPC with ENI cold starts).

**Forces:**
- **Latency:** ~3.5s warm / ~6s cold; per-invocation S3 fetch + token mint + client build dominate.
- **Attack surface:** reaching EKS from Lambda pushes toward a *public* API endpoint — an odd posture for a security tool.
- **Portability / testability:** AWS-coupled; the local stack had to reimplement the SNS→SQS→poller path in LocalStack to run off-cloud.
- **Tamper-resistance (counter-force):** an out-of-cluster responder is harder for a cluster-admin-level attacker to disable than an in-cluster pod they could `kubectl delete`. Legitimate.
- **Audit durability:** SNS + SQS DLQ + CloudWatch alarms give an out-of-band record that survives cluster loss.

## Decision

Adopt a **hybrid split**: move fast actuation **into** the cluster, keep AWS as the **durable audit + out-of-band watchdog** path — rather than leaving actuation on the cross-boundary Lambda hop.

## Options Considered

### Option A: Status quo — out-of-cluster Lambda actuator
| Dimension | Assessment |
|---|---|
| Complexity | High — S3 kubeconfig, token minting, access entries, VPC/public-endpoint decision |
| Latency | ~3.5–6s (setup-dominated) |
| Attack surface | Pushes toward public EKS API endpoint |
| Portability | Low — AWS-coupled; needs LocalStack to test |
| Tamper-resistance | High |
| Ops burden | Low (serverless) |

**Pros:** tamper-resistant; durable AWS-native audit; showcases broad cloud-native skills.
**Cons:** slow, complex, inverted actuation path, requires API exposure, hard to test off-cloud.

### Option B: In-cluster controller (or adopt Falco Talon)
A controller/operator — or the CNCF-native **Falco Talon** response engine — runs in-cluster, consumes Falco output directly, applies NetworkPolicies via a scoped ServiceAccount. Delete the Lambda actuation path.

| Dimension | Assessment |
|---|---|
| Complexity | Low — mounted SA token, `kubernetes.default.svc` one hop; no S3/token/access-entry |
| Latency | Sub-second |
| Attack surface | No API exposure |
| Portability | High — any K8s incl. kind, no LocalStack |
| Tamper-resistance | Low — a cluster-admin attacker can delete the controller before it acts |
| Ops burden | Medium — a Deployment to run |

**Pros:** dramatically simpler, fast, portable, industry-standard.
**Cons:** loses the tamper-resistant watchdog property and the AWS-native audit trail unless re-added.

### Option C: Hybrid — in-cluster actuation + out-of-cluster watchdog (recommended)
Falcosidekick fans out to **both**: (1) an in-cluster controller that quarantines in <1s with no API exposure, and (2) SNS → Lambda that now does **audit + notification + reconciliation** (re-assert the NetworkPolicy if the in-cluster controller was tampered with or missed the event).

| Dimension | Assessment |
|---|---|
| Complexity | Medium — two actuators, each simpler than today's Lambda |
| Latency | Sub-second common path; Lambda async backstop |
| Attack surface | Common path in-cluster; no hard public-endpoint requirement |
| Portability | High |
| Tamper-resistance | High — out-of-cluster watchdog survives cluster compromise |
| Ops burden | Medium |

**Pros:** keeps both good properties (speed + tamper-resistance), drops the bad one (inverted primary path).
**Cons:** two code paths to keep coherent; reconciliation must be idempotent (it already is — 409-safe).

## Trade-off analysis

The crux is **who the adversary is**. If it's *malware inside a workload* (the app-RCE case the rules target), an in-cluster controller kills it in <1s and the S3/token/public-endpoint apparatus is pure cost — Option B wins. If it's *a human at cluster-admin*, only an out-of-cluster watchdog survives — which is what Option A really buys, at the price of making the common case slow and forcing API exposure. Option C resolves this: fast in-cluster response for the 99% case, out-of-cluster backstop for the tamper case. Today's design pays the tamper-case price on *every* alert.

## The portfolio caveat

This repo's demonstrated purpose is a DevSecOps/Cloud-Security portfolio piece. Under that goal, Option A's Terraform + Lambda + IRSA + SNS + KMS sprawl deliberately showcases more cloud-native breadth than a lean controller would.
- **Optimizing the engineering:** do Option C (or B). The current actuation path is inverted.
- **Optimizing the portfolio:** keep the current design but *write down the trade-off* (this ADR) and add the missing fast path additively as Option C — which itself demonstrates architectural maturity.

## Consequences
- **Easier:** sub-second quarantine; no public EKS endpoint needed; local stack stops needing LocalStack to exercise actuation.
- **Harder:** two actuators to keep idempotent and non-conflicting; a new in-cluster Deployment + RBAC to maintain.
- **Revisit:** whether the Lambda downgrades from actuator to auditor+reconciler; whether to adopt Falco Talon vs. hand-maintained controller code.

## Action Items
1. [ ] Spike Falco Talon as the in-cluster actuator; compare its NetworkPolicy action to `_build_quarantine_policy`.
2. [ ] Reduce the Lambda to audit+reconcile (drop per-invocation S3/token from the common path).
3. [ ] Move the EKS API endpoint to private once Lambda no longer needs it directly.
4. [ ] Add a reconciliation test: delete the NetworkPolicy → Lambda backstop re-asserts it.
5. [ ] Keep this ADR current as the topology evolves.

## Evidence from the codebase
The local test stack's Calico-CRD dependency (`scripts/local-bootstrap.sh` applies `crd.projectcalico.org/v1` NetworkPolicies that a stock kind cluster rejects) is a direct symptom of the AWS/Calico coupling this ADR describes: an in-cluster, CNI-agnostic actuator would not require that coupling to be reproduced locally.
