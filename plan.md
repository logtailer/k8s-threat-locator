# k8s-threat-locator — End-to-End Test Report

**Date:** 2026-07-08  
**Cluster:** `k8s-threat-locator` (EKS 1.36, us-east-1, 2× t3.medium nodes)  
**Lambda:** `k8s-threat-locator-responder` (Python 3.11, 128 MB)  
**Falco:** modern_ebpf driver, AL2023 kernel 6.x  
**Falcosidekick:** v2.32.0 (2 replicas)  
**Unit tests:** 19/19 passing

---

## Architecture Flow Verified

```
kubectl exec (shell in container)
      │
      ▼
Falco (eBPF)  ─────────────────────────────────────────────────── < 2 s
      │  rule: shell_in_container (priority: ERROR)
      ▼
Falcosidekick ──► SNS topic: falco-alerts ─────────────────────── < 1 s
                          │ FilterPolicy: priority ∈ {ERROR, CRITICAL}
                          ▼
              Lambda k8s-threat-locator-responder ─────────────── ≈ 3.5 s (warm)
                  │                                               ≈ 6 s (cold)
                  ├─ 1. Download kubeconfig from S3
                  ├─ 2. Generate EKS bearer token (SigV4QueryAuth)
                  ├─ 3. Build k8s CoreV1 + NetworkingV1 + RbacV1 clients
                  ├─ 4. enrich() — read pod spec, services, RBAC, namespace labels
                  ├─ 5. score() — shell_in_container in _FORCE_QUARANTINE_RULES
                  │              → severity=critical, action=QUARANTINE (score bypassed)
                  ├─ 6. PATCH pod: label quarantine=true
                  ├─ 7. CREATE NetworkPolicy: deny-all ingress + egress
                  └─ 8. PutMetricData: QuarantineApplied (CloudWatch)
                          │
                          ▼
             Pod fully isolated — both directions timed out
             Unaffected pods: connectivity unchanged
```

---

## Test Results

### TC-01 — shell_in_container → QUARANTINE + Network Isolation

**Trigger:** `kubectl exec -n threat-demo <pod> -- /bin/sh -c "id && hostname"`

| Check | Result |
|---|---|
| Lambda HTTP 200 | ✅ |
| Log: `forced quarantine (active-compromise rule)` | ✅ |
| Pod labeled `quarantine=true` | ✅ |
| NetworkPolicy `quarantine-<pod>` created with deny-all spec | ✅ |
| Quarantined pod → clean pod TCP/5000 | ✅ **BLOCKED** (timeout) |
| Clean pod → quarantined pod TCP/5000 (ingress rule) | ✅ **BLOCKED** (timeout) |
| Clean pod → clean pod TCP/5000 | ✅ **CONNECTED** |
| CloudWatch `QuarantineApplied` metric emitted | ✅ |
| CloudWatch `TriageScore` metric (severity=critical) emitted | ✅ |

Network isolation is enforced by the **VPC CNI network policy agent** (`aws-eks-nodeagent` container, enabled via `enableNetworkPolicy: true` on the `vpc-cni` addon). Without it, the NetworkPolicy object is accepted but unenforced.

---

### TC-02 — write_to_etc → QUARANTINE

**Trigger:** `kubectl exec -n threat-demo <pod> -- /bin/sh -c "echo test > /etc/falco-test && rm /etc/falco-test"`

| Check | Result |
|---|---|
| Lambda HTTP 200 | ✅ |
| Log: `forced quarantine (active-compromise rule)` for `write_to_etc` | ✅ |
| Pod labeled `quarantine=true` | ✅ |
| NetworkPolicy created | ✅ |
| CloudWatch `QuarantineApplied` with `Rule=write_to_etc` | ✅ |

`write_to_etc` is in `_FORCE_QUARANTINE_RULES` alongside `shell_in_container`. Both rules short-circuit the risk-score path — active compromise indicators always quarantine regardless of pod risk profile.

---

### TC-03 — unexpected_outbound_connection (WARNING priority) → Filtered by SNS

**Rationale:** The SNS subscription FilterPolicy must drop WARNING-priority alerts so Lambda isn't invoked for lower-severity signals.

**Method:** Published to the SNS topic with `priority` message attribute = `Warning`.

| Check | Result |
|---|---|
| SNS publish acknowledged | ✅ |
| Lambda invoked after publish | ✅ **NO** — last invocation predates the publish |
| `unexpected_outbound_connection` absent from `_FORCE_QUARANTINE_RULES` | ✅ (by design) |

WARNING-priority rules are visible via Falcosidekick's other outputs (Slack, S3) but do not trigger automated quarantine. The FilterPolicy acts as the boundary between "observe" and "respond."

---

### TC-04 — Idempotency: Duplicate Alert on Same Pod → 409 Handled

**Method:** Lambda invoked twice for the same pod within seconds.

| Check | Result |
|---|---|
| First invocation: HTTP 200 | ✅ |
| Second invocation: HTTP 200 (no exception raised) | ✅ |
| Log first: `Quarantine NetworkPolicy applied` | ✅ |
| Log second: `Quarantine policy already exists … — skipping` | ✅ |
| Only one NetworkPolicy exists in the namespace | ✅ |

`create_namespaced_network_policy` catches `ApiException(status=409 Conflict)` and logs a warning. The pod label PATCH is a merge-patch and is idempotent.

---

### TC-05 — CloudWatch Metrics

All five metric series present in namespace `k8s-threat-locator`:

| MetricName | Pod | Additional Dimension |
|---|---|---|
| `TriageScore` | items-api-77d88b6f5b-x6xtz | Severity=low (pre-RBAC-fix invocations) |
| `TriageScore` | items-api-77d88b6f5b-x6xtz | Severity=critical |
| `TriageScore` | items-api-77d88b6f5b-xnkqh | Severity=critical |
| `QuarantineApplied` | items-api-77d88b6f5b-x6xtz | Rule=shell_in_container |
| `QuarantineApplied` | items-api-77d88b6f5b-xnkqh | Rule=write_to_etc |

---

### Unit Tests

```
lambda/tests/test_triage.py — 19/19 passed (4.96 s)
```

| Class | Count | Covers |
|---|---|---|
| `TestScore` | 13 | privileged, cluster-admin, LoadBalancer, hostNetwork, system namespace, score clamping (≤ 100), prod/dev/staging modifiers, reason field |
| `TestEnrich` | 6 | privileged container, LoadBalancer service, cluster-admin ClusterRoleBinding, pod-not-found (partial context), init container privilege, RBAC 403 (does not raise) |

---

## Issues Found During Testing

| # | Issue | Root Cause | Fix |
|---|---|---|---|
| 1 | Falcosidekick `MissingAuthenticationToken` on SNS | v2.32.0 reads its own Viper config keys (`AWS_ACCESSKEYID`/`AWS_SECRETACCESSKEY`), not the standard SDK chain, bypassing IRSA | Added `checkidentity: false` to values.yaml; SNS publishing works when static creds are provided |
| 2 | Lambda `No such file or directory: 'aws'` | Kubeconfig used `aws eks get-token` exec plugin; `aws` CLI is not present in Lambda | Replaced with in-process EKS token via `botocore.auth.SigV4QueryAuth` |
| 3 | Lambda k8s API 401 Unauthorized | Lambda IAM role absent from `aws-auth` ConfigMap | Added role to `aws-auth`; created `ClusterRole` + `ClusterRoleBinding` for group `k8s-threat-locator-responders` |
| 4 | Triage score 10 → `alert_only` for items-api | Pod runs as root (+10 pts only) — not enough for quarantine threshold | Added `_FORCE_QUARANTINE_RULES` frozenset: `shell_in_container` and `write_to_etc` skip scoring |
| 5 | NetworkPolicy not enforced | EKS VPC CNI doesn't enforce NetworkPolicies without the network policy agent | Enabled `enableNetworkPolicy: true` on the `vpc-cni` addon; `aws-eks-nodeagent` now programs per-pod eBPF rules |
| 6 | CoreDNS `plugin/kubernetes` unsynced since day 1 | CoreDNS started before kube-proxy programmed the ClusterIP DNAT rule for `172.20.0.1:443`; 5-second retry window expired at boot | Does not affect this project (items-api and Lambda make no in-cluster DNS calls); documented as known limitation |

---

## End-to-End Timing

| Stage | Latency |
|---|---|
| Falco eBPF detection | < 2 s |
| Falcosidekick → SNS | < 1 s |
| Lambda cold start + init | ≈ 2.6 s |
| S3 download + token generation + k8s API calls | ≈ 2.8 s |
| **Total (cold start)** | **≈ 6 s** |
| **Total (warm Lambda)** | **≈ 3.5 s** |

---

## Known Limitations

1. **Falcosidekick IRSA bypass:** Static credentials required for SNS in v2.32.0. Pin to a version with proper credential chain support for production.
2. **NetworkPolicy enforcement is opt-in:** The VPC CNI network policy agent must be enabled (`enableNetworkPolicy: true`). The quarantine mechanism creates correct objects regardless, but enforcement requires the agent.
3. **CoreDNS:** In-cluster service DNS is unresolved due to a bootstrap race. Non-blocking for this project.
4. **WARNING-priority rules:** `unexpected_outbound_connection` (WARNING) is filtered by the SNS subscription and never reaches Lambda in the current setup. Visibility requires Falcosidekick's non-SNS outputs.

## 1. Production Signals

- [ ] `LICENSE` — MIT
- [ ] `SECURITY.md` — vulnerability reporting policy (fitting for a security project)
- [ ] `Makefile` — targets: `lint`, `docker-build`, `tf-plan`, `lambda-build`, `simulate-attack`
- [ ] `lambda/tests/test_handler.py` — unit tests mocking boto3 + kubernetes client
- [ ] `.github/pull_request_template.md`
- [ ] `.github/CODEOWNERS`

## 2. Feature Additions

- [ ] **Lambda DLQ** — dead letter queue in `lambda/template.yaml` so failed quarantine attempts are captured, not silently dropped
- [ ] **CloudWatch alarm** — alert when `QuarantineApplied` fires more than N times in 5 minutes (runaway attack signal)
- [ ] **`terraform/modules/lambda/`** — bring Lambda/SAM under Terraform so the entire stack is one `terraform apply`, no separate SAM deploy step
- [ ] **KMS encryption** on the kubeconfig S3 bucket (`aws:kms` SSE in Terraform)

## 3. README Overhaul

- [ ] GitHub badges — CI status, Python 3.11, Terraform, MIT license
- [ ] Rewrite opener — punchy problem statement, not a bullet list
- [ ] "How the attack pipeline works" — numbered narrative, more readable than raw ASCII
- [ ] "Key design decisions" callouts:
  - Why Python k8s client and not `kubectl` in Lambda
  - Why IRSA and not instance profiles
  - Why Calico and not standard `networking.k8s.io/v1` NetworkPolicy
  - Why intentional CVEs in Flask deps (shift-left proof)

## 4. Local Demo Path

- [ ] `scripts/simulate-attack.sh` — gets the running pod name, execs a write to `/etc/`, polls until the quarantine NetworkPolicy appears, prints pass/fail with timing

## 5. LinkedIn Post

- [ ] Draft a ~300-word post: problem-first, 4–5 key engineering decisions, link to repo
- [ ] Pull 2–3 concrete numbers from the project (e.g. "quarantine applied in < 10 seconds", "0 manual steps in the response chain")

---

## Order of Execution

1. Production signals (fastest wins — LICENSE, SECURITY.md, Makefile, tests)
2. Feature additions (DLQ → CloudWatch alarm → Terraform Lambda module → KMS)
3. README overhaul (do last so it reflects all the above)
4. Local demo script
5. LinkedIn post draft

---

## 6. Article / Reddit Post — The Triage Gap

Source: [r/devsecops thread on autonomous pentesting in CI/CD](https://www.reddit.com/r/devsecops/comments/1uee45s/the_hard_part_of_autonomous_pentesting_in_cicd/)

### The Reddit post's core argument

- Shift-left security in CI mostly produces noise — devs learn to ignore it (`// nosec`, merge, move on)
- Real bugs (IDOR, broken object-level auth, logic flaws) are invisible to signature scanners because they require understanding *intent*, not matching patterns
- Finding a vuln is **20% of the problem**; triage — "is this exploitable in *this* deployment?" — is **80%**
- Without that triage step, autonomous security tools are just expensive linters with a bigger compute bill
- Three practical pain points the author hit:
  1. **Auth state** — getting valid sessions into ephemeral CI runs is harder than the actual testing
  2. **Non-determinism** — same commit, different result between runs → devs stop trusting output instantly
  3. **Placement** — full validation is too slow to block PRs; real exploit validation ended up nightly against staging

### The connection to k8s-threat-locator

- The CI Trivy gate is exactly the shift-left pattern the post critiques — it catches a known CVE but misses a broken RBAC rule that lets a pod read secrets it shouldn't
- The Falco → Lambda quarantine loop is *response without triage* — it fires on a syscall pattern, not on whether the pod is exposed, privileged, or in a sensitive namespace
- The missing layer: enrich each finding with runtime context (is the pod running? does it have a LoadBalancer? what namespace/RBAC scope?) before deciding to quarantine

### Angle for the article

**Title idea:** "I built a K8s security project and accidentally recreated every mistake the security industry already made"

**Structure:**
1. Open with the triage argument from the Reddit post
2. Show k8s-threat-locator as a concrete example of detect-without-triage
3. Walk through what a triage layer would look like in practice (runtime context enrichment)
4. Show the actual implementation added to this project (Section 7 below)

---

## 7. Triage Layer (implement in this repo)

**The gap:** Lambda currently quarantines every ERROR alert blindly. A shell exec in a debug pod in a dev namespace is not the same threat as a shell exec in a prod pod with a LoadBalancer and a cluster-admin service account.

**What to build:**

### `lambda/triage.py` — context enrichment + scoring
Gather runtime context from the Kubernetes API before deciding to quarantine:
- **Pod spec** — is any container `privileged`? does it have `hostNetwork`/`hostPID`? dangerous capabilities (`CAP_SYS_ADMIN`)?
- **Service exposure** — does the pod have an associated `LoadBalancer` or `NodePort` service? (exposed to internet = higher risk)
- **Service account RBAC** — what `ClusterRoleBindings`/`RoleBindings` does the pod's service account have? (`cluster-admin` = critical)
- **Namespace sensitivity** — is the namespace labelled `env=prod`? is it the `kube-system` or `falco` namespace?

Produce a `TriageResult`:
```
severity: low | medium | high | critical
action:   alert_only | annotate | quarantine
reason:   human-readable explanation of the decision
score:    int (0–100)
context:  dict of all enriched fields
```

### `lambda/handler.py` — call triage before acting
Replace the unconditional quarantine with:
1. Call `triage.enrich(core_v1, rbac_v1, pod_name, namespace)` → `TriageResult`
2. Log the full context + score
3. If `action == quarantine` → apply NetworkPolicy (existing logic)
4. If `action == annotate` → patch pod with `triage-severity` annotation, emit metric, do not isolate
5. If `action == alert_only` → log + metric only
6. Always emit `TriageScore` CloudWatch metric with severity dimension

### New IAM permissions needed
- `rbac.authorization.k8s.io` read via kubeconfig (no AWS changes — k8s RBAC)
- New CloudWatch metric: `TriageScore{Namespace, Pod, Severity}`

### `lambda/tests/test_triage.py`
Unit tests for each scoring branch:
- Privileged container → critical
- LoadBalancer service + root container → high
- ClusterIP only + non-root → medium
- Dev namespace + no exposure → low

### SAM / Terraform changes
- Add `rbac.authorization.k8s.io` read permissions to the kubeconfig user (update the kubeconfig generation docs)
- Add `TriageScore` metric emission to `lambda/template.yaml` IAM policy (already covered by `cloudwatch:PutMetricData`)

### README additions
- "Triage layer" section explaining the scoring logic and the four action outcomes
- Update the architecture diagram to show the triage decision box between Falco alert and quarantine
- Add the article angle as a "Why this matters" callout
