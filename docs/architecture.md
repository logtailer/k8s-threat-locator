# Architecture Diagrams

## Top-Down Flow

```mermaid
flowchart TD
    DEV[Developer] -->|git push| GH[GitHub Actions]
    GH --> TV{Trivy CVE gate}
    TV -->|CRITICAL CVEs| FAIL[Pipeline blocked\nFlask==1.0.0 unfixed]
    TV -->|clean image| ECR[ECR Registry]
    ECR -->|deploy| EKS

    subgraph EKS["EKS — threat-demo namespace"]
        direction TB
        APP[items-api pod\nruns as root]
        FALCO[Falco DaemonSet\nmodern_ebpf]
        APP -->|shell exec / write /etc| FALCO
    end

    FALCO -->|ERROR alert JSON| FSK[Falcosidekick]
    FSK -->|priority=ERROR attribute| SNS[SNS falco-alerts\nFilterPolicy: ERROR + CRITICAL only]
    SNS -->|invoke| LAMBDA

    subgraph LAMBDA["Lambda — k8s-threat-locator-responder"]
        direction TB
        PARSE[parse alert\nextract pod + namespace]
        ENRICH[enrich\npod spec · services · RBAC · ns labels]
        FORCE{force-quarantine\nrule?}
        SCORE[score  0–100]
        PARSE --> ENRICH --> FORCE
        FORCE -->|shell_in_container\nwrite_to_etc| CRIT[severity=critical\nQUARANTINE]
        FORCE -->|other rules| SCORE
        SCORE -->|score >= 70| CRIT
        SCORE -->|20-69| ANN[annotate pod]
        SCORE -->|less than 20| AONLY[alert only]
    end

    CRIT -->|PATCH| LABEL[pod label\nquarantine=true]
    CRIT -->|CREATE| NP[NetworkPolicy\ndeny-all ingress + egress]
    CRIT -->|PutMetricData| CW[CloudWatch\nQuarantineApplied + TriageScore]
```

---

## Zone Layout

```mermaid
flowchart LR
    subgraph CI["CI/CD Zone"]
        DEV[Developer] --> GH[GitHub Actions]
        GH --> TV{Trivy scan}
        TV -->|CRITICAL| FAIL[Pipeline fails]
        TV -->|clean| ECR[ECR]
    end

    subgraph CLUSTER["EKS Cluster — threat-demo ns"]
        ECR -->|pull| APP[items-api\nruns as root]
        FALCO[Falco eBPF\nDaemonSet] -->|watches syscalls| APP
    end

    subgraph AWS["AWS Services"]
        FSK[Falcosidekick] --> SNS[SNS\nfalco-alerts]
        SNS --> LFN[Lambda\nresponder]
        S3[S3\nkubeconfig] --> LFN
        LFN --> CW[CloudWatch\nmetrics]
    end

    subgraph K8S["Kubernetes Response"]
        NP[NetworkPolicy\ndeny-all]
        POD_LABEL[Pod label\nquarantine=true]
    end

    APP -->|syscall alert| FALCO
    FALCO -->|ERROR JSON| FSK
    LFN -->|enrich · score · act| NP
    LFN -->|enrich · score · act| POD_LABEL
```

---

## Incident Timeline

```mermaid
sequenceDiagram
    actor Developer
    participant Falco as Falco (eBPF)
    participant Falcosidekick
    participant SNS
    participant Lambda
    participant k8sAPI as Kubernetes API
    participant CloudWatch

    Developer->>+Falco: kubectl exec -- /bin/sh
    Note over Falco: syscall intercepted in < 2s
    Falco->>Falcosidekick: shell_in_container (priority: ERROR)
    Falcosidekick->>SNS: Publish JSON + priority=ERROR attribute
    Note over SNS: FilterPolicy passes ERROR/CRITICAL only
    SNS->>Lambda: Invoke (cold start ≈ 2.6s)
    Lambda->>Lambda: parse_alert — pod name + namespace
    Lambda->>k8sAPI: GET pod spec (privileged? hostNetwork? caps?)
    Lambda->>k8sAPI: GET services (LoadBalancer? NodePort?)
    Lambda->>k8sAPI: GET ClusterRoleBindings (cluster-admin?)
    Lambda->>Lambda: score() — shell_in_container in FORCE_QUARANTINE_RULES
    Note over Lambda: severity=critical, action=QUARANTINE (score bypassed)
    Lambda->>k8sAPI: PATCH pod label quarantine=true
    Lambda->>k8sAPI: CREATE NetworkPolicy deny-all ingress + egress
    Lambda->>CloudWatch: PutMetricData QuarantineApplied + TriageScore
    Note over Lambda,CloudWatch: Total latency: cold ≈ 6s / warm ≈ 3.5s
    Falco-->>-Developer: pod isolated — TCP connections time out
```

---

## Timing Reference

| Stage | Latency |
|---|---|
| Falco eBPF detection | < 2 s |
| Falcosidekick → SNS | < 1 s |
| Lambda cold start | ≈ 2.6 s |
| k8s API calls + token generation | ≈ 2.8 s |
| **Total (cold start)** | **≈ 6 s** |
| **Total (warm Lambda)** | **≈ 3.5 s** |

## SNS Filter Policy

The SNS subscription uses a `FilterPolicy` that passes only `ERROR` and `CRITICAL` priority alerts to Lambda. `WARNING`-priority rules (e.g. `unexpected_outbound_connection`) are visible via Falcosidekick's other outputs (Slack, S3) but do not trigger automated quarantine.

## Force-Quarantine Rules

Two Falco rules bypass the 0–100 scoring path entirely and always map to `severity=critical, action=QUARANTINE`:

- `shell_in_container` / `Terminal shell in container`
- `write_to_etc` / `Write below etc`

All other rules go through the scoring function, which maps score to action as: `>= 70` critical/quarantine, `40–69` high/quarantine, `20–39` medium/annotate, `< 20` low/alert-only. The threshold for quarantine via scoring is `score >= 40`.
