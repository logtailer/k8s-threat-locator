# Plan 002 — Make pod enrichment resilient (stop silently under-scoring on partial failure)

**Written against commit:** `eab3bd5` (verify with `git rev-parse --short HEAD`; if different, re-read cited files first).
**Category:** correctness / security · **Impact:** MED-HIGH · **Effort:** M · **Risk of the fix:** LOW.

## Why this matters

The Lambda responder scores a threat from the pod's live context (privileged, hostNetwork,
dangerous caps, service exposure, RBAC, namespace). Today `enrich()` wraps **all** of that in
a single `try/except client.ApiException`: if any one enrichment call fails partway, it logs a
warning and returns **partial context** with the un-populated risk flags left at their `False`
defaults. The scorer then runs on that partial context and can **under-count**, so a genuinely
dangerous pod scores below the quarantine threshold (40) and is **not** isolated — a silent
false negative in a security control.

Concretely: if `read_namespaced_pod` succeeds but `_enrich_service_exposure` throws (e.g. a
transient error or a namespace-scoped RBAC gap listing services), `ctx.service_type` stays
`"None"`, missing a LoadBalancer's +40 — potentially the difference between quarantine and
"alert only". Force-quarantine rules bypass scoring so they're unaffected, but the six
detect-only ERROR rules (and any future non-force rule) ride the weighted path and are exposed.

## Current state (read it yourself)

`lambda/triage.py:112-139`:
```python
def enrich(
    core_v1: client.CoreV1Api,
    rbac_v1: client.RbacAuthorizationV1Api,
    pod_name: str,
    namespace: str,
    apps_v1: client.AppsV1Api | None = None,
) -> PodContext:
    ctx = PodContext(pod_name=pod_name, namespace=namespace)
    ctx.is_system_namespace = namespace in _SYSTEM_NAMESPACES
    logger.info("Enriching pod context: pod=%s/%s", namespace, pod_name)

    try:
        pod = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        _enrich_pod_spec(ctx, pod)
        _enrich_service_exposure(ctx, core_v1, pod, namespace)
        _enrich_rbac(ctx, rbac_v1, namespace)
        _enrich_namespace(ctx, core_v1, namespace)
        if apps_v1 is not None:
            _enrich_owner(ctx, apps_v1, pod, namespace)
    except client.ApiException as exc:
        logger.warning(
            "Could not fully enrich pod context for %s/%s: status=%s — using partial context",
            namespace, pod_name, exc.status,
        )

    return ctx
```

The helper functions `_enrich_pod_spec`, `_enrich_service_exposure`, `_enrich_rbac`,
`_enrich_namespace`, `_enrich_owner` are defined immediately below `enrich` in the same file.
Note `_enrich_rbac` and `_enrich_namespace` **already** have their own inner `try/except`
(read them). The pattern to follow for a defensive metric-style swallow is
`lambda/handler.py:_emit_triage_metric` (added in commit `eab3bd5`): a `try/except Exception`
that logs a warning and continues — telemetry/enrichment must not silently corrupt the result.

## Scope
- **In scope:** `lambda/triage.py` (the `enrich` function and, if needed, small guards in the
  per-aspect helpers), `lambda/tests/test_triage.py`.
- **Out of scope:** `handler.py`, scoring weights/thresholds, Falco rules, Terraform.

## Change — two coupled improvements

### 1. Isolate each enrichment aspect so one failure can't skip the rest
Restructure `enrich` so that a failure in one aspect (pod-not-found aside) does not prevent the
others from running. Recommended shape: keep the single `read_namespaced_pod` (if that fails,
partial context is unavoidable and correct — the pod is gone), then run each remaining aspect in
its own guard so `service_exposure` failing does not skip `rbac`/`namespace`/`owner`:

```python
    try:
        pod = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
    except client.ApiException as exc:
        logger.warning("Pod read failed for %s/%s: status=%s — minimal context",
                       namespace, pod_name, exc.status)
        ctx.enrichment_complete = False
        return ctx

    for step_name, step in (
        ("pod_spec", lambda: _enrich_pod_spec(ctx, pod)),
        ("service_exposure", lambda: _enrich_service_exposure(ctx, core_v1, pod, namespace)),
        ("rbac", lambda: _enrich_rbac(ctx, rbac_v1, namespace)),
        ("namespace", lambda: _enrich_namespace(ctx, core_v1, namespace)),
    ):
        try:
            step()
        except client.ApiException as exc:
            logger.warning("enrich step %s failed for %s/%s: status=%s",
                           step_name, namespace, pod_name, exc.status)
            ctx.enrichment_complete = False
    if apps_v1 is not None:
        try:
            _enrich_owner(ctx, apps_v1, pod, namespace)
        except client.ApiException as exc:
            logger.warning("enrich step owner failed for %s/%s: status=%s",
                           namespace, pod_name, exc.status)
            ctx.enrichment_complete = False
```
(Match the file's existing style — plain functions, `logger.warning`, no new deps. The `lambda:`
wrappers are fine, or unroll to explicit try/except blocks if the executor prefers clarity.)

### 2. Make partial enrichment *visible to scoring* so it can't silently under-quarantine
Add a field to `PodContext` (dataclass at `lambda/triage.py:18-39`), e.g.
`enrichment_complete: bool = True`, and set it `False` in any failing guard above.

Then in `score()` (same file), when `enrichment_complete is False` **and** the computed weighted
action would be less severe than QUARANTINE, do the fail-safe thing: **do not downgrade below
ANNOTATE**, and add a reason like `"partial enrichment — verify manually"`. Rationale: if we
couldn't fully assess a pod that a rule already flagged, err toward surfacing it, never toward
silently ignoring it. **Do not** force it all the way to QUARANTINE (that would over-isolate on
every transient API blip); ANNOTATE (which pages ops via the existing notify path) is the right
floor. Escape hatch: if the maintainer wants a different floor (alert-only vs quarantine),
STOP and confirm — this is a policy choice.

## Test plan (extend `lambda/tests/test_triage.py`, mirror the existing `TestEnrich` class)
The existing tests mock the k8s clients with `MagicMock` and raise
`client.ApiException(status=...)` via `side_effect` — follow that exactly. Add:
- **Partial-failure isolation:** `read_namespaced_pod` returns a pod with a LoadBalancer-selecting
  service, but `list_namespaced_service` raises `ApiException(status=500)`. Assert the *other*
  aspects still populated (e.g. `_enrich_rbac` ran) and `ctx.enrichment_complete is False`.
- **Fail-safe scoring:** `score()` on a context with `enrichment_complete=False` whose weighted
  score would be `< 20` (alert-only) returns `Action.ANNOTATE` (not ALERT_ONLY) with a reason
  mentioning "partial enrichment".
- **No regression:** a fully-enriched context (`enrichment_complete=True`) scores exactly as before
  (keep an existing assertion or add one pinning a known score).
- Also add the **N5** coverage while here: a test for `_enrich_owner` resolving
  ReplicaSet→Deployment (it feeds the workload-quarantine fallback and is currently untested).

## Done when (machine-checkable)
- `cd lambda && python -m pytest tests/ -q` passes (all existing + new tests).
- `cd lambda && ruff check triage.py && ruff format --check triage.py` clean.
- `make lint` passes.
- `grep -n enrichment_complete lambda/triage.py` shows the field set in failing guards and read in `score()`.

## Maintenance note
This changes what a *partially-enriched* alert does (now ANNOTATE-floor instead of possibly
alert-only). Watch that it doesn't create annotation noise if the cluster has a chronic RBAC gap
for the responder's ServiceAccount — if so, the real fix is the RBAC (`k8s/lambda-rbac.yaml`
grants services/namespaces/rbac read cluster-wide), not loosening this guard. Pairs with **N3**
(the per-alert cluster-wide ClusterRoleBinding list in `_enrich_rbac`) — revisit that scoping as a
follow-up once this lands.
