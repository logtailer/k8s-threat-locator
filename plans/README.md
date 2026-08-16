# Improvement Plans

Self-contained plans from an `/improve` audit. Each is written to be executed by
someone (or an agent) with **no prior context** on this repo.

**Written against commit:** `eab3bd5` — every plan stamps this; if `git rev-parse --short HEAD`
differs, re-read the cited files before editing (line numbers may have drifted).

## Status

| # | Plan | Category | Impact | Effort | Status |
|---|------|----------|--------|--------|--------|
| 001 | [Restrict the EKS public API endpoint](001-eks-endpoint-lockdown.md) | security | HIGH | S | TODO |
| 002 | [Make pod enrichment resilient (no silent under-scoring)](002-enrich-resilience.md) | correctness/security | MED-HIGH | M | TODO |

## Recommended order

Independent — either can go first. 001 is a smaller, lower-risk change; 002 needs
the Python test venv. No dependency between them.

## Verification available in this repo
- Python: `cd lambda && python -m pytest tests/ -q && ruff check handler.py triage.py`
  (needs Python 3.11+; the macOS system `python3` is 3.9 and fails on `X | None`).
- YAML/Make: `make lint`.
- Terraform: `terraform -chdir=terraform init -backend=false && terraform -chdir=terraform validate`.

## Considered and rejected / deferred (not planned)
- **N3** — `enrich()` lists all ClusterRoleBindings cluster-wide per alert (perf). Real, but
  wait until 002 restructures `enrich`; revisit as a follow-up with a scoping/caching change.
- **N4** — T4 "detect-only" rules can still quarantine a ≥40-posture pod. Behaviour clarity, not
  a defect for the ClusterIP demo pod; document rather than change.
- **N5** — `_enrich_owner` untested. Fold into 002's test work rather than a separate plan.
- Already fixed this session (do not re-report): the metric-emitter-blocks-quarantine bug
  (commit `eab3bd5`), and the whole local test stack.
