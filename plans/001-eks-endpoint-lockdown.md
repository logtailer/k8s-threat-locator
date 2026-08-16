# Plan 001 — Restrict the EKS public API endpoint (stop defaulting to 0.0.0.0/0)

**Written against commit:** `eab3bd5` (verify with `git rev-parse --short HEAD`; if different, re-read cited files first).
**Category:** security · **Impact:** HIGH · **Effort:** S · **Risk of the fix:** LOW-MED (can lock out API access if the private path isn't reachable — see escape hatch).

## Why this matters

This project is a Kubernetes runtime **security** system, yet its own EKS control-plane
API is exposed to the entire internet by default. The cluster is created with a public
endpoint open to `0.0.0.0/0`. Even though EKS still requires IAM+RBAC auth, exposing the
API server to the whole internet is a well-known weakness (Checkov `CKV_AWS_39`), enlarges
the attack surface, and is exactly the posture a security tool should not ship.

Context: today the out-of-cluster Lambda responder reaches the cluster over this public
endpoint (see `docs/adr/ADR-0001-actuation-topology.md`), which is *why* the public
endpoint exists. `endpoint_private_access` is **already `true`**, so a private path exists.

## Current state (read these yourself before editing)

`terraform/modules/eks/main.tf:38-42`:
```hcl
  vpc_config {
    ...
    endpoint_private_access  = true
    endpoint_public_access   = true
    public_access_cidrs      = var.cluster_public_access_cidrs
  }
```

`terraform/modules/eks/variables.tf:61-65`:
```hcl
variable "cluster_public_access_cidrs" {
  description = "CIDR blocks permitted to reach the public Kubernetes API endpoint. Restrict to your IP or VPN range in production."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
```

`terraform/variables.tf:49-53` (the root var passed into the module via `terraform/main.tf`'s `module "eks"` block, arg `cluster_public_access_cidrs = var.eks_public_access_cidrs`):
```hcl
variable "eks_public_access_cidrs" {
  description = "CIDR blocks permitted to reach the EKS public API endpoint. Set to your IP or VPN CIDR in production."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
```

## Scope

- **In scope:** `terraform/variables.tf`, `terraform/modules/eks/variables.tf`,
  `terraform/modules/eks/main.tf`, `README.md`/`RUNBOOK.md` (doc note only).
- **Out of scope:** the Lambda responder code, VPC/networking module internals, anything non-Terraform.
- Do **not** run `terraform apply` — validation is `fmt`/`validate` only (see Done).

## Change — pick ONE of two postures, defaulting to the safer

The maintainer must choose; **default to Option A** unless they say otherwise. Both change
the *default*; a real deployment can still override via tfvars.

### Option A (recommended): keep the public endpoint but stop defaulting it open
Change **both** variable defaults from `["0.0.0.0/0"]` to an **empty list** and require the
operator to opt in to specific CIDRs:
- `terraform/variables.tf` `eks_public_access_cidrs` default → `[]`
- `terraform/modules/eks/variables.tf` `cluster_public_access_cidrs` default → `[]`

AWS semantics: `endpoint_public_access = true` with `public_access_cidrs = []` still exposes
the endpoint but denies all source IPs unless CIDRs are supplied — so this fails safe (no
one can reach it until the operator lists their IP/VPN CIDR). Update the two `description`
strings to say the default denies all and must be set to reach the public endpoint.

### Option B: private-only by default
Add a boolean `enable_public_endpoint` (default `false`) to the module, wire it to
`endpoint_public_access = var.enable_public_endpoint` in `main.tf:41`, and keep
`endpoint_private_access = true`. This is stronger but means the Lambda (which reaches the
API over the public endpoint today) can't connect until it's moved into the VPC — coordinate
with ADR-0001 action items. **If choosing B, STOP and confirm the Lambda's VPC path is in
place first**, otherwise the responder breaks.

## Steps (Option A)
1. Edit the two variable defaults to `[]` and update their `description` text to state the
   default denies all source IPs.
2. `terraform -chdir=terraform fmt` the changed files.
3. Add a one-line note to `RUNBOOK.md` Step 1 (Terraform apply): "The public API endpoint
   now denies all source IPs by default — set `eks_public_access_cidrs` to your IP/VPN CIDR
   in `terraform.tfvars` before applying, or you will not be able to reach the cluster."

## Escape hatch
If `endpoint_private_access` is *not* `true` at the cited line when you read it (someone
changed it), or if the module has no private networking, **STOP and report** — narrowing
public access without a working private path would lock out all cluster access.

## Done when (machine-checkable)
- `grep -n '0.0.0.0/0' terraform/variables.tf terraform/modules/eks/variables.tf` returns nothing.
- `terraform -chdir=terraform init -backend=false >/dev/null && terraform -chdir=terraform validate` → "Success!".
- `terraform -chdir=terraform fmt -check terraform/variables.tf terraform/modules/eks/variables.tf` → clean.
- The two variable `description`s state that the default denies all.

## Test plan
Terraform has no unit tests here; validation is `validate` + `fmt -check` (above). Optionally,
if `checkov` is installed: `checkov -d terraform --compact | grep CKV_AWS_39` should no longer
report the wide-open-endpoint finding once a deployment supplies scoped CIDRs (note: checkov
flags the resource config, so this is informational).

## Maintenance note
This ties to `docs/adr/ADR-0001-actuation-topology.md` action item #3 ("move the EKS API
endpoint to private once Lambda no longer needs it directly"). If the responder is ever moved
in-cluster (ADR Option B/C), switch this to Option B (private-only) as the default.
