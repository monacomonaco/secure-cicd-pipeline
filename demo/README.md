# Demo: pushing a deliberately vulnerable commit

The point of this pipeline isn't the YAML — it's that a bad commit *cannot
quietly become a deployed container*. This demo proves it with one patch
that trips three independent gates at once, each from a different security
domain (SAST, secrets, IaC).

## What's in the patch

[`vulnerable-commit.patch`](vulnerable-commit.patch) makes three changes that would each, alone, be a plausible real-world mistake:

| # | File | Change | Gate that catches it | Why it's realistic |
|---|---|---|---|---|
| 1 | [`app/app.py`](../app/app.py) | New `/ping` route shells out to `ping` using `subprocess` with `shell=True` and unsanitized request input | **Semgrep** (`pr-checks.yml` → `sast-semgrep`) | This exact pattern — "convenience" endpoint that pings/curls/dig's a user-supplied host — shows up in real codebases constantly. |
| 2 | `app/app.py` | A hardcoded AWS access key constant, added while "temporarily" debugging | **Gitleaks** (`pr-checks.yml` → `secrets-gitleaks`) | Copy-pasting a real credential into code "just for a quick local test" and forgetting to remove it before committing is one of the most common real leak vectors. |
| 3 | `infra/terraform/eks.tf` | `cluster_endpoint_public_access = true` with `cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]` | **Checkov** (`pr-checks.yml` → `iac-scan`, and again in `terraform.yml` before apply) | "I just need kubectl to work from home, I'll open it up and lock it down later" is exactly how EKS control planes end up internet-facing. |

## Running it

```bash
git checkout -b demo/vulnerable-commit
git apply demo/vulnerable-commit.patch
git add -A
git commit -m "demo: intentionally vulnerable commit"
git push -u origin demo/vulnerable-commit
```

Then open a PR against `main` on GitHub. `pr-checks.yml` runs automatically
and — assuming the repo's branch protection requires these checks to pass —
the PR cannot be merged. See [`EXPECTED_RESULTS.md`](EXPECTED_RESULTS.md)
for exactly what each job reports and why, without needing to actually run it
to know what you're looking at.

**This requires a real GitHub repo with Actions enabled** (this scaffold was
built and reviewed locally; running the workflow live needs your own
GitHub/AWS setup — see the root [README](../README.md#setup) for the pieces
that only you can provide: an AWS account, the Terraform-created OIDC role
ARNs as repo variables, and branch protection turned on for `main`).

## Cleaning up

```bash
git checkout main
git branch -D demo/vulnerable-commit
git push origin --delete demo/vulnerable-commit  # if you pushed it
```

The patch file stays in the repo — it's meant to be reusable, not a one-shot.
