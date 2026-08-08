# secure-cicd-pipeline

A secure CI/CD pipeline for a trivial Flask API on AWS EKS — the app is not
the point, **the pipeline is**. Every stage from PR to running pod has a
security gate in front of it, and the deliberately-vulnerable-commit demo in
[`demo/`](demo/) proves each gate actually catches something, rather than
just existing in the YAML.

```
PR opened ──▶ Semgrep (SAST) ──▶ Gitleaks (secrets) ──▶ Checkov (IaC) ──▶ Trivy (image)
                                                                              │
                                                        merge blocked until all pass
                                                                              ▼
Merge to main ──▶ build image ──▶ Trivy (blocking) ──▶ push to ECR ──▶ Syft SBOM
                                                                              │
                                                          cosign sign (keyless, GitHub OIDC)
                                                                              ▼
                                              kubectl apply ──▶ Kyverno admission
                                                                 (rejects unsigned images)
                                                                              ▼
                                                              running pod ──▶ Falco
                                                                          (runtime detection)
```

## Why this exists

It's a portfolio piece built to demo in about 60 seconds: open a PR with a
known-bad commit, watch three unrelated gates fail for three different
reasons, then look at a policy in the cluster that makes "signed images
only" an actual enforced fact instead of a slide in a deck. See
[`SECURITY.md`](SECURITY.md) for the threat model behind *why* each piece
is here — that document is the actual point of the project; this README is
just the "how to run it" companion.

## What's in the pipeline

| Stage | Tool | Gate |
|---|---|---|
| IaC scan | [Checkov](https://github.com/bridgecrewio/checkov) | Terraform (`infra/terraform`) fails the build on HIGH/CRITICAL findings |
| SAST | [Semgrep](https://semgrep.dev) | Every PR, `--error` fails the job on any finding |
| Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) | Every PR, full-history diff scan |
| Container scan | [Trivy](https://github.com/aquasecurity/trivy) | Runs on every PR build *and* again, blocking, before the release image is pushed |
| SBOM | [Syft](https://github.com/anchore/syft) | Generated from the pushed image, CycloneDX format |
| Signing | [Cosign](https://github.com/sigstore/cosign) | Keyless — signs with GitHub Actions' own OIDC identity, no key to manage or leak |
| Admission control | [Kyverno](https://kyverno.io) | In-cluster policy rejects any pod whose image doesn't verify against that exact signing identity |
| Runtime | [Falco](https://falco.org) | Optional polish (see [Scope](#scope)) — anomaly detection, alerts to Slack |

## Repo layout

```
app/                  Flask API + tests + Dockerfile
infra/terraform/      VPC, EKS, ECR, GitHub OIDC IAM roles
k8s/                  Deployment/Service + Kyverno ClusterPolicies
falco/                Helm values + custom runtime-detection rules
.github/workflows/    pr-checks.yml, cd.yml, terraform.yml, cluster-bootstrap.yml
demo/                 The vulnerable-commit patch + walkthrough
SECURITY.md           Threat model — read this one
```

## Prerequisites

- An AWS account (EKS + a NAT gateway cost real money — see [Cost](#cost-and-teardown))
- A GitHub repo (this one, pushed to your own remote) with Actions enabled
- Terraform ≥ 1.7, AWS CLI, `kubectl`, `helm`, `cosign`, `syft` installed locally for the one-time bootstrap
- `gh` CLI or the GitHub web UI, to set repo variables/environments

## Setup

This is a from-scratch build — nothing here has been applied against a real
AWS account by me; you're standing up your own instance of it.

> Published at [github.com/monacomonaco/secure-cicd-pipeline](https://github.com/monacomonaco/secure-cicd-pipeline).
> The org/repo placeholders (`infra/terraform/variables.tf`,
> `terraform.tfvars.example`, `k8s/kyverno/require-image-signature.yaml`,
> `app/Dockerfile`, `SECURITY.md`) already point at that repo. If you fork
> this instead, swap those to `<your-org>/<your-repo>` first — the Kyverno
> policy and the OIDC trust policy both check that string exactly.

1. **Bootstrap Terraform remote state** (one-time, by hand):
   ```bash
   AWS_REGION=us-east-1 BUCKET=your-org-tfstate-secure-cicd-demo ./scripts/bootstrap-backend.sh
   cp infra/terraform/backend.tf.example infra/terraform/backend.tf   # fill in your bucket
   cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
   ```

2. **Apply the infrastructure** from your laptop the first time (later
   changes flow through `terraform.yml`):
   ```bash
   cd infra/terraform
   terraform init
   terraform apply
   ```

3. **Wire GitHub up to what Terraform just created** — in repo Settings →
   Secrets and variables → Actions, add as **variables** (not secrets; role
   ARNs aren't sensitive, the trust policy is what protects them):
   `AWS_DEPLOY_ROLE_ARN`, `AWS_TERRAFORM_ROLE_ARN`, `ECR_REPOSITORY_URL`
   (all three are printed by `terraform output`, though the output names use
   underscores — e.g. `ecr_repository_url` — while the GitHub variable names
   above are what the workflows actually read). Also set `AWS_REGION`,
   `CLUSTER_NAME`, and `ECR_REPOSITORY` (the short `namespace/name` form,
   default `secure-cicd-demo/flask-api`) if you changed any of those
   Terraform defaults. Add `SLACK_WEBHOOK_URL` as a **secret** if you're
   standing up Falco.

4. **Turn on branch protection for `main`**, requiring the `pr-checks.yml`
   jobs to pass before merge — the pipeline can fail a PR check all day,
   but only branch protection actually blocks the merge button.

5. **Bootstrap cluster add-ons** (Kyverno + Falco) by running the
   `cluster-bootstrap.yml` workflow manually (Actions tab → Cluster
   bootstrap → Run workflow), or by hand following the `helm` commands in
   [`falco/values.yaml`](falco/values.yaml) and
   [`cluster-bootstrap.yml`](.github/workflows/cluster-bootstrap.yml).

6. **Push a change under `app/`** to trigger `cd.yml` end to end: build →
   Trivy → SBOM → cosign sign → deploy → Kyverno verifies the signature at
   admission.

## The 60-second demo

1. Show `SECURITY.md`'s trust-boundary diagram — 10 seconds on "PRs get
   zero cloud credentials, only `main` can deploy."
2. Push [`demo/vulnerable-commit.patch`](demo/vulnerable-commit.patch) as a
   PR (see [`demo/README.md`](demo/README.md)) — three checks go red for
   three unrelated reasons (SAST, secrets, IaC).
3. Point at the Kyverno policy
   ([`k8s/kyverno/require-image-signature.yaml`](k8s/kyverno/require-image-signature.yaml))
   and say the sentence that actually matters: *"Cosign signs the image;
   this is what makes that signature mean something — an unsigned image
   cannot schedule in this cluster, full stop."*

## Scope

The brief for this project explicitly allows scoping down — signing +
scanning + admission control is already the strong version of this
project. Falco is genuinely optional polish: everything up through "unsigned
images can't run" stands on its own without it. It's included here because
runtime detection is the one layer none of the earlier gates can cover (see
`SECURITY.md`, section 2.3E) — but if you're short on cluster budget, skip
`cluster-bootstrap.yml`'s Falco step and the pipeline's core claim is
unaffected.

## Cost and teardown

An EKS control plane (~$0.10/hr) + a NAT gateway (~$0.045/hr + data) + 2×
`t3.medium` nodes add up fast if left running. Tear down when you're not
actively demoing it:

```bash
cd infra/terraform
terraform destroy
```

## License

[MIT](LICENSE)
