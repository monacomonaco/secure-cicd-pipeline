# Expected results — vulnerable-commit demo

This describes what each gate should report when `vulnerable-commit.patch`
is applied and pushed as a PR, based on how each tool actually behaves.
It was written by reasoning through the tools' documented behavior against
this specific patch, **not** copied from a live pipeline run — this repo
was assembled and reviewed locally, without a live AWS account or GitHub
remote attached. Treat this as "what you should see," and if a real run
ever disagrees with it, trust the real run and file an issue.

## 1. `sast-semgrep` — fails

The added route looks like:

```python
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output
```

Semgrep's `auto` config (which pulls in the `p/security-audit` /
`p/python` rule packs) flags `subprocess` calls with `shell=True` built
from an f-string that includes a variable — the rule id is typically
`python.lang.security.audit.subprocess-shell-true` or
`python.flask.security.injection.raw-html-format` depending on ruleset
version. `semgrep scan --error` exits non-zero on any finding, so the
job fails and the finding also lands in the PR's Files Changed tab via the
uploaded SARIF.

**Why it's a real bug, not just a lint nit:** `host` is attacker-controlled
and reaches a shell. `?host=1; cat /etc/passwd` (or worse, a reverse shell)
executes inside the container. This is exactly the class of bug the Falco
rule `Shell Spawned in Flask API Container` (`falco/rules/custom-rules.yaml`)
is written to catch *if* it ever reached a running pod — the SAST gate's
job is to make sure it never gets that far.

## 2. `secrets-gitleaks` — fails

The patch adds a line resembling:

```python
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # TODO: move to env before merging
```

Gitleaks' default ruleset includes an `aws-access-token` detector matching
the `AKIA[0-9A-Z]{16}` pattern — this matches regardless of the trailing
comment or the fact that it's a well-known *example* key from AWS's own
docs; Gitleaks doesn't know that, which is exactly the point (a real key
looks identical in shape). The `gitleaks/gitleaks-action@v2` action exits
non-zero on any detected finding and annotates the file/line in the PR.

## 3. `iac-scan` (Checkov) — fails

The patch changes `infra/terraform/eks.tf`'s call site to pass:

```hcl
cluster_endpoint_public_access       = true
cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]
```

This trips Checkov's EKS public-endpoint checks (commonly `CKV_AWS_38`
"Ensure Amazon EKS public endpoint disabled" and/or `CKV_AWS_39` depending
on Checkov version) at HIGH severity, which is above this pipeline's
`--hard-fail-on HIGH,CRITICAL` threshold — the job exits non-zero and the
SARIF upload surfaces it as a code-scanning alert on the PR.

**Why 0.0.0.0/0 specifically matters:** with the endpoint public and open
to the entire internet, the only thing standing between an attacker and
`kubectl` access is a valid IAM identity/token — network exposure is a
layer of defense that a config like this deletes for free, with no
corresponding benefit (see `variables.tf`'s
`cluster_endpoint_public_access_cidrs` comment for the intended, scoped
usage).

## 4. `container-scan` (Trivy) and `unit-tests` — pass, unaffected

The patch doesn't touch the Dockerfile, base image, or dependency pins, and
`test_app.py` doesn't exercise the new `/ping` route, so these two jobs are
expected to stay green. That's deliberate: it shows the other three gates
catching the issue on their own merits, not as a side effect of an
unrelated job also failing.

## Net result

3 of 5 `pr-checks.yml` jobs fail, from three different security domains,
off of one small patch. With branch protection configured to require these
checks, the PR's merge button is blocked — the vulnerable code never
reaches `main`, so `cd.yml` never builds, signs, or deploys it.
