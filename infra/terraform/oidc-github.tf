# ---------------------------------------------------------------------------
# GitHub Actions -> AWS trust, via OIDC federation. No long-lived AWS access
# keys are ever stored in GitHub secrets — each workflow run exchanges a
# short-lived, repo/branch-scoped OIDC token for temporary AWS credentials.
# See SECURITY.md "Secrets management" for the rationale.
# ---------------------------------------------------------------------------

# Computed, not hand-typed: GitHub has rotated its OIDC signing CA before,
# and a stale or (as an earlier version of this file had) mistyped
# thumbprint fails validation or, worse, silently trusts the wrong cert.
# Pulling the live chain's root fingerprint at plan/apply time means this
# self-corrects instead of bit-rotting.
data "tls_certificate" "github_actions" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]

  thumbprint_list = [
    data.tls_certificate.github_actions.certificates[
      length(data.tls_certificate.github_actions.certificates) - 1
    ].sha1_fingerprint
  ]
}

data "aws_caller_identity" "current" {}

locals {
  # Roles are usable only from pushes to main, never from a pull_request
  # event — PRs (including from forks) get zero cloud credentials. PR
  # workflows run SAST/secrets/IaC-static-analysis only.
  github_sub_main = "repo:${var.github_repo}:ref:refs/heads/main"
  iam_role_path   = "/secure-cicd-pipeline/"
}

# A permissions boundary applied to every role this stack creates (itself
# included). It doesn't grant anything — it caps what these roles can ever
# be granted, even by a future, over-broad policy edit. This is the backstop
# for the fact that the terraform-apply role necessarily has broad
# infrastructure permissions (see SECURITY.md, "the CI-as-root problem").
resource "aws_iam_policy" "ci_permissions_boundary" {
  name        = "secure-cicd-ci-permissions-boundary"
  path        = local.iam_role_path
  description = "Boundary for CI-assumed roles: blocks IAM/Org/Billing takeover paths."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyIdentityAndBillingEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateAccessKey",
          "iam:AttachUserPolicy",
          "iam:PutUserPolicy",
          "iam:CreateLoginProfile",
          "iam:UpdateAssumeRolePolicy",
          "organizations:*",
          "account:*",
          "aws-portal:*",
          "budgets:*",
        ]
        Resource = "*"
      },
      {
        Sid         = "DenyIAMOutsideOwnPath"
        Effect      = "Deny"
        Action      = ["iam:CreateRole", "iam:DeleteRole", "iam:PutRolePolicy", "iam:AttachRolePolicy"]
        NotResource = "arn:aws:iam::*:role${local.iam_role_path}*"
      }
    ]
  })
}

# --- Role 1: build/scan/sign/deploy (cd.yml) --------------------------------
# Least privilege: push signed images to one ECR repo, describe the cluster,
# and (via the EKS access entry in eks.tf) edit workloads in one namespace.
resource "aws_iam_role" "github_actions_deploy" {
  name                 = "gha-secure-cicd-deploy"
  path                 = local.iam_role_path
  permissions_boundary = aws_iam_policy.ci_permissions_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github_actions.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = local.github_sub_main }
      }
    }]
  })
}

data "aws_iam_policy_document" "deploy_permissions" {
  statement {
    sid       = "ECRAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # this action does not support resource scoping
  }
  statement {
    sid    = "ECRPushPullOneRepo"
    effect = "Allow"
    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
    ]
    resources = [aws_ecr_repository.app.arn]
  }
  statement {
    sid       = "EKSDescribeForKubeconfig"
    effect    = "Allow"
    actions   = ["eks:DescribeCluster", "eks:AccessKubernetesApi"]
    resources = [module.eks.cluster_arn]
  }
  statement {
    # Required because aws_kms_key.ecr has an explicit key policy (see
    # ecr.tf) that delegates to IAM rather than granting principals
    # directly — without this statement, docker push/pull against the
    # KMS-encrypted repo fails with AccessDenied despite the ECR-level
    # permissions above looking sufficient.
    sid       = "KMSForECREncryption"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.ecr.arn]
  }
}

resource "aws_iam_role_policy" "deploy_permissions" {
  name   = "deploy-permissions"
  role   = aws_iam_role.github_actions_deploy.id
  policy = data.aws_iam_policy_document.deploy_permissions.json
}

# --- Role 2: terraform plan/apply (terraform.yml, main branch only) --------
# This role is intentionally broad — it provisions the VPC/EKS/ECR/IAM
# stack itself, so it needs the corresponding create/update/delete actions.
# The permissions boundary above stops it from being a path to full account
# takeover; branch restriction + required PR review + a manual-approval GitHub
# Environment (see terraform.yml) stop it from being a path to unreviewed
# infra changes. See SECURITY.md, "the CI-as-root problem", for the full
# writeup of this tradeoff.
resource "aws_iam_role" "github_actions_terraform" {
  name                 = "gha-secure-cicd-terraform"
  path                 = local.iam_role_path
  permissions_boundary = aws_iam_policy.ci_permissions_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github_actions.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = local.github_sub_main }
      }
    }]
  })
}

resource "aws_iam_role_policy" "terraform_permissions" {
  # Checkov's inline-skip parser only honors a comment whose line falls
  # *inside* the resource block (start_line < line < end_line) — a comment
  # placed above the resource, which is what the tool's own docs show, is
  # silently ignored. Confirmed empirically against checkov 3.3.9 before
  # relying on it here.
  #checkov:skip=CKV_AWS_290:Terraform-apply role provisions the VPC/EKS/ECR/IAM stack itself and needs the matching write actions; scoped by the permissions boundary above, branch=main-only OIDC trust, and the infra-apply manual-approval Environment. See SECURITY.md, "the CI-as-root problem".
  #checkov:skip=CKV_AWS_289:Same tradeoff as CKV_AWS_290 — see SECURITY.md, "the CI-as-root problem".
  #checkov:skip=CKV_AWS_355:Resource "*" is required for the ec2:*/eks:*/ecr:*/kms:*/logs:*/elasticloadbalancing:*/autoscaling:* actions above, which don't uniformly support resource-level scoping; capped by the permissions boundary instead. See SECURITY.md.
  #checkov:skip=CKV_AWS_287:Same tradeoff as CKV_AWS_290 — see SECURITY.md, "the CI-as-root problem".
  #checkov:skip=CKV_AWS_286:Same tradeoff as CKV_AWS_290 — see SECURITY.md, "the CI-as-root problem".
  name = "terraform-permissions"
  role = aws_iam_role.github_actions_terraform.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InfraProvisioning"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "eks:*",
          "ecr:*",
          "kms:*",
          "logs:*",
          "elasticloadbalancing:*",
          "autoscaling:*",
          "application-autoscaling:*",
          "iam:GetRole",
          "iam:GetPolicy",
          "iam:PassRole",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:TagRole",
          "iam:CreateOpenIDConnectProvider",
          "iam:GetOpenIDConnectProvider",
        ]
        Resource = "*"
      }
    ]
  })
}
