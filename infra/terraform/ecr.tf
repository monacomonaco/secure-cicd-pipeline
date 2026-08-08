# An explicit key policy (Checkov CKV2_AWS_64) rather than relying on the
# implicit AWS default. The root statement below is the standard
# AWS-recommended pattern: it delegates authorization to IAM policies
# instead of hardcoding every allowed principal into the key policy itself
# — the actual push/pull grant lives on aws_iam_role_policy.deploy_permissions
# in oidc-github.tf (kms:Decrypt/GenerateDataKey/DescribeKey, scoped to this
# key's ARN). Without both halves present, ECR's KMS encryption silently
# breaks docker push/pull with AccessDenied even though the ECR-level IAM
# permissions look correct.
data "aws_iam_policy_document" "ecr_kms" {
  statement {
    #checkov:skip=CKV_AWS_111:This is a KMS key policy, not an IAM identity policy — "resources" here is inherently scoped to only the key this policy is attached to, so kms:* / "*" is AWS's own documented "enable IAM user permissions" baseline statement, not an unconstrained grant.
    #checkov:skip=CKV_AWS_356:Same key-policy-vs-IAM-policy distinction as CKV_AWS_111 above.
    #checkov:skip=CKV_AWS_109:Same key-policy-vs-IAM-policy distinction as CKV_AWS_111 above.
    sid    = "EnableRootAccountPermissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "ecr" {
  description             = "Encrypts the ${var.ecr_repository_name} ECR repository"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ecr_kms.json
}

resource "aws_ecr_repository" "app" {
  name = var.ecr_repository_name

  # Immutable tags: once :sha-abc123 is pushed it can never be silently
  # overwritten. Combined with cosign signing this means a signature always
  # refers to exactly one, permanent set of bytes.
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      }
    ]
  })
}

# Repository policy: only the CI deploy role (and the account root, for
# break-glass) may push/pull. No public or cross-account access.
data "aws_iam_policy_document" "ecr_repo_policy" {
  statement {
    sid    = "AllowCIPushPull"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.github_actions_deploy.arn]
    }
    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
    ]
  }
}

resource "aws_ecr_repository_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy     = data.aws_iam_policy_document.ecr_repo_policy.json
}
