# terraform-aws-modules/eks is the industry-standard module (it wires up
# IRSA, the OIDC provider for the cluster itself, node IAM roles, security
# groups, etc. correctly — the stuff that's easy to get subtly wrong by
# hand). Where security-relevant knobs exist, they're set explicitly below
# rather than left on module defaults.
module "eks" {
  #checkov:skip=CKV_TF_1:Registry module (not git-sourced) — a commit hash doesn't apply here; version = "~> 20.24" is the registry-equivalent pin, and CKV_TF_2 (which does apply) passes.
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.25"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Every IAM role this module creates (cluster role, node role, IRSA roles)
  # lives under the same path and carries the same permissions boundary as
  # the CI roles in oidc-github.tf — one blast-radius cap for the whole stack.
  iam_role_path                 = "/secure-cicd-pipeline/"
  iam_role_permissions_boundary = aws_iam_policy.ci_permissions_boundary.arn

  # Nodes and control plane talk over the private endpoint; public access is
  # off unless explicitly enabled (see variables.tf).
  cluster_endpoint_private_access      = true
  cluster_endpoint_public_access       = var.cluster_endpoint_public_access
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs

  # Encrypt Kubernetes Secrets at rest with a customer-managed KMS key
  # (envelope encryption on top of the etcd volume encryption EKS already
  # does). This is the #1 Checkov/Terrascan finding on unmanaged EKS code.
  cluster_encryption_config = {
    resources = ["secrets"]
  }

  # Ship control-plane audit/api logs to CloudWatch — required to reconstruct
  # "who did what" during an incident, and a control called out in SECURITY.md.
  cluster_enabled_log_types              = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  cloudwatch_log_group_retention_in_days = 30

  # Modern EKS Cluster Access Management (access entries) instead of the
  # legacy aws-auth ConfigMap — lets us grant the CI role kubectl access
  # scoped to a namespace instead of cluster-admin.
  authentication_mode                      = "API"
  enable_cluster_creator_admin_permissions = true

  access_entries = {
    github_actions_deploy = {
      principal_arn = aws_iam_role.github_actions_deploy.arn
      policy_associations = {
        namespace_edit = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"
          access_scope = {
            type       = "namespace"
            namespaces = ["secure-demo"]
          }
        }
      }
    }
  }

  eks_managed_node_groups = {
    default = {
      instance_types = var.node_instance_types
      capacity_type  = "ON_DEMAND"

      min_size     = var.node_min_size
      max_size     = var.node_max_size
      desired_size = var.node_desired_size

      # EKS-optimized AL2023 AMI, gp3 root volume, encrypted.
      ami_type  = "AL2023_x86_64_STANDARD"
      disk_size = 30
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 30
            volume_type           = "gp3"
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      # Force IMDSv2 and cap hop limit — blocks the classic
      # SSRF-to-instance-credentials pivot (the Capital One breach pattern).
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 1
      }

      labels = {
        role = "app"
      }
    }
  }

  tags = {
    Project = "secure-cicd-pipeline"
  }
}
