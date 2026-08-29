locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 2)
}

data "aws_availability_zones" "available" {
  state = "available"
}

# terraform-aws-modules/vpc is the de facto standard module for this — hand
# rolling route tables/NAT/IGW wiring adds a lot of code for no security
# benefit and is a common source of subtle misconfig.
module "vpc" {
  #checkov:skip=CKV_TF_1:Registry module (not git-sourced) — a commit hash doesn't apply here; version = "~> 5.8" is the registry-equivalent pin, and CKV_TF_2 (which does apply) passes.
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.7"

  name = "${var.cluster_name}-vpc"
  cidr = var.vpc_cidr
  azs  = local.azs

  private_subnets = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 8)]

  enable_nat_gateway   = true
  single_nat_gateway   = true # cost tradeoff for a demo cluster; use one-per-AZ in prod
  enable_dns_hostnames = true

  # VPC Flow Logs — cheap, and it's the thing you wish you had during an
  # incident. Sent to CloudWatch Logs with a short retention for demo cost.
  enable_flow_log                                 = true
  create_flow_log_cloudwatch_log_group            = true
  create_flow_log_cloudwatch_iam_role             = true
  flow_log_cloudwatch_log_group_retention_in_days = 14

  # Tags EKS/the AWS Load Balancer Controller expect to find on subnets.
  public_subnet_tags = {
    "kubernetes.io/role/elb"                    = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"           = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}
