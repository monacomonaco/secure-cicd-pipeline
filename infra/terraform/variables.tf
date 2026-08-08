variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Short environment name, used in resource naming/tags."
  type        = string
  default     = "demo"
}

variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
  default     = "secure-cicd-demo"
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS control plane."
  type        = string
  default     = "1.30"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "node_instance_types" {
  description = "Instance types for the managed node group."
  type        = list(string)
  default     = ["t3.medium"]
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "node_min_size" {
  type    = number
  default = 1
}

variable "node_max_size" {
  type    = number
  default = 3
}

variable "cluster_endpoint_public_access" {
  description = <<-EOT
    Whether the EKS API endpoint is reachable from outside the VPC at all.
    Off by default — cluster_endpoint_private_access is always on, so
    kubectl works from inside the VPC (a bastion, VPN, or Cloud9). Flip
    this on only if you need to run kubectl from a laptop, and pair it
    with a tight cluster_endpoint_public_access_cidrs.
  EOT
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach the public Kubernetes API endpoint, only
    consulted when cluster_endpoint_public_access = true. Never set this to
    0.0.0.0/0 — Checkov (CKV_AWS_38/39) and demo/vulnerable-commit.patch
    both exist to catch exactly that mistake.
  EOT
  type        = list(string)
  default     = [] # must be set explicitly if public access is enabled
}

variable "github_repo" {
  description = "GitHub \"org/repo\" allowed to assume the CI OIDC roles."
  type        = string
  default     = "monacomonaco/secure-cicd-pipeline"
}

variable "ecr_repository_name" {
  description = "Name of the ECR repository the app image is pushed to."
  type        = string
  default     = "secure-cicd-demo/flask-api"
}
