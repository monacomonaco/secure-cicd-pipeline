provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "secure-cicd-pipeline"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
