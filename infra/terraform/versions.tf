terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.64"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Remote state is intentionally NOT configured here — see backend.tf.example.
  # A local backend must never be used beyond a first `terraform init` on a
  # laptop; CI always needs a shared, locking remote backend.
}
