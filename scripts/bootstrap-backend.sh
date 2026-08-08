#!/usr/bin/env bash
# One-time, run-by-hand bootstrap of the Terraform remote state backend.
# This can't live in the Terraform this repo manages: the state bucket has
# to exist before `terraform init` can use it as a backend.
#
# Usage: AWS_REGION=us-east-1 BUCKET=your-org-tfstate-secure-cicd-demo ./bootstrap-backend.sh
set -euo pipefail

: "${AWS_REGION:?set AWS_REGION}"
: "${BUCKET:?set BUCKET, e.g. your-org-tfstate-secure-cicd-demo}"
TABLE="${TABLE:-terraform-locks}"

echo "Creating S3 bucket: $BUCKET"
aws s3api create-bucket \
  --bucket "$BUCKET" \
  --region "$AWS_REGION" \
  $( [ "$AWS_REGION" != "us-east-1" ] && echo --create-bucket-configuration LocationConstraint="$AWS_REGION" )

aws s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket "$BUCKET" \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "Creating DynamoDB lock table: $TABLE"
aws dynamodb create-table \
  --table-name "$TABLE" \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region "$AWS_REGION"

echo "Done. Copy infra/terraform/backend.tf.example -> backend.tf and fill in:"
echo "  bucket = \"$BUCKET\""
echo "  region = \"$AWS_REGION\""
echo "  dynamodb_table = \"$TABLE\""
