# Remote state in S3 with DynamoDB locking.
# Run the bootstrap commands in README before `terraform init`:
#   aws s3 mb s3://k8s-threat-locator-tfstate
#   aws dynamodb create-table --table-name k8s-threat-locator-tflock ...
terraform {
  backend "s3" {
    bucket         = "k8s-threat-locator-tfstate"
    key            = "k8s-threat-locator/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "k8s-threat-locator-tflock"
    # kms_key_id is optional — set to your CMK ARN for customer-managed encryption
  }
}
