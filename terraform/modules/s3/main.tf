locals {
  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_key" "kubeconfig" {
  description             = "CMK for kubeconfig S3 bucket — encrypts kubeconfig at rest"
  deletion_window_in_days = 14
  enable_key_rotation     = true

  tags = merge(local.tags, {
    Name = "${var.bucket_name}-key"
  })
}

resource "aws_kms_alias" "kubeconfig" {
  name          = "alias/${var.bucket_name}"
  target_key_id = aws_kms_key.kubeconfig.key_id
}

resource "aws_s3_bucket" "kubeconfig" {
  bucket        = var.bucket_name
  force_destroy = false

  tags = merge(local.tags, {
    Name = var.bucket_name
  })
}

resource "aws_s3_bucket_versioning" "kubeconfig" {
  bucket = aws_s3_bucket.kubeconfig.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kubeconfig" {
  bucket = aws_s3_bucket.kubeconfig.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.kubeconfig.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "kubeconfig" {
  bucket = aws_s3_bucket.kubeconfig.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "kubeconfig" {
  bucket = aws_s3_bucket.kubeconfig.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}
