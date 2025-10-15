locals {
  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  oidc_issuer = replace(var.cluster_oidc_issuer_url, "https://", "")
}

resource "aws_iam_role" "app" {
  name = "${var.cluster_name}-irsa-app"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = var.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.oidc_issuer}:aud" = "sts.amazonaws.com"
            "${local.oidc_issuer}:sub" = "system:serviceaccount:${var.namespace}:${var.service_account_name}"
          }
        }
      }
    ]
  })

  tags = local.tags
}

resource "aws_iam_policy" "app_s3" {
  name        = "${var.cluster_name}-irsa-app-s3"
  description = "Least-privilege S3 read access for the app pod"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowS3ReadOnSpecificBucket"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [var.s3_bucket_arn, "${var.s3_bucket_arn}/*"]
      },
      {
        Sid       = "DenyAllOtherS3Actions"
        Effect    = "Deny"
        Action    = "s3:*"
        NotResource = [var.s3_bucket_arn, "${var.s3_bucket_arn}/*"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app_s3" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app_s3.arn

  depends_on = [aws_iam_role.app, aws_iam_policy.app_s3]
}

# Explicit deny on all other S3 actions ensures even future IAM grants
# cannot escalate the pod's S3 permissions beyond this bucket.
resource "aws_iam_role_policy" "app_s3_explicit_deny" {
  name = "deny-all-other-s3"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ExplicitDenyAllOtherBuckets"
        Effect   = "Deny"
        Action   = ["s3:*"]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:ResourceAccount" = ["${data.aws_caller_identity.current.account_id}"]
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}
