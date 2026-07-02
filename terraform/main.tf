locals {
  common_tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    CreatedAt   = timestamp()
  }

  sns_topic_arn     = "arn:aws:sns:${var.aws_region}:${data.aws_caller_identity.current.account_id}:falco-alerts"
  oidc_issuer_plain = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
}

data "aws_caller_identity" "current" {}

module "vpc" {
  source = "./modules/vpc"

  vpc_cidr     = var.vpc_cidr
  cluster_name = var.cluster_name
  environment  = var.environment
  project      = var.project
}

module "eks" {
  source = "./modules/eks"

  cluster_name        = var.cluster_name
  cluster_version     = var.cluster_version
  vpc_id              = module.vpc.vpc_id
  private_subnet_ids  = module.vpc.private_subnet_ids
  environment         = var.environment
  project             = var.project
  ecr_repository_arn          = module.ecr.repository_arn
  cluster_public_access_cidrs = var.eks_public_access_cidrs
  node_instance_type          = var.node_instance_type
  desired_nodes       = var.desired_nodes
  min_nodes           = var.min_nodes
  max_nodes           = var.max_nodes
}

module "ecr" {
  source = "./modules/ecr"

  repository_name = var.project
  environment     = var.environment
  project         = var.project
}

module "irsa" {
  source = "./modules/irsa"

  cluster_name            = var.cluster_name
  oidc_provider_arn       = module.eks.oidc_provider_arn
  cluster_oidc_issuer_url = module.eks.cluster_oidc_issuer_url
  s3_bucket_arn           = "arn:aws:s3:::${var.app_s3_bucket_name}"
  environment             = var.environment
  project                 = var.project
}

resource "aws_iam_role" "falcosidekick" {
  name = "${var.cluster_name}-falcosidekick"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.oidc_issuer_plain}:aud" = "sts.amazonaws.com"
            "${local.oidc_issuer_plain}:sub" = "system:serviceaccount:falco:falco-falcosidekick"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-falcosidekick"
  })
}

resource "aws_iam_role_policy" "falcosidekick_sns" {
  name = "sns-publish-falco-alerts"
  role = aws_iam_role.falcosidekick.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowPublishToFalcoAlertsTopic"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = local.sns_topic_arn
      }
    ]
  })
}
