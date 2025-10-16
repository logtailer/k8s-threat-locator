locals {
  common_tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

module "vpc" {
  source = "./modules/vpc"

  vpc_cidr     = var.vpc_cidr
  cluster_name = var.cluster_name
  environment  = var.environment
  project      = var.project
}

module "eks" {
  source = "./modules/eks"

  cluster_name       = var.cluster_name
  cluster_version    = var.cluster_version
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  environment        = var.environment
  project            = var.project
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
