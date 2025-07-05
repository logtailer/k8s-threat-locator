output "cluster_endpoint" {
  description = "EKS cluster API server endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "ecr_repository_url" {
  description = "ECR repository URL — use this as the image prefix in K8s manifests"
  value       = module.ecr.repository_url
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.vpc.private_subnet_ids
}

output "irsa_role_arn" {
  description = "IAM role ARN for IRSA — set this as the eks.amazonaws.com/role-arn annotation on the ServiceAccount"
  value       = module.irsa.role_arn
}

output "oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider"
  value       = module.eks.oidc_provider_arn
}

output "node_group_role_arn" {
  description = "IAM role ARN of the EKS node group"
  value       = module.eks.node_group_role_arn
}

output "ecr_repository_name" {
  description = "Name of the ECR repository"
  value       = module.ecr.repository_name
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = module.vpc.vpc_cidr
}

output "node_group_name" {
  description = "Name of the EKS managed node group"
  value       = module.eks.node_group_name
}

output "cluster_version" {
  description = "Kubernetes version running on the EKS cluster"
  value       = module.eks.cluster_version
}

output "cluster_certificate_authority_data" {
  description = "Base64-encoded CA data for the EKS cluster — used to build kubeconfig"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}
