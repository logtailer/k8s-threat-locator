variable "cluster_name" {
  type = string
}

variable "oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider"
  type        = string
}

variable "cluster_oidc_issuer_url" {
  description = "OIDC issuer URL from the EKS cluster (without https://)"
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace the service account lives in"
  type        = string
  default     = "threat-demo"
}

variable "service_account_name" {
  description = "Name of the Kubernetes service account"
  type        = string
  default     = "app-sa"
}

variable "s3_bucket_arn" {
  description = "ARN of the S3 bucket the app pod needs read access to"
  type        = string
}

variable "environment" {
  type = string
}

variable "project" {
  type = string
}

variable "tags" {
  description = "Additional tags to merge onto IRSA resources"
  type        = map(string)
  default     = {}
}
