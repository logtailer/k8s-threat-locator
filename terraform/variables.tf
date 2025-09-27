variable "aws_region" {
  description = "AWS region to deploy resources into"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "k8s-threat-locator"
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS cluster. Align with EKS supported versions."
  type        = string
  default     = "1.29"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "environment" {
  description = "Deployment environment tag"
  type        = string
  default     = "dev"
}

variable "project" {
  description = "Project name tag applied to all resources"
  type        = string
  default     = "k8s-threat-locator"
}

variable "app_s3_bucket_name" {
  description = "Name of the S3 bucket the app pod needs read access to via IRSA"
  type        = string
}

variable "node_instance_type" {
  description = "EC2 instance type for EKS managed node group workers"
  type        = string
  default     = "t3.medium"
}
