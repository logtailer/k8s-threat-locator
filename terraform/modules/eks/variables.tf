variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "cluster_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.29"
}

variable "vpc_id" {
  description = "ID of the VPC to deploy the cluster into"
  type        = string
}

variable "private_subnet_ids" {
  description = "IDs of the private subnets for node group placement"
  type        = list(string)
}

variable "environment" {
  description = "Deployment environment tag"
  type        = string
}

variable "project" {
  description = "Project name tag"
  type        = string
}

variable "ecr_repository_arn" {
  description = "ARN of the ECR repository — used to scope node IAM read policy"
  type        = string
}

variable "node_instance_type" {
  description = "EC2 instance type for the managed node group"
  type        = string
  default     = "t3.medium"
}

variable "desired_nodes" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 2
}

variable "min_nodes" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 1
}

variable "max_nodes" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 3
}

variable "cluster_public_access_cidrs" {
  description = "CIDR blocks permitted to reach the public Kubernetes API endpoint. Restrict to your IP or VPN range in production."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
