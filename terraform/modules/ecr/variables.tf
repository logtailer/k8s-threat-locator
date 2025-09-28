variable "repository_name" {
  description = "Name of the ECR repository"
  type        = string
}

variable "environment" {
  description = "Deployment environment tag"
  type        = string
}

variable "project" {
  description = "Project name tag"
  type        = string
}

variable "image_tag_mutability" {
  description = "Image tag mutability setting for the ECR repository"
  type        = string
  default     = "IMMUTABLE"
}
