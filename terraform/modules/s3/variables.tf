variable "bucket_name" {
  description = "Name of the S3 bucket — must be globally unique"
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
