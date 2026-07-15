variable "project" {
  description = "Project name — used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Deployment environment tag"
  type        = string
}

variable "account_id" {
  description = "AWS account ID — appended to the artifacts bucket name for global uniqueness"
  type        = string
}

variable "aws_region" {
  description = "AWS region where Lambda and supporting resources are deployed"
  type        = string
}

variable "kubeconfig_bucket" {
  description = "S3 bucket name that holds the Lambda kubeconfig"
  type        = string
}

variable "kubeconfig_key" {
  description = "S3 object key for the kubeconfig file"
  type        = string
  default     = "kubeconfig"
}

variable "kubeconfig_kms_key_arn" {
  description = "ARN of the KMS CMK used to encrypt the kubeconfig bucket"
  type        = string
}

variable "falcosidekick_role_arn" {
  description = "IAM role ARN used by Falcosidekick to publish alerts — only this principal may publish to the Falco alerts SNS topic"
  type        = string
}

variable "lambda_src_dir" {
  description = "Absolute path to the lambda/ source directory containing handler.py, triage.py, requirements.txt"
  type        = string
}

variable "reserved_concurrency" {
  description = "Max concurrent responder executions — caps fan-out during an alert wave so the K8s API isn't overwhelmed"
  type        = number
  default     = 10
}
