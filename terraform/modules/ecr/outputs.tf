output "repository_url" {
  description = "Full URL of the ECR repository — use this in the K8s deployment image field"
  value       = aws_ecr_repository.this.repository_url
}

output "repository_arn" {
  description = "ARN of the ECR repository — used to scope IAM policies"
  value       = aws_ecr_repository.this.arn
}

output "registry_id" {
  description = "Registry ID (AWS account ID) owning this repository"
  value       = aws_ecr_repository.this.registry_id
}

output "repository_name" {
  description = "Name of the ECR repository"
  value       = aws_ecr_repository.this.name
}
