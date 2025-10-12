output "role_arn" {
  description = "ARN of the IAM role — annotate the K8s ServiceAccount with this value"
  value       = aws_iam_role.app.arn
}

output "role_name" {
  description = "Name of the IAM role"
  value       = aws_iam_role.app.name
}

output "s3_policy_arn" {
  description = "ARN of the managed S3 read policy attached to the IRSA role"
  value       = aws_iam_policy.app_s3.arn
}
