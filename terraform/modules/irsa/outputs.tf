output "role_arn" {
  description = "ARN of the IAM role — annotate the K8s ServiceAccount with this value"
  value       = aws_iam_role.app.arn
}
