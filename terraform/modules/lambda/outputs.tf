output "function_name" {
  description = "Name of the incident responder Lambda function"
  value       = aws_lambda_function.responder.function_name
}

output "function_arn" {
  description = "ARN of the incident responder Lambda function"
  value       = aws_lambda_function.responder.arn
}

output "falco_alerts_topic_arn" {
  description = "ARN of the Falco alerts SNS topic — wire this into Falcosidekick config"
  value       = aws_sns_topic.falco_alerts.arn
}

output "ops_alerts_topic_arn" {
  description = "ARN of the ops alerts SNS topic — subscribe your email/PagerDuty endpoint here"
  value       = aws_sns_topic.ops_alerts.arn
}

output "dlq_url" {
  description = "URL of the DLQ — monitor for failed quarantine attempts"
  value       = aws_sqs_queue.dlq.url
}

output "dlq_arn" {
  description = "ARN of the dead-letter queue"
  value       = aws_sqs_queue.dlq.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role — create an EKS access entry for this role"
  value       = aws_iam_role.lambda.arn
}
