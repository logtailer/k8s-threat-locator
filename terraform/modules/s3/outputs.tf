output "bucket_name" {
  description = "Name of the kubeconfig S3 bucket"
  value       = aws_s3_bucket.kubeconfig.id
}

output "bucket_arn" {
  description = "ARN of the kubeconfig S3 bucket"
  value       = aws_s3_bucket.kubeconfig.arn
}

output "kms_key_arn" {
  description = "ARN of the KMS CMK used to encrypt kubeconfig at rest — grant Lambda kms:Decrypt on this key"
  value       = aws_kms_key.kubeconfig.arn
}
