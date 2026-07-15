locals {
  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  # Hash source files so that code changes trigger a rebuild and Lambda redeploy.
  source_hash = sha256(join(",", [
    filesha256("${var.lambda_src_dir}/handler.py"),
    filesha256("${var.lambda_src_dir}/triage.py"),
    filesha256("${var.lambda_src_dir}/requirements.txt"),
  ]))
}

# ── Artifacts S3 bucket ────────────────────────────────────────────────────────
# Uses SSE-S3 (not CMK) so Lambda service can read the deployment package
# without needing extra KMS permissions.

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.project}-lambda-artifacts-${var.account_id}"
  force_destroy = true

  tags = merge(local.tags, {
    Name = "${var.project}-lambda-artifacts"
  })
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ── Build + upload Lambda package ─────────────────────────────────────────────
# Runs a Docker-based linux/amd64 build so cryptography binaries are correct
# regardless of the host platform (e.g. Apple Silicon).

resource "null_resource" "build_and_upload" {
  triggers = {
    source_hash = local.source_hash
    bucket      = aws_s3_bucket.artifacts.bucket
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail
      BUILD_DIR=$(mktemp -d)
      docker run --rm --platform linux/amd64 \
        --entrypoint /bin/sh \
        -v '${var.lambda_src_dir}:/src:ro' \
        -v "$BUILD_DIR:/build" \
        public.ecr.aws/lambda/python:3.13 \
        -c "pip install -r /src/requirements.txt -t /build -q && cp /src/handler.py /src/triage.py /build/"
      ZIP_PATH="$BUILD_DIR/lambda.zip"
      (cd "$BUILD_DIR" && zip -r "$ZIP_PATH" . -x '*.pyc' -x '__pycache__/*' -q)
      aws s3 cp "$ZIP_PATH" "s3://${aws_s3_bucket.artifacts.bucket}/lambda.zip" --region "${var.aws_region}"
      rm -rf "$BUILD_DIR"
    EOT
  }

  depends_on = [aws_s3_bucket.artifacts]
}

# ── IAM execution role ─────────────────────────────────────────────────────────

resource "aws_iam_role" "lambda" {
  name = "${var.project}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy" "s3_kubeconfig_read" {
  name = "S3KubeconfigRead"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowKubeconfigGet"
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "arn:aws:s3:::${var.kubeconfig_bucket}/${var.kubeconfig_key}"
    }]
  })
}

resource "aws_iam_role_policy" "kms_decrypt" {
  name = "KmsDecryptKubeconfig"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowDecryptKubeconfigKey"
      Effect   = "Allow"
      Action   = "kms:Decrypt"
      Resource = var.kubeconfig_kms_key_arn
    }]
  })
}

resource "aws_iam_role_policy" "cloudwatch_logs" {
  name = "CloudWatchLogs"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/${var.project}-responder:*"
    }]
  })
}

resource "aws_iam_role_policy" "cloudwatch_metrics" {
  name = "CloudWatchMetrics"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "cloudwatch:PutMetricData"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "dlq_send" {
  name = "DLQSendMessage"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.dlq.arn
    }]
  })
}

resource "aws_iam_role_policy" "sns_publish_ops" {
  name = "SnsPublishOpsAlerts"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sns:Publish"
      Resource = aws_sns_topic.ops_alerts.arn
    }]
  })
}

# ── SNS topics ─────────────────────────────────────────────────────────────────

resource "aws_sns_topic" "falco_alerts" {
  name = "falco-alerts"
  tags = local.tags
}

resource "aws_sns_topic_policy" "falco_alerts" {
  arn = aws_sns_topic.falco_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowFalcosidekickPublish"
        Effect    = "Allow"
        Principal = { AWS = var.falcosidekick_role_arn }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.falco_alerts.arn
      },
      {
        Sid       = "DenyPublishFromOtherPrincipals"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.falco_alerts.arn
        Condition = {
          ArnNotEquals = {
            "aws:PrincipalArn" = var.falcosidekick_role_arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic" "ops_alerts" {
  name = "${var.project}-ops-alerts"
  tags = local.tags
}

# ── SQS dead-letter queue ──────────────────────────────────────────────────────

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.project}-dlq"
  message_retention_seconds = 1209600 # 14 days
  sqs_managed_sse_enabled   = true

  tags = local.tags
}

# ── Lambda function ────────────────────────────────────────────────────────────

resource "aws_lambda_function" "responder" {
  function_name = "${var.project}-responder"
  description   = "Quarantines compromised Kubernetes pods on Falco alert"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.13"
  handler       = "handler.handler"
  memory_size   = 256
  timeout       = 60

  # Cap fan-out: an alert wave (or a runaway Falco rule) could otherwise spawn
  # unbounded concurrent invocations, each writing to the K8s API.
  reserved_concurrent_executions = var.reserved_concurrency

  s3_bucket        = aws_s3_bucket.artifacts.bucket
  s3_key           = "lambda.zip"
  source_code_hash = base64sha256(local.source_hash)

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      KUBECONFIG_BUCKET    = var.kubeconfig_bucket
      KUBECONFIG_KEY       = var.kubeconfig_key
      OPS_ALERTS_TOPIC_ARN = aws_sns_topic.ops_alerts.arn
    }
  }

  tags = local.tags

  depends_on = [null_resource.build_and_upload]
}

resource "aws_lambda_permission" "sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.falco_alerts.arn
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.falco_alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.responder.arn

  filter_policy_scope = "MessageBody"
  filter_policy = jsonencode({
    priority = ["ERROR", "CRITICAL", "Error", "Critical"]
  })
}

# ── CloudWatch alarms ──────────────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "quarantine_rate" {
  alarm_name          = "${var.project}-quarantine-rate"
  alarm_description   = "Fires when more than 5 pods are quarantined in 5 minutes — possible attack wave or runaway rule"
  namespace           = var.project
  metric_name         = "QuarantineApplied"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.ops_alerts.arn]
  ok_actions    = [aws_sns_topic.ops_alerts.arn]

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "${var.project}-dlq-depth"
  alarm_description   = "Fires when failed quarantine attempts accumulate in the DLQ"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }

  alarm_actions = [aws_sns_topic.ops_alerts.arn]
  ok_actions    = [aws_sns_topic.ops_alerts.arn]

  tags = local.tags
}
