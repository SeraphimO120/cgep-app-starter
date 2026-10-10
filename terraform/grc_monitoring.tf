######################################################################
# Continuous monitoring and detection
#   AWS Config: records governed resource types and evaluates managed
#   rules that mirror the Rego gate, so drift in the live account is
#   caught between deploys.
#   EventBridge: alerts on (1) any Config rule going NON_COMPLIANT and
#   (2) control-relevant API calls made outside the pipeline.
# HIPAA 164.308(a)(1)(ii)(D) Information System Activity Review,
#       164.312(b) Audit Controls
######################################################################

# ---------- Config recorder ----------

resource "aws_iam_role" "config" {
  name = "${local.name_prefix}-config-${local.suffix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Config delivers snapshots to the CloudTrail bucket under config/.
resource "aws_iam_role_policy" "config_delivery" {
  name = "config-delivery"
  role = aws_iam_role.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DeliverSnapshots"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectAcl"]
        Resource = "${aws_s3_bucket.trail.arn}/config/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Sid      = "CheckBucketAcl"
        Effect   = "Allow"
        Action   = ["s3:GetBucketAcl"]
        Resource = aws_s3_bucket.trail.arn
      }
    ]
  })
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${local.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  # Only the resource types this system governs, which keeps cost to cents.
  recording_group {
    all_supported = false
    resource_types = [
      "AWS::S3::Bucket",
      "AWS::DynamoDB::Table",
      "AWS::KMS::Key",
      "AWS::IAM::Role",
      "AWS::Lambda::Function",
      "AWS::CloudTrail::Trail",
    ]
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${local.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.trail.id
  s3_key_prefix  = "config"
  depends_on     = [aws_config_configuration_recorder.main, aws_iam_role_policy.config_delivery]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# ---------- Managed rules: the live-state twin of the Rego gate ----------

locals {
  config_rules = {
    "s3-uploads-cmk" = {
      identifier  = "S3_DEFAULT_ENCRYPTION_KMS"
      control     = "164.312(a)(2)(iv)"
      types       = ["AWS::S3::Bucket"]
      resource_id = aws_s3_bucket.uploads.id
      params      = { kmsKeyArns = aws_kms_key.phi.arn }
    }
    "s3-evidence-cmk" = {
      identifier  = "S3_DEFAULT_ENCRYPTION_KMS"
      control     = "164.312(a)(2)(iv)"
      types       = ["AWS::S3::Bucket"]
      resource_id = aws_s3_bucket.evidence.id
      params      = { kmsKeyArns = aws_kms_key.phi.arn }
    }
    "dynamodb-cmk" = {
      identifier  = "DYNAMODB_TABLE_ENCRYPTED_KMS"
      control     = "164.312(a)(2)(iv)"
      types       = ["AWS::DynamoDB::Table"]
      resource_id = null
      params      = { kmsKeyArns = aws_kms_key.phi.arn }
    }
    "s3-tls-only" = {
      identifier  = "S3_BUCKET_SSL_REQUESTS_ONLY"
      control     = "164.312(e)(1)"
      types       = ["AWS::S3::Bucket"]
      resource_id = null
      params      = null
    }
    "s3-versioning" = {
      identifier  = "S3_BUCKET_VERSIONING_ENABLED"
      control     = "164.308(a)(7)(ii)(A)"
      types       = ["AWS::S3::Bucket"]
      resource_id = null
      params      = null
    }
    "kms-rotation" = {
      identifier  = "CMK_BACKING_KEY_ROTATION_ENABLED"
      control     = "164.312(a)(2)(iv)"
      types       = []
      resource_id = null
      params      = null
    }
    "cloudtrail-multi-region" = {
      identifier  = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
      control     = "164.312(b)"
      types       = []
      resource_id = null
      params      = null
    }
    "cloudtrail-log-validation" = {
      identifier  = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
      control     = "164.312(c)(1)"
      types       = []
      resource_id = null
      params      = null
    }
  }
}

resource "aws_config_config_rule" "hipaa" {
  for_each = local.config_rules

  name             = "${local.name_prefix}-${each.key}"
  description      = "HIPAA ${each.value.control}: AWS managed rule ${each.value.identifier}."
  input_parameters = each.value.params == null ? null : jsonencode(each.value.params)

  source {
    owner             = "AWS"
    source_identifier = each.value.identifier
  }

  dynamic "scope" {
    for_each = length(each.value.types) > 0 ? [1] : []
    content {
      compliance_resource_types = each.value.types
      compliance_resource_id    = each.value.resource_id
    }
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ---------- Alert routing ----------

# Alerts carry resource names and API call metadata, never PHI. The topic
# uses SNS default encryption rather than the CMK, because EventBridge can
# only publish to a CMK-encrypted topic if the key policy grants it. The
# email subscription is created outside Terraform so the subscriber address
# stays out of this public repo and its evidence bundles.
resource "aws_sns_topic" "grc_alerts" {
  name = "${local.name_prefix}-grc-alerts-${local.suffix}"
}

resource "aws_cloudwatch_event_rule" "config_noncompliant" {
  name        = "${local.name_prefix}-config-noncompliant"
  description = "Any HIPAA Config rule in this system evaluates a resource as NON_COMPLIANT."
  event_pattern = jsonencode({
    source        = ["aws.config"]
    "detail-type" = ["Config Rules Compliance Change"]
    detail = {
      configRuleName      = [{ prefix = "${local.name_prefix}-" }]
      newEvaluationResult = { complianceType = ["NON_COMPLIANT"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "config_noncompliant" {
  rule = aws_cloudwatch_event_rule.config_noncompliant.name
  arn  = aws_sns_topic.grc_alerts.arn
  input_transformer {
    input_paths = {
      rule     = "$.detail.configRuleName"
      resource = "$.detail.resourceId"
      type     = "$.detail.resourceType"
      time     = "$.time"
    }
    input_template = "\"[GRC ALERT] Control drift at <time>: <resource> (<type>) is NON_COMPLIANT with Config rule <rule>.\""
  }
}

# Changes to governed controls made by anyone other than the pipeline's
# apply role. Out-of-band changes bypass the Rego gate and its evidence.
resource "aws_cloudwatch_event_rule" "out_of_band_change" {
  name        = "${local.name_prefix}-out-of-band-change"
  description = "Control-relevant API call made outside the grc-gate apply role."
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    source        = ["aws.iam", "aws.kms", "aws.s3", "aws.cloudtrail", "aws.dynamodb", "aws.config"]
    detail = {
      eventName = [
        "PutRolePolicy", "DeleteRolePolicy", "AttachRolePolicy", "DetachRolePolicy",
        "CreatePolicyVersion", "UpdateAssumeRolePolicy",
        "DisableKey", "DisableKeyRotation", "ScheduleKeyDeletion", "PutKeyPolicy",
        "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketEncryption", "DeleteBucketEncryption",
        "PutBucketVersioning", "PutObjectLockConfiguration",
        "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
        "UpdateTable",
        "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteConfigRule", "DeleteDeliveryChannel",
      ]
      userIdentity = {
        arn = [{
          "anything-but" = { prefix = "arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.gha_apply.name}/" }
        }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "out_of_band_change" {
  rule = aws_cloudwatch_event_rule.out_of_band_change.name
  arn  = aws_sns_topic.grc_alerts.arn
  input_transformer {
    input_paths = {
      event  = "$.detail.eventName"
      source = "$.detail.eventSource"
      who    = "$.detail.userIdentity.arn"
      time   = "$.time"
    }
    input_template = "\"[GRC ALERT] Out-of-band change at <time>: <event> on <source> by <who>. Governed resources should change only through the grc-gate pipeline.\""
  }
}

resource "aws_sns_topic_policy" "grc_alerts" {
  arn = aws_sns_topic.grc_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.grc_alerts.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = [
            aws_cloudwatch_event_rule.config_noncompliant.arn,
            aws_cloudwatch_event_rule.out_of_band_change.arn,
          ]
        }
      }
    }]
  })
}

output "grc_alerts_topic_arn" {
  value = aws_sns_topic.grc_alerts.arn
}

output "config_rule_names" {
  value = [for r in aws_config_config_rule.hipaa : r.name]
}
