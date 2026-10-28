# Audit integrity and threat detection. Addresses T09, T10, T02.
resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = var.audit_bucket_name
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true # digest files make tampering detectable (T09)
  kms_key_id                    = aws_kms_key.secrets.arn
}

resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_guardduty_detector_feature" "eks_runtime" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"
}

# Central bucket policy (apply in the log-archive account): write-only for trail, deny delete/disable, TLS only.
data "aws_iam_policy_document" "audit_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::${var.audit_bucket_name}", "arn:aws:s3:::${var.audit_bucket_name}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "DenyObjectDeletion"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketVersioning"]
    resources = ["arn:aws:s3:::${var.audit_bucket_name}", "arn:aws:s3:::${var.audit_bucket_name}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}
# Also required in production (not shown): S3 Object Lock (compliance mode) on the audit bucket, an SCP denying
# cloudtrail:StopLogging/DeleteTrail and guardduty:Disable* for all but a break-glass role.
