######################################################################
# GRC baseline: customer-managed encryption for PHI
# HIPAA 164.312(a)(2)(iv)
######################################################################

resource "aws_kms_key" "phi" {
  description             = "CMK for Acme Health PHI data stores"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}

# GAP-01: uploads bucket encrypted with the customer CMK
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}