# METADATA
# title: GAP-01 S3 encryption with a customer-managed KMS key
# description: Every S3 bucket that can hold PHI must use SSE-KMS with a customer-managed key. CloudTrail log buckets are exempt (account activity, not PHI; see DECISIONS.md).
# custom:
#   gap: GAP-01
#   control_id: "164.312(a)(2)(iv)"
#   framework: hipaa
#   severity: high
#   remediation: Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm "aws:kms" and kms_master_key_id referencing an aws_kms_key.
package compliance.hipaa_s3_cmk

import rego.v1

resources := input.configuration.root_module.resources

deny contains msg if {
	some bucket in phi_buckets
	not has_cmk_encryption(bucket)
	msg := sprintf("[HIPAA 164.312(a)(2)(iv)] GAP-01 %s: not encrypted with SSE-KMS under a customer-managed key. Remediation: add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm \"aws:kms\" and kms_master_key_id set to an aws_kms_key.", [bucket])
}

buckets contains addr if {
	some r in resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

# Buckets that receive CloudTrail logs are the documented exception.
trail_buckets contains b if {
	some r in resources
	r.type == "aws_cloudtrail"
	some ref in r.expressions.s3_bucket_name.references
	some b in buckets
	refs_bucket(ref, b)
}

phi_buckets := buckets - trail_buckets

has_cmk_encryption(bucket) if {
	some r in resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	refs_bucket(ref, bucket)
	some rule in r.expressions.rule
	some sse in rule.apply_server_side_encryption_by_default
	sse.sse_algorithm.constant_value == "aws:kms"
	some key_ref in sse.kms_master_key_id.references
	startswith(key_ref, "aws_kms_key.")
}

refs_bucket(ref, b) if ref == b
refs_bucket(ref, b) if ref == sprintf("%s.id", [b])
refs_bucket(ref, b) if ref == sprintf("%s.bucket", [b])
