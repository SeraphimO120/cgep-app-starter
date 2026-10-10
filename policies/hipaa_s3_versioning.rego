# METADATA
# title: GAP-04 S3 versioning enabled
# description: Every S3 bucket must have versioning enabled so overwritten or deleted objects can be recovered.
# custom:
#   gap: GAP-04
#   controls:
#     - "164.308(a)(7)(ii)(A)"
#   framework: hipaa
#   severity: medium
#   remediation: Add aws_s3_bucket_versioning with versioning_configuration status = "Enabled".
package compliance.hipaa_s3_versioning

import rego.v1

resources := input.configuration.root_module.resources

deny contains msg if {
	some r in resources
	r.type == "aws_s3_bucket"
	bucket := sprintf("aws_s3_bucket.%s", [r.name])
	not has_versioning(bucket)
	msg := sprintf("[HIPAA 164.308(a)(7)(ii)(A)] GAP-04 %s: versioning is not enabled, so overwritten PHI cannot be recovered. Remediation: add aws_s3_bucket_versioning with status = \"Enabled\".", [bucket])
}

has_versioning(bucket) if {
	some r in resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	refs_bucket(ref, bucket)
	some vc in r.expressions.versioning_configuration
	vc.status.constant_value == "Enabled"
}

refs_bucket(ref, b) if ref == b
refs_bucket(ref, b) if ref == sprintf("%s.id", [b])
refs_bucket(ref, b) if ref == sprintf("%s.bucket", [b])
