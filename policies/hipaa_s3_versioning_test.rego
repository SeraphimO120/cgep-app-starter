package compliance.hipaa_s3_versioning_test

import rego.v1

import data.compliance.hipaa_s3_versioning

cfg_bucket := {"type": "aws_s3_bucket", "name": "uploads", "expressions": {}}

versioning(status) := {
	"type": "aws_s3_bucket_versioning",
	"name": "uploads",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"versioning_configuration": [{"status": {"constant_value": status}}],
	},
}

plan(rs) := {"configuration": {"root_module": {"resources": rs}}}

test_pass_enabled if {
	count(hipaa_s3_versioning.deny) == 0 with input as plan([cfg_bucket, versioning("Enabled")])
}

test_fail_missing if {
	count(hipaa_s3_versioning.deny) == 1 with input as plan([cfg_bucket])
}

test_fail_suspended if {
	count(hipaa_s3_versioning.deny) == 1 with input as plan([cfg_bucket, versioning("Suspended")])
}
