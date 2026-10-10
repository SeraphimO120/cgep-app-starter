package compliance.hipaa_s3_cmk_test

import rego.v1

import data.compliance.hipaa_s3_cmk

bucket(name) := {"type": "aws_s3_bucket", "name": name, "expressions": {}}

sse(name, bucket_name, algo) := {
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"name": name,
	"expressions": {
		"bucket": {"references": [sprintf("aws_s3_bucket.%s.id", [bucket_name]), sprintf("aws_s3_bucket.%s", [bucket_name])]},
		"rule": [{"apply_server_side_encryption_by_default": [{
			"sse_algorithm": {"constant_value": algo},
			"kms_master_key_id": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
		}]}],
	},
}

trail := {
	"type": "aws_cloudtrail",
	"name": "mgmt",
	"expressions": {"s3_bucket_name": {"references": ["aws_s3_bucket.trail.id", "aws_s3_bucket.trail"]}},
}

plan(rs) := {"configuration": {"root_module": {"resources": rs}}}

test_pass_cmk_encrypted if {
	count(hipaa_s3_cmk.deny) == 0 with input as plan([bucket("uploads"), sse("uploads", "uploads", "aws:kms")])
}

test_fail_no_encryption_config if {
	count(hipaa_s3_cmk.deny) == 1 with input as plan([bucket("uploads")])
}

test_fail_sse_s3_only if {
	count(hipaa_s3_cmk.deny) == 1 with input as plan([bucket("uploads"), sse("uploads", "uploads", "AES256")])
}

test_pass_trail_bucket_exempt if {
	count(hipaa_s3_cmk.deny) == 0 with input as plan([bucket("trail"), trail])
}

# Edge: an AWS-managed key passed by alias string is not a customer-managed key.
test_fail_aws_managed_alias if {
	cfg := {
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"name": "uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
			"rule": [{"apply_server_side_encryption_by_default": [{
				"sse_algorithm": {"constant_value": "aws:kms"},
				"kms_master_key_id": {"constant_value": "alias/aws/s3"},
			}]}],
		},
	}
	count(hipaa_s3_cmk.deny) == 1 with input as plan([bucket("uploads"), cfg])
}

# Edge: two buckets, only one encrypted, reports exactly the unencrypted one.
test_fail_only_unencrypted_bucket_reported if {
	result := hipaa_s3_cmk.deny with input as plan([bucket("uploads"), bucket("exports"), sse("uploads", "uploads", "aws:kms")])
	count(result) == 1
	some msg in result
	contains(msg, "aws_s3_bucket.exports")
}
