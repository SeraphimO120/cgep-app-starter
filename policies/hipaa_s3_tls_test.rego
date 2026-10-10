package compliance.hipaa_s3_tls_test

import rego.v1

import data.compliance.hipaa_s3_tls

cfg_bucket := {"type": "aws_s3_bucket", "name": "uploads", "expressions": {}}

cfg_policy := {
	"type": "aws_s3_bucket_policy",
	"name": "uploads",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
}

tls_doc := {"Version": "2012-10-17", "Statement": [{
	"Sid": "DenyInsecureTransport",
	"Effect": "Deny",
	"Principal": "*",
	"Action": "s3:*",
	"Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
	"Condition": {"Bool": {"aws:SecureTransport": "false"}},
}]}

other_doc := {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}

plan(cfg, pv) := {
	"configuration": {"root_module": {"resources": cfg}},
	"planned_values": {"root_module": {"resources": pv}},
}

pv_policy(doc) := [{"address": "aws_s3_bucket_policy.uploads", "type": "aws_s3_bucket_policy", "values": {"policy": json.marshal(doc)}}]

test_pass_tls_deny if {
	count(hipaa_s3_tls.deny) == 0 with input as plan([cfg_bucket, cfg_policy], pv_policy(tls_doc))
}

test_fail_no_bucket_policy if {
	count(hipaa_s3_tls.deny) == 1 with input as plan([cfg_bucket], [])
}

test_fail_policy_without_tls_deny if {
	count(hipaa_s3_tls.deny) == 1 with input as plan([cfg_bucket, cfg_policy], pv_policy(other_doc))
}

test_warn_when_policy_unknown if {
	result := hipaa_s3_tls with input as plan([cfg_bucket, cfg_policy], [{"address": "aws_s3_bucket_policy.uploads", "type": "aws_s3_bucket_policy", "values": {}}])
	count(result.deny) == 0
	count(result.warn) == 1
}
