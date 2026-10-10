package compliance.hipaa_dynamodb_cmk_test

import rego.v1

import data.compliance.hipaa_dynamodb_cmk

table(exprs) := {"configuration": {"root_module": {"resources": [{"type": "aws_dynamodb_table", "name": "intake", "expressions": exprs}]}}}

test_pass_cmk if {
	count(hipaa_dynamodb_cmk.deny) == 0 with input as table({"server_side_encryption": [{
		"enabled": {"constant_value": true},
		"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
	}]})
}

test_fail_default_encryption if {
	count(hipaa_dynamodb_cmk.deny) == 1 with input as table({})
}

test_fail_enabled_without_cmk if {
	count(hipaa_dynamodb_cmk.deny) == 1 with input as table({"server_side_encryption": [{"enabled": {"constant_value": true}}]})
}

# Edge: encryption explicitly disabled with a key reference still fails.
test_fail_explicitly_disabled if {
	count(hipaa_dynamodb_cmk.deny) == 1 with input as table({"server_side_encryption": [{
		"enabled": {"constant_value": false},
		"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
	}]})
}
