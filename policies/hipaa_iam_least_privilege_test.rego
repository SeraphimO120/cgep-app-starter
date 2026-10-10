package compliance.hipaa_iam_least_privilege_test

import rego.v1

import data.compliance.hipaa_iam_least_privilege

plan(doc) := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"values": {"policy": json.marshal(doc)},
}]}}}

scoped := {"Version": "2012-10-17", "Statement": [
	{"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/t"},
	{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "arn:aws:s3:::b/uploads/*"},
]}

broad := {"Version": "2012-10-17", "Statement": [
	{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/t"},
	{"Effect": "Allow", "Action": "s3:*", "Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"]},
]}

deny_wildcard := {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}

test_pass_scoped_actions if {
	count(hipaa_iam_least_privilege.deny) == 0 with input as plan(scoped)
}

test_fail_service_wildcards if {
	count(hipaa_iam_least_privilege.deny) == 2 with input as plan(broad)
}

test_pass_wildcard_in_deny_statement if {
	count(hipaa_iam_least_privilege.deny) == 0 with input as plan(deny_wildcard)
}

test_warn_when_policy_unknown if {
	result := hipaa_iam_least_privilege with input as {"planned_values": {"root_module": {"resources": [{"address": "aws_iam_role_policy.lambda_inline", "type": "aws_iam_role_policy", "values": {}}]}}}
	count(result.deny) == 0
	count(result.warn) == 1
}

# Edge: a bare "*" action in a single (non-array) Statement on a managed policy.
test_fail_full_wildcard_single_statement if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_policy.ops",
		"type": "aws_iam_policy",
		"values": {"policy": json.marshal({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})},
	}]}}}
	count(hipaa_iam_least_privilege.deny) == 1 with input as inp
}

# Edge: scoped prefixes like s3:Get* are not service-wide wildcards.
test_pass_scoped_prefix_wildcard if {
	count(hipaa_iam_least_privilege.deny) == 0 with input as plan({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::b/*"}]})
}
