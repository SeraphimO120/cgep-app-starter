# METADATA
# title: GAP-02 DynamoDB encryption with a customer-managed KMS key
# description: Every DynamoDB table must enable server-side encryption with a customer-managed key, not the AWS-owned default.
# custom:
#   gap: GAP-02
#   control_id: "164.312(a)(2)(iv)"
#   framework: hipaa
#   severity: high
#   remediation: Add a server_side_encryption block with enabled = true and kms_key_arn referencing an aws_kms_key.
package compliance.hipaa_dynamodb_cmk

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	not has_cmk(r)
	msg := sprintf("[HIPAA 164.312(a)(2)(iv)] GAP-02 aws_dynamodb_table.%s: not encrypted with a customer-managed key. Remediation: add server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.<name>.arn }.", [r.name])
}

has_cmk(r) if {
	some sse in r.expressions.server_side_encryption
	sse.enabled.constant_value == true
	some key_ref in sse.kms_key_arn.references
	startswith(key_ref, "aws_kms_key.")
}
