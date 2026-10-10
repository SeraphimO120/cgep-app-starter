# METADATA
# title: GAP-07 No wildcard actions in IAM Allow statements
# description: IAM policies must not grant service-wide wildcards (for example dynamodb:* or s3:*) or "*" in Allow statements.
# custom:
#   gap: GAP-07
#   control_id: "164.312(a)(1)"
#   framework: hipaa
#   severity: high
#   remediation: Replace wildcard actions with the specific API calls the workload makes.
package compliance.hipaa_iam_least_privilege

import rego.v1

policy_types := {"aws_iam_role_policy", "aws_iam_policy"}

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type in policy_types
	is_string(r.values.policy)
	doc := json.unmarshal(r.values.policy)
	some s in statements(doc)
	s.Effect == "Allow"
	some action in actions(s)
	is_wildcard(action)
	msg := sprintf("[HIPAA 164.312(a)(1)] GAP-07 %s: Allow statement grants wildcard action %q. Remediation: list only the specific actions the workload calls.", [r.address, action])
}

warn contains msg if {
	some r in input.planned_values.root_module.resources
	r.type in policy_types
	not policy_known(r)
	msg := sprintf("[HIPAA 164.312(a)(1)] GAP-07 %s: policy text is unknown until apply; wildcard check not verified at plan time.", [r.address])
}

policy_known(r) if is_string(r.values.policy)

statements(doc) := doc.Statement if is_array(doc.Statement)
statements(doc) := [doc.Statement] if is_object(doc.Statement)

actions(s) := s.Action if is_array(s.Action)
actions(s) := [s.Action] if is_string(s.Action)

is_wildcard(a) if a == "*"
is_wildcard(a) if endswith(a, ":*")
