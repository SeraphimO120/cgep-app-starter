# METADATA
# title: GAP-03 S3 buckets deny non-TLS requests
# description: Every S3 bucket must have a bucket policy that denies requests where aws:SecureTransport is false.
# custom:
#   gap: GAP-03
#   control_id: "164.312(e)(1)"
#   framework: hipaa
#   severity: high
#   remediation: Attach an aws_s3_bucket_policy with a Deny statement conditioned on aws:SecureTransport = false.
package compliance.hipaa_s3_tls

import rego.v1

resources := input.configuration.root_module.resources

buckets contains addr if {
	some r in resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

# Bucket policy resources (by address) attached to each bucket.
policy_for(bucket) := {addr |
	some r in resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	refs_bucket(ref, bucket)
	addr := sprintf("aws_s3_bucket_policy.%s", [r.name])
}

deny contains msg if {
	some bucket in buckets
	count(policy_for(bucket)) == 0
	msg := sprintf("[HIPAA 164.312(e)(1)] GAP-03 %s: no bucket policy, so plaintext HTTP requests are not denied. Remediation: add an aws_s3_bucket_policy denying aws:SecureTransport = false.", [bucket])
}

# A policy exists and its rendered JSON is known at plan time, but it has no TLS deny.
deny contains msg if {
	some bucket in buckets
	some addr in policy_for(bucket)
	doc := known_policy(addr)
	not has_tls_deny(doc)
	msg := sprintf("[HIPAA 164.312(e)(1)] GAP-03 %s: bucket policy %s does not deny requests where aws:SecureTransport is false.", [bucket, addr])
}

# Policy text unknown until apply (new resources): flag for review, do not block.
warn contains msg if {
	some bucket in buckets
	some addr in policy_for(bucket)
	not known_policy(addr)
	msg := sprintf("[HIPAA 164.312(e)(1)] GAP-03 %s: policy text for %s is unknown until apply; TLS deny not verified at plan time.", [bucket, addr])
}

known_policy(addr) := json.unmarshal(r.values.policy) if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	is_string(r.values.policy)
}

has_tls_deny(doc) if {
	some s in statements(doc)
	s.Effect == "Deny"
	v := s.Condition.Bool["aws:SecureTransport"]
	is_false(v)
}

statements(doc) := doc.Statement if is_array(doc.Statement)
statements(doc) := [doc.Statement] if is_object(doc.Statement)

is_false(v) if v == "false"
is_false(v) if v == false

is_false(v) if {
	is_array(v)
	some x in v
	x in {"false", false}
}

refs_bucket(ref, b) if ref == b
refs_bucket(ref, b) if ref == sprintf("%s.id", [b])
refs_bucket(ref, b) if ref == sprintf("%s.bucket", [b])
