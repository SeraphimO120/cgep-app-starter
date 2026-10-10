# Design Decisions

## Primary framework: HIPAA Security Rule

The Patient Intake API stores and processes PHI, which makes HIPAA a legal obligation the day the system goes live. SOC 2 answers one enterprise customer's request, and CMMC Level 2 depends on a federal pilot that may never close. I chose the obligation over the opportunities.

Scope stays honest about what code can prove. This build implements the Technical Safeguards (164.312) and the contingency requirement in 164.308(a)(7). Physical Safeguards (164.310) are inherited from AWS under the shared responsibility model and are not claimed here.

## Gap selection

Five gaps carry a primary HIPAA control and are detectable in a Terraform plan, so they anchor the policy suite.

| Gap | Remediation | HIPAA control |
|---|---|---|
| GAP-01 | Uploads bucket encrypted with SSE-KMS under a customer-managed key | 164.312(a)(2)(iv) |
| GAP-02 | DynamoDB table encrypted with the same customer-managed key | 164.312(a)(2)(iv) |
| GAP-03 | Uploads bucket policy denies any request not made over TLS | 164.312(e)(1) |
| GAP-04 | Versioning enabled on the uploads bucket | 164.308(a)(7) |
| GAP-07 | Lambda role reduced from dynamodb:* and s3:* to PutItem and PutObject on the uploads/ prefix | 164.312(a)(1) |

GAP-06 maps only to SOC 2 and CMMC. It carries no primary policy under HIPAA. If closed, it is closed in Terraform and cross-referenced to SOC 2 CC7.2.

## Encryption key

One customer-managed KMS key protects every PHI store and the evidence vault, with automatic rotation enabled. S3 Bucket Keys are on to reduce KMS request volume and cost. The 7-day deletion window fits a sandbox.

## Evidence vault: GOVERNANCE mode, 30-day retention

Every bundle is locked for 30 days, which keeps retention active through grading. GOVERNANCE mode allows an authorized principal to remove objects after review, so the sandbox can be cleaned up afterward. COMPLIANCE mode would block every deletion, by anyone, for the full 30 days. In production, evidence would move to COMPLIANCE mode with retention aligned to HIPAA's six-year documentation requirement (164.316(b)(2)).

## CloudTrail: AWS-managed encryption

The trail bucket uses SSE-S3 rather than the customer-managed key. Using the CMK would require granting CloudTrail rights in the key policy, and these logs record account activity, not PHI. Log-file validation is enabled, so tampering stays detectable regardless of the encryption key. This is a documented trade-off, not a gap.

## Open items

- Rego policies for the five gaps above, each citing its HIPAA control in the deny message
- GitHub Actions gate: plan, policy check, apply, sign, upload
- OSCAL component definition citing NIST SP 800-66 Rev. 2 as the catalog

