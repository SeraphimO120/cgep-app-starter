# Decision Log

Decisions in the order they were made, with the reason and the trade-off. [WRITEUP.md](WRITEUP.md) tells the same story as a narrative for stakeholders; this file is the record.

## 2026-10-04: Design and baseline

**1. Primary framework: HIPAA Security Rule.**
The Patient Intake API stores PHI, which makes HIPAA a legal obligation the day the system goes live. SOC 2 answers one enterprise customer's request, and CMMC Level 2 depends on a federal pilot that may never close. Scope: Technical Safeguards (164.312) plus 164.308(a)(7)(ii)(A). Physical Safeguards (164.310) are inherited from AWS and not claimed. SOC 2 and CMMC appear only as cross-references.

**2. Gap selection: GAP-01, 02, 03, 04, 07.**
Each carries a primary HIPAA control and is visible in a Terraform plan, which is what makes a plan-time gate meaningful. GAP-06 maps only to SOC 2 and CMMC, so it cannot carry a primary policy under HIPAA. GAP-05 and GAP-08 were deferred for time; see WRITEUP.md for the approach to each.

**3. One customer-managed KMS key for every PHI store and the evidence vault.**
Rotation on. S3 Bucket Keys on to cut KMS request volume and cost. 7-day deletion window, which fits a sandbox. One key keeps the custody story simple; production would split keys by data class so a single key policy does not govern everything.

**4. Lambda reduced to what the handler actually calls.**
The handler only calls `PutItem` and `PutObject`, so the role grants `dynamodb:PutItem` on the table, `s3:PutObject` on `uploads/*`, and the KMS actions for the one key the stores now use. The first smoke test after this change returned a 500; a retry 60 seconds later passed. IAM and encryption changes need a short propagation window, which matters for any automated post-deploy test.

**5. Evidence vault: Object Lock GOVERNANCE mode, 30-day default retention.**
Retention covers the grading window and the sandbox can still be cleaned up by a principal holding `s3:BypassGovernanceRetention`. COMPLIANCE mode would block every deletion by anyone for 30 days. Production: COMPLIANCE mode, retention aligned to HIPAA's six-year documentation requirement (164.316(b)(2)).

**6. CloudTrail bucket on SSE-S3, not the CMK.**
Using the CMK would mean granting CloudTrail rights in the key policy, and the logs record account activity, not PHI. Log-file validation keeps tampering detectable regardless of the key. Documented trade-off, not a gap.

## 2026-10-10: Policy, pipeline, OSCAL

**7. Policies read plan references, not values.**
At plan time many values are unknown, but `configuration` references are always present, so the policies ask "is an encryption resource wired to this bucket?" rather than comparing names. Additional rules:
- `hipaa_s3_cmk` exempts CloudTrail log buckets by detecting which bucket an `aws_cloudtrail` resource writes to, not by name, so the exemption cannot be claimed by renaming a PHI bucket.
- `hipaa_iam_least_privilege` checks Allow statements only, because the TLS Deny statements correctly use `s3:*`.
- `hipaa_s3_tls` and `hipaa_iam_least_privilege` warn instead of failing when the rendered policy JSON is unknown (brand-new resources), so a first deploy is not blocked. Against the running stack both evaluate fully.
- Metadata follows the starter's convention: `framework`, `controls`, `severity`, `remediation`. Every deny message cites the 164.x control.

**8. TLS deny added to the CloudTrail bucket.**
Writing `hipaa_s3_tls` exposed that the trail bucket built on 10-04 had no TLS deny. Fixed the bucket rather than exempting it.

**9. Remote state in S3 with native locking.**
The pipeline cannot read state on a laptop. State moved to a versioned bucket with public access blocked and Terraform's native S3 lockfile (Terraform 1.10 or later), so no DynamoDB lock table is needed. The bucket was created with the AWS CLI because Terraform cannot create the bucket that holds its own state, which leaves it outside the policy suite. Its name uses the deployment suffix, not the account ID, because the repo is public.

**10. Two CI roles instead of one.**
Pull requests assume a plan role: `ReadOnlyAccess`, the state lockfile, and evidence upload, with `kms:GenerateDataKey` but no `kms:Decrypt`, so an untrusted PR can neither change infrastructure nor read PHI. Only pushes to `main` assume the apply role. Trade-off: the apply role holds `AdministratorAccess`; a scoped deploy policy is next-sprint work.

**11. OIDC trust pinned to GitHub's immutable subject.**
The first run failed because GitHub issues this repo's tokens as `repo:SeraphimO120@324516250/cgep-app-starter@1404925327:...`. Kept the immutable form rather than switching the repo back to name-based subjects: a released name can be claimed by someone else, a numeric ID cannot.

**12. Pipeline built from the course's reference workflow.**
Adapted, not rewritten: two-role switch, an apply step, five named steps (Plan, Policy check, Apply, Sign, Upload), and run metadata plus policy test output in every bundle. tfsec was dropped because it is deprecated and was first on the scope-cut list. Evidence is signed and stored even when the gate fails; the job fails last. Each run also publishes the bundle as a GitHub Actions artifact so a grader without AWS access can verify it.

**13. Tool versions pinned to match local tooling.**
Terraform 1.16.5, Conftest 0.71.0, Cosign v3.1.3. Older Terraform cannot read state written by newer Terraform, and Cosign v3 changed its bundle format, so mismatched signing and verifying versions were a real risk.

**14. Apply on merge, no manual approval gate.**
The gate is the reviewer for a single-engineer system, and apply runs only with zero policy failures. Branch protection on `main` requires the `grc-gate` check; admins are exempt so the final commits could land. Production: enforce for admins and add a GitHub environment with a required reviewer.

**15. Single AWS account, us-east-1.**
Acceptable for 30 days per the brief; us-east-1 is the starter default and HIPAA sets no residency requirement. The weak point is that an administrator in the audited account could bypass GOVERNANCE retention. Production: dedicated log-archive account in COMPLIANCE mode.

**16. OSCAL catalog: NIST SP 800-66 Rev. 2.**
No official OSCAL catalog exists for HIPAA, so the component cites SP 800-66 Rev. 2 as `source` and carries each 164.x citation as a prop, with SOC 2 and CMMC cross-references as secondary props. 164.312(d) is marked partial: the pipeline authenticates with OIDC, but the intake API accepts unauthenticated requests.

**17. Verification pinned to this workflow's identity.**
The reference verify script accepted any signer (`.*`). `scripts/verify-evidence.sh` requires the certificate identity to be this repo's `grc-gate.yml`, which proves who signed, not just that something was signed.

## 2026-10-10: After first review

**18. Continuous monitoring with AWS Config managed rules.**
Eight managed rules mirror the Rego gate against the live account, each tagged with its 164.x control. Managed over custom rules because AWS maintains them and there is no rule code to keep correct. The recorder covers only the six resource types this system governs, which keeps cost to cents, and delivers to the CloudTrail bucket under `config/` instead of a new bucket. KMS rules are pinned to the PHI key ARN, so encryption under any other key fails.

**19. Two alert paths: non-compliance and out-of-band change.**
EventBridge routes NON_COMPLIANT Config results, and control-relevant API calls by any identity other than the apply role, to one SNS topic. The second path exists because out-of-band changes skip the gate and its evidence, and because no managed rule evaluates inline role policies, so it is the live-state control for GAP-07. Going forward, local applies will alert by design: governed resources should change only through the pipeline.

**20. Alert subscription created outside Terraform; topic on default encryption.**
The subscriber email would otherwise sit in a public repo and in every plan inside the evidence bundles. The topic does not use the CMK because EventBridge can only publish to a CMK-encrypted topic if the key policy grants it; alerts carry resource names and API metadata, not PHI.

**21. Live control tests in every bundle.**
`scripts/control-tests.sh` runs eleven tests against the deployed stack after every apply and every night, and writes JSON into the signed bundle. Plan-time checks prove intent; these prove the controls operate. The TLS test sends a real plaintext request and expects 403; the least-privilege test uses IAM policy simulation rather than attempting destructive calls against PHI stores.

**22. Nightly drift run under the read-only role.**
Scheduled and manual runs assume the plan role, whose trust now also accepts `main`. A nightly check needs to read everything and change nothing. Drift is a plan with changes, detected with `-detailed-exitcode`. The job fails only after the evidence is signed and stored.

**23. Zip file mode pinned to remove false drift.**
`archive_file` embeds file permissions. Linux Mint creates files as `664` and GitHub's checkout as `644`, so laptop and CI produced different Lambda hashes and each saw the other's deploy as drift. `output_file_mode = "0644"` makes the artifact identical everywhere.

**24. Every step runs under `bash -eo pipefail`.**
GitHub's default `bash -e` does not set `pipefail`, so `terraform apply | tee` could report success on a failed apply. Found while adding the drift step; fixed at the job level.

**25. Supply-chain hygiene.**
All actions pinned to full commit SHAs on their current major versions (behavior unchanged, tag hijack ruled out). `.terraform.lock.hcl` committed so CI uses the provider builds tested locally. Adaptive retries on all AWS calls in the pipeline. The run-metadata step reads runner environment variables and builds JSON with `jq` instead of interpolating `${{ }}` into the script.

**26. State bucket TLS deny added out of band.**
The account-wide `s3-tls-only` rule would have flagged the remote-state bucket. Added a TLS-deny bucket policy with the AWS CLI before enabling Config. The bucket remains outside Terraform, which is still listed as a trade-off.
