# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

The primary framework is the **HIPAA Security Rule** (45 CFR 164, Subpart C). The Patient Intake API stores and processes PHI, which makes HIPAA a legal obligation the day the system goes live; SOC 2 answers one enterprise customer's request, and CMMC Level 2 depends on a federal pilot that may never close. I chose the obligation over the opportunities, and every Rego policy and OSCAL requirement in this repo cites a 164.x control.

Scope stays honest about what code can prove. This build implements Technical Safeguards (164.312) and the data backup requirement in 164.308(a)(7)(ii)(A). Physical Safeguards (164.310) are inherited from AWS under the shared responsibility model and are not claimed. The OSCAL component cites NIST SP 800-66 Rev. 2 as its catalog source, because there is no official OSCAL catalog for HIPAA itself.

## Control coverage

| Gap | Finding | HIPAA control | Terraform | Rego policy | Cross-reference (SOC 2; CMMC L2) |
|---|---|---|---|---|---|
| GAP-01 | Uploads bucket on AWS-managed SSE-S3 | 164.312(a)(2)(iv) | Closed: SSE-KMS under `aws_kms_key.phi`, Bucket Keys on | `hipaa_s3_cmk` | CC6.1; SC.L2-3.13.11 |
| GAP-02 | DynamoDB on the AWS-owned key | 164.312(a)(2)(iv) | Closed: `server_side_encryption` with `aws_kms_key.phi` | `hipaa_dynamodb_cmk` | CC6.1; SC.L2-3.13.11 |
| GAP-03 | No TLS-only bucket policy | 164.312(e)(1) | Closed on all three buckets | `hipaa_s3_tls` | CC6.7; SC.L2-3.13.8 |
| GAP-04 | No versioning on PHI uploads | 164.308(a)(7)(ii)(A) | Closed on all three buckets | `hipaa_s3_versioning` | A1.2; MP.L2-3.8.9 |
| GAP-07 | Lambda role holds `dynamodb:*` and `s3:*` | 164.312(a)(1) | Closed: `PutItem`, `PutObject` on `uploads/*`, and key-scoped KMS actions | `hipaa_iam_least_privilege` | CC6.3; AC.L2-3.1.5 |
| GAP-05 | Lambda outside the VPC | 164.312(e)(1) | Open | None | CC6.6; SC.L2-3.13.1 |
| GAP-06 | No concurrency limit, DLQ, or tracing | No HIPAA mapping | Open | None | CC7.2; SI.L2-3.14.6 |
| GAP-08 | No API access logging or throttling | 164.312(b) | Open | None | CC7.2; AU.L2-3.3.1 |

Beyond the gaps, the baseline adds one customer-managed KMS key with rotation, an Object Lock evidence vault, a multi-region CloudTrail trail with log-file validation, remote state in S3, and two GitHub OIDC roles. The five policies carry 18 unit tests (`opa test policies`), each with passing and failing fixtures.

One finding came from the policy suite itself. Writing `hipaa_s3_tls` exposed that the CloudTrail bucket I had just built had no TLS deny. I fixed the bucket rather than exempting it, so the policy passes for an honest reason.

## Design decisions

**Region: us-east-1.** It is the starter's default and HIPAA imposes no data-residency requirement. The trail is multi-region, so activity outside us-east-1 is still recorded.

**Object Lock: GOVERNANCE mode, 30-day default retention.** Every bundle stays locked through grading (the latest verified bundle is retained until 2026-11-09), and a principal holding `s3:BypassGovernanceRetention` can still clean up the sandbox afterward. COMPLIANCE mode would block every deletion, by anyone, for the full period. The trade-off is tamper resistance against operational flexibility. In production I would run COMPLIANCE mode with retention aligned to HIPAA's six-year documentation requirement (164.316(b)(2)).

**Apply on merge, no manual approval gate.** A merge to `main` applies automatically, but only if the policy gate reports zero failures, and only the `main` branch can assume the apply role. Pull requests run under a separate plan role with `ReadOnlyAccess`, a state-lock permission, and evidence upload; it holds no `kms:Decrypt`, so an untrusted PR can neither change infrastructure nor read PHI. Auto-apply gives the pipeline real deploy power, and I accepted that for a single-engineer system where the gate is the reviewer. Branch protection on `main` requires the `grc-gate` check, so a pull request that fails the gate cannot be merged. Repository admins are not yet bound by that rule; for production I would enforce it for admins too and add a GitHub environment with a required reviewer in front of the apply step.

**Single AWS account.** The vault lives in the same account it audits. That is acceptable for 30 days but it is the weakest link in the chain: an administrator in this account could bypass GOVERNANCE retention. Production moves the vault to a dedicated log-archive account with COMPLIANCE mode, so a compromise of the workload account cannot rewrite its own evidence.

**Terraform versus policy split.** All five closed gaps are fixed in Terraform and enforced in policy. Terraform makes the control true today; the policy keeps it true on every future change. Each of the five is a configuration property visible in a Terraform plan, which is what makes a plan-time gate meaningful for it. The three open gaps have neither, and I say so below rather than claim partial credit.

**CloudTrail bucket encryption.** The trail bucket uses SSE-S3 rather than the CMK. Using the CMK would require granting CloudTrail rights in the key policy, and these logs record account activity, not PHI. Log-file validation keeps tampering detectable regardless of the encryption key. `hipaa_s3_cmk` exempts CloudTrail log buckets by detecting them from the `aws_cloudtrail` resource, not by name, and the exemption is documented in the policy metadata.

**Pipeline identity.** GitHub issues this repository's OIDC tokens with immutable subjects (`repo:SeraphimO120@324516250/cgep-app-starter@1404925327:...`). The first pipeline run failed because the trust policies expected the older name-based subject. I kept the immutable form and pinned both roles to it: a name can be released and claimed by someone else, a numeric ID cannot, so a renamed or re-created repository cannot assume either role.

**Remote state.** State lives in a versioned S3 bucket with public access blocked and Terraform's native lockfile, so the pipeline and my laptop share one source of truth without a DynamoDB lock table. The bucket was bootstrapped with the AWS CLI, which keeps it outside the policy suite (see trade-offs). Its name uses the deployment suffix rather than the account ID because the repo is public.

**Scanner scope.** The reference workflow ran tfsec beside Conftest. I removed it: tfsec is deprecated, it was first on my scope-cut list, and the five HIPAA policies are the gate this design is graded on. A maintained scanner (Trivy or Checkov) in report-only mode is a reasonable next addition.

**Tool pinning.** CI pins Terraform 1.16.5, Conftest 0.71.0, and Cosign v3.1.3 to match local tooling. Terraform state written by a newer version cannot be read by an older one, and Cosign v3 changed its bundle format, so signing and verifying on mismatched versions was a real risk.

## How the pipeline produces evidence

Every run of `.github/workflows/grc-gate.yml` executes five named steps in order: **Plan, Policy check, Apply, Sign, Upload.**

1. **Plan.** `terraform plan` against remote state, saved as `plan.txt` and `plan.json`. Policy unit tests run first and their output is captured.
2. **Policy check.** Conftest evaluates all five HIPAA policies against `plan.json`. The step records failures and warnings but does not stop the job, so a failing run still produces evidence.
3. **Apply.** Runs only on `main`, only with zero failures.
4. **Sign.** The `evidence/` folder (plan, policy results, policy tests, run metadata, apply output) is bundled, hashed with SHA-256, and signed with Cosign keyless signing. The signing certificate is bound to this workflow's GitHub OIDC identity and the signature is recorded in the public Rekor transparency log.
5. **Upload.** The bundle, hash, signature bundle, and a receipt (version ID, retain-until date, hash, commit) land in the Object Lock vault under `runs/<run_id>/`.

The job fails last, after evidence is stored. A blocked change leaves the same signed record as an approved one.

**Runs an assessor can verify:**

| Run | Event | Result |
|---|---|---|
| 38050326602 | PR #1 (green) | Gate passed, merged |
| 38050849986 | Merge to `main` | Gate passed, apply ran |
| 38051205888 | PR #2 (red, reintroduces `dynamodb:*`) | Gate failed on GAP-07, blocked |
| 38051692529 | Push to `main` | All five steps passed |

`scripts/verify-evidence.sh` returned `CHAIN INTACT` for 38051692529 and for the red run 38051205888. The OSCAL component links to both, so an assessor can start at a control, follow its evidence link into the vault, and verify the object.

## Trade-offs and what I'd do with another sprint

- **Plan-time blind spot.** `hipaa_s3_tls` and `hipaa_iam_least_privilege` read rendered policy JSON, which Terraform cannot compute for resources that do not exist yet. In that case the policies warn instead of failing, so a first-time deploy is not blocked. Against the existing stack every policy is fully evaluated. The fix is a post-apply check of the same rules against live state or AWS Config.
- **Apply role breadth.** The apply role holds `AdministratorAccess` because the stack spans KMS, IAM, VPC, Lambda, API Gateway, and CloudTrail. Next step: a scoped deploy policy generated from CloudTrail activity over a few weeks of runs.
- **State bucket outside the gate.** The remote-state bucket was bootstrapped with the AWS CLI (Terraform cannot create the bucket that holds its own state). It is versioned and blocks public access, but it sits outside Terraform and outside the policy suite, with no TLS deny or CMK. Next step: a small bootstrap configuration with its own policy run.
- **Separate evidence account and COMPLIANCE mode,** as described above.

## What I didn't get to

- **GAP-05 (Lambda outside the VPC, 164.312(e)(1)).** Approach: add `vpc_config` on the starter's private subnets, add gateway endpoints for S3 and DynamoDB so the function needs no NAT gateway, restrict security-group egress to those endpoints, and add a policy that denies any `aws_lambda_function` without `vpc_config`.
- **GAP-08 (API access logging, 164.312(b)).** Approach: `access_log_settings` to a CloudWatch log group encrypted with the CMK, default route throttling, and a policy requiring both. This is the next gap I would close, because it extends the audit-control story the vault already tells.
- **GAP-06 (concurrency, DLQ, tracing).** It has no HIPAA mapping, so I deprioritized it under a HIPAA-primary design. It would be closed in Terraform and cross-referenced to SOC 2 CC7.2.

### Known gaps outside GAPS.md

- **Patient data lifecycle.** There is no deletion, export, or retention schedule for submissions. `WORKLOAD.md` calls this out as a known gap. Approach: a documented retention period enforced with S3 lifecycle rules and DynamoDB TTL, with versioned objects expiring after the same window, and an export path for patient requests. Retention has to be weighed against the versioning added for GAP-04, which deliberately keeps old object versions.
- **API-layer authentication.** The intake endpoint accepts unauthenticated requests. `WORKLOAD.md` scopes API authentication out of the capstone, so the OSCAL marks 164.312(d) as **partial**: the pipeline authenticates with OIDC, the API does not. Approach: a JWT authorizer on the HTTP API backed by the patient portal's identity provider.
- **Runner maintenance.** GitHub flagged that the Node 20 actions in this workflow are deprecated and that `ubuntu-latest` moves to Ubuntu 26 starting 2026-10-19. Pinning the runner image and upgrading the action versions keeps future runs reproducible.

## Reflection

The most useful moments were the failures. The first pipeline run could not authenticate, and CloudTrail's record of the rejected token showed exactly why: GitHub had moved to immutable subjects, and the fix was also the stronger design. The policy suite caught a gap in infrastructure I had built that same week. Both reinforced the point of the course: controls are only as good as the evidence that they ran, and a gate earns trust when it can fail, record the failure, and hand an assessor something they can verify without ever meeting the engineer.
