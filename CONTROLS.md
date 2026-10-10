# Control Matrix

Every HIPAA control this system claims, traced from requirement to code to evidence. Each control is enforced at up to four points in time:

- **Plan time:** a Rego policy blocks the pull request before anything changes.
- **After apply and nightly:** a live test in `scripts/control-tests.sh` checks the deployed resource.
- **Continuously:** an AWS Config rule re-evaluates the live resource whenever it changes.
- **In real time:** an EventBridge rule emails an alert when someone changes the control outside the pipeline.

| HIPAA control | Requirement | Terraform | Rego policy (unit tests) | Live test | AWS Config rule | Out-of-band alert on |
|---|---|---|---|---|---|---|
| 164.312(a)(2)(iv) | Encryption at rest | `aws_kms_key.phi`, `aws_s3_bucket_server_side_encryption_configuration.uploads` and `.evidence`, `aws_dynamodb_table.intake` | `hipaa_s3_cmk` (6), `hipaa_dynamodb_cmk` (4) | T01, T02, T03, T04 | `s3-uploads-cmk`, `s3-evidence-cmk`, `dynamodb-cmk`, `kms-rotation` | `DisableKey`, `DisableKeyRotation`, `ScheduleKeyDeletion`, `PutKeyPolicy`, `PutBucketEncryption`, `DeleteBucketEncryption`, `UpdateTable` |
| 164.312(e)(1) | Transmission security | `aws_s3_bucket_policy.uploads`, `.evidence`, `.trail` | `hipaa_s3_tls` (6) | T05 | `s3-tls-only` | `PutBucketPolicy`, `DeleteBucketPolicy` |
| 164.308(a)(7)(ii)(A) | Data backup | `aws_s3_bucket_versioning.uploads`, `.evidence`, `.trail` | `hipaa_s3_versioning` (4) | T06 | `s3-versioning` | `PutBucketVersioning` |
| 164.312(a)(1) | Access control | `aws_iam_role_policy.lambda_inline`, `aws_iam_role.gha_plan`, `aws_iam_role.gha_apply` | `hipaa_iam_least_privilege` (6) | T07 | None (managed rules do not evaluate inline role policies) | `PutRolePolicy`, `DeleteRolePolicy`, `AttachRolePolicy`, `DetachRolePolicy`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy` |
| 164.312(b) | Audit controls | `aws_cloudtrail.mgmt`, `aws_config_configuration_recorder.main`, `aws_cloudwatch_event_rule.*` | None | T08, T09 | `cloudtrail-multi-region` | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteConfigRule`, `DeleteDeliveryChannel` |
| 164.312(c)(1) | Integrity | `aws_s3_bucket_object_lock_configuration.evidence`, Cosign signing in `grc-gate.yml` | None | T10 | `cloudtrail-log-validation` | `PutObjectLockConfiguration` |
| 164.312(d) (partial) | Person or entity authentication | `aws_iam_openid_connect_provider.github`, OIDC trust on both CI roles | None | None | None | `UpdateAssumeRolePolicy` |
| 164.308(a)(1)(ii)(D) (partial) | Information system activity review | `grc_monitoring.tf`: Config recorder, 8 rules, 2 EventBridge rules, SNS topic | None | T09 | All 8 feed the non-compliance alert | Both alert rules |

T11 is an end-to-end test: a synthetic intake submission must still succeed with every control in place.

**Partial controls.** 164.312(d) covers the pipeline only; the intake API accepts unauthenticated requests (out of scope per `WORKLOAD.md`). 164.308(a)(1)(ii)(D) is automated collection and alerting; the human review cadence is an organizational process not codified here.

**Evidence.** Every run of `grc-gate.yml` signs a bundle containing `plan.json`, `conftest-results.json`, `policy-tests.txt`, and run metadata. Runs on `main`, nightly runs, and manual runs add `control-tests.json`; nightly and manual runs add `drift.txt`. Bundles land in `s3://acme-health-intake-evidence-5434b2b8/runs/<run_id>/` under Object Lock. The OSCAL component in `oscal/components/acme-health-intake.json` carries the same mapping in machine-readable form.

Config rule names in this table omit the `acme-health-intake-` prefix used in AWS.
