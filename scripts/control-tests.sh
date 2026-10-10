#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2329  # conditions run via bash -c with positional args; eq() is called through check()
# scripts/control-tests.sh
# Live control tests: verify the HIPAA controls work in the deployed
# environment, not just in the Terraform plan.
#
# Usage (from the repo root, after terraform init):
#   scripts/control-tests.sh [results.json]
#
# Writes a JSON array of results (default: control-tests.json) and exits
# non-zero if any test fails. Read-only except test 11, which submits one
# synthetic intake record through the public API.

set -uo pipefail

OUT_FILE="${1:-control-tests.json}"
REGION="${AWS_REGION:-us-east-1}"
TF_OUT=$(terraform -chdir=terraform output -json)
out() { jq -r --arg k "$1" '.[$k].value' <<<"$TF_OUT"; }

UPLOADS=$(out uploads_bucket)
EVIDENCE=$(out evidence_bucket)
TABLE=$(out intake_table)
KEY_ARN=$(out kms_key_arn)
TRAIL=$(out cloudtrail_name)
API_URL=$(out api_url)
FUNCTION=$(out lambda_function_name)
ROLE_ARN=$(aws lambda get-function-configuration --function-name "$FUNCTION" --query Role --output text)
TABLE_ARN=$(aws dynamodb describe-table --table-name "$TABLE" --query Table.TableArn --output text)

RESULTS="[]"
FAILS=0
record() { # id control result description detail
  RESULTS=$(jq --arg id "$1" --arg c "$2" --arg r "$3" --arg d "$4" --arg x "$5" \
    '. + [{id: $id, control: $c, result: $r, description: $d, detail: $x}]' <<<"$RESULTS")
  [[ "$3" == "PASS" ]] || FAILS=$((FAILS + 1))
  printf '%-4s %-22s %-5s %s\n' "$1" "$2" "$3" "$4"
}
check() { # id control description detail condition-command...
  local id=$1 c=$2 d=$3 x=$4; shift 4
  if "$@"; then record "$id" "$c" PASS "$d" "$x"; else record "$id" "$c" FAIL "$d" "$x"; fi
}
eq() { [[ "$1" == "$2" ]]; }

# 164.312(a)(2)(iv) Encryption at rest under the customer-managed key
V=$(aws s3api get-bucket-encryption --bucket "$UPLOADS" \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' --output text 2>&1)
check T01 "164.312(a)(2)(iv)" "Uploads bucket default encryption is SSE-KMS with the PHI key" "$V" \
  eq "$V" "$(printf 'aws:kms\t%s' "$KEY_ARN")"

V=$(aws s3api get-bucket-encryption --bucket "$EVIDENCE" \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' --output text 2>&1)
check T02 "164.312(a)(2)(iv)" "Evidence vault default encryption is SSE-KMS with the PHI key" "$V" \
  eq "$V" "$(printf 'aws:kms\t%s' "$KEY_ARN")"

V=$(aws dynamodb describe-table --table-name "$TABLE" \
  --query 'Table.SSEDescription.[Status,SSEType,KMSMasterKeyArn]' --output text 2>&1)
check T03 "164.312(a)(2)(iv)" "Submissions table is encrypted with the PHI key" "$V" \
  eq "$V" "$(printf 'ENABLED\tKMS\t%s' "$KEY_ARN")"

V=$(aws kms get-key-rotation-status --key-id "$KEY_ARN" --query KeyRotationEnabled --output text 2>&1)
check T04 "164.312(a)(2)(iv)" "PHI key has automatic rotation enabled" "$V" eq "$V" "True"

# 164.312(e)(1) Transmission security: a plaintext HTTP request is refused
HTTPS=$(aws s3api head-bucket --bucket "$UPLOADS" 2>&1 && echo OK)
HTTP=$(aws s3api head-bucket --bucket "$UPLOADS" --endpoint-url "http://s3.${REGION}.amazonaws.com" 2>&1 && echo OK)
check T05 "164.312(e)(1)" "Uploads bucket refuses plaintext HTTP but accepts HTTPS" "https=[${HTTPS}] http=[${HTTP}]" \
  bash -c '[[ "$1" == *OK* && "$2" == *403* ]]' _ "$HTTPS" "$HTTP"

# 164.308(a)(7)(ii)(A) Data backup
V=$(aws s3api get-bucket-versioning --bucket "$UPLOADS" --query Status --output text 2>&1)
check T06 "164.308(a)(7)(ii)(A)" "Uploads bucket versioning is Enabled" "$V" eq "$V" "Enabled"

# 164.312(a)(1) Access control: the Lambda role can do only what the handler needs
sim() { aws iam simulate-principal-policy --policy-source-arn "$ROLE_ARN" \
  --action-names "$1" --resource-arns "$2" --query 'EvaluationResults[0].EvalDecision' --output text 2>&1; }
A1=$(sim dynamodb:PutItem "$TABLE_ARN")
A2=$(sim s3:PutObject "arn:aws:s3:::${UPLOADS}/uploads/control-test")
D1=$(sim dynamodb:Scan "$TABLE_ARN")
D2=$(sim dynamodb:DeleteItem "$TABLE_ARN")
D3=$(sim s3:GetObject "arn:aws:s3:::${UPLOADS}/uploads/control-test")
D4=$(sim s3:DeleteObject "arn:aws:s3:::${UPLOADS}/uploads/control-test")
check T07 "164.312(a)(1)" "Lambda role allows PutItem/PutObject and denies Scan, DeleteItem, GetObject, DeleteObject" \
  "PutItem=$A1 PutObject=$A2 Scan=$D1 DeleteItem=$D2 GetObject=$D3 DeleteObject=$D4" \
  bash -c '[[ $1 == allowed && $2 == allowed && $3 != allowed && $4 != allowed && $5 != allowed && $6 != allowed ]]' _ "$A1" "$A2" "$D1" "$D2" "$D3" "$D4"

# 164.312(b) Audit controls
V=$(aws cloudtrail get-trail-status --name "$TRAIL" --query IsLogging --output text 2>&1)
W=$(aws cloudtrail describe-trails --trail-name-list "$TRAIL" \
  --query 'trailList[0].[IsMultiRegionTrail,LogFileValidationEnabled]' --output text 2>&1)
check T08 "164.312(b)" "CloudTrail is logging, multi-region, with log-file validation" "logging=$V multiregion,validation=$W" \
  bash -c '[[ $1 == True && $2 == "$(printf "True\tTrue")" ]]' _ "$V" "$W"

V=$(aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[0].[recording,lastStatus]' --output text 2>&1)
check T09 "164.312(b)" "AWS Config recorder is recording" "$V" bash -c '[[ $1 == True* ]]' _ "$V"

# 164.312(c)(1) Integrity: evidence vault is immutable by default
V=$(aws s3api get-object-lock-configuration --bucket "$EVIDENCE" \
  --query 'ObjectLockConfiguration.[ObjectLockEnabled,Rule.DefaultRetention.Mode,Rule.DefaultRetention.Days]' --output text 2>&1)
check T10 "164.312(c)(1)" "Evidence vault has Object Lock with GOVERNANCE 30-day default retention" "$V" \
  eq "$V" "$(printf 'Enabled\tGOVERNANCE\t30')"

# End to end: the governed system still does its job
BODY=$(jq -n --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{patient_id: "P-CONTROL-TEST", submitted_at: $t, fields: {reason_for_visit: "automated control test"}}')
V=$(curl -sS -m 20 -X POST "$API_URL" -H 'Content-Type: application/json' -d "$BODY" 2>&1)
check T11 "end-to-end" "Intake API accepts a synthetic submission with all controls in place" "$V" \
  bash -c '[[ $(jq -r .status <<<"$1" 2>/dev/null) == received ]]' _ "$V"

jq --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson fails "$FAILS" \
  '{generated_at: $ts, failures: $fails, total: length, results: .}' <<<"$RESULTS" > "$OUT_FILE"
echo
echo "Control tests: $(jq .total "$OUT_FILE") run, ${FAILS} failed. Results: ${OUT_FILE}"
exit $(( FAILS > 0 ? 1 : 0 ))
