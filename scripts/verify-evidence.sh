#!/usr/bin/env bash
# scripts/verify-evidence.sh
# Verify one pipeline evidence bundle: integrity, authenticity, preservation.
#
# Usage:
#   scripts/verify-evidence.sh <run_id> [--vault <bucket>] [--profile <aws-profile>]
#
# Prints CHAIN INTACT and exits 0 only if all three checks pass.

set -euo pipefail

RUN_ID="${1:-}"
[[ -z "$RUN_ID" ]] && { echo "Usage: $0 <run_id> [--vault <bucket>] [--profile <p>]" >&2; exit 2; }
shift || true

VAULT="${EVIDENCE_VAULT:-acme-health-intake-evidence-5434b2b8}"
PROFILE_ARG=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG=(--profile "$2"); shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

# The signer must be this repo's grc-gate workflow (name-based or immutable-ID form).
IDENTITY_RE='^https://github\.com/SeraphimO120(@[0-9]+)?/cgep-app-starter(@[0-9]+)?/\.github/workflows/grc-gate\.yml@refs/.+$'
ISSUER='https://token.actions.githubusercontent.com'

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
PREFIX="runs/${RUN_ID}"

echo "=== Fetching s3://${VAULT}/${PREFIX}/ ==="
aws "${PROFILE_ARG[@]}" s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive --only-show-errors
BUNDLE=$(ls evidence-*.tar.gz 2>/dev/null | head -1 || true)
[[ -z "$BUNDLE" ]] && { echo "FAIL: no bundle found for run ${RUN_ID}" >&2; exit 1; }
echo "  bundle: ${BUNDLE}"

echo "=== 1. Integrity (SHA-256) ==="
EXPECTED=$(tr -d '[:space:]' < "${BUNDLE}.sha256")
if command -v sha256sum >/dev/null; then ACTUAL=$(sha256sum "$BUNDLE" | awk '{print $1}'); else ACTUAL=$(shasum -a 256 "$BUNDLE" | awk '{print $1}'); fi
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA-256 mismatch (expected $EXPECTED, got $ACTUAL)" >&2; exit 1; }
echo "  OK  ${ACTUAL}"

echo "=== 2. Authenticity (Cosign keyless, Rekor transparency log) ==="
cosign verify-blob \
  --bundle "${BUNDLE}.sigstore.json" \
  --certificate-identity-regexp "$IDENTITY_RE" \
  --certificate-oidc-issuer "$ISSUER" \
  "$BUNDLE"
echo "  OK  signed by this repo's grc-gate workflow"

echo "=== 3. Preservation (S3 Object Lock) ==="
read -r MODE RETAIN_UNTIL < <(aws "${PROFILE_ARG[@]}" s3api get-object-retention \
  --bucket "$VAULT" --key "${PREFIX}/${BUNDLE}" \
  --query '[Retention.Mode, Retention.RetainUntilDate]' --output text)
[[ -z "${RETAIN_UNTIL:-}" || "$RETAIN_UNTIL" == "None" ]] && { echo "FAIL: no Object Lock retention on the bundle" >&2; exit 1; }
NOW_EPOCH=$(date -u +%s)
RETAIN_EPOCH=$(date -u -d "$RETAIN_UNTIL" +%s 2>/dev/null || date -u -j -f "%Y-%m-%dT%H:%M:%S" "${RETAIN_UNTIL%%.*}" +%s)
(( RETAIN_EPOCH > NOW_EPOCH )) || { echo "FAIL: retention expired at $RETAIN_UNTIL" >&2; exit 1; }
echo "  OK  ${MODE} until ${RETAIN_UNTIL}"

echo
echo "CHAIN INTACT for run ${RUN_ID}"
