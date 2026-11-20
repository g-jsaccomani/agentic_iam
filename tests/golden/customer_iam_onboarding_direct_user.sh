#!/usr/bin/env bash
# ==============================================================================
# Agentic IAM Accelerator — Zero-Trust Customer Onboarding Script
# Connection Mode: Direct User Read-Only Access
# ==============================================================================
set -euo pipefail

CUSTOMER_NAME='Acme Financial Corp'
DEFAULT_ORG_ID=123456789012
DEFAULT_SEED_PROJECT_ID=prj-sec-governance
AUTHORIZED_USER_MEMBER=group:iam-auditors@acme.com

ORG_ID="${DEFAULT_ORG_ID}"
if [[ $# -ge 1 && -n "${1}" ]]; then
  ORG_ID="${1}"
fi
SEED_PROJECT_ID="${DEFAULT_SEED_PROJECT_ID}"
if [[ $# -ge 2 && -n "${2}" ]]; then
  SEED_PROJECT_ID="${2}"
fi
ORG_READER_MEMBER="${AUTHORIZED_USER_MEMBER}"

echo "=============================================================================="
echo "🛡️  AGENTIC IAM ACCELERATOR • READ-ONLY ORGANIZATION ONBOARDING"
printf '   Customer        : %s\n' "${CUSTOMER_NAME}"
printf '   Organization ID : organizations/%s\n' "${ORG_ID}"
printf '   Seed Project    : %s\n' "${SEED_PROJECT_ID}"
printf '   Authorized User : %s\n' "${AUTHORIZED_USER_MEMBER}"
echo "=============================================================================="

printf '▶️ [1/2] Enabling Read-Only Telemetry & IAM Credentials APIs on %s...\n' "${SEED_PROJECT_ID}"
gcloud services enable \
    cloudasset.googleapis.com \
    cloudresourcemanager.googleapis.com \
    iam.googleapis.com \
    iamcredentials.googleapis.com \
    orgpolicy.googleapis.com \
    recommender.googleapis.com \
    policyanalyzer.googleapis.com \
    policysimulator.googleapis.com \
    logging.googleapis.com \
    --project="${SEED_PROJECT_ID}" --quiet

printf '▶️ [2/2] Granting 6 Strictly Read-Only Roles on organizations/%s directly to %s...\n' "${ORG_ID}" "${AUTHORIZED_USER_MEMBER}"
gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="${ORG_READER_MEMBER}" \
  --role="roles/browser" \
  --condition=None --quiet >/dev/null

gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="${ORG_READER_MEMBER}" \
  --role="roles/cloudasset.viewer" \
  --condition=None --quiet >/dev/null

gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="${ORG_READER_MEMBER}" \
  --role="roles/iam.securityReviewer" \
  --condition=None --quiet >/dev/null

gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="${ORG_READER_MEMBER}" \
  --role="roles/orgpolicy.policyViewer" \
  --condition=None --quiet >/dev/null

gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="${ORG_READER_MEMBER}" \
  --role="roles/recommender.viewer" \
  --condition=None --quiet >/dev/null

gcloud organizations add-iam-policy-binding "${ORG_ID}" \
  --member="${ORG_READER_MEMBER}" \
  --role="roles/logging.viewer" \
  --condition=None --quiet >/dev/null

echo "=============================================================================="
echo "✅ ONBOARDING COMPLETE!"
printf '   • Authorized Direct Reader: %s\n' "${AUTHORIZED_USER_MEMBER}"
echo "   • Next Step: Return to Agentic IAM Accelerator -> Connect Target Organization"
echo "=============================================================================="
