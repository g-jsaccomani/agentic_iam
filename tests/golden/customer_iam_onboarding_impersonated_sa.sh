#!/usr/bin/env bash
# ==============================================================================
# Agentic IAM Accelerator — Zero-Trust Customer Onboarding Script
# Connection Mode: Service Account Impersonation (Zero Static Keys)
# ==============================================================================
set -euo pipefail

CUSTOMER_NAME='O'"'"'Reilly & Sons (BR) - Co., Inc.'
DEFAULT_ORG_ID=123456789012
DEFAULT_SEED_PROJECT_ID=prj-sec-governance
AUTHORIZED_USER_MEMBER=user:alice@oreilly.example.com
SA_ACCOUNT_ID=sa-iam-assessor
AUTHORIZED_USER_EMAIL=alice@oreilly.example.com
ORG_DOMAIN_HINT=oreilly.example.com

ORG_ID="${DEFAULT_ORG_ID}"
if [[ $# -ge 1 && -n "${1}" ]]; then
  ORG_ID="${1}"
fi
SEED_PROJECT_ID="${DEFAULT_SEED_PROJECT_ID}"
if [[ $# -ge 2 && -n "${2}" ]]; then
  SEED_PROJECT_ID="${2}"
fi
SA_EMAIL="${SA_ACCOUNT_ID}@${SEED_PROJECT_ID}.iam.gserviceaccount.com"
SA_DESCRIPTION="Strictly read-only identity impersonated by authorized user ${AUTHORIZED_USER_EMAIL} (Zero JSON Keys)"
ORG_READER_MEMBER="serviceAccount:${SA_EMAIL}"

echo "=============================================================================="
echo "🛡️  AGENTIC IAM ACCELERATOR • READ-ONLY ORGANIZATION ONBOARDING"
printf '   Customer        : %s\n' "${CUSTOMER_NAME}"
printf '   Organization ID : organizations/%s\n' "${ORG_ID}"
printf '   Seed Project    : %s\n' "${SEED_PROJECT_ID}"
printf '   Authorized User : %s\n' "${AUTHORIZED_USER_MEMBER}"
echo "=============================================================================="

printf '▶️ [1/4] Enabling Read-Only Telemetry & IAM Credentials APIs on %s...\n' "${SEED_PROJECT_ID}"
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

printf '▶️ [2/4] Creating Read-Only Assessor Service Account (%s)...\n' "${SA_EMAIL}"
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${SEED_PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_ACCOUNT_ID}" \
    --display-name="Agentic IAM Read-Only Posture Assessor" \
    --description="${SA_DESCRIPTION}" \
    --project="${SEED_PROJECT_ID}" --quiet
fi

printf '▶️ [3/4] Granting Impersonation (Service Account Token Creator) to %s...\n' "${AUTHORIZED_USER_MEMBER}"
if ! gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
  --project="${SEED_PROJECT_ID}" \
  --member="${AUTHORIZED_USER_MEMBER}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --condition=None --quiet >/dev/null; then
  printf '❌ Blocked by Domain Restricted Sharing (constraints/iam.allowedPolicyMemberDomains) on project %s.\n' "${SEED_PROJECT_ID}"
  printf '   Either authorize an internal user (@%s) OR allow the consultant Cloud Identity ID ONLY on project %s.\n' "${ORG_DOMAIN_HINT}" "${SEED_PROJECT_ID}"
  exit 1
fi

printf '▶️ [4/4] Granting 6 Strictly Read-Only Roles on organizations/%s...\n' "${ORG_ID}"
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
printf '   • Target Service Account to Impersonate: %s\n' "${SA_EMAIL}"
echo "   • Next Step: Return to Agentic IAM Accelerator -> Connect Target Organization"
echo "=============================================================================="
