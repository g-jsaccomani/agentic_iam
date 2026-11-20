#!/usr/bin/env bash
# ==============================================================================
# Agentic IAM Accelerator — Customer Organization Onboarding (Impersonation Edition)
# Zero Static JSON Keys • Strictly Read-Only Org Roles • User-Scoped Impersonation
#
# Creates `sa-iam-assessor@<SEED_PROJECT_ID>.iam.gserviceaccount.com` in the target
# environment, binds 6 strictly read-only roles on `organizations/<CUSTOMER_ORG_ID>`,
# and grants `roles/iam.serviceAccountTokenCreator` ONLY to the specified user!
#
# Usage (run in Customer's Google Cloud Shell by Organization Admin):
#   bash 03_onboard_customer_org.sh <CUSTOMER_ORG_ID> <SEED_PROJECT_ID> <AUTHORIZED_USER_EMAIL>
# ==============================================================================
set -euo pipefail

export CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity"

ORG_ID="${1:-}"
SEED_PROJECT_ID="${2:-$(gcloud config get-value project 2>/dev/null || true)}"
AUTHORIZED_USER="${3:-}"
SA_NAME="${SA_NAME:-sa-iam-assessor}"

G_ACCOUNT_FLAGS=()
if [[ -n "${ACCOUNT:-}" ]]; then
  G_ACCOUNT_FLAGS=(--account="${ACCOUNT}")
fi

if [[ -z "${ORG_ID}" || -z "${SEED_PROJECT_ID}" || "${SEED_PROJECT_ID}" == "(unset)" || -z "${AUTHORIZED_USER}" ]]; then
  echo "❌ Usage: bash $0 <CUSTOMER_ORG_ID> <SEED_PROJECT_ID> <AUTHORIZED_USER_EMAIL>"
  exit 1
fi

ORG_ID="${ORG_ID#organizations/}"
if [[ "${AUTHORIZED_USER}" != *:* ]]; then
  AUTHORIZED_USER="user:${AUTHORIZED_USER}"
fi
SA_EMAIL="${SA_NAME}@${SEED_PROJECT_ID}.iam.gserviceaccount.com"

echo "=============================================================================="
echo "🛡️  AGENTIC IAM ACCELERATOR • USER-IMPERSONATED READ-ONLY ONBOARDING"
echo "   Organization ID       : organizations/${ORG_ID}"
echo "   Seed Project          : ${SEED_PROJECT_ID}"
echo "   Assessor Service Acct : ${SA_EMAIL}"
echo "   Authorized Impersonat.: ${AUTHORIZED_USER}"
echo "=============================================================================="

echo "▶️  [1/4] Enabling Read-Only Telemetry & IAM Credentials APIs on ${SEED_PROJECT_ID}..."
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
  --project="${SEED_PROJECT_ID}" ${G_ACCOUNT_FLAGS[@]+"${G_ACCOUNT_FLAGS[@]}"} --quiet

echo "▶️  [2/4] Creating Read-Only Assessor Service Account (${SA_EMAIL})..."
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${SEED_PROJECT_ID}" ${G_ACCOUNT_FLAGS[@]+"${G_ACCOUNT_FLAGS[@]}"} >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Agentic IAM Read-Only Posture Assessor" \
    --description="Strictly read-only identity impersonated by ${AUTHORIZED_USER} (Zero JSON Keys)" \
    --project="${SEED_PROJECT_ID}" ${G_ACCOUNT_FLAGS[@]+"${G_ACCOUNT_FLAGS[@]}"} --quiet
fi

echo "▶️  [3/4] Granting Impersonation (Token Creator) ONLY to ${AUTHORIZED_USER}..."
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
  --project="${SEED_PROJECT_ID}" \
  --member="${AUTHORIZED_USER}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --condition=None \
  ${G_ACCOUNT_FLAGS[@]+"${G_ACCOUNT_FLAGS[@]}"} --quiet >/dev/null

READ_ONLY_ORG_ROLES=(
  "roles/browser"
  "roles/cloudasset.viewer"
  "roles/iam.securityReviewer"
  "roles/orgpolicy.policyViewer"
  "roles/recommender.viewer"
  "roles/logging.viewer"
)

echo "▶️  [4/4] Binding 6 Strictly Read-Only IAM Roles on organizations/${ORG_ID} to ${SA_EMAIL}..."
for ROLE in "${READ_ONLY_ORG_ROLES[@]}"; do
  echo "   + ${ROLE}"
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --condition=None \
    ${G_ACCOUNT_FLAGS[@]+"${G_ACCOUNT_FLAGS[@]}"} \
    --quiet >/dev/null
done

echo "=============================================================================="
echo "✅ CUSTOMER ONBOARDING COMPLETE!"
echo "   • Organization Scope               : organizations/${ORG_ID}"
echo "   • Service Account to Impersonate   : ${SA_EMAIL}"
echo "   • Authorized User (Token Creator)  : ${AUTHORIZED_USER}"
echo "=============================================================================="
