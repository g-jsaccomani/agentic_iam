#!/usr/bin/env bash
# ==============================================================================
# Agentic IAM Accelerator — GCP Resource Hierarchy & API Bootstrap Script
# Positioning: Consultative IAM Posture Assessment, Modernization, and
#              Least-Privilege Acceleration Engine (Shared Responsibility Model)
#
# Required environment variables (validated before running any gcloud command):
#   ACCOUNT     Deploying GCP administrator email
#   ORG_ID      Numeric GCP Organization ID
#   PROJECT_ID  Target GCP Project ID (or pass as first positional argument)
#
# Optional environment variables:
#   DRY_RUN=1             Print all commands without executing them
#   FOLDER_DISPLAY_NAME   Folder name under Organization (default: agentic_iam)
#   ENV_SUFFIX            Environment label suffix (default: dev)
#   REGION                Default GCP region (default: us-central1)
#   BQ_LOCATION           BigQuery dataset location (default: US)
#   BQ_DATASET            BigQuery dataset name (default: iam_posture_lake)
#   SA_NAME               Runtime service account ID (default: sa-agentic-iam-engine)
#   BILLING_ACCOUNT       Optional billing account ID to link
#
# ==============================================================================
# LEGACY GRANT REVOCATION (DOCUMENTATION ONLY — DO NOT AUTO-EXECUTE):
# Older versions of this script granted extra project-level roles to the runtime
# SA. To revoke those legacy grants on an existing deployment, run manually:
#
#   for legacy_role in \
#     roles/bigquery.dataEditor \
#     roles/bigquery.jobUser \
#     roles/cloudasset.viewer \
#     roles/recommender.iamViewer; do
#     gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \
#       --member="serviceAccount:${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
#       --role="${legacy_role}" \
#       --condition=None
#   done
# ==============================================================================
set -euo pipefail

export CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity"

# Validate mandatory inputs BEFORE executing any gcloud/bq command
PROJECT_ID="${1:-${PROJECT_ID:-}}"
: "${ACCOUNT:?Set ACCOUNT to the deploying GCP administrator email}"
: "${ORG_ID:?Set ORG_ID to the numeric GCP Organization ID}"
: "${PROJECT_ID:?Set PROJECT_ID or pass it as the first argument}"

ORG_ID="${ORG_ID#organizations/}"
if [[ ! "${ORG_ID}" =~ ^[0-9]+$ ]]; then
  echo "[ERROR] ORG_ID must be numeric (got: '${ORG_ID}')." >&2
  exit 1
fi

DRY_RUN="${DRY_RUN:-0}"
FOLDER_DISPLAY_NAME="${FOLDER_DISPLAY_NAME:-agentic_iam}"
ENV_SUFFIX="${ENV_SUFFIX:-dev}"
REGION="${REGION:-us-central1}"
BQ_LOCATION="${BQ_LOCATION:-US}"
BQ_DATASET="${BQ_DATASET:-iam_posture_lake}"
SA_NAME="${SA_NAME:-sa-agentic-iam-engine}"
BILLING_ACCOUNT="${BILLING_ACCOUNT:-}"

export CLOUDSDK_CORE_DISABLE_PROMPTS=1

G_FLAGS=(--account="${ACCOUNT}")

run_cmd() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    printf '[DRY_RUN]'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

query_cmd() {
  local placeholder="$1"
  shift
  if [[ "${DRY_RUN}" == "1" ]]; then
    printf '[DRY_RUN]' >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    printf '%s\n' "${placeholder}"
    return 0
  fi
  "$@"
}

echo "=============================================================================="
echo "Agentic IAM Accelerator — GCP Infrastructure Bootstrap"
echo "  Account     : ${ACCOUNT}"
echo "  Org ID      : organizations/${ORG_ID}"
echo "  Folder Name : ${FOLDER_DISPLAY_NAME}"
echo "  Project ID  : ${PROJECT_ID}"
echo "  Region      : ${REGION}"
echo "  Dry Run     : ${DRY_RUN}"
echo "=============================================================================="

# 1. Describe Organization
ORG_DOMAIN="$(query_cmd "example.com" gcloud organizations describe "${ORG_ID}" "${G_FLAGS[@]}" --format="value(displayName)")"
echo "[1/6] Verified Organization: organizations/${ORG_ID} (${ORG_DOMAIN})"

# 2. Resolve or Create Folder under Organization
echo "[2/6] Configuring Folder '${FOLDER_DISPLAY_NAME}' under organizations/${ORG_ID}..."
FOLDER_ID="$(query_cmd "000000000001" gcloud resource-manager folders list \
  --organization="${ORG_ID}" \
  "${G_FLAGS[@]}" \
  --filter="displayName='${FOLDER_DISPLAY_NAME}'" \
  --format="value(name)")"
FOLDER_ID="${FOLDER_ID%%$'\n'*}"
FOLDER_ID="${FOLDER_ID#folders/}"

if [[ -z "${FOLDER_ID}" ]]; then
  FOLDER_ID="$(query_cmd "000000000001" gcloud resource-manager folders create \
    --display-name="${FOLDER_DISPLAY_NAME}" \
    --organization="${ORG_ID}" \
    "${G_FLAGS[@]}" \
    --format="value(name)")"
  FOLDER_ID="${FOLDER_ID#folders/}"
  echo "  Created Folder '${FOLDER_DISPLAY_NAME}' -> folders/${FOLDER_ID}"
else
  echo "  Reusing existing Folder '${FOLDER_DISPLAY_NAME}' -> folders/${FOLDER_ID}"
fi

# 3. Create or Verify Project inside Folder
echo "[3/6] Configuring Project '${PROJECT_ID}' inside folders/${FOLDER_ID}..."
if [[ "${DRY_RUN}" == "1" ]]; then
  run_cmd gcloud projects describe "${PROJECT_ID}" "${G_FLAGS[@]}"
  run_cmd gcloud projects create "${PROJECT_ID}" \
    --folder="${FOLDER_ID}" \
    --name="Agentic IAM Accelerator - ${ENV_SUFFIX}" \
    --labels="platform=agentic-iam-accelerator,environment=${ENV_SUFFIX},managed-by=antigravity,posture=least-privilege" \
    "${G_FLAGS[@]}"
elif ! gcloud projects describe "${PROJECT_ID}" "${G_FLAGS[@]}" >/dev/null 2>&1; then
  run_cmd gcloud projects create "${PROJECT_ID}" \
    --folder="${FOLDER_ID}" \
    --name="Agentic IAM Accelerator - ${ENV_SUFFIX}" \
    --labels="platform=agentic-iam-accelerator,environment=${ENV_SUFFIX},managed-by=antigravity,posture=least-privilege" \
    "${G_FLAGS[@]}"
  echo "  Created Project '${PROJECT_ID}' in folders/${FOLDER_ID}"
else
  echo "  Verified existing Project '${PROJECT_ID}'"
fi

PROJECT_NUMBER="$(query_cmd "000000000000" gcloud projects describe "${PROJECT_ID}" "${G_FLAGS[@]}" --format="value(projectNumber)")"
echo "  Project Number: ${PROJECT_NUMBER}"

# 4. Link Billing Account (when provided)
echo "[4/6] Configuring Billing Account for '${PROJECT_ID}'..."
if [[ -n "${BILLING_ACCOUNT}" ]]; then
  run_cmd gcloud billing projects link "${PROJECT_ID}" \
    --billing-account="${BILLING_ACCOUNT}" \
    "${G_FLAGS[@]}" \
    --format="value(billingEnabled)"
  echo "  Linked Billing Account: ${BILLING_ACCOUNT}"
else
  echo "  BILLING_ACCOUNT not set; skipping automatic billing link."
fi

# 5. Enable Mandatory Service APIs
echo "[5/6] Enabling Mandatory IAM, Policy, Vertex AI, BigQuery & Cloud Run APIs..."
REQUIRED_APIS=(
  "cloudasset.googleapis.com"
  "cloudresourcemanager.googleapis.com"
  "recommender.googleapis.com"
  "policyanalyzer.googleapis.com"
  "policysimulator.googleapis.com"
  "aiplatform.googleapis.com"
  "run.googleapis.com"
  "bigquery.googleapis.com"
  "admin.googleapis.com"
  "logging.googleapis.com"
  "iamcredentials.googleapis.com"
  "iam.googleapis.com"
  "privilegedaccessmanager.googleapis.com"
  "cloudbuild.googleapis.com"
  "artifactregistry.googleapis.com"
)

run_cmd gcloud services enable "${REQUIRED_APIS[@]}" \
  --project="${PROJECT_ID}" \
  "${G_FLAGS[@]}" \
  --quiet
echo "  Enabled ${#REQUIRED_APIS[@]} Google Cloud APIs on ${PROJECT_ID}"

# 6. Provision Least-Privilege Runtime Service Account (Vertex AI Compute + Logging ONLY)
echo "[6/6] Provisioning Least-Privilege Runtime Service Account & BigQuery Dataset..."
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
if [[ "${DRY_RUN}" == "1" ]]; then
  run_cmd gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Agentic IAM Accelerator Runtime SA (Compute Only)" \
    --description="Least-privilege workload identity for Agentic IAM Accelerator on Cloud Run" \
    --project="${PROJECT_ID}" \
    "${G_FLAGS[@]}"
elif ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" "${G_FLAGS[@]}" >/dev/null 2>&1; then
  run_cmd gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Agentic IAM Accelerator Runtime SA (Compute Only)" \
    --description="Least-privilege workload identity for Agentic IAM Accelerator on Cloud Run" \
    --project="${PROJECT_ID}" \
    "${G_FLAGS[@]}"
  sleep 5
fi

# Strictly minimal runtime compute roles (ZERO target org/asset/BigQuery permissions on host SA)
RUNTIME_PROJECT_ROLES=(
  "roles/aiplatform.user"
  "roles/logging.logWriter"
)
for r in "${RUNTIME_PROJECT_ROLES[@]}"; do
  run_cmd gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${r}" \
    --condition=None \
    "${G_FLAGS[@]}" \
    --format="none"
done
echo "  Configured Least-Privilege Runtime Service Account: ${SA_EMAIL}"

# Create optional BigQuery dataset with attribution label
if [[ "${DRY_RUN}" == "1" ]]; then
  run_cmd bq --location="${BQ_LOCATION}" --project_id="${PROJECT_ID}" mk \
    --dataset \
    --label datacloud:antigravity \
    --description="Agentic IAM Accelerator Telemetry & Posture Findings Lake" \
    "${PROJECT_ID}:${BQ_DATASET}"
elif ! bq --project_id="${PROJECT_ID}" show --dataset "${PROJECT_ID}:${BQ_DATASET}" >/dev/null 2>&1; then
  run_cmd bq --location="${BQ_LOCATION}" --project_id="${PROJECT_ID}" mk \
    --dataset \
    --label datacloud:antigravity \
    --description="Agentic IAM Accelerator Telemetry & Posture Findings Lake" \
    "${PROJECT_ID}:${BQ_DATASET}"
fi

echo "=============================================================================="
echo "Bootstrap Complete!"
echo "  Organization : organizations/${ORG_ID} (${ORG_DOMAIN})"
echo "  Folder       : folders/${FOLDER_ID} (${FOLDER_DISPLAY_NAME})"
echo "  Project ID   : ${PROJECT_ID} (Number: ${PROJECT_NUMBER})"
echo "  Runtime SA   : ${SA_EMAIL} (roles/aiplatform.user, roles/logging.logWriter)"
echo "  BQ Dataset   : ${PROJECT_ID}:${BQ_DATASET}"
echo "=============================================================================="
