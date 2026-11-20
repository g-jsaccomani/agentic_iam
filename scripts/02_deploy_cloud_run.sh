#!/usr/bin/env bash
# ==============================================================================
# Agentic IAM Accelerator — Zero-Trust Cloud Run + Service-Scoped IAP Deployment
#
# Required environment variables (validated BEFORE executing any gcloud command):
#   ACCOUNT              Deploying GCP administrator email
#   PROJECT_ID           Target GCP compute project ID (or pass as $1)
#   ALLOWED_IAP_DOMAINS  Comma-separated allowed email domains (e.g. "corp.example").
#                        Wildcard "*" is rejected unless ALLOW_ANY_GOOGLE_ACCOUNT=true.
#   IAP_MEMBERS          Comma-separated IAM principals granted Cloud Run IAP access
#                        at the Cloud Run SERVICE level (e.g. "domain:corp.example,user:admin@corp.example").
#                        Required unless ALLOW_ANY_GOOGLE_ACCOUNT=true.
#
# Optional environment variables:
#   DRY_RUN=1                      Print every command without executing any of them
#   ALLOW_ANY_GOOGLE_ACCOUNT=true  Explicit opt-in to bind allAuthenticatedUsers on service IAP
#                                  and allow ALLOWED_IAP_DOMAINS="*"
#   REGION                         Cloud Run region (default: us-central1, or pass as $2)
#   SERVICE_NAME                   Cloud Run service name (default: agentic-iam-accelerator, or $3)
#   GEMINI_MODEL                   Vertex AI model ID (default: gemini-3.1-pro-preview-customtools, or $4)
#   IAP_EXTERNAL_OAUTH_CLIENT_ID   Optional external OAuth client ID (requires iap-external-oauth-secret)
#   IAM_OAUTH_CLIENT_ID            Optional Web Sign-In OAuth client ID
#   IAM_ALLOWED_TOKEN_AZP          Comma-separated allowlisted OAuth2 client IDs for access tokens
#   WORKSPACE_RETENTION_DAYS       Default workspace retention offered in the console, in days
#                                  (default: 30; 0 = persist nothing). The consultant picks the
#                                  retention per customer when connecting.
#   WORKSPACE_MAX_RETENTION_DAYS   Hard retention ceiling in days (default: 365). Enforced by the app
#                                  and by a lifecycle rule on the workspace bucket.
#   ENABLE_PERSISTENT_DELEGATION=true  Explicit opt-in to OFFER runtime-SA token auto-renew (default: false).
#                                  When false, the runtime Service Account is never used to mint tokens
#                                  for a customer Service Account and the onboarding kit grants it nothing.
# ==============================================================================
set -euo pipefail

export CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity"
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

# 0. Strictly validate mandatory variables BEFORE running any gcloud command
PROJECT_ID="${1:-${PROJECT_ID:-}}"
REGION="${2:-${REGION:-us-central1}}"
SERVICE_NAME="${3:-${SERVICE_NAME:-agentic-iam-accelerator}}"
GEMINI_MODEL="${4:-${GEMINI_MODEL:-gemini-3.1-pro-preview-customtools}}"

: "${ACCOUNT:?Set ACCOUNT to the deploying GCP administrator email}"
: "${PROJECT_ID:?Set PROJECT_ID or pass it as the first argument}"
: "${ALLOWED_IAP_DOMAINS:?Set ALLOWED_IAP_DOMAINS (comma-separated domains; never '*' without ALLOW_ANY_GOOGLE_ACCOUNT=true)}"

ALLOW_ANY_GOOGLE_ACCOUNT="${ALLOW_ANY_GOOGLE_ACCOUNT:-false}"
IAP_MEMBERS="${IAP_MEMBERS:-}"
DRY_RUN="${DRY_RUN:-0}"

if [[ "${ALLOWED_IAP_DOMAINS}" == *"*"* ]] && [[ "${ALLOW_ANY_GOOGLE_ACCOUNT}" != "true" ]]; then
  echo "[ERROR] ALLOWED_IAP_DOMAINS='*' is forbidden by default. Set ALLOW_ANY_GOOGLE_ACCOUNT=true to explicitly opt in." >&2
  exit 1
fi

if [[ -z "${IAP_MEMBERS}" ]] && [[ "${ALLOW_ANY_GOOGLE_ACCOUNT}" != "true" ]]; then
  echo "[ERROR] Set IAP_MEMBERS (comma-separated principals for service-level IAP) or set ALLOW_ANY_GOOGLE_ACCOUNT=true." >&2
  exit 1
fi

if [[ "${IAP_MEMBERS}" == *"allUsers"* ]]; then
  echo "[ERROR] allUsers is never allowed in IAP_MEMBERS." >&2
  exit 1
fi

if [[ "${IAP_MEMBERS}" == *"allAuthenticatedUsers"* ]] && [[ "${ALLOW_ANY_GOOGLE_ACCOUNT}" != "true" ]]; then
  echo "[ERROR] allAuthenticatedUsers requires ALLOW_ANY_GOOGLE_ACCOUNT=true." >&2
  exit 1
fi

if [[ "${GEMINI_MODEL}" != "gemini-3.1-pro-preview-customtools" ]]; then
  echo "[ERROR] Unsupported GEMINI_MODEL '${GEMINI_MODEL}'. Standardized model: gemini-3.1-pro-preview-customtools" >&2
  exit 1
fi

SA_NAME="${SA_NAME:-sa-agentic-iam-engine}"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
INGRESS_MODE="${INGRESS_MODE:-all}"
IAM_OAUTH_CLIENT_ID="${IAM_OAUTH_CLIENT_ID:-}"
IAP_EXTERNAL_OAUTH_CLIENT_ID="${IAP_EXTERNAL_OAUTH_CLIENT_ID:-}"
IAM_ALLOWED_TOKEN_AZP="${IAM_ALLOWED_TOKEN_AZP:-}"
VPC_NAME="${VPC_NAME:-vpc-iam-zero-trust}"
SUBNET_NAME="${SUBNET_NAME:-snet-iam-analyzer-${REGION}}"
SUBNET_CIDR="${SUBNET_CIDR:-10.160.0.0/24}"
SESSION_SECRET_NAME="${SESSION_SECRET_NAME:-iam-accelerator-session-secret}"
WORKSPACE_STATE_BUCKET="${WORKSPACE_STATE_BUCKET:-agentic-iam-workspaces-${PROJECT_ID}}"
WORKSPACE_RETENTION_DAYS="${WORKSPACE_RETENTION_DAYS:-30}"
WORKSPACE_MAX_RETENTION_DAYS="${WORKSPACE_MAX_RETENTION_DAYS:-365}"
# IAM_ENABLE_PERSISTENT_DELEGATION (the name the service itself reads) is accepted as an alias
ENABLE_PERSISTENT_DELEGATION="${ENABLE_PERSISTENT_DELEGATION:-${IAM_ENABLE_PERSISTENT_DELEGATION:-false}}"

if ! [[ "${WORKSPACE_RETENTION_DAYS}" =~ ^[0-9]+$ ]] || ! [[ "${WORKSPACE_MAX_RETENTION_DAYS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "[ERROR] WORKSPACE_RETENTION_DAYS must be a whole number >= 0 and WORKSPACE_MAX_RETENTION_DAYS a whole number >= 1." >&2
  exit 1
fi
if (( WORKSPACE_RETENTION_DAYS > WORKSPACE_MAX_RETENTION_DAYS )); then
  echo "[ERROR] WORKSPACE_RETENTION_DAYS cannot exceed WORKSPACE_MAX_RETENTION_DAYS." >&2
  exit 1
fi
if [[ "${ENABLE_PERSISTENT_DELEGATION}" != "true" ]] && [[ "${ENABLE_PERSISTENT_DELEGATION}" != "false" ]]; then
  echo "[ERROR] ENABLE_PERSISTENT_DELEGATION must be 'true' or 'false'." >&2
  exit 1
fi

EDGE_AUTH_FLAGS=(--no-allow-unauthenticated --iap)
if [[ "${IAM_ENABLE_CLOUD_IAP:-true}" == "false" ]]; then
  EDGE_AUTH_FLAGS=(--no-invoker-iam-check --no-iap)
fi

G_FLAGS=(--account="${ACCOUNT}")

# Cleanup trap ensuring any temporary YAML holding an OAuth client secret is always removed
TMP_IAP_YAML=""
cleanup() {
  if [[ -n "${TMP_IAP_YAML}" ]] && [[ -f "${TMP_IAP_YAML}" ]]; then
    rm -f "${TMP_IAP_YAML}"
  fi
}
trap cleanup EXIT

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
echo "Deploying Agentic IAM Accelerator to Google Cloud Run (Zero-Trust + Service IAP)"
echo "  Compute Project     : ${PROJECT_ID}"
echo "  Region              : ${REGION}"
echo "  Service Name        : ${SERVICE_NAME}"
echo "  Vertex AI Model     : ${GEMINI_MODEL} (GOOGLE_CLOUD_LOCATION=global)"
echo "  Workspace Store     : gs://${WORKSPACE_STATE_BUCKET}"
echo "  Workspace Retention : default ${WORKSPACE_RETENTION_DAYS}d, max ${WORKSPACE_MAX_RETENTION_DAYS}d"
echo "  Runtime-SA AutoRenew: ${ENABLE_PERSISTENT_DELEGATION}"
echo "  Dedicated VPC       : ${VPC_NAME} (${SUBNET_NAME} - ${SUBNET_CIDR})"
echo "  Runtime SA          : ${SA_EMAIL}"
echo "  Allowed Domains     : ${ALLOWED_IAP_DOMAINS}"
echo "  Allow Any Google    : ${ALLOW_ANY_GOOGLE_ACCOUNT}"
echo "  Dry Run             : ${DRY_RUN}"
echo "=============================================================================="

# 1. Enable Compute, IAP, Secret Manager, Storage & IAM Credentials APIs
run_cmd gcloud services enable \
  compute.googleapis.com \
  iap.googleapis.com \
  secretmanager.googleapis.com \
  storage.googleapis.com \
  iamcredentials.googleapis.com \
  --project="${PROJECT_ID}" \
  "${G_FLAGS[@]}" \
  --quiet

PROJECT_NUMBER="$(query_cmd "000000000000" gcloud projects describe "${PROJECT_ID}" "${G_FLAGS[@]}" --format="value(projectNumber)")"
IAP_SA="service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com"
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
IAP_AUDIENCE="/projects/${PROJECT_NUMBER}/locations/${REGION}/services/${SERVICE_NAME}"

run_cmd gcloud beta services identity create --service=iap.googleapis.com --project="${PROJECT_ID}" "${G_FLAGS[@]}" --quiet
run_cmd gcloud beta services identity create --service=aiplatform.googleapis.com --project="${PROJECT_ID}" "${G_FLAGS[@]}" --quiet

# 1.2 Ensure persistent HMAC / AES-256-GCM master key in Secret Manager
if [[ "${DRY_RUN}" == "1" ]]; then
  run_cmd gcloud secrets describe "${SESSION_SECRET_NAME}" --project="${PROJECT_ID}" "${G_FLAGS[@]}"
elif ! gcloud secrets describe "${SESSION_SECRET_NAME}" --project="${PROJECT_ID}" "${G_FLAGS[@]}" >/dev/null 2>&1; then
  python3 -c "import secrets; print(secrets.token_urlsafe(48), end='')" | \
    gcloud secrets create "${SESSION_SECRET_NAME}" --project="${PROJECT_ID}" "${G_FLAGS[@]}" --replication-policy="automatic" --data-file=-
fi
run_cmd gcloud secrets add-iam-policy-binding "${SESSION_SECRET_NAME}" \
  --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor" \
  --format="none"

# 1.3 Provision Dedicated Private GCS Bucket for Per-User Encrypted Workspace Persistence
echo "[0.5/4] Ensuring Encrypted Per-User Workspace Bucket (gs://${WORKSPACE_STATE_BUCKET})..."
if [[ "${DRY_RUN}" == "1" ]]; then
  run_cmd gcloud storage buckets create "gs://${WORKSPACE_STATE_BUCKET}" \
    --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
    --location="${REGION}" \
    --uniform-bucket-level-access \
    --public-access-prevention
elif ! gcloud storage buckets describe "gs://${WORKSPACE_STATE_BUCKET}" --project="${PROJECT_ID}" "${G_FLAGS[@]}" >/dev/null 2>&1; then
  run_cmd gcloud storage buckets create "gs://${WORKSPACE_STATE_BUCKET}" \
    --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
    --location="${REGION}" \
    --uniform-bucket-level-access \
    --public-access-prevention
fi
run_cmd gcloud storage buckets add-iam-policy-binding "gs://${WORKSPACE_STATE_BUCKET}" \
  --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/storage.objectAdmin" \
  --format="none"

# Hard retention ceiling: GCS itself deletes objects older than WORKSPACE_MAX_RETENTION_DAYS, even if the
# application never runs again. The application enforces the (shorter) retention chosen per customer.
LIFECYCLE_FILE="$(mktemp)"
printf '{"rule":[{"action":{"type":"Delete"},"condition":{"age":%s}}]}\n' "${WORKSPACE_MAX_RETENTION_DAYS}" > "${LIFECYCLE_FILE}"
run_cmd gcloud storage buckets update "gs://${WORKSPACE_STATE_BUCKET}" \
  --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
  --lifecycle-file="${LIFECYCLE_FILE}" \
  --format="none"
rm -f "${LIFECYCLE_FILE}"

# 1.4 Provision Dedicated Zero-Trust IAM VPC
echo "[1/4] Provisioning Dedicated Zero-Trust IAM VPC (${VPC_NAME})..."
if [[ "${DRY_RUN}" == "1" ]]; then
  run_cmd gcloud compute networks create "${VPC_NAME}" \
    --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
    --subnet-mode=custom \
    --bgp-routing-mode=regional \
    --description="Dedicated Agentic IAM Accelerator Zero-Trust Least-Privilege Engine VPC"
elif ! gcloud compute networks describe "${VPC_NAME}" --project="${PROJECT_ID}" "${G_FLAGS[@]}" >/dev/null 2>&1; then
  run_cmd gcloud compute networks create "${VPC_NAME}" \
    --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
    --subnet-mode=custom \
    --bgp-routing-mode=regional \
    --description="Dedicated Agentic IAM Accelerator Zero-Trust Least-Privilege Engine VPC"
fi

if [[ "${DRY_RUN}" == "1" ]]; then
  run_cmd gcloud compute networks subnets create "${SUBNET_NAME}" \
    --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
    --network="${VPC_NAME}" \
    --region="${REGION}" \
    --range="${SUBNET_CIDR}" \
    --enable-private-ip-google-access \
    --enable-flow-logs \
    --logging-aggregation-interval=interval-5-sec \
    --logging-flow-sampling=1.0
elif ! gcloud compute networks subnets describe "${SUBNET_NAME}" --region="${REGION}" --project="${PROJECT_ID}" "${G_FLAGS[@]}" >/dev/null 2>&1; then
  run_cmd gcloud compute networks subnets create "${SUBNET_NAME}" \
    --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
    --network="${VPC_NAME}" \
    --region="${REGION}" \
    --range="${SUBNET_CIDR}" \
    --enable-private-ip-google-access \
    --enable-flow-logs \
    --logging-aggregation-interval=interval-5-sec \
    --logging-flow-sampling=1.0
fi

if [[ "${DRY_RUN}" == "1" ]]; then
  run_cmd gcloud compute firewall-rules create "fw-iam-zerotrust-deny-all-ingress" \
    --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
    --network="${VPC_NAME}" \
    --direction=INGRESS \
    --action=DENY \
    --rules=all \
    --source-ranges="0.0.0.0/0" \
    --enable-logging \
    --priority=1000 \
    --description="Zero-Trust IAM baseline: explicit priority-1000 deny-all inbound connections"
elif ! gcloud compute firewall-rules describe "fw-iam-zerotrust-deny-all-ingress" --project="${PROJECT_ID}" "${G_FLAGS[@]}" >/dev/null 2>&1; then
  run_cmd gcloud compute firewall-rules create "fw-iam-zerotrust-deny-all-ingress" \
    --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
    --network="${VPC_NAME}" \
    --direction=INGRESS \
    --action=DENY \
    --rules=all \
    --source-ranges="0.0.0.0/0" \
    --enable-logging \
    --priority=1000 \
    --description="Zero-Trust IAM baseline: explicit priority-1000 deny-all inbound connections"
fi

# 2. Configure Cloud Build SA (NO roles/storage.admin!) & Runtime SA permissions
echo "[1.5/4] Configuring Cloud Build & Runtime Service Account permissions..."
for role in roles/run.builder roles/logging.logWriter roles/artifactregistry.writer; do
  run_cmd gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="${role}" \
    --condition=None \
    "${G_FLAGS[@]}" \
    --format="none"
done

# Runtime SA holds ONLY Vertex AI Compute + Log Writer (ZERO target org/asset permissions)
for ai_role in roles/aiplatform.user roles/logging.logWriter; do
  run_cmd gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ai_role}" \
    --condition=None \
    "${G_FLAGS[@]}" \
    --format="none"
done

ENV_STR="GOOGLE_GENAI_USE_VERTEXAI=TRUE#GOOGLE_CLOUD_PROJECT=${PROJECT_ID}#GOOGLE_CLOUD_LOCATION=global#GEMINI_MODEL=${GEMINI_MODEL}#ALLOWED_IAP_DOMAINS=${ALLOWED_IAP_DOMAINS}#IAM_IAP_AUDIENCE=${IAP_AUDIENCE}#IAM_OAUTH_CLIENT_ID=${IAM_OAUTH_CLIENT_ID}#GOOGLE_OAUTH_CLIENT_ID=${IAM_OAUTH_CLIENT_ID}#IAM_ALLOWED_TOKEN_AZP=${IAM_ALLOWED_TOKEN_AZP}#WORKSPACE_STATE_BUCKET=${WORKSPACE_STATE_BUCKET}#IAM_WORKSPACE_RETENTION_DAYS=${WORKSPACE_RETENTION_DAYS}#IAM_WORKSPACE_MAX_RETENTION_DAYS=${WORKSPACE_MAX_RETENTION_DAYS}#IAM_ENABLE_PERSISTENT_DELEGATION=${ENABLE_PERSISTENT_DELEGATION}"
# The runtime SA is only named as a delegation target when auto-renew was explicitly enabled
if [[ "${ENABLE_PERSISTENT_DELEGATION}" == "true" ]]; then
  ENV_STR="${ENV_STR}#PERSISTENT_DELEGATION_SA=${SA_EMAIL}"
fi

# 3. Deploy Cloud Run Service
# Cost & State Note (T08/T09):
#   --min-instances=1 and --max-instances=1 with --session-affinity keep in-memory session
#   vault & ADK chat state on a single deterministic instance without split-brain.
#   --no-cpu-throttling keeps CPU allocated for background POST /api/v1/scans jobs.
#   NOTE: --min-instances=1 + --no-cpu-throttling (2 vCPU, 4GiB) incurs continuous idle
#   instance billing (~$70-120/month depending on region). Scale down or remove the service
#   when idle in non-production environments.
echo "[2/4] Building container and deploying '${SERVICE_NAME}'..."
run_cmd gcloud beta run deploy "${SERVICE_NAME}" \
  --source . \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  "${G_FLAGS[@]}" \
  --service-account="${SA_EMAIL}" \
  "${EDGE_AUTH_FLAGS[@]}" \
  --network="${VPC_NAME}" \
  --subnet="${SUBNET_NAME}" \
  --vpc-egress=private-ranges-only \
  --ingress="${INGRESS_MODE}" \
  --execution-environment=gen2 \
  --memory=4Gi \
  --cpu=2 \
  --min-instances=1 \
  --max-instances=1 \
  --session-affinity \
  --no-cpu-throttling \
  --timeout=300 \
  --set-secrets="IAM_SESSION_SECRET=${SESSION_SECRET_NAME}:latest" \
  --set-env-vars="^#^${ENV_STR}"

# 4. Bind roles/run.invoker STRICTLY to the IAP service agent (no direct user/domain bypass)
echo "[3/4] Configuring Cloud Run Invoker (IAP Service Agent ONLY) & Service-Level IAP Access..."
run_cmd gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  "${G_FLAGS[@]}" \
  --member="serviceAccount:${IAP_SA}" \
  --role="roles/run.invoker" \
  --format="none"

# Bind IAP access strictly at the Cloud Run SERVICE level (never project-wide)
if [[ "${IAM_ENABLE_CLOUD_IAP:-true}" != "false" ]]; then
  IAP_BINDING_MEMBERS=()
  if [[ -n "${IAP_MEMBERS}" ]]; then
    IFS=',' read -r -a RAW_MEMBERS <<< "${IAP_MEMBERS}"
    for m in "${RAW_MEMBERS[@]}"; do
      m_trimmed="${m#"${m%%[![:space:]]*}"}"
      m_trimmed="${m_trimmed%"${m_trimmed##*[![:space:]]}"}"
      if [[ -n "${m_trimmed}" ]]; then
        IAP_BINDING_MEMBERS+=("${m_trimmed}")
      fi
    done
  fi
  if [[ "${ALLOW_ANY_GOOGLE_ACCOUNT}" == "true" ]] && [[ "${IAP_MEMBERS}" != *"allAuthenticatedUsers"* ]]; then
    IAP_BINDING_MEMBERS+=("allAuthenticatedUsers")
  fi

  for iap_member in "${IAP_BINDING_MEMBERS[@]}"; do
    run_cmd gcloud beta iap web add-iam-policy-binding \
      --resource-type=cloud-run \
      --service="${SERVICE_NAME}" \
      --region="${REGION}" \
      --project="${PROJECT_ID}" \
      "${G_FLAGS[@]}" \
      --member="${iap_member}" \
      --role="roles/iap.httpsResourceAccessor" \
      --condition=None \
      --format="none"
  done
fi

# Optional external OAuth client for IAP (requires explicit IAP_EXTERNAL_OAUTH_CLIENT_ID + secret)
if [[ "${IAM_ENABLE_CLOUD_IAP:-true}" != "false" ]] && [[ -n "${IAP_EXTERNAL_OAUTH_CLIENT_ID}" ]]; then
  if [[ "${DRY_RUN}" == "1" ]]; then
    run_cmd gcloud secrets versions access latest --secret="iap-external-oauth-secret" --project="${PROJECT_ID}" "${G_FLAGS[@]}"
    run_cmd gcloud iap settings set "/tmp/dry-run-iap-settings.yaml" \
      --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
      --resource-type=cloud-run --region="${REGION}" --service="${SERVICE_NAME}"
  elif gcloud secrets describe "iap-external-oauth-secret" --project="${PROJECT_ID}" "${G_FLAGS[@]}" >/dev/null 2>&1; then
    OAUTH_SEC="$(gcloud secrets versions access latest --secret="iap-external-oauth-secret" --project="${PROJECT_ID}" "${G_FLAGS[@]}")"
    URLS_JSON="$(gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" "${G_FLAGS[@]}" --format="value(metadata.annotations['run.googleapis.com/urls'])")"
    TMP_IAP_YAML="$(mktemp)"
    chmod 600 "${TMP_IAP_YAML}"
    URLS_JSON="${URLS_JSON}" CID="${IAP_EXTERNAL_OAUTH_CLIENT_ID}" CSEC="${OAUTH_SEC}" python3 - "${TMP_IAP_YAML}" <<'PY'
import json, os, sys, urllib.parse
hosts = [urllib.parse.urlparse(u).hostname for u in json.loads(os.environ.get("URLS_JSON") or "[]") if urllib.parse.urlparse(u).hostname]
lines = [
    "accessSettings:",
    "  allowedDomainsSettings:",
    "    enable: true",
    "    domains:",
    *[f"      - {json.dumps(h)}" for h in hosts],
    "  oauthSettings:",
    f'    clientId: {json.dumps(os.environ["CID"])}',
    f'    clientSecret: {json.dumps(os.environ["CSEC"])}',
]
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PY
    unset OAUTH_SEC
    run_cmd gcloud iap settings set "${TMP_IAP_YAML}" \
      --project="${PROJECT_ID}" "${G_FLAGS[@]}" \
      --resource-type=cloud-run --region="${REGION}" --service="${SERVICE_NAME}"
    rm -f "${TMP_IAP_YAML}"
    TMP_IAP_YAML=""
  fi
fi

SERVICE_URL="https://${SERVICE_NAME}-${PROJECT_NUMBER}.${REGION}.run.app"

echo "=============================================================================="
echo "[4/4] Cloud Run Native IAP + Clean-Slate Deployment Complete!"
echo "  Service URL   : ${SERVICE_URL}"
echo "  Edge Auth     : Service-Scoped Native Cloud Run IAP"
echo "  Runtime SA    : ${SA_EMAIL} (Vertex AI Compute + Logging ONLY)"
echo "=============================================================================="
