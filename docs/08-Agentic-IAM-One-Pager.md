# OnePage : Agentic IAM (Customer & Sales One-Pager)

> **Repository Deliverable:** [docs/08-Agentic-IAM-One-Pager.md](08-Agentic-IAM-One-Pager.md)

---

## Banner
- **Title:** Agentic IAM Accelerator — *Cloud Identity Posture, Attack Path Graph & Least-Privilege Modernization*
- **Header Badge:** Overview: Agentic IAM Posture Review

## What is the Agentic IAM Accelerator?
The Agentic IAM Accelerator is a 6-week Google Cloud Consulting engagement where deterministic collectors and Gemini AI specialist agents (built on Google ADK and Vertex AI) perform a **100% read-only** inspection of your Google Cloud IAM bindings, Cloud Identity groups, Service Accounts, and Organization Policies, model hidden multi-hop privilege-escalation chains using **NetworkX**, and pair with structured 7-domain stakeholder interviews to deliver an auditable posture scorecard, evidence-backed least-privilege recommendations, and an advisory (unvalidated) Terraform/PAM modernization blueprint.

## Is this offering right for you?
- **Identity Sprawl & Standing Privilege Visibility:** You need a complete, automated **Identity Triad** baseline across Internal Employees, External Partners/Contractors, and Automated Service Accounts without months of manual spreadsheets.
- **Multi-Hop Escalation & Choke-Point Discovery:** You want to uncover hidden Service Account impersonation chains (`actAs` / `TokenCreator`), static JSON keys (>90 days), Default Compute SA risks, and Separation-of-Duties (SoD) gaps.
- **Safe Least-Privilege & PAM JIT Modernization:** You want to transition standing `Owner`/`Editor` admins to **Privileged Access Manager (PAM)** Just-In-Time access and downsize over-privileged roles using IAM Recommender insights and bounded Cloud Audit Log samples — with customer-led Policy Simulator & `terraform plan` validation before production rollout.

## What does your team gain?
- **Identity Triad & NetworkX Attack Graph:** Automated discovery of human, external, group, WIF, and Service Account bindings paired with a high-DPI multi-hop privilege-escalation graph and centrality choke-point ranking.
- **7-Domain Area Readiness & Executive Scorecard:** Maturity assessment across 7 organizational areas (Levels 1.0–5.0), an auditable 0–100% IAM Posture Scorecard, and executive `.docx` / `.pdf` board deliverables.
- **Advisory Terraform, Custom Role & PAM Blueprint (Unvalidated):** Tailored OpenTofu/Terraform modules (`main.tf`, `variables.tf`, `iam.tf`, `pam_entitlements.tf`, `org_policies.tf`) paired with bounded Cloud Audit Log sample impact estimates for customer-led Policy Simulator validation and CI/CD adoption (zero changes executed by Google in your environment).

## Engagement Overview (Right Column Badges)
- **Key deliverables:**
  - `Identity Triad & CSPR Findings`
  - `7-Domain IAM Readiness Report`
  - `NetworkX Attack Path Topology`
  - `Advisory Terraform & PAM Book`
- **Google team could include:**
  - `GSD Security Architect`
  - `PSO IAM Security Consultant`
  - `SCE Cloud Security Specialist`
  - `SCE Hybrid & Network Lead`
- **Your team includes:**
  - `CISO / Security Executive`
  - `IAM & Cloud Identity Lead`
  - `Cloud Platform / Landing Zone Lead`
  - `AppDev & CI/CD Pipeline Lead`
  - `SecOps / SIEM Lead`
  - `GRC & Risk Committee`
- **Key engagement details:**
  - `Delivery time est: 6 weeks - 224 hours`

## Key items we need from you
- Participation of IAM, Cloud Identity, Platform, AppDev/CI-CD, SecOps & GRC leads in Weeks 3–4 readiness interviews
- 1-line keyless read-only `sa-iam-assessor` setup executed in Cloud Shell before Week 1 Kickoff
- Read-only metadata access to Cloud Asset Inventory, Resource Manager, IAM, Recommender & Cloud Audit Logs

## Other Google Cloud solutions that complement your cloud journey
### Complementary Google Cloud Offerings (`Complementary Solutions`)
- Privileged Access Manager (PAM) Just-In-Time Access
- Workload Identity Federation (WIF) Keyless CI/CD & Multi-Cloud
- Cloud Identity Premium & Context-Aware Access (BeyondCorp)
- Security Command Center (SCC) Enterprise CIEM & Attack Exposure
- VPC Service Controls (VPC-SC) Zero-Trust Data Perimeters
