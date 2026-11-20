# Agentic IAM Executive Presentation Deck (14-Slide Plain-Language Guide)
**Google Cloud Consulting — Automated Identity Triad Discovery, Attack Path Graph & Least-Privilege Acceleration**

> **Repository Deliverable:** [docs/02-Agentic-IAM-Executive-Presentation-Deck.md](02-Agentic-IAM-Executive-Presentation-Deck.md)

---

## Slide 1 — Cover
- **Title:** Agentic IAM: Cloud Identity Posture & Least-Privilege Acceleration
- **Subtitle:** 6-Week Identity Triad Review, Attack Path Analysis & Zero-Trust Modernization

---

## Slide 2 — Agentic IAM in Plain Language
- **What is the Problem? ("Master Keys" & Identity Sprawl):** Over years of fast cloud adoption, employees, external contractors, and automated scripts accumulate permanent "master keys" (`Owner` and `Editor` permissions) and unrotated Service Account JSON keys. Attackers no longer break in — they log in and hop across connected accounts.
- **What is Zero-Trust IAM Modernization?** Replacing 24/7 standing admin rights with **1-hour approved passes** (Privileged Access Manager JIT), replacing static JSON keys with **keyless federation** (Workload Identity Federation), and sizing roles to the permissions workloads actually use.
- **What is Agentic IAM?** Deterministic collectors and Gemini AI specialist agents perform a **100% read-only IAM & Cloud Identity inspection**, model hidden multi-hop escalation chains using **NetworkX** graph math, and pair with structured stakeholder interviews to deliver a complete **IAM Posture Acceleration Book & Advisory Terraform Blueprint**.

---

## Slide 3 — What We Will Cover Today (Simple 8-Point Executive Guide)
1. **Why Act Now?** (Identity Sprawl & Lateral Movement Risk)
2. **How Our AI Agents Work** (100% Read-Only & Clean-Slate Multi-User Isolation)
3. **What We Inspect Across Your Cloud** (4 Core Identity Vectors)
4. **7-Domain Area Readiness Questionnaire & Stakeholder Interviews**
5. **Graph-Based Attack Path & Blast-Radius Prioritization**
6. **Advisory PAM Just-In-Time, Keyless WIF & Terraform Blueprints**
7. **Our 6-Week Posture Review Program (Step-by-Step)**
8. **Why Google Cloud & What Your Team Receives**

---

## Slide 4 — Agentic IAM at a Glance
- **Who Needs This?** Banks, healthcare, public sector, telecom, retail, and any enterprise running multi-project Google Cloud environments under ISO 27001, PCI-DSS v4.0, DORA, BACEN, or SOX controls.
- **The Challenge (Fear of Breaking Production):** Security teams know standing `Owner`/`Editor` roles and old Service Account keys are dangerous, but auditing tens of thousands of bindings across nested groups takes months — and revoking roles blindly risks breaking live applications.
- **Our Solution (Agentic IAM):**
  - Powered by deterministic read-only collectors and five **Google ADK** agents running **Gemini (`gemini-3.1-pro-preview-customtools`)** on Vertex AI (`location=global`), our hybrid engine inventories your Organization IAM policies, Cloud Identity groups, Service Accounts, and bounded Cloud Audit Log samples in minutes.
  - It is **100% read-only & zero-key** — using 1-hour keyless Service Account impersonation without ever touching customer data, secrets, or live workloads.
  - Combines automated graph analysis with **7-Domain Area Readiness Interviews** to deliver advisory Custom Roles, PAM JIT entitlements, and unvalidated Terraform blueprints ready for customer-led staging verification.
- **Business Value:**
  - Replaces 4+ weeks of manual IAM spreadsheet review with automated, evidence-backed telemetry.
  - Reveals multi-hop Service Account impersonation paths invisible in flat IAM policy tables.
  - Identifies 80%–95%+ of unused standing permissions using IAM Recommender insights and bounded Cloud Audit Log samples for customer-led staging validation.
  - Aligns IAM, Cloud Platform, SecOps, AppDev, and GRC teams around a single 3-Wave Modernization Roadmap.
  - Delivers ready-to-review OpenTofu/Terraform modules (`iam.tf`, `pam_entitlements.tf`, `org_policies.tf`) for customer-led CI/CD adoption.

---

## Slide 5 — What the AI Agents Inspect in Your Cloud
| Area | Focus | What the AI Agents Do in Plain English |
| :--- | :--- | :--- |
| **1. Internal Workforce & Groups** | Employees & Cloud Identity | Audits direct `user:` grants vs. Group RBAC, standing `Owner`/`Editor` admins, 2SV/MFA status, and Cloud Identity group hygiene. |
| **2. External & Partner Access** | Contractors, Domains & Public | Checks Domain Restricted Sharing (`iam.allowedPolicyMemberDomains`), consumer `@gmail.com` bindings, and `allUsers` public exposure. |
| **3. Workloads & Service Accounts** | Machine Identities & Keys | Inventories every Service Account, static user-managed JSON key (>90 days), Default Compute SA over-privilege, and Workload Identity Pools. |
| **4. Escalation Graph & Guardrails** | Attack Paths & Org Policies | Builds a live **NetworkX** directed graph of `actAs` / `TokenCreator` hops, toxic combinations, and preventive Organization Policy drift. |

---

## Slide 6 — How We Prioritize Identity & Escalation Findings (No Guesswork)
1. **Public & Unscoped External Exposure (`CRITICAL`):** Any `allUsers` / `allAuthenticatedUsers` grant or unapproved external domain/consumer account when Domain Restricted Sharing is un-enforced.
2. **Multi-Hop Service Account Impersonation Chains (`CRITICAL`):** Paths where a developer, CI/CD runner, or unconditioned WIF pool can hop via `serviceAccountTokenCreator` / `actAs` into a production database or KMS key.
3. **Unrotated Static Service Account Keys & Default SAs (`HIGH`):** User-managed `.json` keys older than 90 days and workloads running on Default Compute Engine Service Accounts with broad `roles/editor`.
4. **Standing Human Primitive Roles (`HIGH`):** Workforce users holding 24/7 unconditioned `roles/owner`, `roles/editor`, or `organizationAdmin` instead of 1-hour **Privileged Access Manager (PAM)** JIT elevation.
5. **Excess Permission Bloat (`MEDIUM`–`HIGH`):** Roles granting thousands of permissions where IAM Recommender insights and bounded Cloud Audit Log samples show minimal exercised surface.

---

## Slide 7 — Illustrative Example: Executive IAM Posture Scorecard
*Badge: SAMPLE READ-ONLY CLOUD SCAN*

| Security Dimension Checked | Score / Result | Posture Finding & Advisory Recommendation |
| :--- | :---: | :--- |
| **Overall IAM Posture Score** | **62.4% (Developing)** | Live bindings, Service Accounts, and Org Policies evaluated across all active projects in minutes. |
| **Internal Workforce Identities** | **58.0%** | Direct `user:` primitive grants detected — migrate to Cloud Identity Security Groups & PAM JIT. |
| **External & Partner Identities** | **75.0%** | Enforce `constraints/iam.allowedPolicyMemberDomains` and time-bound partner group conditions. |
| **Workload & Service Accounts** | **54.0%** | Static SA keys >90d and Default Compute SA `Editor` grants — transition to keyless WIF & dedicated SAs. |
| **Least-Privilege & Graph Resilience** | **64.5%** | High-centrality SA choke points & thousands of unused permissions removable via Custom Roles. |

---

## Slide 8 — Identity Posture Review & Advisory Modernization Guidelines
### Left Column: Identity Triad, Graph & Telemetry Review
1. **3-Pillar Identity Triad Audit:** Separates human workforce, external partner, and machine Service Account findings aligned with CSPR views (`iam-2eus`, `iam-xl3c`, `iam-p1ri`, `iam-d067`).
2. **NetworkX Centrality & Choke-Point Math:** Calculates `betweenness_centrality` and `degree_centrality` to pinpoint which single binding removal breaks the most escalation paths.
3. **Bounded Cloud Audit Log Impact Evidence:** Correlates proposed role downsizing against bounded Cloud Audit Log samples (reporting exact sample size and observed window; no Policy Simulator replay is executed automatically).

### Right Column: Area Readiness & Architectural Advisory
- **Privileged Access Manager (PAM) JIT Design:** Maps standing admins to 1-hour approval-gated PAM entitlements with dual-custody approver groups.
- **Keyless Workload Identity Federation (WIF):** Advises CI/CD and multi-cloud teams on OIDC `attributeCondition` hardening and static key retirement.
- **Preventive Organization Policy Templates:** Delivers declarative Terraform (`org_policies.tf`) to block future static SA keys, Default SA grants, and public buckets.

---

## Slide 9 — How We Work Together: 6-Week Posture Review Program
- **Weeks 1–2 (Keyless Onboarding & Identity Triad Discovery):** We provision 1-line keyless read-only access (`sa-iam-assessor`), run automated discovery across CAI, Cloud Identity, SA keys, and Org Policies, and build the Identity Triad baseline. *Key deliverables: 6-point pre-flight validation, Identity Triad inventory, CSPR-aligned findings baseline.*
- **Weeks 3–4 (7-Domain Readiness Interviews & Attack Path Graph):** We apply the 7-Domain IAM Discovery Questionnaire across stakeholder areas, model the live NetworkX privilege-escalation graph, and identify toxic combinations and choke points. *Key deliverables: 7-domain maturity scorecard, high-DPI Attack Path topology, prioritized blast-radius matrix.*
- **Weeks 5–6 (PAM JIT, Least-Privilege IaC Synthesis & Executive Roadmap):** We synthesize Custom Roles, PAM JIT entitlements, and bounded Cloud Audit Log change-impact estimates, compile the advisory (unvalidated) Terraform bundle for customer Policy Simulator & `terraform plan` review, and present the 3-Wave Modernization Roadmap to leadership. *Key deliverables: Advisory Terraform `.zip` bundle, Executive Posture Book (`.docx`/`.pdf`), Board readout.*

---

## Slide 10 — Why Google Cloud & Agentic IAM?
- **Subtitle:** Combining Gemini ADK Specialist Agents with Google Cloud Identity & Security Architects
- **Business Impact & Time Saved:**
  - **Replaces Months of Manual Policy Audits:** Compresses manual role-by-role spreadsheet reviews into an automated, graph-verified 6-week posture program.
  - **Time to First Attack-Path & Triad Baseline:** 120–160 hrs ➔ < 5 mins — 85% less manual effort for your IAM and Cloud Platform teams.
  - **100% Read-Only, Zero-Key & Clean-Slate:** Zero static JSON keys, private per-user workspaces (users never see each other's data; stored documents are application-encrypted with AES-256-GCM and kept only for the retention the consultant chooses — 0 to 365 days, default 30, where 0 persists nothing), and zero risk to running production workloads.
- **3 Reasons Customers Choose Google Cloud:**
  1. **Graph-Theoretic Escalation Visibility:** Combines Cloud Asset Inventory with **NetworkX** centrality math to uncover multi-hop SA impersonation chains missed by flat scanners.
  2. **Native Recommender + Bounded Audit Log Grounding:** Pairs Gemini reasoning with live IAM Recommender insights and transparent Cloud Audit Log sample coverage so teams validate changes safely in staging.
  3. **6-Week Expert Posture Review & IaC Blueprint:** Our Consultants (`224h` across 6 weeks) deliver board-ready `.docx`/`.pdf` reports alongside modular OpenTofu/Terraform code.

---

## Slide 11 — What You Receive in 6 Weeks
*The Agentic IAM Accelerator is deployed on Cloud Run with Native IAP & Clean-Slate Session Isolation, producing 4 executive and engineering deliverable packages:*

**4 Key Deliverables for Leadership & Engineering:**
1. **01. Executive IAM Posture Scorecard & Board Report (`.docx` / `.pdf`)** *(Scorecard, Identity Triad & CISO Narrative)*
2. **02. 7-Domain IAM & Cloud Identity Readiness Assessment** *(35-Question Rubric & Stakeholder Interviews)*
3. **03. NetworkX Attack Path & Escalation Topology (`.png` + Matrix)** *(Impersonation Chains, SoD & Choke Points)*
4. **04. Advisory Terraform / OpenTofu Bundle (`.zip`) & 3-Wave Roadmap** *(`iam.tf`, `pam_entitlements.tf`, `org_policies.tf`)*
- **Why Customers Trust Our Approach:**
  - **100% Live Cloud Telemetry (Zero Hallucinations):** Every principal, permission count, and key age comes verbatim from your Google Cloud APIs.
  - **100% Read-Only & Advisory:** We inspect IAM metadata and interview your teams — your engineers control all Terraform/CI-CD rollouts.
  - **Tailored to Your Sector:** Governance baselines for Banking/Fintech, Healthcare, Government, Telecom, Energy, and Retail.

---

## Slide 12 — Commercial Proposal & Engagement Investment
- **Header:** `COMMERCIAL PROPOSAL & ENGAGEMENT INVESTMENT`
- **Title:** 6-Week IAM Posture Assessment, Modernization & Least-Privilege Review
- **Subtitle:** Fixed-scope Google Cloud Consulting (GCC) engagement combining automated read-only IAM/Cloud Identity discovery, attack-path modeling, area interviews, and advisory IaC synthesis:
- **Commercial Investment & Engagement Parameters:**
  - **R$ 248,000** — Consolidated Investment (Fixed-Scope Fee, Taxes Excl.)
  - **6 Weeks** — Fixed Delivery Timeline (Discovery, Interviews, Graph & Advisory IaC)
  - **Up to 50 Projects** — Bounded Assessment Scope (1 GCP Org, Cloud Identity Domain, 7 Areas)
  - **Lean GCC Squad** — Expert Security Delivery (PSO Consultant + SCE + GSD Architect)
- **Included Scope, Governance & Key Premises:**
  - **Complete 6-Deliverable Package:** Identity Triad Baseline, 7-Domain Readiness Report, NetworkX Attack Graph, PAM/Custom Role Synthesis, Advisory Terraform Bundle & Executive Recommendations Book.
  - **Read-Only & Zero Data Exposure:** Strictly 100% read-only GCP control-plane metadata and stakeholder interviews — zero changes executed in customer environments.
  - **Key Execution Premises:** 1-line keyless read-only `sa-iam-assessor` provisioned by Day 3; Customer ensures area SME participation in Weeks 3–4 interviews.

---

## Slide 13 — Engagement Execution Path: Next Steps
- **STEP 1 (01) — Commercial Approval:** Review and approve the commercial proposal, bounded GCP Organization/project scope, and 6-week posture assessment model. *Key Actions: Confirm Organization & project scope, Validate 6-week delivery model, Approve commercial proposal, Confirm CISO sponsorship.*
- **STEP 2 (02) — SOW Preparation & Signature:** Finalize the Statement of Work (SOW) and complete legal and procurement review for formal execution. *Key Actions: Finalize Statement of Work (SOW), Complete legal & procurement review, Execute SOW & Order Form, Align weekly steering checkpoints.*
- **STEP 3 (03) — Timeline Alignment & Kickoff:** Align kickoff date, run the 1-line read-only `sa-iam-assessor` onboarding script in Cloud Shell, schedule the 7 area interviews, and launch Week 1. *Key Actions: Lock kickoff & interview calendar, Run 1-line keyless read-only setup, Conduct Week 1 kickoff session.*

---

## Slide 14 — Closing
- **Thank You** — Google Cloud Consulting
