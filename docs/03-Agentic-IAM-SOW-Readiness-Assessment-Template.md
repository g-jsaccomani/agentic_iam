# Agentic IAM SOW Readiness Assessment Template
**Google Cloud Consulting — 6-Week Statement of Work (SOW), RACI Governance & T-Shirt Sizing Guide**

> **Repository Deliverable:** [docs/03-Agentic-IAM-SOW-Readiness-Assessment-Template.md](03-Agentic-IAM-SOW-Readiness-Assessment-Template.md)

> **Executive Summary:** This Statement of Work (SOW) template defines the contractual scope, 6-week Work Breakdown Structure (WBS), deliverables, acceptance criteria, RACI matrix, and governance model for a Google Cloud Consulting — Professional Services Organization (PSO) **IAM & Cloud Identity Posture Assessment, Attack-Path Review & Least-Privilege Acceleration** engagement. By pairing senior PSO Security Architects with the 100% read-only **Agentic IAM Accelerator** (powered by Google ADK and Vertex AI Gemini), Google Cloud completes keyless onboarding and automated 3-pillar Identity Triad discovery in Weeks 1–2, conducts structured 7-Domain Readiness Questionnaires, cross-functional stakeholder interviews, and NetworkX privilege-escalation graph modeling in Weeks 3–4, and dedicates Weeks 5–6 to a comprehensive Least-Privilege Persona Synthesis, Privileged Access Manager (PAM) Just-In-Time & Workload Identity Federation (WIF) advisory architecture, Policy Simulator verification review, and the 3-Wave IAM Modernization Roadmap (strictly consultative and read-only — zero hands-on policy mutation or workload modification in Customer environments).

---

## 1. Engagement Identification & Customer Environment Parameterization

This Statement of Work ("SOW") is entered into between Google Cloud Consulting — Professional Services Organization ("Google Cloud PSO") and Customer (`<CUSTOMER-LEGAL-NAME>`) to execute a 6-week Consultative IAM & Cloud Identity Posture Assessment, Attack-Path Review, and Least-Privilege Acceleration engagement across the Customer's designated Google Cloud estate. Populate the engagement parameters below prior to contract execution:

| Contractual / Technical Parameter | Placeholder / Config Token | Expected Value / Selection Options | Customer Contracted Value (Populate at SOW Signing) |
| --- | --- | --- | --- |
| Customer Legal Entity Name | `<CUSTOMER-LEGAL-NAME>` | Full legal entity name of the contracting organization | [ Leave Blank — Populate for Customer ] |
| Primary Regulated Industry Vertical | `<SECTOR-CODE>` | `BFSI-BANKING` \| `HEALTHCARE-GENOMICS` \| `PUBLIC-SECTOR-DEFENSE` \| `TELECOM-5G-CLOUD` \| `ENERGY-OT-INDUSTRIAL` | [ Leave Blank — Populate for Customer ] |
| In-Scope GCP Organization ID(s) | `<CUSTOMER-ORG-ID>` | `organizations/<12-DIGIT-ORG-ID>` (or `organizations/<ORG-ID>/projects:<P1>,<P2>`) | [ Leave Blank — Populate for Customer ] |
| Primary Cloud Identity / Workspace Domain | `<CUSTOMER-PRIMARY-DOMAIN>` | Primary verified corporate domain (e.g., `corp.example.com`, Customer ID `C0...`) | [ Leave Blank — Populate for Customer ] |
| Engagement Sizing Tier & Duration | `<SIZING-TIER>` | Standard Enterprise Tier — 6 Calendar Weeks (30 Business Days) | 6 Calendar Weeks (Weeks 1 to 6) |
| Selected Agent Deployment Topology | `<DEPLOYMENT-TOPOLOGY>` | Topology A (Customer Cloud Run + IAP + VPC-SC) \| Topology B (Cross-Org Keyless SA Impersonation) \| Topology C (Workstation) | [ Leave Blank — Populate for Customer ] |
| Customer Seed / Host Project & Endpoint | `<CUSTOMER-SEED-PROJECT-ID>` | Seed Project hosting `sa-iam-assessor` / Cloud Run URL | [ Leave Blank — Populate in Customer Environment ] |
| Customer Executive Sponsor & CISO POC | `<CUSTOMER-SPONSOR-NAME>` | Name, Title, Email of CISO / VP of Security / Head of IAM & Cloud Platform | [ Leave Blank — Populate for Customer ] |

## 2. Strategic Objectives, Regulatory Drivers & Consultative Positioning

Customer has engaged Google Cloud PSO to establish an empirical, evidence-backed baseline of its Google Cloud IAM and Cloud Identity posture, assess organizational readiness across identity, platform, and application teams, uncover multi-hop privilege-escalation chains, and deliver an advisory Zero-Trust Least-Privilege & PAM JIT modernization blueprint. This engagement directly addresses the technical, operational, and governance imperatives introduced by:

- **Zero-Trust Identity Architecture Standards:** NIST SP 800-207 (Zero Trust Architecture), NIST SP 800-53 Rev. 5 (`AC-2` Account Management, `AC-5` Separation of Duties, `AC-6` Least Privilege), CISA Zero Trust Maturity Model v2.0 (Identity Pillar), and the CIS Google Cloud Platform Foundation Benchmark v3.0+ (Section 1: Identity and Access Management).
- **Global & Sector Access-Governance Mandates:** ISO/IEC 27001:2022 & 27002:2022 (`A.5.15` Access Control, `A.5.16` Identity Management, `A.5.18` Access Rights, `A.8.2` Privileged Access Rights), PCI-DSS v4.0.1 (Requirements 7 & 8: Restrict Access by Business Need-to-Know & Strong Authentication), EU DORA (Article 9: Protection and Prevention / Least Privilege), Central Bank of Brazil BACEN BCB Resolution 85/4893, SOX ITGC logical access controls, HIPAA Security Rule (`164.312(a)(1)`), and LGPD/GDPR data-access minimization.
- **Cloud Infrastructure Entitlement Management (CIEM) & Lateral-Movement Prevention:** Eliminating standing primitive roles (`roles/owner`, `roles/editor`), direct human `user:` bindings bypassing Cloud Identity Security Groups, unrotated static Service Account JSON keys (`>90 days`), Default Compute/AppEngine Service Account over-privilege, unconditioned Workload Identity Federation (WIF) OIDC pools, and multi-hop `actAs` / `serviceAccountTokenCreator` escalation chains.
- **Read-Only Discovery & Consultative Posture Advisory (Zero Implementation / Non-Audit Positioning):** Under the Google Cloud Shared Responsibility Model, Google Cloud PSO performs a **100% read-only** IAM & Cloud Identity Inventory, 7-Domain Area Readiness Assessment, NetworkX Attack-Path Review, and Least-Privilege / IaC Advisory. Google Cloud PSO does **not** perform hands-on policy mutations, role revocations, key deletions, or Terraform applies in Customer environments, nor does it act as a statutory, regulatory, QSA, or compliance certification auditor.

## 3. Detailed 6-Week Work Breakdown Structure (WBS) & Execution Plan

The engagement is structured across three 2-week workstreams executed over six (6) consecutive calendar weeks: **Weeks 1–2 (Keyless Onboarding & Automated Identity Triad Discovery)**, **Weeks 3–4 (7-Domain Readiness Questionnaire, Area Interviews & NetworkX Attack-Path Analysis)**, and **Weeks 5–6 (Least-Privilege Persona Synthesis, PAM JIT / WIF / IaC Advisory Blueprint & Executive Modernization Roadmap)**:

| Week & Phase | Primary Focus Area | Key PSO & Agentic Activities | Weekly Outputs & Exit Criteria |
| --- | --- | --- | --- |
| Week 1 (Phase 1A) | Mobilization, Kickoff & Keyless Read-Only Onboarding | Deliver Executive Kickoff (`Agentic IAM README`); lock stakeholder interview calendar across the 7 areas; execute 1-line Cloud Shell setup creating `sa-iam-assessor` (zero JSON keys) and verify the 6 live pre-flight probes (`POST /api/v1/session/connect`). | Kickoff completed; interview schedule locked; 6/6 read-only GCP telemetry probes passing in isolated Clean-Slate session. |
| Week 2 (Phase 1B) | Automated Identity Triad, SA Key & Org Policy Discovery | Run `triad_analyzer` collectors (`collect_cai_iam_bindings`, `collect_cai_service_account_inventory`, `collect_cloud_identity_posture`) across Cloud Asset Inventory, Resource Manager Organization Policies, IAM v1 SA keys, WIF pools, and Cloud Identity groups. | 100% in-scope IAM bindings, Service Accounts, static key ages, WIF pools, Cloud Identity groups, and 6 key Org Policy constraints baselined; CSPR-aligned findings (`GcpIamPostureFinding`) exported. |
| Week 3 (Phase 2A) | 7-Domain Readiness Questionnaire & Stakeholder Interviews | Distribute the `Agentic IAM Discovery Questionnaire` and conduct structured readiness interviews across all 7 areas (Cloud Identity/IdP, Group RBAC, PAM/Break-Glass, WIF/CI-CD, Impersonation/SoD, External/VPC-SC, and IaC Governance). | Completed 35-question 7-Domain IAM Readiness Rubric (Levels 1.0–5.0); documented JML lifecycle, SSO/2SV, PAM approver groups, and CI/CD constraints. |
| Week 4 (Phase 2B) | NetworkX Attack Path Graph, Toxic Combinations & Blast Radius | Execute `attack_path_agent` (`build_iam_privilege_graph`, `analyze_iam_attack_paths`) to construct the live `nx.DiGraph`, compute `betweenness_centrality` and `degree_centrality`, map multi-hop escalation chains, and hold Mid-Engagement CISO Checkpoint. | High-DPI NetworkX Attack Path Graph (`attack_path_graph.png`), Centrality Choke-Point Ranking, Toxic Combination Matrix, and Executive IAM Posture Scorecard reviewed by Security Leadership. |
| Week 5 (Phase 3A) | Least-Privilege Persona Synthesis, PAM JIT & WIF Advisory | Execute `recommender_agent` & `iac_generator` over live IAM Recommender insights, Policy Analyzer telemetry, IAM Roles API permission counts, Cloud Audit Log 90-day usage, and Policy Simulator baselines to design Custom Roles, PAM JIT entitlements, and keyless WIF patterns. | Validated Least-Privilege Persona Matrix (`granted vs. exercised` permissions), PAM JIT Entitlement Design, Keyless WIF Reference Guide, and Policy Simulator Verification Ledger. |
| Week 6 (Phase 3B) | Advisory Terraform Bundle, Posture Book & Board Closeout | Package the OpenTofu/Terraform bundle rendered by deterministic code from the ADK agents' typed remediation plan (`main.tf`, `variables.tf`, `iam.tf`, `pam_entitlements.tf`, `org_policies.tf`); finalize the `Agentic IAM Security Recommendations Book` (`.docx` & `.pdf`) and 3-Wave Modernization Roadmap; deliver Executive Board Closeout. | Complete 6-Deliverable Handover Package accepted; Clean-Slate workspace wiped via **Disconnect & Wipe**; formal Deliverable Acceptance Form signed. |

### 3.1 Week 1 (Phase 1A): Mobilization, Kickoff & Keyless Read-Only IAM Onboarding

- **Executive & Technical Kickoff:** Deliver the formal engagement kickoff presentation (aligned with `Agentic IAM Executive Presentation Deck`) to align executive sponsors, IAM architects, Cloud Identity administrators, platform leads, and GRC stakeholders on the 6-week schedule, interview cadence, and deliverables.
- **Zero-Key Read-Only Service Account Onboarding:** Provision `sa-iam-assessor@<CUSTOMER-SEED-PROJECT-ID>.iam.gserviceaccount.com` via the 1-line Cloud Shell setup or Zero-Key Onboarding Kit (`customer_iam_onboarding.sh` / `customer_iam_onboarding.tf`), binding the six strictly read-only Organization roles (`roles/browser`, `roles/cloudasset.viewer`, `roles/iam.securityReviewer`, `roles/orgpolicy.policyViewer`, `roles/recommender.viewer`, `roles/logging.viewer`), `roles/serviceusage.serviceUsageConsumer` on the seed project, and `roles/iam.serviceAccountTokenCreator` on `sa-iam-assessor` only to the named consultant user in the default and recommended mode (`constraints/iam.disableServiceAccountKeyCreation` compliant). Optional persistent auto-renew is OFF by default: only if the deployment sets `IAM_ENABLE_PERSISTENT_DELEGATION=true` **and** the consultant ticks the explicit option when generating the onboarding kit does the kit additionally grant `roles/iam.serviceAccountTokenCreator` on `sa-iam-assessor` to the platform's Cloud Run runtime Service Account so sessions can be renewed without the consultant's token; the platform then holds standing read-only access to the Customer's Organization until the Customer removes that binding, and revoking the consultant's own grant does not remove it (the offboarding snippet in the kit removes both bindings).
- **6-Point Live Pre-Flight Verification & Scope Confirmation:** Connect via `POST /api/v1/session/connect` and validate live reachability across Resource Manager, Cloud Asset Inventory IAM & Resources, Organization Policy API, IAM Recommender, and Cloud Audit Logging, confirming in-scope projects.
- **Week 1 Exit Criteria:** 6/6 read-only pre-flight checks passing; kickoff completed; 7-area stakeholder interview calendar confirmed.

### 3.2 Week 2 (Phase 1B): Automated 3-Pillar Identity Triad, Service Account & Organization Policy Discovery

- **Pillar 1 — Internal Workforce & Cloud Identity Governance:** Execute `collect_cai_iam_bindings` and `collect_cloud_identity_posture` across the target scope to inventory all human (`user:`) and group (`group:`) bindings, compute the Group RBAC Adoption Ratio, correlate Cloud Audit Log recent activity, and inspect Workspace Directory 2SV/MFA & Cloud Identity security-group labels where delegated.
- **Pillar 2 — External, Partner & Public Access Exposure:** Evaluate effective Organization Policies (`constraints/iam.allowedPolicyMemberDomains`, `constraints/storage.publicAccessPrevention`) alongside live `domain:`, external `user:`, consumer account (`@gmail.com`), and public (`allUsers` / `allAuthenticatedUsers`) bindings across projects, buckets, datasets, and services.
- **Pillar 3 — Workload Identities, Static SA Keys & WIF Inventory:** Execute `collect_cai_service_account_inventory` across all customer and Default Compute/AppEngine Service Accounts, inspecting user-managed key counts and key age (`>90 days`), `constraints/iam.disableServiceAccountKeyCreation`, `constraints/iam.automaticIamGrantsForDefaultServiceAccounts`, attached GCE/Cloud Run workloads, and Workload Identity Pools/Providers.
- **CSPR-Aligned Baseline Export:** Normalize discovered violations into `GcpIamPostureFinding` (`GcpIamAuditFinding`) records mapped to deterministic CSPR views (`iam-2eus`, `iam-xl3c`, `iam-p1ri`, `iam-d067`).
- **Week 2 Exit Criteria:** 100% of in-scope IAM bindings, Service Accounts, WIF pools, and Organization Policies inventoried and classified across the 3 Identity Triad pillars.

### 3.3 Week 3 (Phase 2A): 7-Domain Area Readiness Questionnaire & Stakeholder Interviews

- **7-Domain Stakeholder Readiness Interviews:** Facilitate structured discovery workshops across all seven weighted domains of the `Agentic IAM Discovery Questionnaire`: (1) Workforce Federation, SSO/MFA & JML Lifecycle, (2) Cloud Identity Security Groups & RBAC Taxonomy, (3) Privileged Access Management (PAM JIT) & Break-Glass Governance, (4) Workload Identity Federation (WIF) & Static Key Elimination, (5) Service Account Impersonation, Custom Roles & Separation of Duties (SoD), (6) External Partner Governance (DRS) & VPC-SC Data Perimeters, and (7) IAM Infrastructure-as-Code (Terraform/OpenTofu) & Policy Simulator CI/CD Gates.
- **Operational Maturity Scoring & Process Gap Analysis:** Score the 35-question rubric (Levels 1.0 to 5.0) across each area, documenting off-cloud IdP federation mechanics (Entra ID, Okta, Ping, Cloud Identity), HR-driven deprovisioning SLAs, emergency break-glass monitoring, and PAM approval workflows.
- **Week 3 Exit Criteria:** 7-Domain Discovery Questionnaire and stakeholder interviews completed across all in-scope areas; maturity scores (Levels 1.0–5.0) and target PAM/RBAC operating model parameters documented.

### 3.4 Week 4 (Phase 2B): NetworkX Attack Path Graph, Toxic Combinations & Blast-Radius Prioritization

- **Directed Privilege & Impersonation Graph Construction (`nx.DiGraph`):** Execute `build_iam_privilege_graph` and `analyze_iam_attack_paths` (`backend/tools/graph_engine.py`) to model every non-agent principal, Cloud Identity group, Workload Identity Pool, Service Account, runtime VM/Cloud Run workload, project convenience member (`projectOwner:`, `projectEditor:`), and target resource as a directed graph.
- **Graph Centrality & Multi-Hop Escalation Analysis:** Compute NetworkX `betweenness_centrality`, `degree_centrality`, and simple paths (`nx.all_simple_paths`) to uncover multi-hop escalation routes (`SA_IMPERSONATION_CHAIN`, `GCE_METADATA_ESCALATION`, `CLOUDBUILD_SA_ABUSE`, `ORG_POLICY_BYPASS`, `PRIMITIVE_STANDING_PRIVILEGE`) and rank high-centrality choke-point identities.
- **Optional Business-Impact Sizing Workshop (Customer Inputs Only):** If requested by Customer's CISO, DPO, and Risk Committee, map crown-jewel datasets reachable via discovered attack paths against Customer-provided data volumes, breach-cost history, BIA figures, and regulatory fine ranges (with explicit assumptions; the agent never invents dollar figures).
- **Mid-Engagement CISO & Architecture Checkpoint:** Present the Executive IAM Posture Scorecard (0–100%), Identity Triad Matrix, and high-DPI `attack_path_graph.png` to Security Leadership.
- **Week 4 Exit Criteria:** Validated IAM Posture Scorecard, NetworkX Attack Path Graph, Centrality Choke-Point Ranking, and Toxic Combination Matrix reviewed with Security Leadership.

### 3.5 Week 5 (Phase 3A): Least-Privilege Persona Synthesis, PAM JIT, Keyless WIF & Policy Simulator Review

- **90-Day Usage & Permission-Surface Reduction Synthesis:** Execute `fetch_iam_role_recommendations` and `recommender_agent` across live GCP IAM Recommender (`google.iam.policy.Recommender`), Policy Analyzer, IAM Roles API (`includedPermissions` counts), and Cloud Audit Log authorization events to quantify `permissions_granted_count` vs. `permissions_exercised_90d` and exact `excess_permissions_removed` per principal.
- **Privileged Access Manager (PAM) JIT & Custom Role Architecture:** Map standing human administrative bindings (`roles/owner`, `roles/editor`, `roles/resourcemanager.organizationAdmin`, `roles/iam.securityAdmin`) to time-bound **PAM Entitlements** (`max_request_duration = 3600s`, mandatory justification, security-group approvers), and map overbroad workload bindings to least-privilege predefined or Custom Roles.
- **Keyless Workload Identity Federation (WIF) & SA Hygiene Advisory:** Deliver reference patterns for migrating CI/CD pipelines (GitHub Actions, GitLab, Jenkins) and multi-cloud workloads from static Service Account JSON keys to OIDC/AWS **Workload Identity Pools** enforced with strict CEL `attributeCondition` filters.
- **Change-Impact Evidence Review (Advisory):** Execute `collect_change_impact_evidence` to correlate proposed role changes and Organization Policy guardrails against bounded Cloud Audit Log samples (reporting `is_sample`, `sample_size`, observed window, and projects queried — without executing Policy Simulator replays), classifying each item as `NO_CONFLICT_IN_SAMPLE`, `REVIEW_REQUIRED`, or `LIKELY_BREAKING`.
- **Week 5 Exit Criteria:** Least-Privilege Persona Matrix, PAM JIT Entitlement Blueprint, Keyless WIF Advisory Guide, and Advisory Change-Impact Estimate Ledger completed.

### 3.6 Week 6 (Phase 3B): Advisory Terraform Remediation Bundle, Posture Book & Executive Board Closeout

- **Advisory OpenTofu / Terraform Remediation Bundle (`iac_generator`):** Compile and verify syntax of the 5-file modular HCL remediation archive (`agentic_iam_terraform_remediation_bundle.zip`: `main.tf`, `variables.tf`, `iam.tf`, `pam_entitlements.tf`, `org_policies.tf`) grounded strictly in Customer's real Organization ID, domain, folders, projects, principals, and un-enforced constraints (delivered as consultative reference code for Customer CI/CD review).
- **Executive Posture Acceleration Book & 3-Wave Roadmap:** Finalize the **Agentic IAM Security Recommendations Book** (`.docx`, `.pdf`, and Markdown) consolidating the Executive Scorecard, Identity Triad findings, NetworkX Attack Graph, PAM/WIF target architecture BOM, and phased **Wave 1 (Days 0–30)**, **Wave 2 (Days 31–60)**, and **Wave 3 (Days 61–90+)** modernization roadmap.
- **Executive Board Closeout & Workspace Wipe:** Conduct the formal closeout presentation for the CISO, CIO, and Platform Engineering leads, hand over all six deliverables, execute **Disconnect & Wipe** (`POST /api/v1/session/disconnect`), which immediately deletes the stored workspace data (connection record, latest posture book, inventory and scan history), and provide the 1-line customer offboarding command to revoke `sa-iam-assessor` (the offboarding snippet in the onboarding kit removes both token-creator bindings: the consultant's and, where the optional persistent auto-renew was enabled, the platform runtime Service Account's — revoking only the consultant's grant would leave the platform with standing read-only access until that second binding is removed).
- **Week 6 Exit Criteria:** All six contractual deliverables (D-01 through D-06) delivered and formally accepted; Executive Board Closeout completed.

## 4. Contractual Deliverables & Acceptance Criteria Matrix

Google Cloud PSO will deliver six (6) formal consultative assessment artifacts grounded in the Customer's live read-only GCP & Cloud Identity telemetry and stakeholder readiness interviews:

| ID | Deliverable Name | Delivery Week & Target Audience | Core Contents & Objective Acceptance Criteria |
| --- | --- | --- | --- |
| D-01 | 3-Pillar Identity Triad Inventory & CSPR Findings Baseline | Week 2 — IAM Leads, SecOps & Cloud Governance | Complete read-only inventory of in-scope Internal, External, and Workload Service Account bindings, static SA key ages, WIF pools, Cloud Identity group RBAC ratios, and 6 effective Org Policies, exported as CSPR-aligned `GcpIamPostureFinding` records. |
| D-02 | 7-Domain IAM & Cloud Identity Readiness Assessment | Week 3 — CISO, GRC, IdP Owners & Platform Leads | Completed 35-question `Agentic IAM Discovery Questionnaire` scorecard (Levels 1.0–5.0 across 7 areas), JML/SSO/MFA gap analysis, break-glass review, and PAM JIT operational governance model. |
| D-03 | NetworkX Attack Path Graph & Executive Posture Scorecard | Week 4 — CISO, CRO, SecOps & Cloud Architects | C-Level BLUF, Auditable 0–100% IAM Posture Scorecard, high-DPI `attack_path_graph.png`, NetworkX `betweenness_centrality` choke-point ranking, and multi-hop escalation / Separation-of-Duties (SoD) findings matrix. |
| D-04 | Least-Privilege Persona Synthesis & PAM JIT / WIF Blueprint (Advisory) | Week 5 — IAM Engineers, Platform SRE & CI/CD Owners | Per-principal `granted vs. exercised` permission reduction matrix, Custom Role specifications, Privileged Access Manager (PAM) JIT entitlement designs, and keyless Workload Identity Federation (WIF) reference patterns. |
| D-05 | Advisory Terraform / OpenTofu Bundle & Change-Impact Estimate Ledger (Unvalidated) | Week 5–6 — Cloud IaC Engineers & DevSecOps | Syntactically valid 5-module advisory HCL archive (`main.tf`, `variables.tf`, `iam.tf`, `pam_entitlements.tf`, `org_policies.tf`) paired with bounded Cloud Audit Log sample impact estimates (`NO_CONFLICT_IN_SAMPLE` / `REVIEW_REQUIRED` / `LIKELY_BREAKING`) for customer-led Policy Simulator & `terraform plan` validation. |
| D-06 | Agentic IAM Security Recommendations Book & 3-Wave Roadmap | Week 6 — CISO, CIO, Board & Architecture Committee | Comprehensive Word (`.docx`), PDF (`.pdf`), and Markdown Recommendations Book uniting all findings, 5-pillar Google Cloud IAM BOM, preventive Org Policy templates, and the Wave 1–3 Modernization Roadmap. |

## 5. Engagement Team Structure, Resource Allocation & RACI Matrix

Successful completion within the 6-week timeline relies on a dedicated Google Cloud PSO delivery pod working alongside Customer subject matter experts (SMEs). The tables below define the PSO specialist roles, weekly effort allocation, and the Responsibility Assignment Matrix (`R` = Responsible, `A` = Accountable, `C` = Consulted, `I` = Informed):

| Role Title | Organization | Primary Responsibilities Across the 6-Week Engagement | Estimated Allocation |
| --- | --- | --- | --- |
| Principal IAM & Zero-Trust Security Architect (Lead) | Google Cloud PSO | Leads kickoff, 7-domain stakeholder readiness interviews, attack-path & SoD risk prioritization, PAM/WIF target architecture, and Executive Board readout. | Weeks 1–6 (Full Engagement Lead) |
| Cloud Identity, CIEM & IaC Specialist | Google Cloud PSO | Executes keyless `sa-iam-assessor` validation, Identity Triad & NetworkX graph collection, Recommender / Policy Simulator analysis, and advisory Terraform bundle synthesis. | Weeks 1–6 (Discovery, Graph & IaC) |
| Engagement Manager / Project Director | Google Cloud PSO | Manages 6-week WBS governance, weekly steering syncs, stakeholder interview scheduling across the 7 areas, and formal Deliverable Acceptance sign-offs. | Weeks 1–6 (Governance & PMO) |
| Executive Sponsor / CISO & IAM Governance Lead | Customer | Approves assessment scope, validates PAM approval governance and risk appetite, chairs Week 4 and Week 6 executive readouts, and signs Deliverable Acceptance. | Weeks 1, 4, 6 (Executive Checkpoints) |
| Cloud Identity, Platform, AppDev/CI-CD, SecOps & GRC SMEs | Customer | Executes 1-line read-only `sa-iam-assessor` setup (Days 1–3), completes the 7-Domain Questionnaire, participates in Weeks 3–4 interviews, and reviews Week 5 IaC/PAM blueprints. | 2–4 Hours / Week (Interviews & Reviews) |

### 5.1 Workstream Responsibility Assignment Matrix (RACI)

| Engagement Workstream / Weekly Milestone | Google PSO Lead Architect | Google PSO IAM & IaC Specialist | Customer CISO / Exec Sponsor | Customer Area SMEs (IdP, Platform, CI/CD, GRC) |
| --- | --- | --- | --- | --- |
| Week 1: Kickoff, 1-Line Keyless Read-Only Setup & Pre-Flight Probes | R | C | A | R |
| Week 2: Automated Identity Triad, SA Key & Org Policy Discovery | A | R | I | C |
| Week 3: 7-Domain IAM Readiness Questionnaire & Area Interviews | R | C | A | R |
| Week 4: NetworkX Attack Path Graph, Centrality & Scorecard Review | R | R | A | C |
| Week 5: Least-Privilege Synthesis, PAM JIT, WIF & Simulator Review | R | R | I | C |
| Week 6: Advisory Terraform Bundle, Posture Book & Board Readout | R | C | A | I |

## 6. Out-of-Scope Boundaries & Engagement Assumptions

To maintain strict scope control and ensure zero operational risk within the 6-week schedule, the following activities are explicitly excluded from this Statement of Work unless added via a mutually executed Project Change Request (PCR):

- **No Direct IAM Policy Mutation, Role Revocation, Key Deletion, or Terraform Apply by Google Cloud PSO:** This engagement is strictly a **100% read-only IAM & Cloud Identity posture assessment, area readiness review, and consultative least-privilege acceleration advisory**. Google Cloud PSO will **not** modify IAM bindings, delete Service Account keys, enforce Organization Policies, deploy PAM entitlements, or run `terraform apply` in any Customer environment (production or non-production). All Terraform/OpenTofu HCL modules, Custom Role YAML/HCL specs, and PAM configurations are delivered strictly as **consultative advisory reference artifacts** for testing and rollout by the Customer's own engineering teams under Customer CAB/CI-CD governance.
- **No Statutory, Regulatory, or Certification Auditing:** Google Cloud PSO does not perform formal statutory, regulatory, ISO 27001 certification, SOC 2 Type II attestation, or PCI-DSS QSA audits. All deliverables represent consultative security posture assessments and engineering modernization advisories.
- **Zero Plaintext Customer Data or Secret Payload Access:** The Agentic IAM Accelerator inspects Google Cloud IAM, Resource Manager, Cloud Identity, Recommender, and Audit Log control-plane metadata only. Google Cloud PSO never reads Secret Manager secret payloads (`secretmanager.versions.access` is never requested), Cloud Storage object contents, BigQuery business table rows, or private Service Account key material.
- **Third-Party On-Premises Legacy Application Refactoring:** Workforce IdP and CI/CD federation reviews cover integration patterns with Google Cloud Identity and Workload Identity Federation, excluding hands-on source-code modification of legacy on-premises Active Directory / LDAP / Kerberos applications.

## 7. Customer Responsibilities, SLA Prerequisites & Governance Cadence

1. **Keyless Read-Only IAM Onboarding (SLA — Within 3 Business Days of Kickoff):** Customer Organization Administrator will execute the 1-line Cloud Shell provisioning command (or Zero-Key Onboarding Terraform script) creating `sa-iam-assessor@<CUSTOMER-SEED-PROJECT-ID>.iam.gserviceaccount.com` with the six read-only Organization roles (`roles/browser`, `roles/cloudasset.viewer`, `roles/iam.securityReviewer`, `roles/orgpolicy.policyViewer`, `roles/recommender.viewer`, `roles/logging.viewer`), `roles/serviceusage.serviceUsageConsumer` on the seed project, and `roles/iam.serviceAccountTokenCreator` scoped by default exclusively to the designated assessment user (the optional, OFF-by-default persistent auto-renew described in Section 3.1 additionally grants it to the platform's Cloud Run runtime Service Account, which then holds standing read-only access until the Customer removes that binding; revoking the consultant's own grant does not remove it), as specified in `Agentic IAM Technical Architecture and Consultant Guide`. Delays beyond Day 3 may result in a day-for-day extension of the 6-week schedule.
2. **Stakeholder Area Interview & Questionnaire Participation:** Customer will ensure timely participation of representatives from the 7 in-scope domains (Identity/IdP Admins, Cloud Identity Group Owners, Cloud Platform/PAM Leads, CI/CD & AppDev Leads, SecOps/SIEM Leads, Third-Party/VPC-SC Leads, and GRC/Internal Audit) to complete the `Agentic IAM Discovery Questionnaire` and attend the Weeks 3–4 readiness workshops.
3. **Weekly Steering Cadence & Deliverable Acceptance Window (5 Business Days):** Google Cloud PSO and Customer Project Managers will conduct a 30-minute Weekly Status & Risk Sync every Friday. Upon submission of each formal deliverable (`D-01` through `D-06`), Customer will review and provide written acceptance or consolidated feedback within five (5) business days, after which the deliverable is deemed accepted.

## 8. Statement of Work Execution & Authorized Sign-Off Block

By signing below, the authorized representatives of Customer (`<CUSTOMER-LEGAL-NAME>`) and Google Cloud Consulting (PSO) agree to the scope, 6-week schedule, deliverables, assumptions, and governance terms set forth in this Statement of Work:

| Signatory Party | Authorized Representative Name & Title | Signature | Execution Date |
| --- | --- | --- | --- |
| Customer (`<CUSTOMER-LEGAL-NAME>`) | [ Leave Blank — Populate Name & Title ] | [ Authorized Electronic or Physical Signature ] | [ YYYY-MM-DD ] |
| Google Cloud Consulting (PSO) | [ Leave Blank — Populate Name & Title ] | [ Authorized Electronic or Physical Signature ] | [ YYYY-MM-DD ] |

## 9. Appendix: Commercial Delivery Model, T-Shirt Sizing Tiers & RACI Summary

### 9.1 End-to-End 3-Stage Delivery Flow (6 Weeks)

1. **Stage 1 — Keyless Read-Only Setup & 3-Pillar Identity Triad Discovery (Weeks 1–2):** Provision zero-key `sa-iam-assessor` impersonation, verify all 6 read-only GCP telemetry probes, and execute automated discovery across Cloud Asset Inventory, Resource Manager Organization Policies, Service Account keys, Workload Identity Pools, and Cloud Identity groups.
2. **Stage 2 — 7-Domain Readiness Interviews & NetworkX Attack-Path Modeling (Weeks 3–4):** Conduct structured readiness workshops across all 7 identity and platform areas using the `Agentic IAM Discovery Questionnaire`, construct the live NetworkX directed privilege-escalation graph (`betweenness_centrality` + multi-hop chains), and review the auditable Executive IAM Posture Scorecard with leadership.
3. **Stage 3 — Least-Privilege Synthesis, Advisory Terraform/PAM Blueprint & Roadmap (Weeks 5–6):** Synthesize 90-day permission reductions, Custom Roles, Privileged Access Manager (PAM) JIT entitlements, keyless WIF patterns, and Policy Simulator verification verdicts; hand over the modular OpenTofu/Terraform `.zip` bundle and `Agentic IAM Security Recommendations Book` (`.docx`/`.pdf`); and deliver the Executive Board Closeout.

### 9.2 Engagement T-Shirt Sizing Matrix (Small / Medium / Large)

| Sizing Tier | Customer Footprint | Manual Effort (Legacy) | Agent-Accelerated Effort | Recommended PSO Staffing |
| --- | --- | --- | --- | --- |
| Small (Fast-Track / Single Domain) | 1–15 GCP Projects \| <500 Non-Agent Bindings | 6–8 Weeks (240–320 Hours) | 2–3 Weeks (88–120 Hours) | 1 PSO IAM Consultant + 1 Security CE (Part-Time) |
| Medium (Standard Enterprise — Baseline SOW) | 15–50 GCP Projects \| 500–10,000 Bindings & SAs | 12–16 Weeks (480–640 Hours) | 6 Weeks (224 Hours: 100h PSO Consultant, 80h Security CE, 44h GSD Architect) | 1 PSO Consultant (100h) + 1 Security/Net CE (80h) + 1 GSD Architect (44h) |
| Large (Global / Multi-Org Regulated) | 50–1,000+ GCP Projects \| Multi-Org & Hybrid IdP | 20–24 Weeks (800–960 Hours) | 8–10 Weeks (320–400 Hours) | 2 PSO IAM Consultants + 1 Security CE + 1 GSD Lead Architect |

### 9.3 RACI Governance Summary

| Workstream / Activity | Google PSO Architect | Google TAM / CE | Customer CISO / GRC | Customer Area SMEs |
| --- | --- | --- | --- | --- |
| Keyless Read-Only `sa-iam-assessor` Onboarding | Consulted (C) | Informed (I) | Approver (A) | Responsible (R) |
| Identity Triad & SA / WIF Automated Discovery | Responsible (R) | Consulted (C) | Informed (I) | Consulted (C) |
| 7-Domain Readiness Questionnaire & Area Interviews | Responsible (R) | Consulted (C) | Consulted (C) | Responsible (R) |
| NetworkX Attack Graph, Scorecard & Executive Readout | Responsible (R) | Accountable (A) | Approver (A) | Informed (I) |
| PAM JIT, Custom Role & Advisory Terraform Blueprint | Responsible (R) | Consulted (C) | Approver (A) | Consulted (C) |
