# Fortinet Security Product Catalog (Cloud Assessment Context)

## Mapping: Finding Category → Recommended Products

| Finding | Products |
|---------|----------|
| Compliance gaps | FortiCNAPP CSPM · FortiGate · FortiManager · FortiAnalyzer |
| CVE / Vulnerabilities | FortiCNAPP CWPP · FortiGate IPS · FortiWeb · FortiEDR · FortiNDR · FortiSandbox |
| Identity / MFA / Over-privilege | FortiCNAPP CIEM · FortiAuthenticator · FortiToken · FortiPAM · FortiClient |
| Critical alerts | FortiCNAPP Threat Detection · FortiSIEM · FortiSOAR · FortiXDR · FortiNDR · FortiMail |
| Exposed secrets | FortiCNAPP Secrets · FortiDLP · FortiPAM |
| App / Web exposure | FortiWeb · FortiADC |
| Network access control | FortiNAC |

## Full Product List

### FortiGate — Network Security Platform
Inline firewall, IPS, virtual patching, ZTNA, east-west microsegmentation.
Addresses: CVE virtual patching, compliance network controls, admin ZTNA.

### FortiManager — Centralized Policy Management
Single-pane management for all FortiGate policies. Change tracking and compliance audit trail.
Addresses: Compliance enforcement, policy drift.

### FortiAnalyzer — Log Management & Analytics
Centralized log aggregation, compliance reporting, and threat analytics across the fabric.
Addresses: Compliance audit trail, alert forensics.

### FortiClient — Unified Endpoint & ZTNA Client
Endpoint protection + ZTNA client for identity-verified, least-privilege remote access.
Addresses: Identity risk, endpoint posture for cloud access.

### FortiAuthenticator — Identity & MFA Services
Centralized MFA, certificate management, and identity federation (SAML/RADIUS/LDAP).
Addresses: Admins without MFA, identity risk.

### FortiToken — Hardware & Software OTP Tokens
TOTP/HOTP tokens that integrate directly with FortiAuthenticator for strong authentication.
Addresses: Admins without MFA.

### FortiEDR — Endpoint Detection & Response
Real-time behavioral threat detection and automated response on endpoints.
Addresses: Active compromise indicators, CVE exploitation at the endpoint.

### FortiXDR — Extended Detection & Response
AI-driven cross-layer (endpoint + network + cloud + email) threat correlation and auto-investigation.
Addresses: Critical alerts, lateral movement across detection surfaces.

### FortiSIEM — Security Information & Event Management
Centralized log collection, compliance monitoring, UEBA, and correlated threat analytics.
Addresses: Critical alerts, compliance audit, anomaly detection.

### FortiSOAR — Security Orchestration, Automation & Response
Playbook-driven automated triage, enrichment, and response for security incidents.
Addresses: Critical alerts, reducing mean-time-to-respond.

### FortiNDR — Network Detection & Response
Deep packet inspection and ML-based network traffic analysis for lateral movement and C2 detection.
Addresses: Critical alerts, CVE exploitation, encrypted threat detection.

### FortiSandbox — Advanced Threat Protection
File and URL detonation sandbox for zero-day and evasive malware detection.
Addresses: Unknown malware on vulnerable workloads, CVE exploits.

### FortiMail — Email Security Gateway
Anti-phishing, anti-spam, BEC/impersonation protection, and email encryption.
Addresses: Phishing/credential theft alerts, identity risks via email vector.

### FortiWeb — Web Application Firewall
ML-driven WAF, API security, bot protection, and virtual patching for web workloads.
Addresses: Vulnerable web workloads (CVE), API exposure.

### FortiADC — Application Delivery Controller
Load balancing, SSL offload, and integrated WAF for cloud applications.
Addresses: Application availability and inspection at ingress.

### FortiDLP — Data Loss Prevention
Discover, classify, and protect sensitive data (PII, credentials, keys) across cloud and endpoint.
Addresses: Exposed secrets, compliance data residency controls.

### FortiCASB — Cloud Access Security Broker (+ SSPM)
SaaS visibility, shadow IT discovery, SaaS Security Posture Management (SSPM), and data governance.
Addresses: Identity risk in SaaS, compliance gaps in M365/Workspace/Salesforce.

### FortiPAM — Privileged Access Management
Credential vaulting, session recording, just-in-time access, and break-glass procedures.
Addresses: Admin accounts without MFA, exposed API keys/secrets.

### FortiNAC — Network Access Control
Device posture verification, automated remediation, and network segmentation at access layer.
Addresses: Unmanaged devices accessing cloud resources, compliance network controls.

### FortiCNAPP — Cloud Native Application Protection Platform
Unified CSPM · CWPP · CIEM · Secrets · Threat Detection for multi-cloud environments.
Addresses: All cloud finding categories.
