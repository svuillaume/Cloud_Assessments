# 🛡️ Fortinet Rapid Cloud Assessment

**Security assessment tools powered by Fortinet APIs**

[![Fortinet](https://img.shields.io/badge/Fortinet-Cloud_Security-DA291C?style=for-the-badge&logo=fortinet&logoColor=white)](https://www.fortinet.com/)
[![FortiCNAPP](https://img.shields.io/badge/FortiCNAPP-Live-2EA043?style=for-the-badge&logo=fortinet&logoColor=white)](cnapp_rca/)
[![FortiCASB / SSPM](https://img.shields.io/badge/FortiCASB%20%2F%20SSPM-Coming_Soon-F0AD4E?style=for-the-badge&logo=fortinet&logoColor=white)](sspm_rca/)
[![Secrets](https://img.shields.io/badge/Secrets-Never_in_Git-2EA043?style=for-the-badge&logo=gitguardian&logoColor=white)](#-security)

[Overview](#-overview) • [Assessment Modules](#-assessment-modules) • [Screenshot](#-screenshot) • [Repository Layout](#-repository-layout) • [Security](#-security)

---

## 📋 Overview

Fortinet Rapid Cloud Assessment (RCA) is a collection of assessment tools that query Fortinet cloud security APIs to produce a fast, evidence-based view of a cloud environment's security posture. Each product has its own self-contained module.

---

## 🧩 Assessment Modules

| # | Product | Directory | Status |
| :-: | ------- | --------- | :----: |
| **1** | **FortiCNAPP** | [`cnapp_rca/`](cnapp_rca/) | ![Live](https://img.shields.io/badge/-Live-2EA043?style=flat-square) |
| **2** | **FortiCASB / SSPM** | [`sspm_rca/`](sspm_rca/) | ![Coming Soon](https://img.shields.io/badge/-Coming_Soon-F0AD4E?style=flat-square) |

> [!NOTE]
> Each module is independent. See the README inside each directory for module-specific setup and usage.

---

## 🖼️ Screenshot

<p align="center">
  <img width="1154" height="921" alt="Fortinet Rapid Cloud Assessment" src="https://github.com/user-attachments/assets/c4d9cde7-51e4-4e03-8a32-d01e03a07edc" />
</p>

---

## 🗂️ Repository Layout

```text
.
├── cnapp_rca/     # FortiCNAPP assessment (Live)
├── sspm_rca/      # FortiCASB / SSPM assessment (Coming Soon)
└── README.md
```

---

## 🛡️ Security

> [!CAUTION]
> **Never commit API keys, API secrets, or other credentials to Git.** Supply credentials through environment variables or a local, git-ignored configuration file.

Recommended `.gitignore` entries:

```gitignore
.env
*.toml
```

---

🔒 Keep secrets out of source control · Rotate API keys regularly
