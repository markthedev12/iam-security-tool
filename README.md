# Identity Security Auditor

Python automation that turns an AWS IAM credential report into explainable JSON findings. Built to demonstrate identity security engineering: validate evidence, apply explicit rules, test boundaries, and report actionable results.

**Status:** offline credential-report auditing implemented and tested. Live AWS collection and AI explanations are planned. The original AD simulation remains in `iam_audit.py`; its original documentation is retained below for reference.

## Run a two-minute demo

Python 3.11+; standard library only. Run from the repository root:

```bash
git clone https://github.com/markthedev12/iam-security-tool.git
cd iam-security-tool
# Until this PR is merged:
git switch feat/identity-security-auditor
python3 -m unittest discover -s tests -v
python3 -m identity_auditor examples/credential-report.csv --as-of 2026-11-10T00:00:00Z
```

The synthetic fixture produces four findings across three accounts. Use `--fail-on high` to return exit 1 when a high or critical finding exists. Exit 0 means evaluation completed without findings at the selected blocking threshold; exit 2 means invalid input or an execution error. Default `--fail-on none` reports findings without blocking.

## Implemented controls

| Rule | Evidence | Result |
| --- | --- | --- |
| IAM-MFA-001 | Root or password-enabled user lacks registered MFA | Critical for root, high for IAM user |
| IAM-ROOT-001 | Root access key is active | Critical |
| IAM-KEY-001 | Active key age exceeds configurable threshold | High; default greater than 90 completed days |
| IAM-DATA-001 | Active key rotation age unavailable | Medium; evidence needs review |

Both key slots are evaluated. Rotation dates must include a timezone and cannot be in the future relative to the audit time. Input errors abort the entire scan without a partial JSON result. All times use the supplied `--as-of` timestamp or current UTC. These are local review rules, not compliance certification.

## Architecture

```text
IAM credential CSV -> validated records -> pure rule engine -> versioned JSON -> CI exit policy
                                                                  |
                                                    future optional AI explanation
```

- `identity_auditor/engine.py`: validation and deterministic rules, no network calls or global audit state.
- `identity_auditor/cli.py`: input, JSON output, and exit policy.
- `tests/test_auditor.py`: healthy/risky fixtures, both slots, age boundaries, unknowns, invalid evidence, CLI behavior.
- `examples/credential-report.csv`: synthetic data only; reduced to the columns this auditor consumes.
- `docs/IMPLEMENTATION.md`: hands-on walkthrough and next implementation milestones.

Full AWS reports with additional columns are accepted. Redirect output to a local file if needed. Real reports can contain identity information; keep them out of the repository. No input is sent externally, no AWS credentials are loaded, and no remediation is executed.

## Important limits

MFA registration does not establish MFA enforcement for sessions or API calls. Credential reports do not describe effective IAM permissions, role trust, Identity Center, SCPs, or all credential types. Key age is an organization-selected review threshold, not proof of compromise. An empty finding list only applies to the implemented rules and supplied rows; completeness and snapshot freshness are not established. Root rows are evaluated when present. No live AWS integration or AI capability is claimed in this release.

AWS report semantics and collection permissions: [AWS IAM credential report documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html).

## Roadmap

1. Optional boto3 collector with scoped IAM permissions, bounded polling, explicit collection failures, and freshness metadata.
2. Policy/trust analysis with clearly documented semantic limits and test fixtures.
3. Redacted cloud demonstration and approved before/after remediation evidence.
4. Optional AI explanation layer with grounding and injection-resistance evaluation; detection stays deterministic.

[Build it step by step](docs/IMPLEMENTATION.md).

---

<details>
<summary>Original AD simulation documentation (historical; not the new auditor)</summary>

The original script and documentation below are preserved. Known legacy issues: the script starts with an invalid `python#!` prefix and uses a fixed home-directory output path; the historical clone URL is incorrect. Its framework mappings, password assumptions, and compliance labels require review before reuse. Use the new module above for the tested demo.

# IAM Security Audit Tool 🔐

> A Python-based Identity and Access Management security audit tool that identifies common Active Directory misconfigurations and HIPAA compliance violations across user accounts.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Security](https://img.shields.io/badge/Security-IAM%20Audit-red?style=flat-square)
![HIPAA](https://img.shields.io/badge/Compliance-HIPAA-green?style=flat-square)
![NIST](https://img.shields.io/badge/Framework-NIST%20SP%20800--53-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

---

## Overview

Built from real-world experience managing IAM operations across a 20,000+ user enterprise healthcare environment, this tool simulates the type of security audit performed on Active Directory environments to identify access control weaknesses before they become incidents or compliance violations.

This tool checks for the most common — and most dangerous — IAM misconfigurations found in small to mid-size organizations, particularly those handling sensitive data under HIPAA or similar regulatory frameworks.

---

## What It Checks

| Check | Description | Framework Reference |
|-------|-------------|-------------------|
| MFA Compliance | Identifies accounts without Multi-Factor Authentication | NIST AC-7, HIPAA 164.312(d) |
| Shared Account Detection | Flags accounts used by multiple users | HIPAA 164.312(a)(2)(i) |
| Privileged Access Review | Identifies accounts with excessive admin rights | NIST AC-6, Least Privilege |
| Inactive Account Detection | Finds enabled accounts with no recent login activity | NIST AC-2(3) |
| Password Policy Compliance | Checks for non-expiring or aged passwords | NIST IA-5 |
| Guest Account Audit | Detects enabled guest or anonymous accounts | NIST AC-2 |

---

## Sample Output

```
╔══════════════════════════════════════════════════════════╗
║           IAM SECURITY AUDIT TOOL v1.0                  ║
║           Author: Mark Schwinn                           ║
║           markschwinn.com                                ║
╚══════════════════════════════════════════════════════════╝

============================================================
  CHECK 1 // MFA COMPLIANCE
============================================================

  [CRITICAL] admin — Admin account 'Admin User' has NO MFA enabled — critical risk
  [HIGH]     jsmith — Standard account 'John Smith' has no MFA enabled
  [PASS]     drwilliams — MFA enabled for Dr. Sarah Williams

============================================================
  AUDIT COMPLETE // EXECUTIVE SUMMARY
============================================================

  Total Accounts Audited:  8
  Total Checks Run:        48
  Critical Findings:       5
  High Findings:           7
  Medium Findings:         3
  Checks Passed:           28

  Overall Risk Score:      0/100
  [!!] HIGH RISK ENVIRONMENT — Immediate remediation required

  Report saved to: ~/iam-security-audit/iam_audit_report.html
```

---

## Report Output

The tool generates a professional **HTML report** including:
- Overall risk score out of 100
- Color-coded findings by severity — Critical, High, Medium
- Per-user breakdown of every check
- NIST SP 800-53 and HIPAA framework citations
- Remediation guidance for each finding

---

## Getting Started

### Requirements
- Python 3.8 or higher
- No external dependencies — uses standard library only

### Installation

```bash
git clone https://github.com/markthedev12/iam-security-audit-tool
cd iam-security-audit-tool
```

### Usage

```bash
python3 iam_audit.py
```

The HTML report will be saved automatically to your working directory.

---

## Extending the Tool

The `USERS` list in `iam_audit.py` represents a simulated Active Directory environment. To adapt this tool for a real environment you can:

- Integrate with `python-ldap` or `ldap3` to pull live AD data
- Connect to Microsoft Graph API to audit Entra ID / Azure AD accounts
- Add additional checks for conditional access policies and role assignments
- Export findings to JSON for integration with SIEM tools

---

## Compliance Mapping

| Finding Type | HIPAA Reference | NIST SP 800-53 |
|-------------|-----------------|----------------|
| No MFA | 45 CFR 164.312(d) | IA-2, AC-7 |
| Shared Accounts | 45 CFR 164.312(a)(2)(i) | AC-2, AU-9 |
| Excessive Privileges | 45 CFR 164.312(a)(1) | AC-6, AC-3 |
| Inactive Accounts | 45 CFR 164.308(a)(3)(ii)(C) | AC-2(3) |
| Password Policy | 45 CFR 164.308(a)(5)(ii)(D) | IA-5 |
| Guest Accounts | 45 CFR 164.312(a)(2)(ii) | AC-2 |

---

## Author

**Mark Schwinn** — IAM & Cybersecurity Professional  
📍 Philadelphia, PA  
🌐 [markschwinn.com](https://markschwinn.com)  
📧 mark@markschwinn.com  
💼 [LinkedIn](https://www.linkedin.com/in/mark-schwinn-994625362/)

---

## License

MIT License — free to use, modify, and distribute with attribution.

</details>

