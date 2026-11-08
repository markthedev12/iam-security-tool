#!/usr/bin/env python3
"""
IAM Security Audit Tool
Author: Mark Schwinn
Description: Simulates an Identity and Access Management security audit
             based on common Active Directory and M365 misconfigurations
Version: 1.0
"""

import datetime
import argparse
from html import escape
from pathlib import Path

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
WHITE = '\033[97m'
BOLD = '\033[1m'
RESET = '\033[0m'

USERS = [
    {"username": "jsmith", "full_name": "John Smith", "role": "Office Manager", "department": "Administration", "is_admin": False, "mfa_enabled": False, "password_expires": True, "last_login_days_ago": 5, "account_enabled": True, "shared_account": False, "password_age_days": 45},
    {"username": "admin", "full_name": "Admin User", "role": "IT Admin", "department": "IT", "is_admin": True, "mfa_enabled": False, "password_expires": False, "last_login_days_ago": 2, "account_enabled": True, "shared_account": True, "password_age_days": 200},
    {"username": "reception1", "full_name": "Front Desk", "role": "Receptionist", "department": "Front Office", "is_admin": False, "mfa_enabled": False, "password_expires": False, "last_login_days_ago": 1, "account_enabled": True, "shared_account": True, "password_age_days": 365},
    {"username": "drwilliams", "full_name": "Dr. Sarah Williams", "role": "Physician", "department": "Clinical", "is_admin": True, "mfa_enabled": True, "password_expires": True, "last_login_days_ago": 3, "account_enabled": True, "shared_account": False, "password_age_days": 30},
    {"username": "mjohnson", "full_name": "Mike Johnson", "role": "Billing Specialist", "department": "Finance", "is_admin": False, "mfa_enabled": True, "password_expires": True, "last_login_days_ago": 90, "account_enabled": True, "shared_account": False, "password_age_days": 90},
    {"username": "svc_backup", "full_name": "Backup Service Account", "role": "Service Account", "department": "IT", "is_admin": True, "mfa_enabled": False, "password_expires": False, "last_login_days_ago": 0, "account_enabled": True, "shared_account": False, "password_age_days": 730},
    {"username": "guest", "full_name": "Guest Account", "role": "Guest", "department": "N/A", "is_admin": False, "mfa_enabled": False, "password_expires": False, "last_login_days_ago": 180, "account_enabled": True, "shared_account": False, "password_age_days": 999},
    {"username": "lthompson", "full_name": "Lisa Thompson", "role": "HR Manager", "department": "Human Resources", "is_admin": False, "mfa_enabled": True, "password_expires": True, "last_login_days_ago": 60, "account_enabled": True, "shared_account": False, "password_age_days": 60}
]

findings = {"critical": [], "high": [], "medium": [], "low": [], "passed": []}
total_checks = 0
passed_checks = 0

def print_banner():
    print(f"\n{CYAN}{BOLD}╔══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}{BOLD}║           IAM SECURITY AUDIT TOOL v1.0                  ║{RESET}")
    print(f"{CYAN}{BOLD}║           Author: Mark Schwinn                           ║{RESET}")
    print(f"{CYAN}{BOLD}║           markschwinn.com                                ║{RESET}")
    print(f"{CYAN}{BOLD}╚══════════════════════════════════════════════════════════╝{RESET}\n")

def print_section(title):
    print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'='*60}{RESET}\n")

def flag_critical(check, user, detail):
    findings["critical"].append({"check": check, "user": user, "detail": detail})
    print(f"  {RED}{BOLD}[CRITICAL]{RESET} {user} — {detail}")

def flag_high(check, user, detail):
    findings["high"].append({"check": check, "user": user, "detail": detail})
    print(f"  {YELLOW}{BOLD}[HIGH]{RESET}     {user} — {detail}")

def flag_medium(check, user, detail):
    findings["medium"].append({"check": check, "user": user, "detail": detail})
    print(f"  {YELLOW}[MEDIUM]{RESET}   {user} — {detail}")

def flag_pass(check, user, detail):
    findings["passed"].append({"check": check, "user": user, "detail": detail})
    print(f"  {GREEN}[PASS]{RESET}     {user} — {detail}")

def check_mfa():
    global total_checks, passed_checks
    print_section("CHECK 1 // MFA COMPLIANCE")
    print(f"  {WHITE}Checking all accounts for Multi-Factor Authentication...{RESET}\n")
    for user in USERS:
        total_checks += 1
        if user["role"] == "Guest":
            continue
        if not user["mfa_enabled"]:
            if user["is_admin"]:
                flag_critical("MFA Compliance", user["username"], f"Admin account '{user['full_name']}' has NO MFA enabled — critical risk")
            else:
                flag_high("MFA Compliance", user["username"], f"Standard account '{user['full_name']}' has no MFA enabled")
        else:
            passed_checks += 1
            flag_pass("MFA Compliance", user["username"], f"MFA enabled for {user['full_name']}")

def check_shared_accounts():
    global total_checks, passed_checks
    print_section("CHECK 2 // SHARED ACCOUNT DETECTION")
    print(f"  {WHITE}Scanning for accounts used by multiple users...{RESET}\n")
    for user in USERS:
        total_checks += 1
        if user["shared_account"]:
            flag_critical("Shared Accounts", user["username"], f"Account '{user['username']}' is a shared credential — review unique-user attribution")
        else:
            passed_checks += 1
            flag_pass("Shared Accounts", user["username"], f"Unique account confirmed for {user['full_name']}")

def check_privileged_access():
    global total_checks, passed_checks
    print_section("CHECK 3 // PRIVILEGED ACCESS REVIEW")
    print(f"  {WHITE}Reviewing accounts with administrative privileges...{RESET}\n")
    for user in USERS:
        total_checks += 1
        if user["is_admin"]:
            if user["role"] not in ["IT Admin", "Service Account"]:
                flag_high("Privileged Access", user["username"], f"'{user['full_name']}' ({user['role']}) has admin rights — violates least privilege")
            else:
                passed_checks += 1
                flag_pass("Privileged Access", user["username"], f"Admin rights appropriate for role: {user['role']}")
        else:
            passed_checks += 1
            flag_pass("Privileged Access", user["username"], f"Standard access confirmed for {user['full_name']}")

def check_inactive_accounts():
    global total_checks, passed_checks
    print_section("CHECK 4 // INACTIVE ACCOUNT DETECTION")
    print(f"  {WHITE}Checking for accounts inactive more than 30 days...{RESET}\n")
    for user in USERS:
        total_checks += 1
        if user["last_login_days_ago"] > 30 and user["account_enabled"]:
            if user["last_login_days_ago"] > 90:
                flag_critical("Inactive Accounts", user["username"], f"Account inactive for {user['last_login_days_ago']} days but still ENABLED")
            else:
                flag_high("Inactive Accounts", user["username"], f"Account inactive for {user['last_login_days_ago']} days — review recommended")
        else:
            passed_checks += 1
            flag_pass("Inactive Accounts", user["username"], f"Account active within acceptable timeframe")

def check_password_policy():
    global total_checks, passed_checks
    print_section("CHECK 5 // PASSWORD POLICY COMPLIANCE")
    print(f"  {WHITE}Auditing password expiration and age settings...{RESET}\n")
    for user in USERS:
        total_checks += 1
        if not user["password_expires"]:
            flag_high("Password Policy", user["username"], f"Password set to NEVER EXPIRE for {user['full_name']} — policy violation")
        elif user["password_age_days"] > 90:
            flag_medium("Password Policy", user["username"], f"Password is {user['password_age_days']} days old — exceeds 90 day policy")
        else:
            passed_checks += 1
            flag_pass("Password Policy", user["username"], f"Password compliant for {user['full_name']}")

def check_guest_accounts():
    global total_checks, passed_checks
    print_section("CHECK 6 // GUEST ACCOUNT AUDIT")
    print(f"  {WHITE}Checking for enabled guest or anonymous accounts...{RESET}\n")
    for user in USERS:
        total_checks += 1
        if user["role"] == "Guest" and user["account_enabled"]:
            flag_critical("Guest Accounts", user["username"], f"Guest account is ENABLED — immediate disable required")
        elif user["role"] != "Guest":
            passed_checks += 1
            flag_pass("Guest Accounts", user["username"], f"Not a guest account — no action needed")

def generate_html_report(output_path="iam_audit_report.html"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_score = 100 - (len(findings["critical"]) * 20) - (len(findings["high"]) * 10) - (len(findings["medium"]) * 5)
    risk_score = max(0, risk_score)
    risk_label = "LOW RISK" if risk_score >= 80 else "MEDIUM RISK" if risk_score >= 50 else "HIGH RISK"
    risk_color = "#00ff88" if risk_score >= 80 else "#ffa500" if risk_score >= 50 else "#ff4444"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IAM Security Audit Report — Mark Schwinn</title>
<style>
body{{font-family:'Courier New',monospace;background:#020408;color:#e0f0ff;margin:0;padding:40px;}}
.header{{border-bottom:2px solid #00f5ff;padding-bottom:20px;margin-bottom:30px;}}
.header h1{{font-size:28px;color:#00f5ff;margin:0 0 8px;letter-spacing:2px;text-transform:uppercase;}}
.header p{{color:rgba(200,230,255,0.5);font-size:13px;margin:4px 0;}}
.score-box{{background:#0d1a2e;border:1px solid #00f5ff;padding:24px;margin:20px 0;text-align:center;display:inline-block;min-width:200px;}}
.score-num{{font-size:48px;font-weight:bold;color:{risk_color};}}
.score-label{{font-size:14px;color:{risk_color};letter-spacing:2px;margin-top:8px;}}
.summary-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0;}}
.summary-box{{background:#0d1a2e;border:1px solid rgba(0,245,255,0.2);padding:16px;text-align:center;}}
.summary-num{{font-size:28px;font-weight:bold;}}
.summary-lbl{{font-size:11px;color:rgba(200,230,255,0.4);letter-spacing:1px;margin-top:4px;text-transform:uppercase;}}
.critical{{color:#ff4444;}}.high{{color:#ffa500;}}.medium{{color:#ffff00;}}.passed{{color:#00ff88;}}
.section{{margin:24px 0;}}
.section h2{{color:#00f5ff;font-size:14px;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid rgba(0,245,255,0.2);padding-bottom:8px;}}
.finding{{background:#0d1a2e;border-left:3px solid;padding:12px 16px;margin:8px 0;font-size:13px;}}
.finding.critical{{border-color:#ff4444;}}.finding.high{{border-color:#ffa500;}}
.finding.medium{{border-color:#ffff00;}}.finding.passed{{border-color:#00ff88;}}
.footer{{margin-top:40px;border-top:1px solid rgba(0,245,255,0.2);padding-top:16px;font-size:12px;color:rgba(200,230,255,0.3);}}
</style>
</head>
<body>
<div class="header">
<h1>// IAM Security Audit Report</h1>
<p>Generated: {timestamp}</p>
<p>Auditor: Mark Schwinn | markschwinn.com | mark@markschwinn.com</p>
<p>Framework: NIST SP 800-53 / HIPAA Security Rule 45 CFR Part 164</p>
</div>
<div class="score-box">
<div class="score-num">{risk_score}/100</div>
<div class="score-label">{risk_label}</div>
</div>
<div class="summary-grid">
<div class="summary-box"><div class="summary-num critical">{len(findings['critical'])}</div><div class="summary-lbl">Critical</div></div>
<div class="summary-box"><div class="summary-num high">{len(findings['high'])}</div><div class="summary-lbl">High</div></div>
<div class="summary-box"><div class="summary-num medium">{len(findings['medium'])}</div><div class="summary-lbl">Medium</div></div>
<div class="summary-box"><div class="summary-num passed">{len(findings['passed'])}</div><div class="summary-lbl">Passed</div></div>
</div>"""

    for severity, label, css in [("critical","CRITICAL FINDINGS","critical"),("high","HIGH FINDINGS","high"),("medium","MEDIUM FINDINGS","medium"),("passed","PASSED CHECKS","passed")]:
        if findings[severity]:
            html += f'<div class="section"><h2>{label}</h2>'
            for f in findings[severity]:
                html += f'<div class="finding {css}"><strong>[{severity.upper()}]</strong> <strong>{escape(str(f["user"]))}</strong> — {escape(str(f["detail"]))}</div>'
            html += '</div>'

    html += f"""
<div class="footer">
<p>// IAM Security Audit Tool by Mark Schwinn | markschwinn.com</p>
<p>// NIST SP 800-53 AC-2, AC-3, AC-6 | HIPAA Security Rule 45 CFR 164.312</p>
</div></body></html>"""

    report_path = Path(output_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(html, encoding="utf-8")
    return str(report_path)

def reset_findings():
    global total_checks, passed_checks
    total_checks = passed_checks = 0
    for values in findings.values():
        values.clear()

def main(argv=None):
    parser = argparse.ArgumentParser(description="Simulated identity-policy review using fictional accounts")
    parser.add_argument("--output", default="iam_audit_report.html")
    args = parser.parse_args(argv)
    reset_findings()
    print_banner()
    print(f"  {WHITE}Starting IAM Security Audit...{RESET}")
    print(f"  {WHITE}Scanning {len(USERS)} user accounts across 6 security domains{RESET}\n")
    check_mfa()
    check_shared_accounts()
    check_privileged_access()
    check_inactive_accounts()
    check_password_policy()
    check_guest_accounts()

    print_section("AUDIT COMPLETE // EXECUTIVE SUMMARY")
    risk_score = 100 - (len(findings["critical"]) * 20) - (len(findings["high"]) * 10) - (len(findings["medium"]) * 5)
    risk_score = max(0, risk_score)
    print(f"  {WHITE}Total Accounts Audited:{RESET}  {len(USERS)}")
    print(f"  {WHITE}Total Checks Run:{RESET}        {total_checks}")
    print(f"  {RED}{BOLD}Critical Findings:{RESET}       {len(findings['critical'])}")
    print(f"  {YELLOW}High Findings:{RESET}           {len(findings['high'])}")
    print(f"  {YELLOW}Medium Findings:{RESET}         {len(findings['medium'])}")
    print(f"  {GREEN}Checks Passed:{RESET}           {len(findings['passed'])}")
    print(f"\n  {CYAN}{BOLD}Overall Risk Score:{RESET}      {risk_score}/100")
    if risk_score < 50:
        print(f"\n  {RED}{BOLD}[!!] HIGH RISK — Immediate remediation required{RESET}")
    elif risk_score < 80:
        print(f"\n  {YELLOW}{BOLD}[!] MEDIUM RISK — Several issues require attention{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}[OK] LOW RISK — Environment is largely compliant{RESET}")
    print(f"\n  {WHITE}Generating HTML report...{RESET}")
    report_path = generate_html_report(args.output)
    print(f"  {GREEN}{BOLD}Report saved to: {report_path}{RESET}")
    print(f"\n  {CYAN}// Audit complete.{RESET}\n")

if __name__ == "__main__":
    main()
