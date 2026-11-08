# IAM Security Review Demo

A standard-library Python simulation of identity-policy checks against eight
fictional accounts. It prints findings and produces an HTML report. No Active
Directory, Microsoft 365, employer environment, or live identity service is
connected. This is a learning project, not a compliance scanner.

## Run

Python 3.12+; no dependencies or credentials required.

```sh
python iam_audit.py
python iam_audit.py --output reports/demo.html
python -m unittest discover -s tests -v
```

Open the generated HTML in a browser. The default output is
`iam_audit_report.html` in the current folder. Parent directories are created
for a custom output path; reports use UTF-8. On terminals with encoding issues,
enable Python UTF-8 mode (`PYTHONUTF8=1`). ANSI colors depend on terminal support.

## Data flow and checks

`USERS fixture -> six rule functions -> severity lists -> console + HTML`

Checks cover missing MFA, shared accounts, privileged roles, inactivity,
password-policy assumptions, and enabled guests. Report values are escaped so
identity text does not become executable HTML. Each CLI run resets findings,
making repeated in-process demos consistent.

Tests cover first-run report creation, nested output paths, repeatability and
HTML injection. GitHub Actions runs them on Python 3.12/3.13.

## Interpretation and limitations

The fixed 30/90-day and password-expiry rules are illustrative organization
policy, not universal requirements. Framework references are educational; a
flag or numerical score does not establish a regulatory violation or prove
compliance. The score is a simple weighted demo metric, not a calibrated risk
model. Skip behavior means total iterations need not equal pass plus fail counts.
No remediation or account changes occur.

## Next steps and contributions

Extract pure checks that accept validated input, distinguish human/service
identities, make policies configurable, add CSV ingestion and explicit skipped
results, and remove global state from the engine. Add a test with any changed
policy behavior. Never commit real identity exports or reports.
