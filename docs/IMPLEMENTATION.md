# Build and understand it, step by step

## 1. Run the baseline

Use Python 3.11 or newer. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m unittest discover -s tests -v
python -m identity_auditor examples/credential-report.csv --as-of 2026-11-10T00:00:00Z
```

Windows PowerShell activation: `.venv\Scripts\Activate.ps1`.
No packages, AWS account, credentials, or paid services are needed.

## 2. Follow one finding through the code

Open `examples/credential-report.csv`. The root row has no registered MFA and an active old key. In `engine.py`, follow CSV validation, boolean parsing, root detection, key age calculation, and finding construction. The demo returns four findings: root MFA, root key, old key, and console-user MFA.

## 3. Make your first change

Create a branch with `git switch -c feat/custom-key-threshold`. Run the demo with `--max-key-age 365`. Explain which finding disappears and why. Add a test that verifies a 365-day threshold. Commit the test and open a PR explaining the behavior and test command.

## 4. Test a failure

Change `true` to `maybe` in a copy of the fixture. The program must exit 2 and emit no JSON. This prevents malformed evidence from becoming a clean report. Restore the copied fixture afterward.

## 5. Add AWS collection as a separate PR

Implement an optional boto3 collector, separate from the rule engine. Use only `iam:GenerateCredentialReport` and `iam:GetCredentialReport`, SSO/role credentials, bounded polling while generation completes, and explicit handling for access denied, throttling, and expired credentials. Record report generation time and reject stale snapshots. Mock the AWS boundary with botocore Stubber; test pagination for any later list APIs. Never turn a collection error into an empty successful scan.

## 6. Add a real cloud demonstration

Use a personal sandbox and a dedicated role. Export a credential report through AWS IAM, keep it outside version control, and audit it locally. Review evidence with the resource owner. Capture a redacted before/after finding and explain the approved remediation. The current CLI only reads files; it never makes AWS calls or changes credentials.

## 7. Add policy analysis

Collect attached/inline user, group, and role policies with pagination. Start with explainable broad-permission heuristics. Test explicit deny, conditions, resource scope, permission boundaries, and SCP limitations. Do not claim to calculate effective permissions until those semantics are addressed.

## 8. Add AI explanations with evaluation

Keep AI optional and downstream of immutable rule findings. Feed synthetic or explicitly approved redacted fields only. Treat resource names and evidence as untrusted data. Require structured output tied to known rule IDs, reject unsupported IDs, label generated text, and keep the deterministic report usable when the model fails. Never let a model change severity, suppress findings, or execute remediation. Compare explanations against a small labeled synthetic set for factual grounding, missing caveats, injection resistance, and secret leakage. Publish the rubric and observed results before claiming AI capabilities.

## Interview demonstration

In three minutes: explain the identity risk; run tests; run the fixture; show evidence and remediation for one finding; deliberately break input; explain why MFA registration is not proof of enforcement and why the tool cannot certify an account as secure.
