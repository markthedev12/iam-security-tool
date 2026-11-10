"""Small rule engine. Missing evidence is an error, never a passing check."""
import csv
import io
from datetime import datetime, timezone


REQUIRED = ('user', 'password_enabled', 'mfa_active', 'access_key_1_active',
            'access_key_1_last_rotated', 'access_key_2_active',
            'access_key_2_last_rotated')


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError) as exc:
        raise ValueError('Expected an ISO 8601 timestamp') from exc
    if result.tzinfo is None:
        raise ValueError('Timestamp must include a timezone')
    return result.astimezone(timezone.utc)


def audit(text, *, as_of, max_key_age=90):
    if as_of.tzinfo is None:
        raise ValueError('Audit time must include a timezone')
    if type(max_key_age) is not int or max_key_age < 1:
        raise ValueError('Key age threshold must be a positive integer')
    reader = csv.DictReader(io.StringIO(text))
    headers = reader.fieldnames or []
    if len(headers) != len(set(headers)) or not set(REQUIRED) <= set(headers):
        raise ValueError('Missing or duplicate credential report columns')
    findings, seen = [], set()
    checks = 0

    def add(rule, severity, user, evidence, remediation):
        findings.append(dict(rule_id=rule, severity=severity, resource=user,
                             evidence=evidence, remediation=remediation))

    for number, row in enumerate(reader, 2):
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f'Row {number}: inconsistent column count')
        user = row['user'].strip()
        if not user or user in seen:
            raise ValueError(f'Row {number}: empty or duplicate user')
        seen.add(user)
        flags = {}
        for field in ('password_enabled', 'mfa_active', 'access_key_1_active', 'access_key_2_active'):
            value = row[field].strip().lower()
            # AWS may report not_supported for root password_enabled.
            if field == 'password_enabled' and user == '<root_account>' and value == 'not_supported':
                flags[field] = None
            elif value not in ('true', 'false'):
                raise ValueError(f'Row {number}: invalid {field}')
            else:
                flags[field] = value == 'true'
        root = user == '<root_account>'
        if root or flags['password_enabled']:
            checks += 1
            if not flags['mfa_active']:
                add('IAM-MFA-001', 'critical' if root else 'high', user,
                    'No MFA device registered', 'Review identity controls and register MFA; device registration does not prove enforcement.')
        for slot in (1, 2):
            if not flags[f'access_key_{slot}_active']:
                continue
            checks += 1
            if root:
                add('IAM-ROOT-001', 'critical', user, f'Root access key slot {slot} is active',
                    'Review dependencies and remove root access keys through an approved change.')
            value = row[f'access_key_{slot}_last_rotated'].strip()
            if value in ('N/A', 'no_information', 'not_supported'):
                add('IAM-DATA-001', 'medium', user, f'Active key slot {slot} has unknown rotation age',
                    'Collect key metadata before deciding whether rotation is needed.')
                continue
            rotated = timestamp(value)
            if rotated > as_of:
                raise ValueError(f'Row {number}: key rotation is after audit time')
            age = (as_of - rotated).days
            if age > max_key_age:
                add('IAM-KEY-001', 'high', user, f'Key slot {slot} is {age} days old; threshold {max_key_age}',
                    'Prefer temporary role credentials; otherwise rotate with dependency testing.')
    if not seen:
        raise ValueError('Credential report has no accounts')
    return dict(schema_version='1.0', as_of=as_of.isoformat(), source='aws-iam-credential-report',
                accounts_scanned=len(seen), checks_evaluated=checks,
                max_key_age_days=max_key_age, findings=findings)
