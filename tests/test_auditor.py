import csv
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

from identity_auditor.engine import REQUIRED, audit, timestamp

NOW = timestamp('2026-11-10T00:00:00Z')


def fixture(**changes):
    row = dict(zip(REQUIRED, ['demo', 'true', 'true', 'false', 'N/A', 'false', 'N/A']))
    row.update(changes)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=REQUIRED)
    writer.writeheader()
    writer.writerow(row)
    return output.getvalue()


class AuditTests(unittest.TestCase):
    def run_audit(self, **changes):
        return audit(fixture(**changes), as_of=NOW)

    def test_healthy_console(self):
        self.assertEqual(self.run_audit()['findings'], [])

    def test_console_mfa(self):
        finding = self.run_audit(mfa_active='false')['findings'][0]
        self.assertEqual((finding['rule_id'], finding['severity']), ('IAM-MFA-001', 'high'))

    def test_root_special_password_value(self):
        result = self.run_audit(user='<root_account>', password_enabled='not_supported', mfa_active='false')
        self.assertEqual(result['findings'][0]['severity'], 'critical')

    def test_service_account_does_not_require_console_mfa(self):
        self.assertEqual(self.run_audit(password_enabled='false', mfa_active='false')['findings'], [])

    def test_root_key_and_age_are_independent(self):
        result = self.run_audit(user='<root_account>', access_key_1_active='true',
                                access_key_1_last_rotated='2026-01-01T00:00:00Z')
        self.assertEqual([f['rule_id'] for f in result['findings']], ['IAM-ROOT-001', 'IAM-KEY-001'])

    def test_age_boundary_and_second_slot(self):
        for day, expected in [('12', []), ('11', ['IAM-KEY-001'])]:
            with self.subTest(day=day):
                result = self.run_audit(access_key_2_active='true',
                                       access_key_2_last_rotated=f'2026-08-{day}T00:00:00Z')
                self.assertEqual([f['rule_id'] for f in result['findings']], expected)

    def test_unknown_age_is_finding(self):
        for marker in ['N/A', 'no_information', 'not_supported']:
            with self.subTest(marker=marker):
                result = self.run_audit(access_key_1_active='true', access_key_1_last_rotated=marker)
                self.assertEqual(result['findings'][0]['rule_id'], 'IAM-DATA-001')

    def test_invalid_evidence_is_error(self):
        cases = [dict(mfa_active='maybe'), dict(user=''),
                 dict(access_key_1_active='true', access_key_1_last_rotated='garbage'),
                 dict(access_key_1_active='true', access_key_1_last_rotated='2027-01-01T00:00:00Z'),
                 dict(access_key_1_active='true', access_key_1_last_rotated='2026-01-01')]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.run_audit(**case)

    def test_invalid_structure(self):
        source = fixture()
        cases = ['', 'user\ndemo\n', source + source.splitlines()[1] + '\n',
                 source.replace('user,', 'user,user,'), source + 'short,row\n']
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                audit(case, as_of=NOW)

    def test_threshold_validation(self):
        for threshold in [0, -1, True]:
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                audit(fixture(), as_of=NOW, max_key_age=threshold)

    def test_determinism(self):
        self.assertEqual(self.run_audit(), self.run_audit())

    def test_cli_json_and_exit_codes(self):
        base = [sys.executable, '-m', 'identity_auditor', 'examples/credential-report.csv',
                '--as-of', NOW.isoformat()]
        for threshold, status in [('none', 0), ('high', 1), ('critical', 1)]:
            result = subprocess.run(base + ['--fail-on', threshold], text=True, capture_output=True)
            self.assertEqual(result.returncode, status, result.stderr)
            self.assertEqual(json.loads(result.stdout)['accounts_scanned'], 3)
        result = subprocess.run(base + ['--max-key-age', '0'], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')

    def test_missing_file(self):
        result = subprocess.run([sys.executable, '-m', 'identity_auditor', 'missing.csv'],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
