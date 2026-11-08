import contextlib
import io
from pathlib import Path
import tempfile
import unittest
import iam_audit

class DemoTests(unittest.TestCase):
    def tearDown(self):
        iam_audit.reset_findings()

    def test_repeated_runs_do_not_accumulate_findings(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / "nested" / "report.html"
            iam_audit.main(["--output", str(path)])
            first = {key: len(value) for key, value in iam_audit.findings.items()}
            iam_audit.main(["--output", str(path)])
            self.assertEqual(first, {key: len(value) for key, value in iam_audit.findings.items()})
            self.assertIn("IAM Security Audit Report", path.read_text(encoding="utf-8"))

    def test_report_escapes_identity_text(self):
        iam_audit.reset_findings()
        iam_audit.findings["high"].append({"user": "<script>evil</script>", "detail": "<img src=x>", "check": "demo"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            iam_audit.generate_html_report(path)
            html = path.read_text(encoding="utf-8")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img src=x&gt;", html)
