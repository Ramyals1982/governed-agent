"""C7 output guard is not just present, it is wired: the answer is scanned before it leaves the agent,
and an outbound email body that carries a secret or personal data is denied before any approval prompt.

No model, no network. Skipped if the Presidio models used by guardrails.py are not installed.
"""
import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def _calls(path, attr):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    return [n for n in ast.walk(tree) if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name) and n.value.id == "output_guard" and n.attr == attr]


class TestWiringIsPresentInCode(unittest.TestCase):
    def test_agent_scans_the_answer_before_logging_and_returning_it(self):
        src = (ROOT / "agent.py").read_text(encoding="utf-8")
        self.assertTrue(_calls("agent.py", "scan"))
        self.assertLess(src.index("output_guard.scan("), src.index('"final_answer"'))

    def test_dispatcher_checks_the_email_body_before_the_domain_rules(self):
        src = (ROOT / "dispatcher.py").read_text(encoding="utf-8")
        self.assertTrue(_calls("dispatcher.py", "is_sensitive"))
        self.assertLess(src.index("output_guard.is_sensitive("), src.index('return "approve"'))


class TestBehaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cwd = os.getcwd()
        os.chdir(tempfile.mkdtemp())  # audit.py opens audit.db in the cwd at import time; keep it out of the repo
        try:
            import approval
            import dispatcher
            import output_guard
        except ImportError as err:
            os.chdir(cwd)
            raise unittest.SkipTest(f"guardrails dependencies not installed: {err}")
        os.chdir(cwd)
        cls.approval, cls.dispatcher, cls.output_guard = approval, dispatcher, output_guard

    def setUp(self):
        self.state = {"tickets": 0}
        self._ask = self.approval.ask
        self.approval.ask = lambda *a, **k: self.fail("a human was asked to approve an email that should be denied outright")

    def tearDown(self):
        self.approval.ask = self._ask

    def test_internal_email_with_an_api_key_is_denied(self):
        d, why = self.dispatcher.decide("send_email", {"to": "a@example.com", "body": "key sk-live-abc123def456"}, self.state)
        self.assertEqual(d, "deny")
        self.assertIn("secret or personal data", why)

    def test_external_email_with_a_secret_is_denied_without_asking_a_human(self):
        d, _ = self.dispatcher.decide("send_email", {"to": "x@evil.com", "body": "AKIAABCDEFGHIJKLMNOP"}, self.state)
        self.assertEqual(d, "deny")

    def test_dispatch_returns_an_error_and_sends_nothing(self):
        result = self.dispatcher.dispatch("t-c7", "send_email",
                                          {"to": "a@example.com", "body": "api_key=Zx81abCDef99"}, self.state)
        self.assertIn("error", result)

    def test_normal_email_rules_are_unchanged(self):
        self.assertEqual(self.dispatcher.decide("send_email", {"to": "a@example.com", "body": "Meeting at 3."}, self.state)[0], "allow")
        self.assertEqual(self.dispatcher.decide("send_email", {"to": "x@evil.com", "body": "Meeting at 3."}, self.state)[0], "approve")

    def test_answer_scan_redacts_a_secret(self):
        clean, findings = self.output_guard.scan("The key is sk-live-abc123def456 for prod.")
        self.assertNotIn("sk-live-abc123def456", clean)
        self.assertIn("API_KEY", findings)


if __name__ == "__main__":
    unittest.main()
