"""Evidence register with expiry: freshness, sufficiency, integrity, and the link to the Section 4 gate."""
import contextlib
import datetime as dt
import io
import json
import os
import sys
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import evidence  # noqa: E402
import mas_rubric  # noqa: E402
import resgister  # noqa: E402
import support_fixtures  # noqa: E402
from resgister import MASComplianceError  # noqa: E402
from test_mas_section4_gate import Section4Base  # noqa: E402

T0 = dt.datetime(2026, 11, 10, 9, 0, tzinfo=dt.timezone.utc)


def days(n):
    return T0 + dt.timedelta(days=n)


class TestEvidenceStatus(Section4Base):
    def setUp(self):
        super().setUp()
        support_fixtures.record_fixture_evidence(self.tmp, now=T0)

    def status(self, when=T0, item="redteam"):
        return next(i for i in evidence.evaluate(self.tmp, when) if i["id"] == item)

    def test_fresh_evidence_is_accepted(self):
        s = self.status(days(1))
        self.assertEqual(s["status"], evidence.ACCEPTED)
        self.assertEqual(s["metrics"]["attacks"], 21)
        self.assertAlmostEqual(s["metrics"]["catch_rate"], 20 / 21, places=3)

    def test_evidence_expires_after_the_policy_window(self):
        self.assertEqual(self.status(days(29))["status"], evidence.ACCEPTED)
        s = self.status(days(31))
        self.assertEqual(s["status"], evidence.NEEDS_REVIEW)
        self.assertIn("expired", s["reason"])

    def test_no_record_means_needs_evidence(self):
        (self.tmp / "evidence" / "redteam.evidence.json").unlink()
        self.assertEqual(self.status()["status"], evidence.NEEDS_EVIDENCE)

    def test_artifact_edited_after_recording_is_rejected(self):
        art = self.tmp / "evidence" / "redteam_results.md"
        art.write_text(art.read_text(encoding="utf-8").replace("MISSED", "CAUGHT"), encoding="utf-8")
        s = self.status()
        self.assertEqual(s["status"], evidence.REJECTED)
        self.assertIn("hash mismatch", s["reason"])

    def test_record_cannot_be_extended_by_editing_valid_until(self):
        rec_path = self.tmp / "evidence" / "redteam.evidence.json"
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
        rec["valid_until_informational"] = "2099-01-01T00:00:00+00:00"
        rec_path.write_text(json.dumps(rec), encoding="utf-8")
        self.assertEqual(self.status(days(45))["status"], evidence.NEEDS_REVIEW)

    def test_record_dated_in_the_future_is_rejected(self):
        self.assertEqual(self.status(days(-10))["status"], evidence.REJECTED)

    def test_corrupt_record_is_rejected(self):
        (self.tmp / "evidence" / "redteam.evidence.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(self.status()["status"], evidence.REJECTED)

    def test_recording_insufficient_evidence_is_refused(self):
        art = self.tmp / "evidence" / "redteam_results.md"
        lines = [ln for ln in art.read_text(encoding="utf-8").splitlines() if "Output guard" not in ln]
        art.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError) as cm:
            evidence.record(self.tmp, "redteam", now=T0)
        self.assertIn("Output guard", str(cm.exception))

    def test_low_catch_rate_is_insufficient(self):
        art = self.tmp / "evidence" / "redteam_results.md"
        art.write_text(art.read_text(encoding="utf-8").replace("| CAUGHT |", "| MISSED |", 6), encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError) as cm:
            evidence.record(self.tmp, "redteam", now=T0)
        self.assertIn("catch rate", str(cm.exception))

    def test_false_positive_is_insufficient(self):
        art = self.tmp / "evidence" / "redteam_results.md"
        art.write_text(art.read_text(encoding="utf-8").replace("| OK |", "| FALSE POSITIVE |", 1), encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError):
            evidence.record(self.tmp, "redteam", now=T0)

    def test_informational_item_does_not_block_the_gate(self):
        self.assertEqual(self.status(item="unit-tests")["status"], evidence.NEEDS_EVIDENCE)
        ok, reasons = evidence.gate_status(self.tmp, T0)
        self.assertTrue(ok, reasons)

    def test_junit_evidence(self):
        xml = '<testsuites><testsuite tests="120" failures="0" errors="0" skipped="5"/></testsuites>'
        (self.tmp / "evidence" / "pytest_junit.xml").write_text(xml, encoding="utf-8")
        evidence.record(self.tmp, "unit-tests", now=T0)
        self.assertEqual(self.status(days(1), "unit-tests")["status"], evidence.ACCEPTED)
        (self.tmp / "evidence" / "pytest_junit.xml").write_text(xml.replace('failures="0"', 'failures="2"'), encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError):
            evidence.record(self.tmp, "unit-tests", now=T0)

    def test_missing_policy_fails_closed(self):
        ok, reasons = evidence.gate_status(self.tmp, T0, policy_path=self.tmp / "nope.yaml")
        self.assertFalse(ok)
        self.assertIn("policy not found", reasons[0])

    def test_unknown_item_is_an_error(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.record(self.tmp, "does-not-exist")


class TestEvidenceAndTheGate(Section4Base):
    """Approval lasts 90 days; red-team evidence lasts 30. The gate must follow the shorter clock."""

    def setUp(self):
        super().setUp()
        support_fixtures.record_fixture_evidence(self.tmp, now=T0)
        self.approve(now=T0)

    def test_boots_while_evidence_is_fresh(self):
        self.assertEqual(self.gate(now=days(10))["residual_tier"], "MEDIUM")

    def test_stale_evidence_blocks_boot_while_the_approval_is_still_valid(self):
        self.gate(now=days(10))
        with self.assertRaises(MASComplianceError) as cm:
            self.gate(now=days(45))
        msg = str(cm.exception)
        self.assertIn("exceeds Board risk appetite", msg)
        self.assertIn("redteam: NEEDS_REVIEW", msg)
        self.assertTrue(self.events("2LoD_RESIDUAL_RISK_EXCEEDS_APPETITE"))

    def test_refreshing_the_evidence_restores_boot_without_a_new_approval(self):
        with self.assertRaises(MASComplianceError):
            self.gate(now=days(45))
        evidence.record(self.tmp, "redteam", now=days(44))
        self.assertEqual(self.gate(now=days(45))["computed_tier"], "HIGH")

    def test_dashboard_status_reports_the_block(self):
        resgister.register(base_dir=self.tmp)
        s = resgister.boot_status(self.tmp, now=days(45))
        self.assertEqual(s["status"], "BLOCKED_CHALLENGE_FAILED")
        self.assertIn("NEEDS_REVIEW", s["reasons"][0])

    def test_readiness_check_c_follows_evidence_status(self):
        checks = {c["id"]: c for c in resgister.control_readiness(self.tmp)}
        self.assertTrue(checks["c"]["passed"], checks["c"])


class TestStaleEvidenceBlocksAtEveryTier(Section4Base):
    """The block must not depend on residual-risk arithmetic. A MEDIUM or LOW system with stale evidence also stops."""

    def start_stale(self, edits, patch_tier=None):
        for old, new in edits:
            self.edit_manifest(old, new)
        if patch_tier:   # stand in for a system the rubric scores as this tier
            unittest.mock.patch.object(mas_rubric, "tier", lambda scores, profile: patch_tier).start()
            self.addCleanup(unittest.mock.patch.stopall)
        support_fixtures.record_fixture_evidence(self.tmp, now=T0)
        self.approve(now=T0)
        self.assertTrue(self.gate(now=days(10)))                     # fine while evidence is fresh
        with self.assertRaises(MASComplianceError) as cm:
            self.gate(now=days(45))                                   # approval valid to day 90, evidence expired day 30
        return str(cm.exception)

    def test_medium_system_with_stale_evidence_is_blocked(self):
        msg = self.start_stale([("architecture_type: AUTONOMOUS_AGENT", "architecture_type: RULE_BASED"),
                                ("declared_inherent_risk: HIGH", "declared_inherent_risk: MEDIUM")])
        self.assertIn("Required evidence is not current", msg)
        self.assertIn("redteam: NEEDS_REVIEW", msg)
        self.assertTrue(any(e["reason"] == "required evidence is not current" for e in self.events("mas_gate_blocked")))

    def test_low_system_with_stale_evidence_is_blocked(self):
        msg = self.start_stale([("declared_inherent_risk: HIGH", "declared_inherent_risk: LOW")], patch_tier="LOW")
        self.assertIn("Required evidence is not current", msg)

    def test_high_system_is_blocked_by_either_rule(self):
        with self.assertRaises(MASComplianceError):
            support_fixtures.record_fixture_evidence(self.tmp, now=T0)
            self.approve(now=T0)
            self.gate(now=days(45))

    def test_dashboard_status_for_a_stale_medium_system(self):
        for old, new in [("architecture_type: AUTONOMOUS_AGENT", "architecture_type: RULE_BASED"),
                         ("declared_inherent_risk: HIGH", "declared_inherent_risk: MEDIUM")]:
            self.edit_manifest(old, new)
        support_fixtures.record_fixture_evidence(self.tmp, now=T0)
        self.approve(now=T0)
        resgister.register(base_dir=self.tmp)
        self.assertEqual(resgister.boot_status(self.tmp, now=days(10))["status"], "APPROVED")
        s = resgister.boot_status(self.tmp, now=days(45))
        self.assertEqual(s["status"], "BLOCKED_CHALLENGE_FAILED")
        self.assertIn("Required evidence is not current", s["reasons"][0])


class TestPolicyIsPartOfTheLockedRubric(unittest.TestCase):
    def test_rubric_hash_covers_the_evidence_policy(self):
        import hashlib
        file_only = hashlib.sha256(Path(mas_rubric.__file__).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        self.assertNotEqual(mas_rubric.rubric_sha256(), file_only)


class TestCli(Section4Base):
    def run_cli(self, *args):
        old = os.getcwd()
        os.chdir(self.tmp)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = evidence.main(list(args))
            return code, buf.getvalue()
        finally:
            os.chdir(old)

    def test_status_strict_exit_codes(self):
        later = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=60)).isoformat()
        code, out = self.run_cli("status", "--strict")
        self.assertEqual(code, 0)                      # red-team evidence is fresh; the informational item has no record
        self.assertIn("NEEDS_EVIDENCE", out)           # ...and is still reported
        code, out = self.run_cli("status", "--strict", "--as-of", later)
        self.assertEqual(code, 1)                      # a blocking item has expired
        self.assertIn("NEEDS_REVIEW", out)
        code, _ = self.run_cli("status", "--as-of", later)
        self.assertEqual(code, 0)                      # without --strict it only reports

    def test_all_flag_also_requires_informational_items(self):
        code, _ = self.run_cli("status", "--all")
        self.assertEqual(code, 1)                      # unit-tests evidence has no record

    def test_record_command(self):
        code, out = self.run_cli("record", "redteam")
        self.assertEqual(code, 0)
        self.assertIn("recorded redteam", out)


if __name__ == "__main__":
    unittest.main()
