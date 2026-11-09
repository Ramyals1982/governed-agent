"""MAS AIRM Section 4, remaining requirements: inventory entry, MEDIUM sign-off, residual risk vs Board appetite,
model binding. Scratch copies only; no model, no network."""
import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import mas_rubric  # noqa: E402
import resgister  # noqa: E402
from resgister import MASComplianceError  # noqa: E402
from test_mas_section4_gate import Section4Base  # noqa: E402


class TestInventoryAndResidualRisk(Section4Base):
    def test_approved_but_unregistered_agent_does_not_boot(self):
        self.approve()
        with self.assertRaises(MASComplianceError) as cm:
            self.gate(autoregister=False)
        self.assertIn("not in the AI inventory", str(cm.exception))
        self.assertTrue(self.events("mas_gate_blocked"))
        resgister.register(base_dir=self.tmp)
        self.assertEqual(self.gate(autoregister=False)["computed_tier"], "HIGH")

    def test_editing_a_registered_system_requires_registering_again(self):
        resgister.register(base_dir=self.tmp)
        self.approve()
        self.gate(autoregister=False)
        self.edit_manifest("version: 0.1.0", "version: 0.1.1")
        with self.assertRaises(MASComplianceError):
            self.gate(autoregister=False)

    def test_inventory_event_carries_tier_residual_and_full_hashes(self):
        resgister.register(base_dir=self.tmp)
        ev = self.events("manifest_registered")[0]
        self.assertEqual((ev["computed_tier"], ev["residual_tier"]), ("HIGH", "MEDIUM"))
        self.assertEqual(len(ev["manifest_sha256"]), 64)

    def test_residual_is_one_tier_below_inherent_when_all_mitigations_verified(self):
        a = resgister.assess(self.tmp, self.db, log=False)
        self.assertEqual((a["computed_tier"], a["residual_tier"], a["missing_mitigations"]), ("HIGH", "MEDIUM", []))

    def test_medium_materiality_also_needs_2lod_signoff(self):
        self.edit_manifest("architecture_type: AUTONOMOUS_AGENT", "architecture_type: RULE_BASED")
        self.edit_manifest("declared_inherent_risk: HIGH", "declared_inherent_risk: MEDIUM")
        with self.assertRaises(MASComplianceError) as cm:
            self.gate()
        self.assertIn("MEDIUM materiality requires an active 2LoD approval", str(cm.exception))
        self.approve()
        self.assertEqual(self.gate()["computed_tier"], "MEDIUM")

    def test_removing_the_output_guard_after_approval_breaches_risk_appetite(self):
        self.approve()
        self.gate()
        self.write("agent.py", self.read("agent.py").replace("output_guard.scan(", "str("))
        with self.assertRaises(MASComplianceError) as cm:
            self.gate()
        self.assertIn("exceeds Board risk appetite", str(cm.exception))
        self.assertIn("output_guard_on_answers", str(cm.exception))
        self.assertTrue(self.events("2LoD_RESIDUAL_RISK_EXCEEDS_APPETITE"))

    def test_no_red_team_evidence_breaches_risk_appetite(self):
        shutil.rmtree(self.tmp / "evidence")
        with self.assertRaises(MASComplianceError) as cm:
            resgister.assess(self.tmp, self.db)
        self.assertIn("red_team_evidence", str(cm.exception))

    def test_appetite_is_part_of_the_pinned_rubric(self):
        self.approve()
        a = resgister.assess(self.tmp, self.db, log=False)
        appr, _ = resgister.find_active_approval(a, self.db, self.tmp / resgister.PUBLIC_KEY_FILE)
        self.assertEqual(appr["rubric_sha256"], mas_rubric.rubric_sha256())
        self.assertTrue(mas_rubric.within_appetite("MEDIUM"))
        self.assertFalse(mas_rubric.within_appetite("HIGH"))

    def test_shadow_model_in_llm_py_is_blocked_and_logged(self):
        self.write("llm.py", self.read("llm.py").replace('"deepseek/deepseek-chat"', '"openai/gpt-4o"'))
        with self.assertRaises(MASComplianceError) as cm:
            resgister.assess(self.tmp, self.db)
        self.assertIn("Shadow Model Detected", str(cm.exception))
        self.assertTrue(self.events("2LoD_SHADOW_MODEL_DETECTED"))

    def test_missing_llm_py_fails_closed(self):
        (self.tmp / "llm.py").unlink()
        with self.assertRaises(MASComplianceError):
            resgister.assess(self.tmp, self.db, log=False)

    def test_tool_logic_moved_into_a_local_module_is_blocked(self):
        (self.tmp / "helper.py").write_text("def f():\n    return 1\n")
        self.write("tools.py", "from helper import f\n" + self.read("tools.py"))
        with self.assertRaises(MASComplianceError) as cm:
            resgister.assess(self.tmp, self.db)
        self.assertIn("Unhashed tool code", str(cm.exception))
        self.assertTrue(self.events("2LoD_UNHASHED_TOOL_CODE"))

    def test_dashboard_reports_not_registered(self):
        self.assertEqual(resgister.boot_status(self.tmp)["status"], "NOT_REGISTERED")


if __name__ == "__main__":
    unittest.main()
