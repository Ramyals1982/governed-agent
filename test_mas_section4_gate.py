"""MAS AIRM Section 4 gate: objective intake, 2LoD challenge, shadow capability, signed sign-off.

No model and no network. Each test builds a scratch copy of manifest.yaml + tools.py with its
own audit.db and its own 2LoD keypair, so the real repo files are never modified.
Runs under pytest or `python -m unittest tests.test_mas_section4_gate`.
"""
import datetime as dt
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import mas_rubric  # noqa: E402
import resgister  # noqa: E402
from resgister import MASComplianceError  # noqa: E402


class Section4Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copy(ROOT / "manifest.yaml", self.tmp / "manifest.yaml")
        for name in ("tools.py", "dispatcher.py", "approval.py", "agent.py", "llm.py"):
            shutil.copy(ROOT / name, self.tmp / name)
        shutil.copytree(ROOT / "evidence", self.tmp / "evidence")
        self.private = self.tmp / "ccor_private.pem"
        resgister.generate_keys(self.private, self.tmp / resgister.PUBLIC_KEY_FILE)
        self.db = self.tmp / "audit.db"
        resgister._PASS_LOGGED.clear()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers
    def read(self, name):
        return (self.tmp / name).read_text(encoding="utf-8")

    def write(self, name, text):
        (self.tmp / name).write_text(text, encoding="utf-8")

    def edit_manifest(self, old, new):
        text = self.read("manifest.yaml")
        self.assertIn(old, text)
        self.write("manifest.yaml", text.replace(old, new, 1))

    def gate(self, autoregister=True, **kw):
        """Gate as the agent calls it. By default the current hash is registered first (the normal
        1LoD step), so these tests isolate the other controls; registration has its own tests."""
        if autoregister:
            try:
                resgister.register(base_dir=self.tmp)
            except MASComplianceError:
                pass
        return resgister.gate_check(base_dir=self.tmp, **kw)

    def approve(self, reviewer="VP_CCOR", **kw):
        return resgister.approve(reviewer, self.private, base_dir=self.tmp, **kw)

    def events(self, name):
        conn = sqlite3.connect(self.db)
        rows = conn.execute("SELECT detail FROM audit WHERE event=?", (name,)).fetchall()
        conn.close()
        return [json.loads(r[0]) for r in rows]


class TestCompliantPath(Section4Base):
    def test_register_scores_and_logs(self):
        a = resgister.register(base_dir=self.tmp)
        self.assertEqual(a["computed_tier"], "HIGH")
        self.assertEqual(a["scores"], {"impact": 3, "complexity": 5, "reliance": 4})
        self.assertEqual(a["tools"], ["create_ticket", "search_policies", "send_email"])
        reg = self.events("manifest_registered")[0]
        self.assertEqual(reg["computed_tier"], "HIGH")
        self.assertEqual(len(reg["sha256_prefix"]), 16)

    def test_high_blocked_until_2lod_approves_then_passes(self):
        with self.assertRaises(MASComplianceError) as ctx:
            self.gate()
        self.assertIn("requires an active 2LoD approval", str(ctx.exception))
        self.assertEqual(len(self.events("mas_gate_blocked")), 1)

        approval_id = self.approve()
        a = self.gate()
        self.assertEqual(a["approval"]["id"], approval_id)
        self.assertEqual(a["approval"]["reviewer"], "VP_CCOR")
        self.assertEqual(len(self.events("mas_gate_passed")), 1)
        self.assertEqual(self.events("2lod_approval_granted")[0]["reviewer"], "VP_CCOR")

    def test_approval_is_keyed_to_both_file_hashes(self):
        self.approve()
        conn = sqlite3.connect(self.db)
        row = conn.execute("SELECT manifest_sha256, tools_sha256, combined_sha256 FROM mas_approvals").fetchone()
        conn.close()
        m, t, c = resgister.file_hashes(self.tmp / "manifest.yaml", self.tmp / "tools.py")
        self.assertEqual(row, (m, t, c))

    def test_line_endings_do_not_change_the_hash(self):
        before = resgister.file_hashes(self.tmp / "manifest.yaml", self.tmp / "tools.py")
        crlf = self.read("manifest.yaml").replace("\r\n", "\n").replace("\n", "\r\n")
        (self.tmp / "manifest.yaml").write_bytes(crlf.encode("utf-8"))
        self.assertEqual(before, resgister.file_hashes(self.tmp / "manifest.yaml", self.tmp / "tools.py"))

    def test_four_eyes_owner_cannot_approve_own_system(self):
        with self.assertRaises(MASComplianceError) as ctx:
            self.approve(reviewer="Ramya L Swaminaathan")
        self.assertIn("cannot be the system owner", str(ctx.exception))

    def test_approvals_table_is_append_only(self):
        self.approve()
        conn = sqlite3.connect(self.db)
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE mas_approvals SET reviewer='me'")
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM mas_approvals")
        conn.close()


class TestShadowCapability(Section4Base):
    SHADOW = (
        "\n\ndef delete_record(record_id):\n    return {'deleted': record_id}\n\n"
        "TOOL_FUNCTIONS['delete_record'] = delete_record\n"
        "TOOL_SCHEMAS.append({'type': 'function', 'function': {'name': 'delete_record',"
        " 'description': 'x', 'parameters': {'type': 'object', 'properties': {}}}})\n"
    )

    def test_undeclared_tool_in_tools_py_is_shadow_capability(self):
        self.write("tools.py", self.read("tools.py") + self.SHADOW)
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.register(base_dir=self.tmp)
        self.assertIn("Shadow Capability Detected", str(ctx.exception))
        self.assertIn("delete_record", str(ctx.exception))
        ev = self.events("2LoD_SHADOW_CAPABILITY_DETECTED")[0]
        self.assertIn("delete_record", ev["actual_tools"])

    def test_under_declared_count_is_shadow_capability(self):
        # developer lists all four names but understates the count
        self.write("tools.py", self.read("tools.py") + self.SHADOW)
        self.edit_manifest("  - name: send_email", "  - name: delete_record\n    effect: x\n    risk: low\n  - name: send_email")
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.register(base_dir=self.tmp)
        self.assertIn("Shadow Capability Detected", str(ctx.exception))

    def test_shadow_capability_also_blocks_the_startup_gate_and_approval(self):
        self.write("tools.py", self.read("tools.py") + self.SHADOW)
        with self.assertRaises(MASComplianceError):
            self.gate()
        with self.assertRaises(MASComplianceError):
            self.approve()

    def test_tool_in_registry_but_not_in_schemas_is_rejected(self):
        self.write("tools.py", self.read("tools.py") +
                   "\ndef hidden():\n    return 1\n\nTOOL_FUNCTIONS['hidden'] = hidden\n")
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.register(base_dir=self.tmp)
        self.assertIn("registry inconsistent", str(ctx.exception))

    def test_phantom_declared_tool_is_rejected(self):
        self.edit_manifest("declared_tool_count: 3", "declared_tool_count: 4")
        self.edit_manifest("  - name: send_email", "  - name: ghost_tool\n    effect: x\n    risk: low\n  - name: send_email")
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.register(base_dir=self.tmp)
        self.assertIn("do not match tools.py", str(ctx.exception))

    def test_unclassified_tool_scores_as_worst_case(self):
        caps = mas_rubric.classify_tools(["mystery"], {}, "x = 1\n")
        self.assertEqual(caps["mystery"], "EXTERNAL_ACTION")

    def test_network_use_inside_a_tool_escalates_its_capability(self):
        src = "import requests\n\ndef search_policies(q):\n    return requests.get('http://x')\n"
        caps = mas_rubric.classify_tools(["search_policies"], {"search_policies": _fn("search_policies")}, src)
        self.assertEqual(caps["search_policies"], "EXTERNAL_ACTION")


def _fn(name):
    def f():
        pass
    f.__name__ = name
    return f


class TestEffectiveChallenge(Section4Base):
    def test_low_claim_on_autonomous_pii_agent_is_blocked_and_logged(self):
        self.edit_manifest("data_sensitivity: INTERNAL", "data_sensitivity: CONFIDENTIAL_PII")
        self.edit_manifest("declared_inherent_risk: HIGH", "declared_inherent_risk: LOW")
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.register(base_dir=self.tmp)
        self.assertIn("effective challenge failed", str(ctx.exception))
        ev = self.events("2LoD_EFFECTIVE_CHALLENGE_FAILED")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["declared_inherent_risk"], "LOW")
        self.assertEqual(ev[0]["computed_tier"], "HIGH")
        self.assertEqual(self.events("manifest_registered"), [])  # nothing registered

    def test_low_claim_cannot_be_approved_or_start(self):
        self.edit_manifest("declared_inherent_risk: HIGH", "declared_inherent_risk: LOW")
        for action in (self.gate, self.approve):
            with self.assertRaises(MASComplianceError):
                action()

    def test_declaring_full_human_review_when_code_is_not_is_blocked(self):
        # developer claims every action is reviewed to lower Reliance, but dispatcher.py only gates send_email
        self.edit_manifest("human_oversight_mode: EXCEPTION_ONLY", "human_oversight_mode: FULL_HUMAN_REVIEW")
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.register(base_dir=self.tmp)
        self.assertIn("human_oversight_mode declared FULL_HUMAN_REVIEW", str(ctx.exception))
        ev = self.events("2LoD_EFFECTIVE_CHALLENGE_FAILED")[0]
        self.assertEqual(ev["introspected_oversight"]["mode"], "EXCEPTION_ONLY")

    def test_tool_impact_is_floored_by_the_rubric_not_the_developer(self):
        # an honest, lower-risk profile registers, but send_email still sets impact = 3
        self.edit_manifest("architecture_type: AUTONOMOUS_AGENT", "architecture_type: RULE_BASED")
        self.edit_manifest("declared_inherent_risk: HIGH", "declared_inherent_risk: MEDIUM")
        a = resgister.register(base_dir=self.tmp)
        self.assertEqual(a["scores"]["impact"], 3)
        self.assertEqual(a["computed_tier"], "MEDIUM")

    def test_invalid_profile_values_are_rejected(self):
        self.edit_manifest("customer_facing: false", "customer_facing: maybe")
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.register(base_dir=self.tmp)
        self.assertIn("customer_facing", str(ctx.exception))

    def test_missing_profile_block_is_rejected(self):
        text = self.read("manifest.yaml")
        start = text.index("mas_use_case_profile:")
        end = text.index("model:")
        self.write("manifest.yaml", text[:start] + text[end:])
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.register(base_dir=self.tmp)
        self.assertIn("no mas_use_case_profile", str(ctx.exception))

    def test_rubric_is_deterministic(self):
        runs = {json.dumps(resgister.assess(self.tmp, self.db)["scores"], sort_keys=True) for _ in range(3)}
        self.assertEqual(len(runs), 1)


class TestTamperingInvalidatesSignoff(Section4Base):
    def test_manifest_change_invalidates_prior_approval(self):
        self.approve()
        self.gate()  # passes
        self.edit_manifest("raises tickets", "raises and closes tickets")
        with self.assertRaises(MASComplianceError) as ctx:
            self.gate()
        self.assertIn("no 2LoD approval for the current", str(ctx.exception))

    def test_tools_py_change_invalidates_prior_approval(self):
        self.approve()
        self.write("tools.py", self.read("tools.py") + "\n# harmless-looking comment\n")
        with self.assertRaises(MASComplianceError):
            self.gate()

    def test_reverting_the_change_restores_the_approval(self):
        self.approve()
        original = self.read("manifest.yaml")
        self.write("manifest.yaml", original.replace("raises tickets", "raises and closes tickets"))
        with self.assertRaises(MASComplianceError):
            self.gate()
        self.write("manifest.yaml", original)
        self.gate()

    def test_developer_forged_approval_row_is_rejected(self):
        a = resgister.assess(self.tmp, self.db)
        resgister._connect(self.db).close()  # ensure the schema exists, as it would after any real run
        conn = sqlite3.connect(self.db)
        conn.execute(
            "INSERT INTO mas_approvals (ts, system_id, reviewer, manifest_sha256, tools_sha256, combined_sha256,"
            " rubric_version, rubric_sha256, computed_tier, scores, expires_at, signature)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("now", a["system_id"], "VP_CCOR", a["manifest_sha256"], a["tools_sha256"], a["combined_sha256"],
             a["rubric_version"], a["rubric_sha256"], "HIGH", "{}",
             (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).isoformat(), "00" * 64))
        conn.commit()
        conn.close()
        with self.assertRaises(MASComplianceError) as ctx:
            self.gate()
        self.assertIn("invalid signature", str(ctx.exception))

    def test_approving_with_a_key_that_is_not_the_2lod_key_is_refused(self):
        other = self.tmp / "other_private.pem"
        resgister.generate_keys(other, self.tmp / "other_public.pem")
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.approve("VP_CCOR", other, base_dir=self.tmp)
        self.assertIn("does not match", str(ctx.exception))

    def test_approval_row_signed_by_a_different_key_is_rejected_by_the_gate(self):
        from cryptography.hazmat.primitives import serialization
        other = self.tmp / "other_private.pem"
        resgister.generate_keys(other, self.tmp / "other_public.pem")
        key = serialization.load_pem_private_key(other.read_bytes(), password=None)
        a = resgister.assess(self.tmp, self.db)
        exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).isoformat()
        sig = key.sign(resgister._payload(a["system_id"], a["combined_sha256"], a["rubric_sha256"],
                                          "HIGH", "VP_CCOR", exp)).hex()
        resgister._connect(self.db).close()
        conn = sqlite3.connect(self.db)
        conn.execute(
            "INSERT INTO mas_approvals (ts, system_id, reviewer, manifest_sha256, tools_sha256, combined_sha256,"
            " rubric_version, rubric_sha256, computed_tier, scores, expires_at, signature)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("now", a["system_id"], "VP_CCOR", a["manifest_sha256"], a["tools_sha256"], a["combined_sha256"],
             a["rubric_version"], a["rubric_sha256"], "HIGH", "{}", exp, sig))
        conn.commit()
        conn.close()
        with self.assertRaises(MASComplianceError) as ctx:
            self.gate()
        self.assertIn("invalid signature", str(ctx.exception))

    def test_generate_keys_refuses_to_replace_an_existing_public_key(self):
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.generate_keys(self.tmp / "second_private.pem", self.tmp / resgister.PUBLIC_KEY_FILE)
        self.assertIn("refusing to overwrite", str(ctx.exception))
        self.assertFalse((self.tmp / "second_private.pem").exists())

    def test_expired_approval_is_rejected(self):
        self.approve(days=-1)
        with self.assertRaises(MASComplianceError) as ctx:
            self.gate()
        self.assertIn("expired", str(ctx.exception))

    def test_rubric_change_invalidates_prior_approval(self):
        self.approve()
        original = mas_rubric.rubric_sha256
        mas_rubric.rubric_sha256 = lambda: "0" * 64  # simulate an edit to mas_rubric.py
        try:
            with self.assertRaises(MASComplianceError) as ctx:
                self.gate()
            self.assertIn("rubric changed", str(ctx.exception))
        finally:
            mas_rubric.rubric_sha256 = original

    def test_missing_public_key_fails_closed(self):
        self.approve()
        (self.tmp / resgister.PUBLIC_KEY_FILE).unlink()
        with self.assertRaises(MASComplianceError) as ctx:
            self.gate()
        self.assertIn("public key", str(ctx.exception))


class TestOversightIntrospection(Section4Base):
    def test_reads_oversight_from_approval_py_and_dispatcher(self):
        r = resgister.introspection_report(self.tmp)
        over = r["introspected"]["oversight"]
        self.assertEqual(over["mode"], "EXCEPTION_ONLY")
        self.assertTrue(over["approval_mechanism"])
        self.assertEqual(over["approval_tools"], ["send_email"])
        self.assertEqual(r["introspected"]["tool_count"], 3)

    def test_removing_the_approval_path_from_dispatcher_is_detected(self):
        src = self.read("dispatcher.py").replace('return "approve", ', 'return "allow", ')
        self.write("dispatcher.py", src)
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.register(base_dir=self.tmp)
        self.assertIn("enforce AUTONOMOUS", str(ctx.exception))

    def test_removing_the_human_prompt_from_approval_py_is_detected(self):
        self.write("approval.py", "def ask(tool, args):\n    return True, 'auto'\n")
        over = resgister.introspection_report(self.tmp)["introspected"]["oversight"]
        self.assertFalse(over["approval_mechanism"])
        self.assertEqual(over["mode"], "AUTONOMOUS")


class TestHashChain(Section4Base):
    def test_approval_is_written_as_a_signed_chain_event(self):
        self.approve()
        ev = resgister.chain_events(self.db)
        self.assertEqual([e["action"] for e in ev], [resgister.ACT_APPROVE])
        self.assertEqual(ev[0]["prev_hash"], resgister.GENESIS)
        self.assertIsNotNone(ev[0]["signature"])
        self.assertTrue(resgister.verify_chain(self.db)["ok"])

    def test_each_event_links_to_the_previous_hash(self):
        self.approve()
        resgister.flag_challenge_failure("VP_CCOR", "x", base_dir=self.tmp)
        resgister.activate_kill_switch("VP_CCOR", "y", base_dir=self.tmp)
        ev = resgister.chain_events(self.db)
        self.assertEqual(ev[1]["prev_hash"], ev[0]["event_hash"])
        self.assertEqual(ev[2]["prev_hash"], ev[1]["event_hash"])
        self.assertEqual(resgister.verify_chain(self.db)["count"], 3)

    def test_chain_events_are_append_only(self):
        resgister.activate_kill_switch("VP_CCOR", "x", base_dir=self.tmp)
        conn = sqlite3.connect(self.db)
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE mas_2lod_events SET actor='someone'")
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM mas_2lod_events")
        conn.close()

    def test_tampering_with_a_past_event_breaks_verification(self):
        resgister.flag_challenge_failure("VP_CCOR", "first", base_dir=self.tmp)
        resgister.activate_kill_switch("VP_CCOR", "second", base_dir=self.tmp)
        conn = sqlite3.connect(self.db)
        conn.execute("DROP TRIGGER mas_2lod_events_no_update")  # someone with file access bypasses the trigger
        conn.execute("UPDATE mas_2lod_events SET detail='{}' WHERE id=1")
        conn.commit()
        conn.close()
        v = resgister.verify_chain(self.db)
        self.assertFalse(v["ok"])
        self.assertEqual(v["broken_at"], 1)

    def test_console_actions_are_mirrored_into_the_audit_table(self):
        resgister.flag_challenge_failure("VP_CCOR", "x", base_dir=self.tmp)
        self.assertEqual(self.events("2lod_console_action")[0]["action"], resgister.ACT_REJECT)
        self.assertEqual(self.events("2LoD_EFFECTIVE_CHALLENGE_FAILED")[0]["source"], "2lod_console")


class TestKillSwitch(Section4Base):
    def test_kill_switch_blocks_boot_even_with_a_valid_approval(self):
        self.approve()
        self.gate()
        resgister.activate_kill_switch("VP_CCOR", "suspected prompt injection", base_dir=self.tmp)
        with self.assertRaises(MASComplianceError) as ctx:
            self.gate()
        self.assertIn("KILL-SWITCH ACTIVE", str(ctx.exception))
        self.assertEqual(resgister.boot_status(self.tmp)["status"], "KILL_SWITCH_ACTIVE")

    def test_release_needs_the_2lod_key_and_restores_boot(self):
        self.approve()
        resgister.activate_kill_switch("VP_CCOR", "drill", base_dir=self.tmp)
        resgister.release_kill_switch("VP_CCOR", "drill over", key_file=self.private, base_dir=self.tmp)
        self.gate()

    def test_forged_unsigned_release_is_ignored(self):
        self.approve()
        resgister.activate_kill_switch("VP_CCOR", "x", base_dir=self.tmp)
        system_id, _ = resgister._current_ids(self.tmp)
        resgister.append_chain_event(self.db, "developer", resgister.ACT_RELEASE, system_id, {"reason": "oops"})
        state = resgister.kill_switch_state(self.db, self.tmp / resgister.PUBLIC_KEY_FILE)
        self.assertTrue(state["active"])
        self.assertEqual(len(state["ignored_releases"]), 1)
        with self.assertRaises(MASComplianceError):
            self.gate()

    def test_release_with_wrong_key_is_refused(self):
        other = self.tmp / "other_private.pem"
        resgister.generate_keys(other, self.tmp / "other_public.pem")
        resgister.activate_kill_switch("VP_CCOR", "x", base_dir=self.tmp)
        with self.assertRaises(MASComplianceError):
            resgister.release_kill_switch("VP_CCOR", "x", key_file=other, base_dir=self.tmp)

    def test_reason_and_reviewer_are_required(self):
        with self.assertRaises(MASComplianceError):
            resgister.activate_kill_switch("VP_CCOR", "  ", base_dir=self.tmp)
        with self.assertRaises(MASComplianceError):
            resgister.activate_kill_switch("", "x", base_dir=self.tmp)


class TestManualRejection(Section4Base):
    def test_flagging_blocks_the_gate_for_that_hash(self):
        self.approve()
        resgister.flag_challenge_failure("VP_CCOR", "reliance understated", base_dir=self.tmp)
        with self.assertRaises(MASComplianceError) as ctx:
            self.gate()
        self.assertIn("flagged an effective-challenge failure", str(ctx.exception))
        self.assertEqual(resgister.boot_status(self.tmp)["status"], "BLOCKED_CHALLENGE_FAILED")

    def test_a_later_signed_approval_supersedes_the_rejection(self):
        resgister.flag_challenge_failure("VP_CCOR", "needs rework", base_dir=self.tmp)
        self.approve()
        self.gate()

    def test_forged_unsigned_approve_event_cannot_undo_a_rejection(self):
        resgister.flag_challenge_failure("VP_CCOR", "no", base_dir=self.tmp)
        system_id, combined = resgister._current_ids(self.tmp)
        resgister.append_chain_event(self.db, "developer", resgister.ACT_APPROVE, system_id, {"combined_sha256": combined})
        with self.assertRaises(MASComplianceError):
            self.gate()

    def test_rejection_of_an_older_hash_does_not_block_a_new_one(self):
        resgister.flag_challenge_failure("VP_CCOR", "old version", base_dir=self.tmp)
        self.edit_manifest("raises tickets", "raises and closes tickets")
        resgister.register(base_dir=self.tmp)
        self.assertEqual(resgister.boot_status(self.tmp)["status"], "PENDING_2LOD_APPROVAL")


class TestConsoleViews(Section4Base):
    def test_boot_status_lifecycle(self):
        self.assertEqual(resgister.boot_status(self.tmp)["status"], "NOT_REGISTERED")
        resgister.register(base_dir=self.tmp)
        self.assertEqual(resgister.boot_status(self.tmp)["status"], "PENDING_2LOD_APPROVAL")
        self.approve()
        s = resgister.boot_status(self.tmp)
        self.assertEqual(s["status"], "APPROVED")
        self.assertEqual(s["approval"]["reviewer"], "VP_CCOR")
        self.edit_manifest("declared_inherent_risk: HIGH", "declared_inherent_risk: LOW")
        self.assertEqual(resgister.boot_status(self.tmp)["status"], "BLOCKED_CHALLENGE_FAILED")

    def test_boot_status_is_read_only(self):
        self.edit_manifest("declared_inherent_risk: HIGH", "declared_inherent_risk: LOW")
        resgister.boot_status(self.tmp)
        resgister.boot_status(self.tmp)
        self.assertFalse(self.db.exists() and self.events("2LoD_EFFECTIVE_CHALLENGE_FAILED"))

    def test_boot_status_and_gate_agree(self):
        for setup in (lambda: None, self.approve):
            setup()
            status = resgister.boot_status(self.tmp)["status"]
            try:
                self.gate()
                gate_ok = True
            except MASComplianceError:
                gate_ok = False
            self.assertEqual(status == "APPROVED", gate_ok)

    def test_hash_status_verified_then_tampered(self):
        self.assertEqual(resgister.hash_status(self.tmp)["status"], "UNATTESTED")
        self.approve()
        self.assertEqual(resgister.hash_status(self.tmp)["status"], "VERIFIED")
        self.write("tools.py", self.read("tools.py") + "\n# edit\n")
        hs = resgister.hash_status(self.tmp)
        self.assertEqual(hs["status"], "TAMPERED")
        self.assertEqual(hs["changed"], ["tools.py"])

    def test_forged_approval_row_does_not_make_the_hash_verified(self):
        a = resgister.assess(self.tmp, self.db)
        resgister._connect(self.db).close()
        conn = sqlite3.connect(self.db)
        conn.execute(
            "INSERT INTO mas_approvals (ts, system_id, reviewer, manifest_sha256, tools_sha256, combined_sha256,"
            " rubric_version, rubric_sha256, computed_tier, scores, expires_at, signature)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("now", a["system_id"], "x", a["manifest_sha256"], a["tools_sha256"], a["combined_sha256"],
             a["rubric_version"], a["rubric_sha256"], "HIGH", "{}", "2099-01-01T00:00:00+00:00", "00" * 64))
        conn.commit()
        conn.close()
        self.assertEqual(resgister.hash_status(self.tmp)["status"], "UNATTESTED")

    def test_readiness_checks(self):
        shutil.rmtree(self.tmp / "evidence")
        (self.tmp / "agent.py").write_text("x = 1\n")
        (self.tmp / "dispatcher.py").write_text("x = 1\n")
        by_id = {c["id"]: c for c in resgister.control_readiness(self.tmp)}
        self.assertTrue(by_id["a"]["passed"])
        self.assertFalse(by_id["b"]["passed"])           # no guardrails.py / output_guard.py in the scratch copy
        self.assertFalse(by_id["c"]["passed"])           # no evidence/ folder in the scratch copy
        self.assertFalse(by_id["d"]["passed"])           # nothing attested yet
        (self.tmp / "guardrails.py").write_text("x")
        (self.tmp / "output_guard.py").write_text("x")
        self.assertIn("NOT WIRED", {c["id"]: c for c in resgister.control_readiness(self.tmp)}["b"]["detail"])
        shutil.copy(ROOT / "agent.py", self.tmp / "agent.py")          # the real, wired files
        shutil.copy(ROOT / "dispatcher.py", self.tmp / "dispatcher.py")
        (self.tmp / "evidence").mkdir()
        (self.tmp / "evidence" / "redteam_results.md").write_text("results")
        self.approve()
        by_id = {c["id"]: c for c in resgister.control_readiness(self.tmp)}
        self.assertTrue(all(c["passed"] for c in by_id.values()), by_id)
        self.edit_manifest("kill_switch_owner: Ramya L Swaminaathan", "kill_switch_owner: ''")
        self.assertFalse({c["id"]: c for c in resgister.control_readiness(self.tmp)}["a"]["passed"])

    def test_guard_files_present_but_only_mentioned_in_a_comment_are_not_wired(self):
        (self.tmp / "guardrails.py").write_text("x")
        (self.tmp / "output_guard.py").write_text("x")
        self.write("agent.py", "# output_guard.scan(answer) is planned\nimport output_guard\n")
        self.write("dispatcher.py", '# output_guard.is_sensitive is planned\ns = "output_guard.is_sensitive"\n')
        b = {c["id"]: c for c in resgister.control_readiness(self.tmp)}["b"]
        self.assertFalse(b["passed"])
        self.assertEqual(b["detail"].count("NOT WIRED"), 2)

    def test_empty_redteam_file_does_not_count_as_evidence(self):
        shutil.rmtree(self.tmp / "evidence")
        (self.tmp / "evidence").mkdir()
        (self.tmp / "evidence" / "redteam_results.md").write_text("")
        self.assertFalse({c["id"]: c for c in resgister.control_readiness(self.tmp)}["c"]["passed"])

    def test_registry_record_has_dependencies_and_third_party_flag(self):
        (self.tmp / "requirements.txt").write_text("openai\npyyaml\n")
        r = resgister.registry_record(self.tmp)
        self.assertTrue(r["model"]["third_party"])
        self.assertEqual(r["python_dependencies"], ["openai", "pyyaml"])
        self.assertEqual(r["kill_switch_owner"], "Ramya L Swaminaathan")

    def test_report_scores_use_enforced_oversight_not_the_declared_one(self):
        honest = resgister.introspection_report(self.tmp)["introspected"]
        self.edit_manifest("human_oversight_mode: EXCEPTION_ONLY", "human_oversight_mode: FULL_HUMAN_REVIEW")
        lied = resgister.introspection_report(self.tmp)
        self.assertEqual(lied["introspected"]["scores"], honest["scores"])
        self.assertEqual(lied["introspected"]["computed_tier"], "HIGH")
        self.assertEqual(lied["declared"]["human_oversight_mode"], "FULL_HUMAN_REVIEW")
        self.assertEqual(lied["introspected"]["oversight"]["mode"], "EXCEPTION_ONLY")

    def test_introspection_report_survives_a_shadow_tool(self):
        self.write("tools.py", self.read("tools.py") + TestShadowCapability.SHADOW)
        r = resgister.introspection_report(self.tmp)
        self.assertEqual(r["introspected"]["tool_count"], 4)
        self.assertEqual(r["declared"]["declared_tool_count"], 3)


class TestAgentWiring(unittest.TestCase):
    def test_run_agent_calls_the_gate_first(self):
        src = (ROOT / "agent.py").read_text(encoding="utf-8")
        body = src.split("def run_agent", 1)[1]
        first_statement = [ln.strip() for ln in body.splitlines()[1:] if ln.strip()][0]
        self.assertEqual(first_statement, "startup_gate()")


if __name__ == "__main__":
    unittest.main()
