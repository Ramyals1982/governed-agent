"""Audit-log hash chain, daily Merkle seals, inclusion proofs and evidence packs.

No model, no network. Every test works on its own scratch database and keys.
Run: python -m unittest test_audit_chain
"""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import audit_chain as ac  # noqa: E402
import resgister  # noqa: E402
from resgister import MASComplianceError  # noqa: E402

D1, D2, D3 = "2020-01-01", "2020-01-02", "2020-01-03"   # safely in the past


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db = self.tmp / "audit.db"
        self.conn = sqlite3.connect(self.db)
        ac.ensure_schema(self.conn)
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def add(self, day, n, tag="e"):
        return [ac.append_event(self.conn, "trace", f"{tag}{i}", {"i": i}, ts=f"{day} 10:00:{i:02d}") for i in range(n)]

    def verify(self):
        c = ac.open_readonly(self.db)
        try:
            return ac.verify_chain(c)
        finally:
            c.close()

    def raw(self):
        return sqlite3.connect(self.db)

    def drop_triggers(self, c):
        for t in ("audit_no_update", "audit_no_delete", "audit_merkle_days_no_update", "audit_merkle_days_no_delete"):
            c.execute(f"DROP TRIGGER IF EXISTS {t}")

    def rebuild_chain(self, row_id, new_detail):
        """The strongest attack: edit one row, then recompute every hash after it so the chain looks fine."""
        c = self.raw()
        self.drop_triggers(c)
        prev = ac.GENESIS
        for rid, ts, tr, ev, det in c.execute("SELECT id, ts, trace_id, event, detail FROM audit ORDER BY id").fetchall():
            det = new_detail if rid == row_id else det
            h = ac.compute_event_hash(prev, ts, tr, ev, det)
            c.execute("UPDATE audit SET detail=?, prev_hash=?, event_hash=? WHERE id=?", (det, prev, h, rid))
            prev = h
        c.commit()
        c.close()


class TestLinearChain(Base):
    def test_rows_link_and_verify(self):
        r = self.add(D1, 4)
        self.assertEqual(r[0]["prev_hash"], ac.GENESIS)
        for a, b in zip(r, r[1:]):
            self.assertEqual(b["prev_hash"], a["event_hash"])
        v = self.verify()
        self.assertEqual((v["status"], v["chained_rows"], v["head"]), ("INTACT", 4, r[-1]["event_hash"]))

    def test_empty_log_is_ok(self):
        self.assertEqual(self.verify()["status"], "EMPTY")

    def test_update_and_delete_are_blocked_by_triggers(self):
        self.add(D1, 2)
        for sql in ("UPDATE audit SET event='x'", "DELETE FROM audit"):
            with self.assertRaises(sqlite3.DatabaseError):
                self.conn.execute(sql)

    def test_edit_is_detected_even_if_triggers_are_bypassed(self):
        self.add(D1, 4)
        c = self.raw()
        self.drop_triggers(c)
        c.execute("UPDATE audit SET detail='{\"i\": 999}' WHERE id=2")
        c.commit()
        v = self.verify()
        self.assertEqual((v["status"], v["broken_at"]), ("BROKEN", 2))
        self.assertIn("edited", v["reason"])

    def test_deleted_row_is_detected(self):
        self.add(D1, 5)
        c = self.raw()
        self.drop_triggers(c)
        c.execute("DELETE FROM audit WHERE id=3")
        c.commit()
        v = self.verify()
        self.assertEqual((v["status"], v["broken_at"]), ("BROKEN", 4))
        self.assertIn("deleted", v["reason"])

    def test_row_inserted_without_a_hash_is_detected(self):
        self.add(D1, 3)
        c = self.raw()
        c.execute("INSERT INTO audit (ts, trace_id, event, detail) VALUES ('2020-01-01 11:00:00','x','forged','{}')")
        c.commit()
        v = self.verify()
        self.assertEqual(v["status"], "BROKEN")
        self.assertIn("without a hash", v["reason"])

    def test_two_writers_interleaving_keep_one_chain(self):
        other = sqlite3.connect(self.db)
        for i in range(6):
            ac.append_event(self.conn if i % 2 else other, "t", f"e{i}", {"i": i}, ts=f"{D1} 10:00:0{i}")
        other.close()
        self.assertEqual(self.verify()["status"], "INTACT")


class TestLegacyMigration(Base):
    def make_old_db(self, rows=5):
        path = self.tmp / "old.db"
        c = sqlite3.connect(path)
        c.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, trace_id TEXT, event TEXT, detail TEXT)")
        for i in range(rows):
            c.execute("INSERT INTO audit (ts, trace_id, event, detail) VALUES (?,?,?,?)",
                      (f"{D1} 09:00:0{i}", "old", f"legacy{i}", json.dumps({"i": i})))
        c.commit()
        return path, c

    def test_unmigrated_database_is_reported_not_silently_trusted(self):
        path, c = self.make_old_db()
        c.close()
        ro = ac.open_readonly(path)
        v = ac.verify_chain(ro)
        ro.close()
        self.assertEqual((v["status"], v["ok"]), ("NOT_CHAINED", False))

    def test_migration_keeps_old_rows_and_seals_them(self):
        path, c = self.make_old_db()
        before = c.execute("SELECT id, ts, trace_id, event, detail FROM audit ORDER BY id").fetchall()
        ac.ensure_schema(c)
        ac.ensure_schema(c)  # idempotent: no second genesis row
        after = c.execute("SELECT id, ts, trace_id, event, detail FROM audit WHERE id<=5 ORDER BY id").fetchall()
        self.assertEqual(before, after)
        self.assertEqual(c.execute("SELECT count(*) FROM audit WHERE event=?", (ac.GENESIS_EVENT,)).fetchone()[0], 1)
        ac.append_event(c, "t", "new", {}, ts=f"{D2} 10:00:00")
        c.close()
        ro = ac.open_readonly(path)
        v = ac.verify_chain(ro)
        ro.close()
        self.assertEqual((v["status"], v["legacy_rows"], v["chained_rows"]), ("INTACT", 5, 2))

    def test_old_rows_edited_after_migration_are_detected(self):
        path, c = self.make_old_db()
        ac.ensure_schema(c)
        for t in ("audit_no_update",):
            c.execute(f"DROP TRIGGER {t}")
        c.execute("UPDATE audit SET detail='{\"i\": 42}' WHERE id=2")
        c.commit()
        v = ac.verify_chain(c)
        c.close()
        self.assertEqual(v["status"], "BROKEN")
        self.assertIn("before hash chaining", v["reason"])


class TestMerkle(unittest.TestCase):
    VECTORS = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
    ROOTS = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
             "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
             "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
             "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
             "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
             "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
             "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
             "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]

    def leaves(self, n):
        return [ac.leaf_hash_bytes(hashlib.sha256(str(i).encode()).digest()) for i in range(n)]

    def test_matches_the_rfc6962_reference_roots(self):
        lv = [ac.leaf_hash_bytes(bytes.fromhex(v)) for v in self.VECTORS]
        for n, want in enumerate(self.ROOTS, start=1):
            self.assertEqual(ac.merkle_root(lv[:n]).hex(), want, f"size {n}")

    def test_every_proof_verifies_and_is_log_sized(self):
        for n in range(1, 41):
            lv = self.leaves(n)
            root = ac.merkle_root(lv)
            for i in range(n):
                path = ac.merkle_path(i, lv)
                self.assertLessEqual(len(path), (n - 1).bit_length())
                self.assertTrue(ac.verify_inclusion(lv[i], i, n, path, root), (n, i))

    def test_altered_leaf_index_or_path_is_rejected(self):
        lv = self.leaves(13)
        root = ac.merkle_root(lv)
        path = ac.merkle_path(5, lv)
        self.assertFalse(ac.verify_inclusion(ac.leaf_hash_bytes(b"other"), 5, 13, path, root))
        self.assertFalse(ac.verify_inclusion(lv[5], 6, 13, path, root))
        self.assertFalse(ac.verify_inclusion(lv[5], 5, 13, [path[0][::-1]] + path[1:], root))
        self.assertFalse(ac.verify_inclusion(lv[5], 5, 13, path[:-1], root))

    def test_changing_any_single_leaf_changes_the_root(self):
        lv = self.leaves(17)
        root = ac.merkle_root(lv)
        for i in range(17):
            changed = list(lv)
            changed[i] = ac.leaf_hash_bytes(b"x")
            self.assertNotEqual(ac.merkle_root(changed), root)

    def test_leaf_and_node_hashing_are_domain_separated(self):
        a, b = self.leaves(2)
        self.assertNotEqual(ac.leaf_hash_bytes(a + b), ac.merkle_root([a, b]))


class TestSeals(Base):
    def seal(self, day, **kw):
        return ac.seal_day(self.conn, day, self.key, "VP_CCOR", **kw)

    def test_seal_verifies_and_stores_the_root(self):
        self.add(D1, 5)
        rec = self.seal(D1)
        rows = ac.day_rows(self.conn, D1)
        self.assertEqual(rec["root"], ac.merkle_root([ac.leaf_hash(r["event_hash"]) for r in rows]).hex())
        s = ac.verify_seals(self.conn, self.pub)[0]
        self.assertEqual((s["status"], s["leaf_count"], s["prev_root"]), ("VERIFIED", 5, ac.GENESIS))

    def test_open_day_needs_explicit_permission_and_later_rows_show_as_late(self):
        self.add(D1, 2)
        with self.assertRaises(ac.AuditChainError):
            self.seal(D1, today=D1)
        self.seal(D1, today=D1, allow_open=True)
        self.add(D1, 1, tag="late")
        s = ac.verify_seals(self.conn, self.pub)[0]
        self.assertEqual((s["status"], s["late_rows"]), ("VERIFIED", 1))

    def test_refuses_to_seal_a_broken_chain(self):
        self.add(D1, 3)
        c = self.raw()
        self.drop_triggers(c)
        c.execute("UPDATE audit SET detail='x' WHERE id=2")
        c.commit()
        with self.assertRaises(ac.AuditChainError) as ctx:
            self.seal(D1)
        self.assertIn("BROKEN", str(ctx.exception))

    def test_a_day_is_sealed_once_and_in_order_with_linked_roots(self):
        self.add(D1, 2)
        self.add(D2, 3)
        with self.assertRaises(ac.AuditChainError) as ctx:
            self.seal(D2)
        self.assertIn(D1, str(ctx.exception))
        r1 = self.seal(D1)
        r2 = self.seal(D2)
        self.assertEqual(r2["prev_root"], r1["root"])
        with self.assertRaises(ac.AuditChainError):
            self.seal(D1)

    def test_seals_are_append_only(self):
        self.add(D1, 2)
        self.seal(D1)
        with self.assertRaises(sqlite3.DatabaseError):
            self.conn.execute("UPDATE audit_merkle_days SET root='x'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.conn.execute("DELETE FROM audit_merkle_days")

    def test_full_chain_rebuild_is_caught_by_the_signed_root(self):
        """Edit a sealed row AND recompute every later hash: the linear chain looks fine, the seal does not."""
        self.add(D1, 6)
        self.seal(D1)
        self.rebuild_chain(3, '{"i": "rewritten"}')
        self.assertEqual(self.verify()["status"], "INTACT")          # the linear chain alone is fooled
        ro = ac.open_readonly(self.db)
        seals = ac.verify_seals(ro, self.pub)
        ro.close()
        self.assertEqual(seals[0]["status"], "FAILED")
        self.assertTrue(any("Merkle root differs" in p for p in seals[0]["problems"]))

    def test_signature_from_another_key_fails(self):
        self.add(D1, 2)
        self.seal(D1)
        other = Ed25519PrivateKey.generate().public_key()
        s = ac.verify_seals(self.conn, other)[0]
        self.assertEqual(s["status"], "FAILED")
        self.assertIn("signature", " ".join(s["problems"]))

    def test_altered_seal_record_fails(self):
        self.add(D1, 3)
        self.seal(D1)
        c = self.raw()
        self.drop_triggers(c)
        c.execute("UPDATE audit_merkle_days SET root=?", ("0" * 64,))
        c.commit()
        self.assertEqual(ac.verify_seals(self.conn, self.pub)[0]["status"], "FAILED")


class TestProofsAndPacks(Base):
    def setUp(self):
        super().setUp()
        self.events = self.add(D1, 7)
        self.rec = ac.seal_day(self.conn, D1, self.key, "VP_CCOR")
        self.pubfile = self.tmp / "mas_2lod_public.pem"
        from cryptography.hazmat.primitives import serialization
        self.pubfile.write_bytes(self.pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def test_every_event_has_a_valid_proof(self):
        for e in self.events:
            res = ac.check_proof(ac.inclusion_proof(self.conn, e["id"]), self.pub)
            self.assertTrue(res["ok"], res)

    def test_tampered_proofs_fail(self):
        base = ac.inclusion_proof(self.conn, self.events[3]["id"])
        for mutate in (lambda p: p["event"].update(detail='{"i": 0}'),
                       lambda p: p.update(tree_size=p["tree_size"] + 1),
                       lambda p: p.update(index=p["index"] ^ 1),
                       lambda p: p["path"].__setitem__(0, "00" * 32),
                       lambda p: p["seal"].update(root="11" * 32)):
            p = json.loads(json.dumps(base))
            mutate(p)
            self.assertFalse(ac.check_proof(p, self.pub)["ok"])

    def test_event_in_an_unsealed_or_late_position_has_no_proof(self):
        later = ac.append_event(self.conn, "t", "later", {}, ts=f"{D2} 10:00:00")
        with self.assertRaises(ac.AuditChainError):
            ac.inclusion_proof(self.conn, later["id"])
        late = ac.append_event(self.conn, "t", "late", {}, ts=f"{D1} 23:59:59")
        with self.assertRaises(ac.AuditChainError) as ctx:
            ac.inclusion_proof(self.conn, late["id"])
        self.assertIn("late", str(ctx.exception))

    def export(self):
        return ac.export_day(self.conn, D1, self.tmp / "pack", self.pubfile)

    def test_export_is_write_once_and_idempotent(self):
        first = self.export()
        self.assertEqual(len(first["newly_written"]), 3)
        for f in first["files"]:
            self.assertFalse(os.access(f, os.W_OK) and os.name == "posix" and os.geteuid() != 0)
        self.assertEqual(self.export()["newly_written"], [])
        events_file = Path(first["files"][0])
        os.chmod(events_file, 0o644)
        events_file.write_bytes(b"tampered\n")
        with self.assertRaises(ac.AuditChainError):
            self.export()

    def test_pack_verifies_from_its_own_files(self):
        self.export()
        res = ac.verify_pack(self.tmp / "pack", D1)
        self.assertTrue(res["ok"], res)
        self.assertGreaterEqual(len(res["checks"]), 6)

    def test_pack_with_an_edited_event_fails(self):
        out = self.export()
        ev = Path(out["files"][0])
        os.chmod(ev, 0o644)
        lines = ev.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[2])
        row["detail"] = '{"i": 12345}'
        lines[2] = json.dumps(row, sort_keys=True)
        ev.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(ac.verify_pack(self.tmp / "pack", D1)["ok"])

    def test_pack_with_edited_event_and_refreshed_file_hash_still_fails(self):
        out = self.export()
        ev, meta_path = Path(out["files"][0]), Path(out["files"][1])
        os.chmod(ev, 0o644)
        os.chmod(meta_path, 0o644)
        lines = ev.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[4])
        row["detail"] = '{"i": 777}'
        row["event_hash"] = ac.compute_event_hash(row["prev_hash"], row["ts"], row["trace_id"], row["event"], row["detail"])
        lines[4] = json.dumps(row, sort_keys=True)
        ev.write_text("\n".join(lines) + "\n", encoding="utf-8")
        meta = json.loads(meta_path.read_text())
        meta["events_sha256"] = hashlib.sha256(ev.read_bytes()).hexdigest()
        meta_path.write_text(json.dumps(meta))
        res = ac.verify_pack(self.tmp / "pack", D1)
        self.assertFalse(res["ok"])
        failed = [c["check"] for c in res["checks"] if not c["ok"]]
        self.assertTrue(any("Merkle root" in f for f in failed), failed)

    def test_pack_checked_against_the_wrong_public_key_fails(self):
        self.export()
        other = self.tmp / "other.pem"
        from cryptography.hazmat.primitives import serialization
        other.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.assertFalse(ac.verify_pack(self.tmp / "pack", D1, other)["ok"])

    def test_unsealed_day_cannot_be_exported(self):
        ac.append_event(self.conn, "t", "x", {}, ts=f"{D2} 10:00:00")
        with self.assertRaises(ac.AuditChainError):
            ac.export_day(self.conn, D2, self.tmp / "pack")

    def test_standalone_cli_verifies_a_pack(self):
        self.export()
        run = lambda *a: subprocess.run([sys.executable, str(ROOT / "audit_chain.py"), *a], capture_output=True, text=True, cwd=self.tmp)
        ok = run("verify-pack", str(self.tmp / "pack"), D1)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("VERIFIED", ok.stdout)
        bad = run("verify-pack", str(self.tmp / "pack"), "1999-01-01")
        self.assertEqual(bad.returncode, 1)


class TestIntegration(unittest.TestCase):
    """audit.py, resgister.py and the dashboard helpers all write and read the same chained table."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        for name in ("manifest.yaml", "tools.py", "dispatcher.py", "approval.py"):
            shutil.copy(ROOT / name, self.tmp / name)
        self.private = self.tmp / "ccor_private.pem"
        resgister.generate_keys(self.private, self.tmp / resgister.PUBLIC_KEY_FILE)
        self.db = self.tmp / "audit.db"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_audit_py(self, code):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=self.tmp, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)

    def past_events(self, n=4, day=D1):
        conn = resgister._connect(self.db)
        for i in range(n):
            ac.append_event(conn, "t", f"e{i}", {"i": i}, ts=f"{day} 10:00:0{i}")
        conn.close()

    def test_audit_py_and_resgister_write_one_intact_chain(self):
        self.run_audit_py("import audit; audit.log('t1','user_input',{'text':'hi'}); audit.log('t1','final_answer',{'text':'yo'})")
        resgister.log_event(self.db, "mas_gate_passed", {"ok": True})
        self.run_audit_py("import audit; audit.log('t2','tool_executed',{'tool':'x'})")
        v = subprocess.run([sys.executable, str(ROOT / "audit_chain.py"), "verify", str(self.db)], capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stdout)
        self.assertEqual(json.loads(v.stdout)["chained_rows"], 4)

    def test_audit_py_blocks_edits_to_old_rows(self):
        self.run_audit_py("import audit; audit.log('t','e',{})")
        self.run_audit_py("import audit, sqlite3\n"
                          "try:\n    audit.db.execute(\"UPDATE audit SET event='x'\")\n    raise SystemExit('edit was allowed')\n"
                          "except sqlite3.DatabaseError:\n    pass")

    def test_seal_wrapper_needs_the_2lod_key_and_writes_a_signed_chain_event(self):
        self.past_events()
        other = self.tmp / "other.pem"
        resgister.generate_keys(other, self.tmp / "other_pub.pem")
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.seal_audit_day("VP_CCOR", D1, key_file=other, base_dir=self.tmp)
        self.assertIn("does not match", str(ctx.exception))
        rec = resgister.seal_audit_day("VP_CCOR", D1, key_file=self.private, base_dir=self.tmp)
        ev = [e for e in resgister.chain_events(self.db) if e["action"] == resgister.ACT_SEAL]
        self.assertEqual(len(ev), 1)
        self.assertEqual(json.loads(ev[0]["detail"])["root"], rec["root"])
        self.assertTrue(ev[0]["signature"])

    def test_seal_wrapper_refuses_an_open_day_with_a_readable_message(self):
        today = __import__("time").strftime("%Y-%m-%d")
        self.past_events(2, today)
        with self.assertRaises(MASComplianceError) as ctx:
            resgister.seal_audit_day("VP_CCOR", today, key_file=self.private, base_dir=self.tmp)
        self.assertIn("still open", str(ctx.exception))

    def test_dashboard_report_lists_unsealed_then_sealed_and_exported(self):
        self.past_events()
        r = resgister.audit_integrity(self.tmp)
        self.assertEqual(r["chain"]["status"], "INTACT")
        self.assertEqual([u["day"] for u in r["unsealed"]], [D1])
        resgister.seal_audit_day("VP_CCOR", D1, key_file=self.private, base_dir=self.tmp)
        resgister.export_audit_day(D1, base_dir=self.tmp)
        r = resgister.audit_integrity(self.tmp)
        self.assertEqual(r["seals"][0]["status"], "VERIFIED")
        self.assertTrue(r["exported"][D1])
        self.assertTrue((self.tmp / "ccor-audit-artifacts" / f"audit-{D1}.seal.json").exists())

    def test_event_proof_wrapper_checks_against_the_2lod_public_key(self):
        self.past_events()
        resgister.seal_audit_day("VP_CCOR", D1, key_file=self.private, base_dir=self.tmp)
        first_id = ac.chained_days(ac.open_readonly(self.db))[0]["first_id"]
        out = resgister.audit_event_proof(first_id, base_dir=self.tmp, export=True)
        self.assertTrue(out["result"]["ok"], out["result"])
        self.assertTrue(Path(out["exported_to"]).exists())
        with self.assertRaises(MASComplianceError):
            resgister.audit_event_proof(10**6, base_dir=self.tmp)

    def test_readiness_check_e_follows_the_chain_state(self):
        self.past_events()
        by_id = {c["id"]: c for c in resgister.control_readiness(self.tmp)}
        self.assertTrue(by_id["e"]["passed"], by_id["e"])
        c = sqlite3.connect(self.db)
        c.execute("DROP TRIGGER audit_no_update")
        c.execute("UPDATE audit SET detail='{}' WHERE id=2")
        c.commit()
        c.close()
        by_id = {c["id"]: c for c in resgister.control_readiness(self.tmp)}
        self.assertFalse(by_id["e"]["passed"])
        self.assertIn("BROKEN", by_id["e"]["detail"])

    def test_cli_verify_audit_exit_code(self):
        self.past_events()
        run = lambda *a: subprocess.run([sys.executable, str(ROOT / "resgister.py"), *a], capture_output=True, text=True,
                                        cwd=self.tmp, env=dict(os.environ, PYTHONPATH=str(ROOT)))
        # the CLI reads ./manifest.yaml and ./audit.db from its working directory
        ok = run("--verify-audit")
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("INTACT", ok.stdout)


if __name__ == "__main__":
    unittest.main()
