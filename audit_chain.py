"""Tamper-evident audit log.

Two layers, both SHA-256:

1. Linear hash chain on every row of the `audit` table.
     event_hash = SHA-256([prev_hash, ts, trace_id, event, detail])
   Editing, deleting or reordering a row breaks the chain from that row onward. Rows that
   existed before this module was introduced are sealed once, by digest, in a genesis row.

2. Daily Merkle root (RFC 6962 hashing) over that day's event hashes, signed by the 2LoD key.
     leaf = SHA-256(0x00 || event_hash)    node = SHA-256(0x01 || left || right)
   A reviewer can be handed one event plus ~log2(N) hashes and check it against the signed root
   without seeing the rest of the log. The signed root is also an anchor: someone who rebuilds
   the entire linear chain after editing a row still cannot reproduce the sealed root.

Limits (also shown in the dashboard):
  * SQLite triggers make the table append-only for normal use. Anyone with write access to the
    database FILE can bypass them, which the chain then detects, unless they also rebuild the
    whole chain. Sealed, signed, exported days are what defeats that.
  * Deleting the newest rows is not detectable until the day is sealed and the pack exported to
    storage the developer cannot write.
  * Timestamps are the writer's local clock; days are bucketed by the date in `ts`.

Standalone auditor check (needs only this file and `cryptography`):
    python audit_chain.py verify-pack ccor-audit-artifacts 2026-11-09
"""
import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

GENESIS = "0" * 64
GENESIS_EVENT = "audit_chain_genesis"
ARTIFACT_DIR = "ccor-audit-artifacts"
PUBLIC_KEY_NAME = "mas_2lod_public.pem"


class AuditChainError(Exception):
    pass


# ------------------------------------------------------------------ schema
BASE_DDL = """
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    trace_id TEXT,
    event TEXT,
    detail TEXT);
"""

EXTRA_DDL = """
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TABLE IF NOT EXISTS audit_merkle_days (
    day TEXT PRIMARY KEY,
    first_id INTEGER NOT NULL,
    last_id INTEGER NOT NULL,
    leaf_count INTEGER NOT NULL,
    root TEXT NOT NULL,
    head_hash TEXT NOT NULL,
    prev_root TEXT NOT NULL,
    day_hash TEXT NOT NULL,
    sealed_at TEXT NOT NULL,
    sealer TEXT NOT NULL,
    signature TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_merkle_days_no_update BEFORE UPDATE ON audit_merkle_days
  BEGIN SELECT RAISE(ABORT, 'audit_merkle_days is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_merkle_days_no_delete BEFORE DELETE ON audit_merkle_days
  BEGIN SELECT RAISE(ABORT, 'audit_merkle_days is append-only'); END;
"""


def _q(conn, sql, args=()):
    """Run a query and return list[dict], whatever row_factory the caller's connection uses."""
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    cur.execute(sql, args)
    rows = [dict(r) for r in cur.fetchall()]
    cur.close()
    return rows


def _has_columns(conn):
    cols = {r["name"] for r in _q(conn, "PRAGMA table_info(audit)")}
    return {"prev_hash", "event_hash"} <= cols


def compute_event_hash(prev_hash, ts, trace_id, event, detail):
    payload = json.dumps([prev_hash, ts, trace_id, event, detail], separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _legacy_digest(rows):
    payload = json.dumps([[r["id"], r["ts"], r["trace_id"], r["event"], r["detail"]] for r in rows],
                         separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _insert(conn, prev, ts, trace_id, event, detail):
    h = compute_event_hash(prev, ts, trace_id, event, detail)
    cur = conn.execute(
        "INSERT INTO audit (ts, trace_id, event, detail, prev_hash, event_hash) VALUES (?,?,?,?,?,?)",
        (ts, trace_id, event, detail, prev, h))
    return cur.lastrowid, h


def ensure_schema(conn):
    """Create or upgrade the audit table in place. Rows written before hashing existed are left
    untouched and sealed by digest in a single genesis row, so they become tamper-evident from now on."""
    conn.executescript(BASE_DDL)
    cols = {r["name"] for r in _q(conn, "PRAGMA table_info(audit)")}
    for col in ("prev_hash", "event_hash"):
        if col not in cols:
            try:
                conn.execute(f"ALTER TABLE audit ADD COLUMN {col} TEXT")
            except sqlite3.OperationalError:
                pass  # another process added it first
    conn.executescript(EXTRA_DDL)
    _seal_legacy(conn)


def _seal_legacy(conn):
    if _q(conn, "SELECT 1 AS x FROM audit WHERE event_hash IS NOT NULL LIMIT 1"):
        return
    if not _q(conn, "SELECT 1 AS x FROM audit LIMIT 1"):
        return
    if conn.in_transaction:
        conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        if _q(conn, "SELECT 1 AS x FROM audit WHERE event_hash IS NOT NULL LIMIT 1"):
            conn.rollback()
            return
        legacy = _q(conn, "SELECT id, ts, trace_id, event, detail FROM audit ORDER BY id")
        detail = json.dumps({"legacy_rows": len(legacy), "legacy_last_id": legacy[-1]["id"],
                             "legacy_sha256": _legacy_digest(legacy),
                             "note": "rows before this one were written before hash chaining existed; "
                                     "they are tamper-evident only from this point"})
        _insert(conn, GENESIS, time.strftime("%Y-%m-%d %H:%M:%S"), "chain", GENESIS_EVENT, detail)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def append_event(conn, trace_id, event, detail, ts=None):
    """Append one chained row. Serialised with BEGIN IMMEDIATE so two writers cannot share a prev_hash."""
    detail_s = detail if isinstance(detail, str) else json.dumps(detail)
    ts = ts or time.strftime("%Y-%m-%d %H:%M:%S")
    if conn.in_transaction:
        conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        last = _q(conn, "SELECT event_hash FROM audit WHERE event_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
        prev = last[0]["event_hash"] if last else GENESIS
        rid, h = _insert(conn, prev, ts, str(trace_id), str(event), detail_s)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"id": rid, "event_hash": h, "prev_hash": prev}


def open_readonly(db_path):
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


# ------------------------------------------------------------------ linear chain verification
def verify_chain(conn):
    """status: INTACT | BROKEN | NOT_CHAINED | EMPTY. Never writes."""
    if not _has_columns(conn):
        n = _q(conn, "SELECT count(*) AS n FROM audit")[0]["n"]
        return {"status": "NOT_CHAINED" if n else "EMPTY", "ok": False if n else True, "rows": n,
                "legacy_rows": n, "chained_rows": 0, "head": GENESIS, "broken_at": None,
                "reason": "audit table has no hash columns yet" if n else None}
    rows = _q(conn, "SELECT id, ts, trace_id, event, detail, prev_hash, event_hash FROM audit ORDER BY id")

    def result(status, **kw):
        base = {"status": status, "ok": status in ("INTACT", "EMPTY"), "rows": len(rows), "legacy_rows": len(legacy),
                "chained_rows": chained, "head": prev, "broken_at": None, "reason": None}
        base.update(kw)
        return base

    legacy, prev, chained, started = [], GENESIS, 0, False
    for r in rows:
        if r["event_hash"] is None:
            if started:
                return result("BROKEN", broken_at=r["id"],
                              reason="a row without a hash appears after the chain started (written outside the audit code)")
            legacy.append(r)
            continue
        started = True
        if r["prev_hash"] != prev:
            return result("BROKEN", broken_at=r["id"],
                          reason="prev_hash does not match the previous row (a row was deleted, reordered or replaced)")
        if compute_event_hash(r["prev_hash"], r["ts"], r["trace_id"], r["event"], r["detail"]) != r["event_hash"]:
            return result("BROKEN", broken_at=r["id"], reason="row content does not match its hash (edited after the fact)")
        if chained == 0 and r["event"] == GENESIS_EVENT:
            meta = json.loads(r["detail"])
            if meta.get("legacy_rows") != len(legacy) or meta.get("legacy_sha256") != _legacy_digest(legacy):
                return result("BROKEN", broken_at=r["id"], reason="rows from before hash chaining were altered after migration")
        prev = r["event_hash"]
        chained += 1
    if not rows:
        return result("EMPTY")
    if legacy and (chained == 0 or rows[len(legacy)]["event"] != GENESIS_EVENT):
        return result("NOT_CHAINED", ok=False, reason="older rows exist but were never sealed; open the log with the new audit code once")
    return result("INTACT")


# ------------------------------------------------------------------ Merkle tree (RFC 6962 / RFC 9162)
def _h(data):
    return hashlib.sha256(data).digest()


def leaf_hash_bytes(data):
    return _h(b"\x00" + data)


def leaf_hash(event_hash_hex):
    return leaf_hash_bytes(bytes.fromhex(event_hash_hex))


def _node(left, right):
    return _h(b"\x01" + left + right)


def _split(n):
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(leaves):
    n = len(leaves)
    if n == 0:
        raise ValueError("cannot build a Merkle tree with no leaves")
    if n == 1:
        return leaves[0]
    k = _split(n)
    return _node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def merkle_path(index, leaves):
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return merkle_path(index, leaves[:k]) + [merkle_root(leaves[k:])]
    return merkle_path(index - k, leaves[k:]) + [merkle_root(leaves[:k])]


def verify_inclusion(leaf, index, size, path, root):
    """RFC 9162 section 2.1.3.2. All arguments are raw bytes (path/root) or ints."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ------------------------------------------------------------------ daily seals
def _valid_day(day):
    try:
        dt.datetime.strptime(day, "%Y-%m-%d")
    except (TypeError, ValueError):
        raise AuditChainError(f"day must be YYYY-MM-DD, got {day!r}")
    return day


def day_rows(conn, day, first_id=None, last_id=None):
    sql = ("SELECT id, ts, trace_id, event, detail, prev_hash, event_hash FROM audit "
           "WHERE event_hash IS NOT NULL AND substr(ts,1,10)=?")
    args = [day]
    if first_id is not None:
        sql += " AND id BETWEEN ? AND ?"
        args += [first_id, last_id]
    return _q(conn, sql + " ORDER BY id", args)


def chained_days(conn):
    if not _has_columns(conn):
        return []
    return _q(conn, "SELECT substr(ts,1,10) AS day, count(*) AS n, min(id) AS first_id, max(id) AS last_id "
                    "FROM audit WHERE event_hash IS NOT NULL GROUP BY day ORDER BY day")


def get_seals(conn):
    return _q(conn, "SELECT * FROM audit_merkle_days ORDER BY day")


def seal_hash(day, first_id, last_id, leaf_count, root, head_hash, prev_root):
    payload = json.dumps([day, first_id, last_id, leaf_count, root, head_hash, prev_root], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def seal_day(conn, day, signing_key, sealer, allow_open=False, today=None):
    """Compute and store the signed Merkle root for one day. signing_key is an Ed25519 private key object."""
    _valid_day(day)
    today = today or time.strftime("%Y-%m-%d")
    if day >= today and not allow_open:
        raise AuditChainError(f"{day} is still open: events can still be added to it. Seal it after the day ends, "
                              "or tick 'allow sealing an open day' (later events will then show as late rows).")
    chain = verify_chain(conn)
    if chain["status"] != "INTACT":
        raise AuditChainError(f"refusing to seal: the audit hash chain is {chain['status']} ({chain['reason']})")
    if any(s["day"] == day for s in get_seals(conn)):
        raise AuditChainError(f"{day} is already sealed (seals are append-only)")
    sealed = {s["day"] for s in get_seals(conn)}
    earlier = [d["day"] for d in chained_days(conn) if d["day"] < day and d["day"] not in sealed]
    if earlier:
        raise AuditChainError(f"seal {earlier[0]} first: days must be sealed in order so the roots chain together")
    rows = day_rows(conn, day)
    if not rows:
        raise AuditChainError(f"no chained events on {day}")
    leaves = [leaf_hash(r["event_hash"]) for r in rows]
    root = merkle_root(leaves).hex()
    prior = [s for s in get_seals(conn) if s["day"] < day]
    prev_root = prior[-1]["root"] if prior else GENESIS
    head = rows[-1]["event_hash"]
    dh = seal_hash(day, rows[0]["id"], rows[-1]["id"], len(rows), root, head, prev_root)
    sig = signing_key.sign(bytes.fromhex(dh)).hex()
    sealed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    if conn.in_transaction:
        conn.commit()
    conn.execute("INSERT INTO audit_merkle_days (day, first_id, last_id, leaf_count, root, head_hash, prev_root, "
                 "day_hash, sealed_at, sealer, signature) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (day, rows[0]["id"], rows[-1]["id"], len(rows), root, head, prev_root, dh, sealed_at, sealer, sig))
    conn.commit()
    return {"day": day, "first_id": rows[0]["id"], "last_id": rows[-1]["id"], "leaf_count": len(rows), "root": root,
            "head_hash": head, "prev_root": prev_root, "day_hash": dh, "sealed_at": sealed_at, "sealer": sealer, "signature": sig}


def _sig_ok(pub, day_hash, signature):
    from cryptography.exceptions import InvalidSignature
    try:
        pub.verify(bytes.fromhex(signature), bytes.fromhex(day_hash))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_seals(conn, pub=None):
    """Re-derive every sealed day from the rows now in the table. pub = Ed25519 public key object or None."""
    out, prev_root = [], GENESIS
    for s in get_seals(conn):
        problems = []
        rows = day_rows(conn, s["day"], s["first_id"], s["last_id"])
        root_now = merkle_root([leaf_hash(r["event_hash"]) for r in rows]).hex() if rows else None
        if len(rows) != s["leaf_count"]:
            problems.append("event count differs from what was sealed")
        if root_now != s["root"]:
            problems.append("Merkle root differs: events of this day changed after sealing")
        if rows and rows[-1]["event_hash"] != s["head_hash"]:
            problems.append("head hash differs from the sealed head")
        if s["prev_root"] != prev_root:
            problems.append("link to the previous day's root is broken")
        if seal_hash(s["day"], s["first_id"], s["last_id"], s["leaf_count"], s["root"], s["head_hash"], s["prev_root"]) != s["day_hash"]:
            problems.append("seal record was altered")
        sig_ok = None
        if pub is not None:
            sig_ok = _sig_ok(pub, s["day_hash"], s["signature"])
            if not sig_ok:
                problems.append("2LoD signature does not verify")
        late = _q(conn, "SELECT count(*) AS n FROM audit WHERE event_hash IS NOT NULL AND substr(ts,1,10)=? AND id>?",
                  (s["day"], s["last_id"]))[0]["n"]
        status = "FAILED" if problems else ("VERIFIED" if sig_ok else "UNCHECKED_SIGNATURE")
        out.append(dict(s, status=status, problems=problems, signature_ok=sig_ok, late_rows=late))
        prev_root = s["root"]
    return out


# ------------------------------------------------------------------ inclusion proofs
def inclusion_proof(conn, event_id):
    rows = _q(conn, "SELECT id, ts, trace_id, event, detail, prev_hash, event_hash FROM audit WHERE id=?", (event_id,))
    if not rows or rows[0]["event_hash"] is None:
        raise AuditChainError(f"event {event_id} is not a chained audit row")
    ev = rows[0]
    day = ev["ts"][:10]
    seal = next((s for s in get_seals(conn) if s["day"] == day), None)
    if seal is None:
        raise AuditChainError(f"{day} is not sealed yet, so event {event_id} has no signed root to prove against")
    if not seal["first_id"] <= ev["id"] <= seal["last_id"]:
        raise AuditChainError(f"event {event_id} was added after {day} was sealed (late row), so the seal does not cover it")
    day_list = day_rows(conn, day, seal["first_id"], seal["last_id"])
    leaves = [leaf_hash(r["event_hash"]) for r in day_list]
    index = next(i for i, r in enumerate(day_list) if r["id"] == ev["id"])
    return {"event": ev, "index": index, "tree_size": len(leaves),
            "path": [p.hex() for p in merkle_path(index, leaves)], "seal": seal}


def check_proof(proof, pub=None):
    """Offline check of a proof dict. Returns {'ok': bool, 'checks': {...}}."""
    ev, seal = proof["event"], proof["seal"]
    checks = {
        "event content matches its hash": compute_event_hash(ev["prev_hash"], ev["ts"], ev["trace_id"], ev["event"], ev["detail"]) == ev["event_hash"],
        # The tree size must come from the SIGNED seal, not from the proof: a Merkle root alone does not bind its size.
        "proof tree size equals the sealed event count": proof["tree_size"] == seal["leaf_count"],
        "hash path leads to the sealed Merkle root": verify_inclusion(
            leaf_hash(ev["event_hash"]), proof["index"], seal["leaf_count"], [bytes.fromhex(p) for p in proof["path"]],
            bytes.fromhex(seal["root"])),
        "seal record is internally consistent": seal_hash(seal["day"], seal["first_id"], seal["last_id"], seal["leaf_count"],
                                                          seal["root"], seal["head_hash"], seal["prev_root"]) == seal["day_hash"],
    }
    if pub is not None:
        checks["2LoD signature on the seal verifies"] = _sig_ok(pub, seal["day_hash"], seal["signature"])
    return {"ok": all(checks.values()), "checks": checks}


# ------------------------------------------------------------------ evidence pack (write-once)
def _write_once(path, data):
    path = Path(path)
    if path.exists():
        if path.read_bytes() == data:
            return path, False
        raise AuditChainError(f"{path.name} already exists with different content; evidence files are write-once")
    with open(path, "xb") as f:
        f.write(data)
    try:
        os.chmod(path, 0o444)
    except OSError:
        pass
    return path, True


def export_day(conn, day, out_dir=ARTIFACT_DIR, public_key_path=None):
    seal = next((s for s in get_seals(conn) if s["day"] == _valid_day(day)), None)
    if seal is None:
        raise AuditChainError(f"{day} must be sealed before it can be exported")
    rows = day_rows(conn, day, seal["first_id"], seal["last_id"])
    events = ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode("utf-8")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ev_name, seal_name = f"audit-{day}.events.jsonl", f"audit-{day}.seal.json"
    meta = {"seal": seal, "events_file": ev_name, "events_sha256": hashlib.sha256(events).hexdigest(),
            "public_key_file": PUBLIC_KEY_NAME,
            "verify_with": f"python audit_chain.py verify-pack {out_dir} {day}"}
    written = [_write_once(out / ev_name, events), _write_once(out / seal_name, (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode())]
    if public_key_path and Path(public_key_path).exists():
        written.append(_write_once(out / PUBLIC_KEY_NAME, Path(public_key_path).read_bytes()))
    return {"directory": str(out), "files": [str(p) for p, _ in written], "newly_written": [p.name for p, new in written if new]}


def export_proof(proof, out_dir=ARTIFACT_DIR):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path, _ = _write_once(out / f"proof-{proof['event']['id']}.json", (json.dumps(proof, indent=2, sort_keys=True) + "\n").encode())
    return str(path)


def verify_pack(directory, day, public_key_path=None):
    """Verify an exported day from the files alone. Raises nothing; returns {'ok', 'checks'}."""
    d = Path(directory)
    checks, problems = [], []

    def check(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    try:
        meta = json.loads((d / f"audit-{day}.seal.json").read_text(encoding="utf-8"))
        events_bytes = (d / meta["events_file"]).read_bytes()
    except (OSError, ValueError, KeyError) as err:
        return {"ok": False, "checks": [{"check": "pack files readable", "ok": False, "detail": str(err)}]}
    seal = meta["seal"]
    rows = [json.loads(line) for line in events_bytes.decode("utf-8").splitlines() if line.strip()]
    check("events file matches its recorded SHA-256", hashlib.sha256(events_bytes).hexdigest() == meta["events_sha256"])
    check("every event hash recomputes from its content",
          all(compute_event_hash(r["prev_hash"], r["ts"], r["trace_id"], r["event"], r["detail"]) == r["event_hash"] for r in rows))
    linked = all(b["prev_hash"] == a["event_hash"] for a, b in zip(rows, rows[1:]) if b["id"] == a["id"] + 1)
    check("consecutive events are chained to each other", linked)
    check("event count matches the seal", len(rows) == seal["leaf_count"])
    root = merkle_root([leaf_hash(r["event_hash"]) for r in rows]).hex() if rows else None
    check("Merkle root recomputed from the events equals the sealed root", root == seal["root"])
    check("seal record is internally consistent",
          seal_hash(seal["day"], seal["first_id"], seal["last_id"], seal["leaf_count"], seal["root"], seal["head_hash"], seal["prev_root"]) == seal["day_hash"])
    pub_path = Path(public_key_path) if public_key_path else d / PUBLIC_KEY_NAME
    if pub_path.exists():
        from cryptography.hazmat.primitives import serialization
        pub = serialization.load_pem_public_key(pub_path.read_bytes())
        check("2LoD signature on the seal verifies", _sig_ok(pub, seal["day_hash"], seal["signature"]), f"key: {pub_path.name}")
    else:
        check("2LoD signature on the seal verifies", False, "public key file not found")
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


# ------------------------------------------------------------------ report for the dashboard
def _load_pub(path):
    if not path or not Path(path).exists():
        return None
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(Path(path).read_bytes())


def integrity_report(db_path, public_key_path=None, artifact_dir=ARTIFACT_DIR):
    """Read-only summary: chain status, seals, unsealed days, which days were exported."""
    p = Path(db_path)
    if not p.exists():
        return {"chain": {"status": "MISSING", "ok": False, "rows": 0, "legacy_rows": 0, "chained_rows": 0,
                          "head": GENESIS, "broken_at": None, "reason": "audit.db not found"},
                "seals": [], "unsealed": [], "exported": {}}
    conn = open_readonly(p)
    try:
        chain = verify_chain(conn)
        try:
            seals = verify_seals(conn, _load_pub(public_key_path))
        except sqlite3.OperationalError:
            seals = []
        sealed = {s["day"] for s in seals}
        today = time.strftime("%Y-%m-%d")
        unsealed = [{"day": d["day"], "events": d["n"], "open": d["day"] >= today}
                    for d in chained_days(conn) if d["day"] not in sealed]
    finally:
        conn.close()
    exported = {s["day"]: (Path(artifact_dir) / f"audit-{s['day']}.seal.json").exists() for s in seals}
    return {"chain": chain, "seals": seals, "unsealed": unsealed, "exported": exported}


def _main(argv):
    if len(argv) >= 2 and argv[0] == "verify":
        conn = open_readonly(argv[1])
        res = verify_chain(conn)
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    if len(argv) >= 3 and argv[0] == "verify-pack":
        res = verify_pack(argv[1], argv[2], argv[3] if len(argv) > 3 else None)
        for c in res["checks"]:
            print(("PASS " if c["ok"] else "FAIL ") + c["check"] + (f" ({c['detail']})" if c["detail"] else ""))
        print("RESULT:", "VERIFIED" if res["ok"] else "NOT VERIFIED")
        return 0 if res["ok"] else 1
    print("usage:\n  python audit_chain.py verify audit.db\n  python audit_chain.py verify-pack <dir> <YYYY-MM-DD> [public_key.pem]")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
