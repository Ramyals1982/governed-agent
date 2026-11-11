"""MAS AIRM Section 4 - registration, 2LoD effective challenge, signed sign-off, startup gate.

The first line (developer) declares objective facts in manifest.yaml -> mas_use_case_profile.
This module (acting for the second line) does NOT trust them: it inspects tools.py, scores the
system with the locked rubric in mas_rubric.py, challenges declared_inherent_risk, and for
HIGH materiality requires a 2LoD approval that is
  * keyed to the SHA-256 of manifest.yaml + tools.py,
  * pinned to the rubric version/hash,
  * signed with the 2LoD private key (Ed25519). The repo only holds the PUBLIC key.

CLI
  python resgister.py                                   register + run all checks
  python resgister.py --status                          show tier, scores and approval state
  python resgister.py --gen-keys ccor_private.pem       2LoD, once (writes mas_2lod_public.pem)
  python resgister.py --approve --reviewer VP_CCOR --key-file ccor_private.pem [--days 90]
"""
import argparse
import ast
import datetime as dt
import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
import time
import uuid
from pathlib import Path

import yaml

import audit_chain
import evidence
import mas_rubric as rubric

PUBLIC_KEY_FILE = "mas_2lod_public.pem"


class MASComplianceError(Exception):
    """Raised when a MAS Section 4 control fails. Never catch this to keep the agent running."""


# ---------------------------------------------------------------- audit.db helpers
AUDIT_DDL = """
CREATE TABLE IF NOT EXISTS mas_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    system_id TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    tools_sha256 TEXT NOT NULL,
    combined_sha256 TEXT NOT NULL,
    rubric_version TEXT NOT NULL,
    rubric_sha256 TEXT NOT NULL,
    computed_tier TEXT NOT NULL,
    scores TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    signature TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS mas_approvals_no_update BEFORE UPDATE ON mas_approvals
  BEGIN SELECT RAISE(ABORT, 'mas_approvals is append-only'); END;
CREATE TRIGGER IF NOT EXISTS mas_approvals_no_delete BEFORE DELETE ON mas_approvals
  BEGIN SELECT RAISE(ABORT, 'mas_approvals is append-only'); END;
CREATE TABLE IF NOT EXISTS mas_2lod_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    system_id TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    signature TEXT);
CREATE TRIGGER IF NOT EXISTS mas_2lod_events_no_update BEFORE UPDATE ON mas_2lod_events
  BEGIN SELECT RAISE(ABORT, 'mas_2lod_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS mas_2lod_events_no_delete BEFORE DELETE ON mas_2lod_events
  BEGIN SELECT RAISE(ABORT, 'mas_2lod_events is append-only'); END;
"""


def _connect(db_path):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    audit_chain.ensure_schema(conn)   # hash-chained audit table (shared with audit.py)
    conn.executescript(AUDIT_DDL)     # MAS approval and 2LoD event tables
    return conn


def log_event(db_path, event, detail, trace_id="mas_gate"):
    """Same chained table as audit.log(), but takes an explicit db path."""
    conn = _connect(db_path)
    try:
        audit_chain.append_event(conn, trace_id, event, detail)
    finally:
        conn.close()


def _utcnow():
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------- 1. objective intake
PROFILE_ENUMS = {
    "financial_impact_tier": rubric.FINANCIAL_IMPACT,
    "data_sensitivity": rubric.DATA_SENSITIVITY,
    "architecture_type": rubric.ARCHITECTURE_COMPLEXITY,
    "human_oversight_mode": rubric.OVERSIGHT_RELIANCE,
    "declared_inherent_risk": {t: None for t in rubric.RISK_TIERS},
}
PROFILE_STRINGS = ("system_id", "business_line", "kill_switch_owner")
PROFILE_REQUIRED = PROFILE_STRINGS + ("customer_facing", "declared_tool_count") + tuple(PROFILE_ENUMS)


def validate_profile(manifest):
    profile = manifest.get("mas_use_case_profile")
    if not isinstance(profile, dict):
        raise MASComplianceError("manifest.yaml has no mas_use_case_profile block")
    errors = [f"missing field '{k}'" for k in PROFILE_REQUIRED if k not in profile]
    if not errors:
        for k in PROFILE_STRINGS:
            if not isinstance(profile[k], str) or not profile[k].strip():
                errors.append(f"'{k}' must be a non-empty string")
        if not isinstance(profile["customer_facing"], bool):
            errors.append("'customer_facing' must be true or false")
        n = profile["declared_tool_count"]
        if isinstance(n, bool) or not isinstance(n, int) or n < 0:
            errors.append("'declared_tool_count' must be a non-negative integer")
        for k, allowed in PROFILE_ENUMS.items():
            if profile[k] not in allowed:
                errors.append(f"'{k}' must be one of {sorted(allowed)}, got {profile[k]!r}")
        if profile["system_id"] != (manifest.get("agent") or {}).get("name"):
            errors.append("'system_id' must equal agent.name so the inventory identity is unambiguous")
    if errors:
        raise MASComplianceError("Invalid mas_use_case_profile: " + "; ".join(errors))
    return profile


# ---------------------------------------------------------------- 2. code introspection
def introspect_tools(tools_path):
    """Import tools.py fresh and return (sorted tool names, {name: function}).
    The runtime registry (TOOL_FUNCTIONS) and the schemas shown to the model
    (TOOL_SCHEMAS) must agree; a tool visible in only one of them is a control failure."""
    tools_path = Path(tools_path)
    spec = importlib.util.spec_from_file_location(f"_mas_tools_{uuid.uuid4().hex}", tools_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    functions = getattr(module, "TOOL_FUNCTIONS", None)
    if not isinstance(functions, dict):
        raise MASComplianceError("tools.py exposes no TOOL_FUNCTIONS registry to inspect")
    schema_names = {s["function"]["name"] for s in getattr(module, "TOOL_SCHEMAS", [])}
    registry = set(functions)
    if registry != schema_names:
        raise MASComplianceError(
            "Tool registry inconsistent: only in TOOL_FUNCTIONS=%s, only in TOOL_SCHEMAS=%s"
            % (sorted(registry - schema_names), sorted(schema_names - registry)))
    return sorted(registry), functions


def verify_tool_inventory(profile, manifest, actual_names):
    declared_names = sorted(t["name"] for t in manifest.get("tools", []))
    declared_count = profile["declared_tool_count"]
    undeclared = sorted(set(actual_names) - set(declared_names))
    if len(actual_names) > declared_count or undeclared:
        raise MASComplianceError(
            "Shadow Capability Detected: tools.py exposes %d tool(s) %s but manifest declares "
            "declared_tool_count=%d with tools %s; undeclared: %s"
            % (len(actual_names), actual_names, declared_count, declared_names, undeclared or "(count only)"))
    if len(actual_names) != declared_count or declared_names != sorted(actual_names):
        raise MASComplianceError(
            "Declared tools do not match tools.py: declared %s (count %d), actual %s"
            % (declared_names, declared_count, actual_names))


def _is_tool_eq(test):
    return (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "tool"
            and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.comparators[0], ast.Constant) and isinstance(test.comparators[0].value, str))


def introspect_oversight(base_dir, tool_caps):
    """What human oversight does the CODE actually enforce? Reads approval.py (is there a human
    prompt?) and dispatcher.decide() (which tools can return 'approve'?). Heuristic AST scan:
    if the structure changes and nothing is found it fails safe to AUTONOMOUS."""
    base = Path(base_dir)
    mechanism = False
    try:
        tree = ast.parse((base / "approval.py").read_text(encoding="utf-8"))
        mechanism = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "input"
                        for n in ast.walk(tree))
    except (OSError, SyntaxError):
        pass
    approval_tools = set()
    try:
        tree = ast.parse((base / "dispatcher.py").read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef) and fn.name == "decide":
                for node in ast.walk(fn):
                    if isinstance(node, ast.If) and _is_tool_eq(node.test):
                        if any(isinstance(r, ast.Return) and isinstance(r.value, ast.Tuple) and r.value.elts
                               and isinstance(r.value.elts[0], ast.Constant) and r.value.elts[0].value == "approve"
                               for r in ast.walk(node)):
                            approval_tools.add(node.test.comparators[0].value)
    except (OSError, SyntaxError):
        pass
    approval_tools &= set(tool_caps)
    if not mechanism or not approval_tools:
        mode = "AUTONOMOUS"
    else:
        consequential = {t for t, c in tool_caps.items() if c != "READ_ONLY"}
        mode = "FULL_HUMAN_REVIEW" if consequential <= approval_tools else "EXCEPTION_ONLY"
    return {"mode": mode, "approval_mechanism": mechanism, "approval_tools": sorted(approval_tools),
            "tools_without_approval": sorted(set(tool_caps) - approval_tools)}


# ---------------------------------------------------------------- hashing
def _normalised(path):
    return Path(path).read_bytes().replace(b"\r\n", b"\n")  # CRLF/LF must not change the hash


def file_hashes(manifest_path, tools_path):
    m = hashlib.sha256(_normalised(manifest_path)).hexdigest()
    t = hashlib.sha256(_normalised(tools_path)).hexdigest()
    combined = hashlib.sha256(f"manifest:{m}\ntools:{t}".encode()).hexdigest()
    return m, t, combined


def _declared_model_in_code(base):
    """The MODEL string assigned in llm.py (AST), or None."""
    try:
        tree = ast.parse((Path(base) / "llm.py").read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return None
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MODEL" for t in n.targets) \
                and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
            return n.value.value
    return None


def verify_model_binding(manifest, base):
    """Shadow-model check: the model the code calls must be the model the manifest declares."""
    declared = (manifest.get("model") or {}).get("name")
    actual = _declared_model_in_code(base)
    if actual is None:
        raise MASComplianceError("Shadow Model check failed: no MODEL constant found in llm.py, so the model cannot be verified")
    if actual != declared:
        raise MASComplianceError("Shadow Model Detected: llm.py calls %r but manifest.yaml declares %r" % (actual, declared))
    return actual


def mitigation_checks(base, profile, oversight, now=None):
    """Controls verified from the code and files on every boot (not self-declared).
    red_team_evidence is true only while the red-team evidence is ACCEPTED: recorded, unchanged,
    sufficient and inside the validity window set by policy/evidence_policy.yaml."""
    base = Path(base)
    red, _ = evidence.gate_status(base, now)
    return {"output_guard_on_answers": _uses_output_guard(base / "agent.py", "scan"),
            "output_guard_on_email": _uses_output_guard(base / "dispatcher.py", "is_sensitive"),
            "human_approval_enforced": oversight["mode"] != "AUTONOMOUS",
            "kill_switch_owner_assigned": bool(str(profile.get("kill_switch_owner") or "").strip()),
            "red_team_evidence": red}


# ---------------------------------------------------------------- assessment (2LoD challenge)
def assess(base_dir=".", db_path=None, log=True, now=None):
    base = Path(base_dir)
    manifest_path, tools_path = base / "manifest.yaml", base / "tools.py"
    db = db_path or base / "audit.db"

    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    profile = validate_profile(manifest)
    provider = (manifest.get("model") or {}).get("provider")
    if not provider:
        raise MASComplianceError("manifest.yaml model.provider is required to assess third-party reliance")

    local = sorted({m for n in ast.walk(ast.parse(tools_path.read_text(encoding="utf-8")))
                    for m in ([a.name.split(".")[0] for a in n.names] if isinstance(n, ast.Import)
                              else [(n.module or "").split(".")[0]] if isinstance(n, ast.ImportFrom) and not n.level else [])
                    if m and (base / (m + ".py")).is_file()})
    if local:
        if log:
            log_event(db, "2LoD_UNHASHED_TOOL_CODE", {"system_id": profile["system_id"], "local_modules": local})
        raise MASComplianceError("Unhashed tool code: tools.py imports local module(s) %s that the approval hash does not cover. "
                                 "Keep tool logic inside tools.py." % ", ".join(local))
    names, functions = introspect_tools(tools_path)
    try:
        verify_tool_inventory(profile, manifest, names)
    except MASComplianceError as err:
        if log:
            log_event(db, "2LoD_SHADOW_CAPABILITY_DETECTED", {
                "system_id": profile["system_id"], "actual_tools": names,
                "declared_tool_count": profile["declared_tool_count"],
                "declared_tools": [t["name"] for t in manifest.get("tools", [])], "error": str(err)})
        raise

    try:
        verify_model_binding(manifest, base)
    except MASComplianceError as err:
        if log:
            log_event(db, "2LoD_SHADOW_MODEL_DETECTED", {"system_id": profile["system_id"], "error": str(err)})
        raise

    caps = rubric.classify_tools(names, functions, tools_path.read_text(encoding="utf-8"))
    oversight = introspect_oversight(base, caps)
    if oversight["mode"] != profile["human_oversight_mode"]:
        if log:
            log_event(db, "2LoD_EFFECTIVE_CHALLENGE_FAILED", {
                "system_id": profile["system_id"], "reason": "human_oversight_mode mismatch",
                "declared_human_oversight_mode": profile["human_oversight_mode"],
                "introspected_oversight": oversight})
        raise MASComplianceError(
            "2LoD effective challenge failed: human_oversight_mode declared %s but approval.py/dispatcher.py enforce %s "
            "(human approval only for %s)" % (profile["human_oversight_mode"], oversight["mode"],
                                              oversight["approval_tools"] or "no tool"))
    scores = rubric.score(profile, caps, rubric.is_third_party_model(provider))
    computed = rubric.tier(scores, profile)
    mitigations = mitigation_checks(base, profile, oversight, now)
    residual, missing = rubric.residual_tier(computed, mitigations)
    m_hash, t_hash, combined = file_hashes(manifest_path, tools_path)

    result = {
        "system_id": profile["system_id"], "owner": (manifest.get("agent") or {}).get("owner", ""),
        "version": (manifest.get("agent") or {}).get("version"), "model": (manifest.get("model") or {}).get("name"),
        "tools": names, "tool_capabilities": caps, "oversight": oversight, "scores": scores,
        "computed_tier": computed, "declared_tier": profile["declared_inherent_risk"],
        "residual_tier": residual, "mitigations": mitigations, "missing_mitigations": missing,
        "risk_appetite_max_residual": rubric.BOARD_RISK_APPETITE_MAX_RESIDUAL,
        "manifest_sha256": m_hash, "tools_sha256": t_hash, "combined_sha256": combined,
        "rubric_version": rubric.RUBRIC_VERSION, "rubric_sha256": rubric.rubric_sha256(),
    }
    if computed != profile["declared_inherent_risk"]:
        if log:
            log_event(db, "2LoD_EFFECTIVE_CHALLENGE_FAILED", {
                "system_id": profile["system_id"], "declared_inherent_risk": profile["declared_inherent_risk"],
                "computed_tier": computed, "scores": scores, "tool_capabilities": caps,
                "rubric_version": rubric.RUBRIC_VERSION, "manifest_sha256": m_hash, "tools_sha256": t_hash})
        raise MASComplianceError(
            "2LoD effective challenge failed: declared_inherent_risk=%s but the locked rubric computes %s "
            "(impact=%d, complexity=%d, reliance=%d)"
            % (profile["declared_inherent_risk"], computed, scores["impact"], scores["complexity"], scores["reliance"]))
    if not rubric.within_appetite(residual):
        if log:
            log_event(db, "2LoD_RESIDUAL_RISK_EXCEEDS_APPETITE", {
                "system_id": profile["system_id"], "inherent": computed, "residual": residual,
                "appetite_max_residual": rubric.BOARD_RISK_APPETITE_MAX_RESIDUAL, "missing_mitigations": missing,
                "evidence": evidence.gate_status(base, now)[1]})
        ev_note = ""
        if "red_team_evidence" in missing:
            ev_note = " [evidence: " + "; ".join(evidence.gate_status(base, now)[1]) + "]"
        raise MASComplianceError(
            "Residual risk %s exceeds Board risk appetite (max %s). Inherent %s; unverified mitigations: %s%s"
            % (residual, rubric.BOARD_RISK_APPETITE_MAX_RESIDUAL, computed, ", ".join(missing) or "none", ev_note))
    return result


# ---------------------------------------------------------------- 3. signed 2LoD approvals
def _payload(system_id, combined, rubric_hash, tier, reviewer, expires_at):
    return json.dumps({"system_id": system_id, "combined_sha256": combined, "rubric_sha256": rubric_hash,
                       "tier": tier, "reviewer": reviewer, "expires_at": expires_at},
                      sort_keys=True).encode()


def generate_keys(private_path, public_path=PUBLIC_KEY_FILE):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if Path(private_path).exists():
        raise MASComplianceError(f"refusing to overwrite existing {private_path}")
    if Path(public_path).exists():
        raise MASComplianceError(f"refusing to overwrite existing {public_path} - approvals already signed "
                                 "with the matching private key would stop verifying; delete it deliberately first")
    key = Ed25519PrivateKey.generate()
    Path(private_path).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    Path(public_path).write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def _load_private_key(key_file=None, key_pem=None, public_key_path=None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if key_pem is None:
        if not key_file:
            raise MASComplianceError("the 2LoD private key is required")
        key_pem = Path(key_file).read_bytes()
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError) as err:
        raise MASComplianceError(f"cannot read the 2LoD private key: {err}")
    if not isinstance(key, Ed25519PrivateKey):
        raise MASComplianceError("the 2LoD key must be an Ed25519 private key")
    if public_key_path and Path(public_key_path).exists():
        got = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        if got.strip() != Path(public_key_path).read_bytes().strip():
            raise MASComplianceError(f"this private key does not match {Path(public_key_path).name}; "
                                     "anything signed with it would be rejected by the gate")
    return key


def approve(reviewer, key_file=None, days=90, base_dir=".", db_path=None, now=None, key_pem=None):
    """Record a 2LoD approval for the CURRENT manifest.yaml + tools.py. Needs the private key
    (a file path, or key_pem bytes held in memory by the dashboard)."""
    base = Path(base_dir)
    db = db_path or base / "audit.db"
    a = assess(base_dir, db, now=now)  # never approve something that fails the 2LoD checks
    if not reviewer or not reviewer.strip():
        raise MASComplianceError("--reviewer is required")
    if reviewer.strip().lower() == str(a["owner"]).strip().lower():
        raise MASComplianceError("2LoD reviewer cannot be the system owner (four-eyes principle)")
    key = _load_private_key(key_file, key_pem, base / PUBLIC_KEY_FILE)
    now = now or _utcnow()
    expires = (now + dt.timedelta(days=days)).isoformat()
    sig = key.sign(_payload(a["system_id"], a["combined_sha256"], a["rubric_sha256"],
                            a["computed_tier"], reviewer, expires)).hex()
    conn = _connect(db)
    try:
        cur = conn.execute(
            "INSERT INTO mas_approvals (ts, system_id, reviewer, manifest_sha256, tools_sha256, combined_sha256,"
            " rubric_version, rubric_sha256, computed_tier, scores, expires_at, signature)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (now.isoformat(), a["system_id"], reviewer, a["manifest_sha256"], a["tools_sha256"],
             a["combined_sha256"], a["rubric_version"], a["rubric_sha256"], a["computed_tier"],
             json.dumps(a["scores"]), expires, sig))
        conn.commit()
        approval_id = cur.lastrowid
    finally:
        conn.close()
    log_event(db, "2lod_approval_granted", {
        "approval_id": approval_id, "system_id": a["system_id"], "reviewer": reviewer,
        "tier": a["computed_tier"], "scores": a["scores"], "combined_sha256": a["combined_sha256"],
        "expires_at": expires})
    append_chain_event(db, reviewer, ACT_APPROVE, a["system_id"], {
        "approval_id": approval_id, "combined_sha256": a["combined_sha256"], "tier": a["computed_tier"],
        "scores": a["scores"], "expires_at": expires}, signing_key=key)
    return approval_id


def find_active_approval(a, db_path, public_key_path, now=None):
    """Return (approval_row | None, reasons). Verifies signature, hash, rubric, tier and expiry."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    now = now or _utcnow()
    public_key_path = Path(public_key_path)
    if not public_key_path.exists():
        return None, [f"2LoD public key {public_key_path.name} not found, so approvals cannot be verified"]
    pub = serialization.load_pem_public_key(public_key_path.read_bytes())
    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM mas_approvals WHERE system_id=? AND combined_sha256=? ORDER BY id DESC",
                            (a["system_id"], a["combined_sha256"])).fetchall()
    finally:
        conn.close()
    if not rows:
        return None, ["no 2LoD approval for the current manifest.yaml + tools.py hash"]
    reasons = []
    for r in rows:
        try:
            pub.verify(bytes.fromhex(r["signature"]),
                       _payload(r["system_id"], r["combined_sha256"], r["rubric_sha256"],
                                r["computed_tier"], r["reviewer"], r["expires_at"]))
        except (InvalidSignature, ValueError):
            reasons.append(f"approval #{r['id']}: invalid signature (not issued by 2LoD key)")
            continue
        if r["rubric_sha256"] != a["rubric_sha256"]:
            reasons.append(f"approval #{r['id']}: scoring rubric changed since approval")
        elif r["computed_tier"] != a["computed_tier"]:
            reasons.append(f"approval #{r['id']}: approved as {r['computed_tier']}, now {a['computed_tier']}")
        elif dt.datetime.fromisoformat(r["expires_at"]) <= now:
            reasons.append(f"approval #{r['id']}: expired {r['expires_at']}")
        else:
            return dict(r), reasons
    return None, reasons


# ---------------------------------------------------------------- 4. hash-chained 2LoD console events
GENESIS = "0" * 64
ACT_APPROVE = "APPROVE_HASH"
ACT_REJECT = "FLAG_CHALLENGE_FAILURE"
ACT_KILL = "KILL_SWITCH_ACTIVATED"
ACT_RELEASE = "KILL_SWITCH_RELEASED"
ACT_SEAL = "AUDIT_DAY_SEALED"
# Actions that make the system LESS restricted need the 2LoD private key. Actions that make it MORE
# restricted (reject, kill-switch) are open to the console: the worst a forger can do is stop the agent.
SIGNED_ACTIONS = {ACT_APPROVE, ACT_RELEASE, ACT_SEAL}


def _event_hash(prev, ts, actor, action, system_id, detail):
    return hashlib.sha256("|".join([prev, ts, actor, action, system_id, detail]).encode()).hexdigest()


def append_chain_event(db_path, actor, action, system_id, detail, signing_key=None):
    """Append one event to the hash chain: event_hash = SHA-256(prev_hash + this event's fields)."""
    detail_json = json.dumps(detail, sort_keys=True)
    ts = _utcnow().isoformat()
    _connect(db_path).close()  # make sure the schema exists
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")  # serialise writers so two events cannot share a prev_hash
        last = conn.execute("SELECT event_hash FROM mas_2lod_events ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["event_hash"] if last else GENESIS
        h = _event_hash(prev, ts, actor, action, system_id, detail_json)
        sig = signing_key.sign(h.encode()).hex() if signing_key is not None else None
        cur = conn.execute(
            "INSERT INTO mas_2lod_events (ts, actor, action, system_id, detail, prev_hash, event_hash, signature)"
            " VALUES (?,?,?,?,?,?,?,?)", (ts, actor, action, system_id, detail_json, prev, h, sig))
        conn.execute("COMMIT")
        event_id = cur.lastrowid
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    log_event(db_path, "2lod_console_action", {"chain_id": event_id, "action": action, "actor": actor,
                                               "system_id": system_id, "event_hash": h}, trace_id="2lod")
    return {"id": event_id, "event_hash": h, "prev_hash": prev, "signed": sig is not None}


def chain_events(db_path, limit=None):
    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM mas_2lod_events ORDER BY id ASC").fetchall()
    finally:
        conn.close()
    rows = [dict(r) for r in rows]
    return rows[-limit:] if limit else rows


def verify_chain(db_path):
    """Recompute every link. Detects edits and reordering. It cannot detect deletion of the newest
    rows, so keep the head hash somewhere the developer cannot write (e.g. the CCOR evidence room)."""
    prev, n = GENESIS, 0
    for ev in chain_events(db_path):
        n += 1
        expected = _event_hash(ev["prev_hash"], ev["ts"], ev["actor"], ev["action"], ev["system_id"], ev["detail"])
        if ev["prev_hash"] != prev or ev["event_hash"] != expected:
            return {"ok": False, "count": n, "broken_at": ev["id"], "head": prev}
        prev = ev["event_hash"]
    return {"ok": True, "count": n, "broken_at": None, "head": prev}


def _load_public_key(path):
    from cryptography.hazmat.primitives import serialization
    p = Path(path)
    return serialization.load_pem_public_key(p.read_bytes()) if p.exists() else None


def _event_signed_ok(pub, ev):
    from cryptography.exceptions import InvalidSignature
    if pub is None or not ev["signature"]:
        return False
    expected = _event_hash(ev["prev_hash"], ev["ts"], ev["actor"], ev["action"], ev["system_id"], ev["detail"])
    if expected != ev["event_hash"]:
        return False
    try:
        pub.verify(bytes.fromhex(ev["signature"]), ev["event_hash"].encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def kill_switch_state(db_path, public_key_path=PUBLIC_KEY_FILE):
    """Active from an ACTIVATED event until a RELEASED event whose signature verifies against the
    2LoD public key. Unsigned or forged releases are ignored (and reported)."""
    pub = _load_public_key(public_key_path)
    state = {"active": False, "activated_by": None, "activated_at": None, "reason": None,
             "released_by": None, "released_at": None, "ignored_releases": []}
    for ev in chain_events(db_path):
        if ev["action"] == ACT_KILL:
            state.update(active=True, activated_by=ev["actor"], activated_at=ev["ts"],
                         reason=json.loads(ev["detail"]).get("reason"), released_by=None, released_at=None)
        elif ev["action"] == ACT_RELEASE:
            if _event_signed_ok(pub, ev):
                state.update(active=False, released_by=ev["actor"], released_at=ev["ts"])
            else:
                state["ignored_releases"].append(ev["id"])
    return state


def latest_decision(db_path, system_id, combined, public_key_path=PUBLIC_KEY_FILE):
    """Latest 2LoD decision on this exact hash: ('APPROVE'|'REJECT', event, detail) or None.
    An APPROVE counts only if its event signature verifies, so it cannot be forged to undo a REJECT."""
    pub = _load_public_key(public_key_path)
    last = None
    for ev in chain_events(db_path):
        if ev["system_id"] != system_id:
            continue
        d = json.loads(ev["detail"])
        if d.get("combined_sha256") != combined:
            continue
        if ev["action"] == ACT_REJECT:
            last = ("REJECT", ev, d)
        elif ev["action"] == ACT_APPROVE and _event_signed_ok(pub, ev):
            last = ("APPROVE", ev, d)
    return last


def _current_ids(base_dir):
    base = Path(base_dir)
    manifest = yaml.safe_load((base / "manifest.yaml").read_text(encoding="utf-8")) or {}
    system_id = (manifest.get("agent") or {}).get("name", "unknown")
    _, _, combined = file_hashes(base / "manifest.yaml", base / "tools.py")
    return system_id, combined


def _need(text, what):
    if not text or not str(text).strip():
        raise MASComplianceError(f"{what} is required")
    return str(text).strip()


def flag_challenge_failure(reviewer, reason, base_dir=".", db_path=None):
    """2LoD rejects the CURRENT manifest.yaml + tools.py hash. The gate then refuses to boot it."""
    reviewer, reason = _need(reviewer, "reviewer"), _need(reason, "reason")
    db = db_path or Path(base_dir) / "audit.db"
    system_id, combined = _current_ids(base_dir)
    ev = append_chain_event(db, reviewer, ACT_REJECT, system_id, {"combined_sha256": combined, "reason": reason})
    log_event(db, "2LoD_EFFECTIVE_CHALLENGE_FAILED", {"system_id": system_id, "source": "2lod_console",
                                                       "reviewer": reviewer, "reason": reason,
                                                       "combined_sha256": combined, "chain_id": ev["id"]})
    return ev


def activate_kill_switch(reviewer, reason, base_dir=".", db_path=None):
    reviewer, reason = _need(reviewer, "reviewer"), _need(reason, "reason")
    db = db_path or Path(base_dir) / "audit.db"
    system_id, _ = _current_ids(base_dir)
    ev = append_chain_event(db, reviewer, ACT_KILL, system_id, {"reason": reason})
    log_event(db, "2LoD_KILL_SWITCH_ACTIVATED", {"system_id": system_id, "reviewer": reviewer,
                                                  "reason": reason, "chain_id": ev["id"]})
    return ev


def release_kill_switch(reviewer, reason, key_file=None, key_pem=None, base_dir=".", db_path=None):
    """Lifting the kill-switch makes the system less restricted, so it needs the 2LoD private key."""
    reviewer, reason = _need(reviewer, "reviewer"), _need(reason, "reason")
    base = Path(base_dir)
    db = db_path or base / "audit.db"
    key = _load_private_key(key_file, key_pem, base / PUBLIC_KEY_FILE)
    system_id, _ = _current_ids(base_dir)
    ev = append_chain_event(db, reviewer, ACT_RELEASE, system_id, {"reason": reason}, signing_key=key)
    log_event(db, "2LoD_KILL_SWITCH_RELEASED", {"system_id": system_id, "reviewer": reviewer,
                                                 "reason": reason, "chain_id": ev["id"]})
    return ev


# ---------------------------------------------------------------- 5. read-only views for the CCOR console
def hash_status(base_dir=".", db_path=None, public_key_path=None):
    """VERIFIED = current manifest.yaml + tools.py match the latest SIGNED 2LoD approval.
    TAMPERED = they differ (changed since 2LoD attested). UNATTESTED = nothing signed to compare to."""
    from cryptography.exceptions import InvalidSignature
    base = Path(base_dir)
    db = db_path or base / "audit.db"
    system_id, _ = _current_ids(base)
    m, t, c = file_hashes(base / "manifest.yaml", base / "tools.py")
    out = {"status": "UNATTESTED", "current": {"manifest": m, "tools": t, "combined": c},
           "baseline": None, "changed": []}
    pub = _load_public_key(public_key_path or base / PUBLIC_KEY_FILE)
    conn = _connect(db)
    try:
        rows = conn.execute("SELECT * FROM mas_approvals WHERE system_id=? ORDER BY id DESC", (system_id,)).fetchall()
    finally:
        conn.close()
    for r in rows:
        if pub is None:
            break
        try:
            pub.verify(bytes.fromhex(r["signature"]), _payload(r["system_id"], r["combined_sha256"], r["rubric_sha256"],
                                                               r["computed_tier"], r["reviewer"], r["expires_at"]))
        except (InvalidSignature, ValueError):
            continue
        out["baseline"] = {"source": f"signed 2LoD approval #{r['id']} by {r['reviewer']}", "manifest": r["manifest_sha256"],
                           "tools": r["tools_sha256"], "combined": r["combined_sha256"]}
        out["changed"] = [f for f, cur, was in (("manifest.yaml", m, r["manifest_sha256"]), ("tools.py", t, r["tools_sha256"]))
                          if cur != was]
        out["status"] = "VERIFIED" if c == r["combined_sha256"] else "TAMPERED"
        break
    return out


def introspection_report(base_dir="."):
    """Non-raising 1LoD-declared vs 2LoD-introspected view for the console."""
    base = Path(base_dir)
    rep = {"errors": [], "declared": {}, "introspected": {}}
    try:
        manifest = yaml.safe_load((base / "manifest.yaml").read_text(encoding="utf-8")) or {}
    except Exception as err:
        rep["errors"].append(f"manifest.yaml unreadable: {err}")
        return rep
    prof = manifest.get("mas_use_case_profile") or {}
    rep["declared"] = {
        "declared_tool_count": prof.get("declared_tool_count"),
        "declared_tool_names": sorted(t.get("name", "?") for t in manifest.get("tools", []) or []),
        "human_oversight_mode": prof.get("human_oversight_mode"),
        "declared_inherent_risk": prof.get("declared_inherent_risk"),
    }
    try:
        names, functions = introspect_tools(base / "tools.py")
    except Exception as err:
        rep["errors"].append(f"tools.py introspection failed: {err}")
        return rep
    caps = rubric.classify_tools(names, functions, (base / "tools.py").read_text(encoding="utf-8"))
    over = introspect_oversight(base, caps)
    intro = {"tool_count": len(names), "tool_names": names, "capabilities": caps, "oversight": over,
             "scores": None, "computed_tier": None}
    try:
        profile = validate_profile(manifest)
        # 2LoD's view: score with what the code actually enforces, not what the developer claims
        profile = dict(profile, human_oversight_mode=over["mode"])
        intro["scores"] = rubric.score(profile, caps, rubric.is_third_party_model((manifest.get("model") or {}).get("provider")))
        intro["computed_tier"] = rubric.tier(intro["scores"], profile)
    except MASComplianceError as err:
        rep["errors"].append(str(err))
    rep["introspected"] = intro
    return rep


def boot_status(base_dir=".", db_path=None, public_key_path=None, now=None):
    """Same decision as gate_check() but read-only (no audit writes), so a dashboard refresh is harmless.
    status: APPROVED | PENDING_2LOD_APPROVAL | BLOCKED_CHALLENGE_FAILED | KILL_SWITCH_ACTIVE"""
    base = Path(base_dir)
    db = db_path or base / "audit.db"
    pub_path = public_key_path or base / PUBLIC_KEY_FILE
    out = {"status": "APPROVED", "reasons": [], "assessment": None, "approval": None,
           "kill_switch": kill_switch_state(db, pub_path), "decision": None}
    failed, pending = [], []
    try:
        a = assess(base_dir, db, log=False, now=now)
        out["assessment"] = a
    except MASComplianceError as err:
        failed.append(str(err))
        a = None
    except Exception as err:
        failed.append(f"gate error: {type(err).__name__}: {err}")
        a = None
    if a:
        dec = latest_decision(db, a["system_id"], a["combined_sha256"], pub_path)
        out["decision"] = dec[0] if dec else None
        ev_ok, ev_why = evidence.gate_status(base, now)
        if not ev_ok:
            failed.append("Required evidence is not current: " + "; ".join(ev_why))
        elif dec and dec[0] == "REJECT":
            failed.append(f"2LoD flagged an effective-challenge failure on this hash ({dec[1]['actor']}: {dec[2].get('reason')})")
        elif not registration_state(db, a)[0]:
            out["status_override"] = "NOT_REGISTERED"
            failed.append(registration_state(db, a)[1])
        elif a["computed_tier"] in rubric.APPROVAL_REQUIRED_TIERS:
            appr, reasons = find_active_approval(a, db, pub_path, now)
            if appr:
                out["approval"] = {"id": appr["id"], "reviewer": appr["reviewer"], "expires_at": appr["expires_at"]}
            else:
                pending.extend(reasons)
    if out["kill_switch"]["active"]:
        out["status"], out["reasons"] = "KILL_SWITCH_ACTIVE", [f"activated by {out['kill_switch']['activated_by']}: {out['kill_switch']['reason']}"]
    elif failed:
        out["status"] = out.pop("status_override", "BLOCKED_CHALLENGE_FAILED")
        out["reasons"] = failed
    elif pending:
        out["status"], out["reasons"] = "PENDING_2LOD_APPROVAL", pending
    else:
        out["reasons"] = ["basic governance path (tier does not require 2LoD approval)"] if not out["approval"] else \
            [f"2LoD approval #{out['approval']['id']} by {out['approval']['reviewer']} valid until {out['approval']['expires_at']}"]
    return out


def _uses_output_guard(path, attr):
    """True if the file really calls output_guard.<attr>(...) (AST, so comments and strings do not count)."""
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return False
    return any(isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "output_guard"
               and n.attr == attr for n in ast.walk(tree))


def control_readiness(base_dir=".", db_path=None, public_key_path=None):
    """Pass/fail checks for the 2LoD control readiness panel."""
    base = Path(base_dir)
    checks = []
    try:
        manifest = yaml.safe_load((base / "manifest.yaml").read_text(encoding="utf-8")) or {}
    except Exception:
        manifest = {}
    owner = str((manifest.get("mas_use_case_profile") or {}).get("kill_switch_owner") or "").strip()
    checks.append({"id": "a", "name": "Kill-switch owner assigned", "passed": bool(owner),
                   "detail": owner or "kill_switch_owner is empty in manifest.yaml"})
    present = {f: (base / f).is_file() for f in ("guardrails.py", "output_guard.py")}
    wired_answer = _uses_output_guard(base / "agent.py", "scan")
    wired_email = _uses_output_guard(base / "dispatcher.py", "is_sensitive")
    checks.append({"id": "b", "name": "Input and output guards present and wired (guardrails.py, output_guard.py)",
                   "passed": all(present.values()) and wired_answer and wired_email,
                   "detail": "; ".join([f"{f}: {'present' if ok else 'MISSING'}" for f, ok in present.items()] + [
                       "answer scan in agent.py: " + ("wired" if wired_answer else "NOT WIRED"),
                       "email-body block in dispatcher.py: " + ("wired" if wired_email else "NOT WIRED")])})
    try:
        items = evidence.evaluate(base)
        ok, _ = evidence.gate_status(base)
        detail = "; ".join(f"{i['id']}: {i['status']} ({i['reason']})" for i in items)
    except evidence.EvidenceError as err:
        ok, detail = False, str(err)
    checks.append({"id": "c", "name": "Evidence is current and sufficient (red-team, within policy age limit)",
                   "passed": ok, "detail": detail})
    try:
        hs = hash_status(base, db_path, public_key_path)
        detail = {"VERIFIED": "matches " + hs["baseline"]["source"] if hs["baseline"] else "",
                  "TAMPERED": "changed since the last signed approval: " + ", ".join(hs["changed"]),
                  "UNATTESTED": "no signed 2LoD approval to compare against"}[hs["status"]]
        checks.append({"id": "d", "name": "Manifest + tools.py SHA-256 matches audit.db", "passed": hs["status"] == "VERIFIED",
                       "detail": detail})
    except Exception as err:
        checks.append({"id": "d", "name": "Manifest + tools.py SHA-256 matches audit.db", "passed": False, "detail": f"error: {err}"})
    try:
        ai = audit_integrity(base, db_path, public_key_path)
        failed_seals = [s["day"] for s in ai["seals"] if s["status"] == "FAILED"]
        ch = ai["chain"]
        ok = ch["status"] in ("INTACT", "EMPTY") and not failed_seals
        detail = (f"{ch['chained_rows']} chained row(s), {len(ai['seals'])} sealed day(s)" if ok else
                  "; ".join(filter(None, [f"chain {ch['status']}: {ch['reason']}" if ch["status"] not in ("INTACT", "EMPTY") else "",
                                          f"seal(s) failed: {', '.join(failed_seals)}" if failed_seals else ""])))
        checks.append({"id": "e", "name": "Main audit log hash chain and Merkle seals verify", "passed": ok, "detail": detail})
    except Exception as err:
        checks.append({"id": "e", "name": "Main audit log hash chain and Merkle seals verify", "passed": False, "detail": f"error: {err}"})
    return checks


def registry_record(base_dir=".", db_path=None):
    """Metadata for the MAS Section 4 asset registry panel."""
    base = Path(base_dir)
    db = db_path or base / "audit.db"
    manifest = yaml.safe_load((base / "manifest.yaml").read_text(encoding="utf-8")) or {}
    agent, prof, model = manifest.get("agent") or {}, manifest.get("mas_use_case_profile") or {}, manifest.get("model") or {}
    deps = []
    req = base / "requirements.txt"
    if req.exists():
        deps = [ln.strip() for ln in req.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    conn = _connect(db)
    try:
        row = conn.execute("SELECT ts FROM audit WHERE event='manifest_registered' ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    return {
        "system_id": prof.get("system_id") or agent.get("name"), "version": agent.get("version"),
        "owner": agent.get("owner"), "purpose": agent.get("purpose"), "environment": agent.get("environment"),
        "business_line": prof.get("business_line"), "kill_switch_owner": prof.get("kill_switch_owner"),
        "customer_facing": prof.get("customer_facing"), "data_sensitivity": prof.get("data_sensitivity"),
        "financial_impact_tier": prof.get("financial_impact_tier"), "architecture_type": prof.get("architecture_type"),
        "model": {"provider": model.get("provider"), "name": model.get("name"),
                  "third_party": rubric.is_third_party_model(model.get("provider")) if model.get("provider") else None,
                  "note": model.get("note")},
        "python_dependencies": deps, "last_registered": row["ts"] if row else None,
    }


# ---------------------------------------------------------------- 6. main audit log: chain, Merkle seals, proofs
def audit_integrity(base_dir=".", db_path=None, public_key_path=None):
    """Read-only integrity report for the hash-chained audit table and its signed daily Merkle roots."""
    base = Path(base_dir)
    return audit_chain.integrity_report(db_path or base / "audit.db", public_key_path or base / PUBLIC_KEY_FILE,
                                        base / audit_chain.ARTIFACT_DIR)


def seal_audit_day(reviewer, day, key_file=None, key_pem=None, allow_open=False, base_dir=".", db_path=None):
    """2LoD signs the Merkle root of one day of audit events. Needs the 2LoD private key."""
    reviewer = _need(reviewer, "reviewer")
    base = Path(base_dir)
    db = db_path or base / "audit.db"
    key = _load_private_key(key_file, key_pem, base / PUBLIC_KEY_FILE)
    system_id, _ = _current_ids(base_dir)
    conn = _connect(db)
    try:
        rec = audit_chain.seal_day(conn, day, key, reviewer, allow_open=allow_open)
    except audit_chain.AuditChainError as err:
        raise MASComplianceError(str(err))
    finally:
        conn.close()
    append_chain_event(db, reviewer, ACT_SEAL, system_id, {
        "day": rec["day"], "root": rec["root"], "leaf_count": rec["leaf_count"], "day_hash": rec["day_hash"]}, signing_key=key)
    return rec


def export_audit_day(day, base_dir=".", db_path=None):
    """Write the sealed day (events + seal + public key) to ccor-audit-artifacts/. Files are write-once."""
    base = Path(base_dir)
    conn = audit_chain.open_readonly(db_path or base / "audit.db")
    try:
        return audit_chain.export_day(conn, day, base / audit_chain.ARTIFACT_DIR, base / PUBLIC_KEY_FILE)
    except audit_chain.AuditChainError as err:
        raise MASComplianceError(str(err))
    finally:
        conn.close()


def audit_event_proof(event_id, base_dir=".", db_path=None, export=False):
    """Inclusion proof for one audit event against its sealed day, checked against the 2LoD public key."""
    base = Path(base_dir)
    conn = audit_chain.open_readonly(db_path or base / "audit.db")
    try:
        proof = audit_chain.inclusion_proof(conn, int(event_id))
    except (audit_chain.AuditChainError, ValueError) as err:
        raise MASComplianceError(str(err))
    finally:
        conn.close()
    result = audit_chain.check_proof(proof, audit_chain._load_pub(base / PUBLIC_KEY_FILE))
    path = audit_chain.export_proof(proof, base / audit_chain.ARTIFACT_DIR) if export else None
    return {"proof": proof, "result": result, "exported_to": path}


def registration_state(db_path, a):
    """(registered, reason). The inventory entry must exist for the CURRENT manifest.yaml + tools.py hashes."""
    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT detail FROM audit WHERE event='manifest_registered' ORDER BY id DESC").fetchall()
    finally:
        conn.close()
    for r in rows:
        try:
            d = json.loads(r["detail"])
        except ValueError:
            continue
        if d.get("agent") == a["system_id"] and d.get("manifest_sha256") == a["manifest_sha256"] \
                and d.get("tools_sha256") == a["tools_sha256"]:
            return True, ""
    return False, ("%s is not in the AI inventory for the current manifest.yaml + tools.py "
                   "(run: python resgister.py)" % a["system_id"])


# ---------------------------------------------------------------- startup gate (used by agent.py)
_PASS_LOGGED = set()


def gate_check(base_dir=".", db_path=None, public_key_path=None, now=None):
    """Raise MASComplianceError unless the agent may start. Recomputes everything every call."""
    base = Path(base_dir)
    db = db_path or base / "audit.db"
    pub_path = public_key_path or base / PUBLIC_KEY_FILE
    ks = kill_switch_state(db, pub_path)
    if ks["active"]:
        log_event(db, "mas_gate_blocked", {"reason": "emergency kill-switch active", "kill_switch": ks})
        raise MASComplianceError("EMERGENCY KILL-SWITCH ACTIVE (activated by %s at %s: %s). "
                                 "Only a signed 2LoD release can lift it." % (ks["activated_by"], ks["activated_at"], ks["reason"]))
    a = assess(base_dir, db, now=now)
    # Evidence the 2LoD policy marks as blocking must be current at EVERY tier. Residual-risk arithmetic alone
    # would only catch it for systems whose residual lands above the Board appetite.
    ev_ok, ev_why = evidence.gate_status(base, now)
    if not ev_ok:
        log_event(db, "mas_gate_blocked", {"system_id": a["system_id"], "reason": "required evidence is not current",
                                           "evidence": ev_why, "combined_sha256": a["combined_sha256"]})
        raise MASComplianceError("Required evidence is not current: " + "; ".join(ev_why))
    decision = latest_decision(db, a["system_id"], a["combined_sha256"], pub_path)
    if decision and decision[0] == "REJECT":
        log_event(db, "mas_gate_blocked", {"system_id": a["system_id"], "reason": "2LoD flagged effective challenge failure",
                                           "chain_id": decision[1]["id"], "combined_sha256": a["combined_sha256"]})
        raise MASComplianceError("2LoD flagged an effective-challenge failure on this exact manifest.yaml + tools.py by %s: %s"
                                 % (decision[1]["actor"], decision[2].get("reason")))
    registered, why = registration_state(db, a)
    if not registered:
        log_event(db, "mas_gate_blocked", {"system_id": a["system_id"], "reason": why,
                                           "combined_sha256": a["combined_sha256"]})
        raise MASComplianceError("AI inventory: " + why)
    if a["computed_tier"] in rubric.APPROVAL_REQUIRED_TIERS:
        approval, reasons = find_active_approval(a, db, pub_path, now)
        if approval is None:
            log_event(db, "mas_gate_blocked", {"system_id": a["system_id"], "tier": a["computed_tier"],
                                               "reasons": reasons, "combined_sha256": a["combined_sha256"]})
            raise MASComplianceError(
                "%s materiality requires an active 2LoD approval: %s" % (a["computed_tier"], "; ".join(reasons)))
        a["approval"] = {"id": approval["id"], "reviewer": approval["reviewer"], "expires_at": approval["expires_at"]}
    marker = (str(db), a["combined_sha256"])
    if marker not in _PASS_LOGGED:
        _PASS_LOGGED.add(marker)
        log_event(db, "mas_gate_passed", {"system_id": a["system_id"], "tier": a["computed_tier"],
                                          "scores": a["scores"], "approval": a.get("approval"),
                                          "combined_sha256": a["combined_sha256"]})
    return a


# ---------------------------------------------------------------- registration + CLI
def register(base_dir=".", db_path=None):
    db = db_path or Path(base_dir) / "audit.db"
    a = assess(base_dir, db)
    log_event(db, "manifest_registered", {
        "agent": a["system_id"], "version": a["version"], "model": a["model"], "tools": a["tools"],
        "sha256_prefix": a["manifest_sha256"][:16], "tools_sha256_prefix": a["tools_sha256"][:16],
        "manifest_sha256": a["manifest_sha256"], "tools_sha256": a["tools_sha256"],
        "computed_tier": a["computed_tier"], "residual_tier": a["residual_tier"], "scores": a["scores"], "rubric_version": a["rubric_version"]},
        trace_id="manifest")
    return a


def _print_assessment(a):
    print(f"{a['system_id']}  tools={a['tools']}")
    print(f"scores {a['scores']} -> {a['computed_tier']} (declared {a['declared_tier']})")
    print(f"manifest {a['manifest_sha256'][:16]}  tools {a['tools_sha256'][:16]}  rubric {a['rubric_version']}")


def main(argv=None):
    p = argparse.ArgumentParser(description="MAS Section 4 registration and 2LoD sign-off")
    p.add_argument("--approve", action="store_true", help="2LoD: sign off the current manifest.yaml + tools.py")
    p.add_argument("--reviewer", help="2LoD reviewer name, e.g. VP_CCOR")
    p.add_argument("--key-file", help="2LoD private key (PEM). Never commit this file.")
    p.add_argument("--days", type=int, default=90, help="approval validity in days (default 90)")
    p.add_argument("--status", action="store_true", help="show tier and approval state")
    p.add_argument("--gen-keys", metavar="PRIVATE_PEM", help="2LoD: create an Ed25519 keypair")
    p.add_argument("--verify-audit", action="store_true", help="verify the audit hash chain and all sealed days")
    p.add_argument("--seal-day", metavar="YYYY-MM-DD", help="2LoD: sign the Merkle root of one day (needs --reviewer, --key-file)")
    p.add_argument("--allow-open", action="store_true", help="allow --seal-day on a day that is not over yet")
    p.add_argument("--export-day", metavar="YYYY-MM-DD", help="write a sealed day to ccor-audit-artifacts/")
    args = p.parse_args(argv)
    try:
        if args.gen_keys:
            generate_keys(args.gen_keys)
            print(f"wrote {args.gen_keys} (keep with 2LoD only) and {PUBLIC_KEY_FILE} (commit it)")
        elif args.verify_audit:
            ai = audit_integrity()
            ch = ai["chain"]
            print(f"chain {ch['status']}: {ch['chained_rows']} chained, {ch['legacy_rows']} pre-chain rows, head {ch['head'][:16]}")
            if ch["reason"]:
                print(" -", ch["reason"], f"(row {ch['broken_at']})" if ch["broken_at"] else "")
            for s in ai["seals"]:
                print(f"  {s['day']}  {s['leaf_count']} events  root {s['root'][:16]}  {s['status']}", *s["problems"])
            for u in ai["unsealed"]:
                print(f"  {u['day']}  {u['events']} events  NOT SEALED" + ("  (day still open)" if u["open"] else ""))
            if not ch["ok"] or any(s["status"] == "FAILED" for s in ai["seals"]):
                sys.exit(1)
        elif args.seal_day:
            if not args.key_file:
                raise MASComplianceError("--seal-day needs --key-file (the 2LoD private key)")
            rec = seal_audit_day(args.reviewer, args.seal_day, key_file=args.key_file, allow_open=args.allow_open)
            print(f"sealed {rec['day']}: {rec['leaf_count']} events, Merkle root {rec['root']}")
        elif args.export_day:
            res = export_audit_day(args.export_day)
            print("evidence pack in", res["directory"], "->", ", ".join(Path(f).name for f in res["files"]))
        elif args.approve:
            if not args.key_file:
                raise MASComplianceError("--approve needs --key-file (the 2LoD private key)")
            print("approval recorded, id", approve(args.reviewer, args.key_file, args.days))
        elif args.status:
            a = assess()
            _print_assessment(a)
            appr, reasons = find_active_approval(a, Path("audit.db"), Path(PUBLIC_KEY_FILE))
            print("2LoD approval:", f"active #{appr['id']} by {appr['reviewer']} until {appr['expires_at']}"
                  if appr else "NONE - " + "; ".join(reasons))
        else:
            a = register()
            _print_assessment(a)
            print("Registered", a["system_id"], "fingerprint", a["manifest_sha256"][:16])
    except MASComplianceError as err:
        print("BLOCKED:", err)
        sys.exit(1)


if __name__ == "__main__":
    main()
