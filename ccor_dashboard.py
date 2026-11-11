"""2LoD CCOR Governance Console (Streamlit).

Run from the repo root, bound to localhost:
    streamlit run ccor_dashboard.py --server.address 127.0.0.1

All decisions come from resgister.py (the same code the agent's startup gate uses), so what this
page shows is what the gate will do. Viewing is read-only: refreshing never writes to audit.db.

Actions:
  Approve Current Hash        needs the 2LoD private key (held in memory for the click only)
  Reject / Flag               open to the console: it can only make the system MORE restricted
  Activate Kill-Switch        open to the console, same reason; the gate refuses to boot while active
  Release Kill-Switch         needs the 2LoD private key: lifting a block must be provably 2LoD
Every action is appended to a SHA-256 hash chain (mas_2lod_events) and mirrored into audit.
Section 5 covers the main audit log: per-row hash chain, daily Merkle roots signed by 2LoD,
write-once evidence packs in ccor-audit-artifacts/, and per-event inclusion proofs.
  Seal Day                    needs the 2LoD private key (signs that day's Merkle root)
"""
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

import evidence
import resgister
from resgister import MASComplianceError

BASE = Path.cwd()  # same convention as audit.py / the rest of the repo: run from the repo root
DB = BASE / "audit.db"

STATUS_UI = {
    "APPROVED": ("success", "APPROVED: the agent may boot"),
    "PENDING_2LOD_APPROVAL": ("warning", "PENDING_2LOD_APPROVAL: the agent will refuse to boot until 2LoD approves this hash"),
    "BLOCKED_CHALLENGE_FAILED": ("error", "BLOCKED_CHALLENGE_FAILED: the agent will refuse to boot"),
    "NOT_REGISTERED": ("error", "NOT_REGISTERED: the agent is not in the AI inventory for this exact manifest + tools hash; it will refuse to boot"),
    "KILL_SWITCH_ACTIVE": ("error", "KILL_SWITCH_ACTIVE: the agent will refuse to boot until 2LoD releases it"),
}


def short(h, n=12):
    return (h[:n] + "...") if h else "-"


def fmt(v):
    if v is None:
        return "-"
    if isinstance(v, (list, tuple)):
        return ", ".join(map(str, v)) or "(none)"
    return str(v)


def flash():
    kind, msg = st.session_state.pop("flash", (None, None))
    if kind == "success":
        st.success(msg)
    elif kind == "error":
        st.error(msg)


def act(fn, ok_msg):
    """Run a 2LoD action, remember the outcome for the next render, then rerun."""
    try:
        result = fn()
        st.session_state["flash"] = ("success", ok_msg(result))
    except MASComplianceError as err:
        st.session_state["flash"] = ("error", f"Refused: {err}")
    except Exception as err:  # keep the console alive on unexpected errors
        st.session_state["flash"] = ("error", f"Unexpected error: {type(err).__name__}: {err}")
    st.rerun()


# ------------------------------------------------------------------ sections
def section_registry(rec, boot, hs, ai):
    st.header("1. MAS Section 4 AI Asset Registry")
    kind, text = STATUS_UI.get(boot["status"], ("error", boot["status"]))
    getattr(st, kind)(f"Boot gate: {text}")
    for reason in boot["reasons"]:
        st.caption(reason)

    left, right = st.columns(2)
    with left:
        st.subheader("Registered system")
        meta = {
            "System ID": rec["system_id"], "Version": rec["version"], "Owner (1LoD)": rec["owner"],
            "Business line": rec["business_line"], "Purpose": rec["purpose"], "Environment": rec["environment"],
            "Architecture": rec["architecture_type"], "Data sensitivity": rec["data_sensitivity"],
            "Financial impact": rec["financial_impact_tier"], "Customer facing": rec["customer_facing"],
            "Kill-switch owner": rec["kill_switch_owner"] or "NOT ASSIGNED",
            "Last registered": rec["last_registered"] or "never",
        }
        st.dataframe(pd.DataFrame({"Field": list(meta), "Value": [fmt(v) for v in meta.values()]}), hide_index=True)
    with right:
        st.subheader("Integrity")
        if hs["status"] == "VERIFIED":
            st.success("SHA-256: VERIFIED. manifest.yaml + tools.py match " + hs["baseline"]["source"])
        elif hs["status"] == "TAMPERED":
            st.error("SHA-256: TAMPERED. Changed since the last signed 2LoD approval: " + ", ".join(hs["changed"]))
            st.caption("Baseline: " + hs["baseline"]["source"])
        else:
            st.warning("SHA-256: UNATTESTED. No signed 2LoD approval exists to compare against yet.")
        ch = ai["chain"]
        if ch["status"] == "INTACT":
            st.success(f"Audit log hash chain: INTACT ({ch['chained_rows']} chained rows)")
        elif ch["status"] == "EMPTY":
            st.info("Audit log hash chain: no events yet")
        else:
            st.error(f"Audit log hash chain: {ch['status']}. {ch['reason'] or ''}")
        with st.expander("Hashes"):
            st.code(f"manifest.yaml  {hs['current']['manifest']}\ntools.py       {hs['current']['tools']}\n"
                    f"combined       {hs['current']['combined']}")
            if hs["baseline"]:
                st.code(f"approved manifest  {hs['baseline']['manifest']}\napproved tools     {hs['baseline']['tools']}\n"
                        f"approved combined  {hs['baseline']['combined']}")
        a = boot["assessment"]
        if a:
            c1, c2 = st.columns(2)
            c1.metric("Inherent risk (2LoD computed)", a["computed_tier"])
            c2.metric("Residual risk (after verified controls)", a["residual_tier"],
                      help="Board appetite: residual must not exceed " + a["risk_appetite_max_residual"])
            st.caption("Mitigations verified from code on every boot: " + ", ".join(
                f"{k} {'yes' if v else 'NO'}" for k, v in a["mitigations"].items()))
            if boot["approval"]:
                st.caption(f"Approval #{boot['approval']['id']} by {boot['approval']['reviewer']}, "
                           f"valid until {boot['approval']['expires_at'][:10]}")

    st.subheader("Third-party dependencies")
    m = rec["model"]
    st.dataframe(pd.DataFrame([{
        "Component": "LLM", "Provider": fmt(m["provider"]), "Name": fmt(m["name"]),
        "Third party": "YES" if m["third_party"] else "no", "Note": fmt(m["note"])}]), hide_index=True)
    with st.expander(f"Python packages ({len(rec['python_dependencies'])})"):
        st.write(", ".join(rec["python_dependencies"]) or "requirements.txt not found")


def comparison_rows(rep):
    d, i = rep["declared"], rep["introspected"]
    over = i.get("oversight") or {}
    rows = []

    def add(attr, declared, actual, evidence):
        ok = actual is not None and declared == actual
        rows.append({"Attribute": attr, "1LoD declared (manifest.yaml)": fmt(declared),
                     "2LoD introspected / computed": fmt(actual), "Evidence": evidence,
                     "Match": "match" if ok else "MISMATCH"})

    add("declared_tool_count", d.get("declared_tool_count"), i.get("tool_count"), "len(TOOL_FUNCTIONS) in tools.py")
    add("tool names", d.get("declared_tool_names"), i.get("tool_names"), "TOOL_FUNCTIONS vs manifest tools[]")
    add("human_oversight_mode", d.get("human_oversight_mode"), over.get("mode"),
        ("approval.py human prompt: %s; dispatcher approval-gated: %s; auto-allowed: %s" % (
            "yes" if over.get("approval_mechanism") else "NO", fmt(over.get("approval_tools")),
            fmt(over.get("tools_without_approval")))) if over else "tools.py could not be introspected")
    add("declared_inherent_risk", d.get("declared_inherent_risk"), i.get("computed_tier"),
        "locked rubric in mas_rubric.py")
    return rows


def section_comparison(rep):
    st.header("2. 1LoD Declaration vs. 2LoD Code Introspection")
    for err in rep["errors"]:
        st.error(err)
    rows = comparison_rows(rep)
    df = pd.DataFrame(rows)
    st.dataframe(df.style.apply(
        lambda r: ["background-color: #ffd6d6; color: #8a0000; font-weight: 600" if r["Match"] == "MISMATCH" else ""] * len(r),
        axis=1), hide_index=True)
    bad = [r["Attribute"] for r in rows if r["Match"] == "MISMATCH"]
    if bad:
        st.error("Discrepancies (the startup gate will reject these): " + ", ".join(bad))
    else:
        st.success("No discrepancies between the 1LoD declaration and the 2LoD introspection.")

    i = rep["introspected"]
    st.subheader("2LoD-computed MAS materiality scores (1-5)")
    if i.get("scores"):
        c1, c2, c3 = st.columns(3)
        c1.metric("Impact", i["scores"]["impact"])
        c2.metric("Complexity", i["scores"]["complexity"])
        c3.metric("Reliance", i["scores"]["reliance"])
    else:
        st.warning("Scores could not be computed (see errors above).")
    if i.get("capabilities"):
        gated = set((i.get("oversight") or {}).get("approval_tools", []))
        st.dataframe(pd.DataFrame([{"Tool": t, "2LoD capability class": c,
                                    "Human approval path in dispatcher": "yes" if t in gated else "no"}
                                   for t, c in i["capabilities"].items()]), hide_index=True)


def section_readiness(checks):
    st.header("3. 2LoD Control Readiness Check")
    passed = sum(1 for c in checks if c["passed"])
    st.metric("Controls ready", f"{passed} / {len(checks)}")
    for c in checks:
        icon, colour = ("PASS", "green") if c["passed"] else ("FAIL", "red")
        st.markdown(f":{colour}[**{icon}**] ({c['id']}) **{c['name']}**: {c['detail']}")
    try:
        items = evidence.evaluate(BASE)
        st.subheader("Evidence register (policy/evidence_policy.yaml)")
        st.dataframe(pd.DataFrame([{
            "Evidence": i["id"], "Status": i["status"], "Controls": ", ".join(i["controls"]),
            "Blocks gate": "yes" if i["blocks_gate"] else "no", "Age (days)": i["age_days"],
            "Expires": (i["expires_at"] or "-")[:10], "Detail": i["reason"]} for i in items]), hide_index=True)
    except evidence.EvidenceError as err:
        st.error(f"Evidence policy could not be read: {err}")


def section_actions(boot, chain_check):
    st.header("4. 2LoD Action Controls")
    reviewer = st.session_state.get("reviewer", "").strip()
    key_file = st.session_state.get("key_upload")
    key_pem = key_file.getvalue() if key_file is not None else None
    if not reviewer:
        st.info("Enter the reviewer name in the sidebar to enable actions.")
    if boot["kill_switch"]["active"]:
        ks = boot["kill_switch"]
        st.error(f"EMERGENCY KILL-SWITCH ACTIVE since {ks['activated_at'][:19]} by {ks['activated_by']}: {ks['reason']}")
    if boot["kill_switch"]["ignored_releases"]:
        st.warning("Unsigned or forged release events were ignored: chain ids %s" % boot["kill_switch"]["ignored_releases"])

    reason = st.text_area("Reason / effective-challenge note (required for Reject, Kill-Switch and Release)")
    days = st.number_input("Approval validity (days)", min_value=1, max_value=365, value=90)
    confirm = st.checkbox("I confirm the kill-switch will stop the agent from booting for everyone")
    ready = bool(reviewer)

    c1, c2, c3, c4 = st.columns(4)
    if c1.button("Approve Current Hash", disabled=not ready):
        act(lambda: resgister.approve(reviewer, days=int(days), base_dir=BASE, db_path=DB, key_pem=key_pem),
            lambda i: f"Approval #{i} recorded, signed and chained for the current manifest.yaml + tools.py hash.")
    if c2.button("Reject / Flag Effective Challenge Failure", disabled=not ready):
        act(lambda: resgister.flag_challenge_failure(reviewer, reason, base_dir=BASE, db_path=DB),
            lambda ev: f"Effective-challenge failure flagged (chain event #{ev['id']}). The gate now blocks this hash.")
    if c3.button("Activate Emergency Kill-Switch", disabled=not (ready and confirm)):
        act(lambda: resgister.activate_kill_switch(reviewer, reason, base_dir=BASE, db_path=DB),
            lambda ev: f"KILL-SWITCH ACTIVATED (chain event #{ev['id']}). The agent will not boot.")
    if c4.button("Release Kill-Switch", disabled=not (ready and boot["kill_switch"]["active"])):
        act(lambda: resgister.release_kill_switch(reviewer, reason, key_pem=key_pem, base_dir=BASE, db_path=DB),
            lambda ev: f"Kill-switch released with a signed 2LoD event (chain event #{ev['id']}).")
    st.caption("Approve and Release need the 2LoD private key (sidebar). Reject and Kill-Switch need no key: "
               "they can only make the system more restricted.")

    st.subheader("2LoD console event chain (separate from the main audit log in section 5)")
    if chain_check["ok"]:
        st.success(f"2LoD event chain intact: {chain_check['count']} event(s). Head {short(chain_check['head'], 16)}. "
                   "This covers console actions only; see section 5 for the main audit log.")
    else:
        st.error(f"CHAIN BROKEN at event #{chain_check['broken_at']}: audit.db was altered after the fact.")
    events = resgister.chain_events(DB, limit=15)
    if events:
        st.dataframe(pd.DataFrame([{
            "#": e["id"], "Time (UTC)": e["ts"][:19], "Actor": e["actor"], "Action": e["action"],
            "Signed": "yes" if e["signature"] else "no", "Prev hash": short(e["prev_hash"], 10),
            "Event hash": short(e["event_hash"], 10)} for e in reversed(events)]), hide_index=True)
    else:
        st.caption("No 2LoD console events yet.")


def section_audit(ai):
    st.header("5. Main audit log integrity: hash chain and Merkle roots")
    st.caption("Protects every agent event in the audit table (user input, tool decisions, answers, gate events). "
               "Separate from the 2LoD event chain in section 4.")
    chain = ai["chain"]
    if chain["status"] == "INTACT":
        st.success(f"Hash chain INTACT: all {chain['chained_rows']} chained row(s) link and recompute.")
    elif chain["status"] == "EMPTY":
        st.info("The audit log has no events yet.")
    elif chain["status"] == "BROKEN":
        st.error(f"HASH CHAIN BROKEN at row #{chain['broken_at']}: {chain['reason']}")
    else:
        st.warning(f"Hash chain {chain['status']}: {chain['reason']}")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total rows", chain["rows"])
    m2.metric("Hash-chained rows", chain["chained_rows"])
    m3.metric("Pre-chain rows (sealed by digest)", chain["legacy_rows"])
    m4.metric("Sealed days", len(ai["seals"]))
    st.caption("Head of the chain (record it somewhere the developer cannot write; sealing a day signs it for you):")
    st.code(chain["head"])

    st.subheader("Daily Merkle roots (signed by 2LoD)")
    if ai["seals"]:
        df = pd.DataFrame([{
            "Day": s["day"], "Events": s["leaf_count"], "Merkle root": short(s["root"], 16),
            "Previous day root": short(s["prev_root"], 10), "Sealed by": s["sealer"], "Sealed at (UTC)": s["sealed_at"][:19],
            "Status": s["status"] if not s["problems"] else "FAILED: " + "; ".join(s["problems"]),
            "Late rows": s["late_rows"], "Exported": "yes" if ai["exported"].get(s["day"]) else "no"} for s in ai["seals"]])
        st.dataframe(df.style.apply(
            lambda r: ["background-color: #ffd6d6; color: #8a0000; font-weight: 600" if str(r["Status"]).startswith("FAILED") else ""] * len(r),
            axis=1), hide_index=True)
        if any(s["late_rows"] for s in ai["seals"]):
            st.warning("Some sealed days have late rows: events written after the seal. They are chained but not covered "
                       "by that day's signed root.")
    else:
        st.caption("No day has been sealed yet.")
    if ai["unsealed"]:
        st.caption("Not sealed yet: " + ", ".join(f"{u['day']} ({u['events']} events{', day still open' if u['open'] else ''})"
                                                  for u in ai["unsealed"]))

    reviewer = st.session_state.get("reviewer", "").strip()
    key_file = st.session_state.get("key_upload")
    key_pem = key_file.getvalue() if key_file is not None else None
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**Seal a day**")
        options = [u["day"] for u in ai["unsealed"]]
        if options:
            day = st.selectbox("Day to seal", options, key="seal_day_choice")
            allow_open = st.checkbox("Allow sealing a day that is still open (later events become late rows)")
            if st.button("Seal day (needs 2LoD key)", disabled=not reviewer):
                act(lambda: resgister.seal_audit_day(reviewer, day, key_pem=key_pem, allow_open=allow_open, base_dir=BASE, db_path=DB),
                    lambda r: f"Sealed {r['day']}: {r['leaf_count']} events, Merkle root {short(r['root'], 16)}, signed and chained.")
        else:
            st.caption("Every day with events is sealed.")
    with c2:
        st.markdown("**Export evidence pack**")
        sealed = [s["day"] for s in ai["seals"]]
        if sealed:
            eday = st.selectbox("Day to export", list(reversed(sealed)), key="export_day_choice")
            if st.button("Export to ccor-audit-artifacts/"):
                act(lambda: resgister.export_audit_day(eday, base_dir=BASE, db_path=DB),
                    lambda r: ("Wrote " + ", ".join(r["newly_written"]) if r["newly_written"] else "Already exported, identical files")
                    + f" in {r['directory']} (write-once).")
            st.caption("An auditor checks it offline: python audit_chain.py verify-pack ccor-audit-artifacts YYYY-MM-DD")
        else:
            st.caption("Seal a day first.")
    with c3:
        st.markdown("**Prove one event is genuine**")
        event_id = st.number_input("Audit event id", min_value=1, value=1, step=1)
        if st.button("Verify inclusion"):
            try:
                out = resgister.audit_event_proof(int(event_id), BASE, DB)
                res, proof = out["result"], out["proof"]
                (st.success if res["ok"] else st.error)(
                    f"Event {proof['event']['id']} ({proof['event']['event']}) on {proof['seal']['day']}: "
                    + ("proven part of the signed Merkle root" if res["ok"] else "PROOF FAILED"))
                st.dataframe(pd.DataFrame([{"Check": k, "Result": "pass" if v else "FAIL"} for k, v in res["checks"].items()]),
                             hide_index=True)
                st.caption(f"{len(proof['path'])} sibling hash(es) cover a day of {proof['tree_size']} events:")
                st.dataframe(pd.DataFrame([{"Level": i + 1, "Sibling hash": short(h, 16)} for i, h in enumerate(proof["path"])]),
                             hide_index=True)
            except MASComplianceError as err:
                st.error(f"No proof: {err}")
        if st.button("Save proof file for this event"):
            act(lambda: resgister.audit_event_proof(int(event_id), BASE, DB, export=True),
                lambda o: f"Proof written to {o['exported_to']} (write-once).")

    with st.expander("How the two layers work, and what they do not cover"):
        st.markdown(
            "- **Hash chain:** every row's hash includes the previous row's hash, so editing, deleting or reordering a row "
            "breaks the chain from that point.\n"
            "- **Merkle root:** each day's event hashes are combined into one root that 2LoD signs. A reviewer can be given one "
            "event plus a handful of hashes and check it against the signed root, without seeing the rest of the log.\n"
            "- **Why both:** someone who edits a row and recomputes the whole chain still cannot reproduce a root that was "
            "already signed and exported.\n"
            "- **Not covered:** deleting the newest events before the day is sealed and exported, and anything before the "
            "chain was introduced (those rows are sealed by digest at migration, so they are protected only from then on). "
            "Keep the exported packs somewhere the developer cannot write.")


def section_recent_audit():
    with st.expander("Recent audit.db events"):
        try:
            conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
            rows = conn.execute("SELECT id, ts, trace_id, event, substr(detail, 1, 140) FROM audit "
                                "ORDER BY id DESC LIMIT 25").fetchall()
            conn.close()
            st.dataframe(pd.DataFrame(rows, columns=["id", "ts", "trace", "event", "detail"]), hide_index=True)
        except sqlite3.Error as err:
            st.caption(f"audit.db not readable yet: {err}")


# ------------------------------------------------------------------ page
def main():
    st.set_page_config(page_title="2LoD CCOR Governance Console", layout="wide")
    st.title("2LoD CCOR Governance Console")
    st.caption("MAS Guidelines on AI Risk Management, Section 4: inventory, materiality and 2LoD sign-off. "
               "Read from audit.db, manifest.yaml and resgister.py.")

    with st.sidebar:
        st.subheader("2LoD reviewer")
        st.text_input("Reviewer name", key="reviewer", placeholder="e.g. VP_CCOR")
        st.file_uploader("2LoD private key (PEM), only for Approve / Release", key="key_upload")
        st.caption("The key is read into memory for the click and never written to disk. "
                   "It is never needed to view this page.")
        st.button("Refresh")
        st.divider()
        st.caption(f"audit.db: {DB}")

    if not (BASE / "manifest.yaml").exists():
        st.error(f"manifest.yaml not found in {BASE}. Start Streamlit from the repo root.")
        return

    flash()
    try:
        rec = resgister.registry_record(BASE, DB)
        boot = resgister.boot_status(BASE, DB)
        hs = resgister.hash_status(BASE, DB)
        rep = resgister.introspection_report(BASE)
        checks = resgister.control_readiness(BASE, DB)
        chain_check = resgister.verify_chain(DB)
        ai = resgister.audit_integrity(BASE, DB)
    except Exception as err:
        st.error(f"Console could not load governance data: {type(err).__name__}: {err}")
        return

    section_registry(rec, boot, hs, ai)
    st.divider()
    section_comparison(rep)
    st.divider()
    section_readiness(checks)
    st.divider()
    section_actions(boot, chain_check)
    st.divider()
    section_audit(ai)
    section_recent_audit()


if __name__ == "__main__":
    main()
