import sqlite3
import json

EVENTS = ("policy_decision", "approval", "injection_flagged", "input_blocked")

db = sqlite3.connect("audit.db")
placeholders = ",".join("?" * len(EVENTS))
rows = db.execute(
    f"SELECT ts, trace_id, event, detail FROM audit "
    f"WHERE event IN ({placeholders}) ORDER BY id",
    EVENTS,
)

for ts, trace, event, detail in rows:
    d = json.loads(detail)

    if event == "policy_decision":
        print(ts, trace, "POLICY    ", d["tool"], d["decision"], "-", d["reason"])

    elif event == "approval":
        outcome = "approved" if d["approved"] else "DENIED"
        print(ts, trace, "APPROVAL  ", d["tool"], outcome, "by", d["approver"])

    elif event == "injection_flagged":
        print(ts, trace, "INJECTION ", d["tool"], "removed:", d["removed"])

    elif event == "input_blocked":
        print(ts, trace, "BLOCKED   ", "user input matched:", d["matched"])