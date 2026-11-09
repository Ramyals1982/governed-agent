import json
import sqlite3

import audit_chain

db = sqlite3.connect("audit.db")
audit_chain.ensure_schema(db)   # creates the table, adds hash columns, seals older rows once, blocks edits/deletes


def log(trace_id, event, detail):
    """Append one row to the hash-chained audit log (each row's hash covers the previous row)."""
    audit_chain.append_event(db, trace_id, event, json.dumps(detail))
