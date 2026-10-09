import sqlite3
import json
import time

db = sqlite3.connect("audit.db")
db.execute("""CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    trace_id TEXT,
    event TEXT,
    detail TEXT)""")
db.commit()

def log(trace_id, event, detail):
    db.execute(
        "INSERT INTO audit (ts, trace_id, event, detail) VALUES (?,?,?,?)",
        (time.strftime("%Y-%m-%d %H:%M:%S"), trace_id, event, json.dumps(detail)),
    )
    db.commit()