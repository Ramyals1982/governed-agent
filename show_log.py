import sqlite3

db = sqlite3.connect("audit.db")
for row in db.execute("SELECT ts, trace_id, event, detail FROM audit ORDER BY id"):
    print(row)