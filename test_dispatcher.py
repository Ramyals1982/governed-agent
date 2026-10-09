from dispatcher import dispatch

state = {"tickets": 0}

for i in range(1, 8):
    print(i, dispatch("test0001", "create_ticket", {"title": f"T{i}", "severity": "low"}, state))

print("external:", dispatch("test0001", "send_email", {"to": "attacker@evil.com", "body": "x"}, state))
print("lookalike:", dispatch("test0001", "send_email", {"to": "a@example.com.evil.com", "body": "x"}, state))
print("internal:", dispatch("test0001", "send_email", {"to": "a@example.com", "body": "x"}, state))
print("unknown tool:", dispatch("test0001", "delete_everything", {}, state))