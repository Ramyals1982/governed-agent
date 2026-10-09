from dispatcher import dispatch

state = {"tickets": 0}
args = {"to": "ramya.home@gmail.com", "body": "test"}

print("Run 1 - type y:")
print(dispatch("test0002", "send_email", args, state))

print("Run 2 - type n:")
print(dispatch("test0002", "send_email", args, state))