import getpass

def ask(tool, args):
    approver = getpass.getuser()
    print("\n" + "=" * 50)
    print("APPROVAL REQUIRED")
    print(f"Tool:      {tool}")
    print(f"Arguments: {args}")
    print("=" * 50)
    try:
        answer = input("Approve this action? (y/n): ").strip().lower()
    except EOFError:
        answer = "n"
    return answer == "y", approver