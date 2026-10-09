import approval
import audit
import re
from injection import sanitize_tool_result
from tools import TOOL_FUNCTIONS


INTERNAL_DOMAIN = "example.com"
MAX_TICKETS_PER_REQUEST = 5


def decide(tool, args, state):
    if tool not in TOOL_FUNCTIONS:
        return "deny", "unknown tool"

    if tool == "search_policies":
        return "allow", "read-only tool"

    if tool == "create_ticket":
        if state["tickets"] >= MAX_TICKETS_PER_REQUEST:
            return "deny", "ticket limit reached for this request"
        return "allow", "within ticket limit"

    if tool == "send_email":
        recipient = str(args.get("to", "")).lower()
        if not re.fullmatch(r"[^@\s,;<>]+@[^@\s,;<>]+", recipient):
            return "deny", "malformed or multiple recipients"
        domain = recipient.rsplit("@", 1)[-1]
        if domain == INTERNAL_DOMAIN:
            return "allow", "internal recipient"
        return "approve", "external recipient needs human approval"

    return "deny", "no rule for this tool"


def dispatch(trace_id, name, args, state):
    decision, reason = decide(name, args, state)
    audit.log(trace_id, "policy_decision", {
        "tool": name, "args": args, "decision": decision, "reason": reason,
    })

    if decision == "deny":
        return {"error": f"Blocked by policy: {reason}"}

    if decision == "approve":
        approved, approver = approval.ask(name, args)
        audit.log(trace_id, "approval", {
            "tool": name, "args": args,
            "approved": approved, "approver": approver,
        })
        if not approved:
            return {"error": "Blocked: a human reviewer denied this action. Do not retry."}

    try:
        result = TOOL_FUNCTIONS[name](**args)
    except TypeError as err:
        audit.log(trace_id, "tool_error", {"tool": name, "error": str(err)})
        return {"error": "Tool called with invalid arguments"}

    result, removed = sanitize_tool_result(result)
    if removed:
        audit.log(trace_id, "injection_flagged", {"tool": name, "removed": removed})

    if name == "create_ticket":
        state["tickets"] += 1

    audit.log(trace_id, "tool_executed", {"tool": name, "result": result})
    return result