import json
import uuid
from llm import chat
from tools import TOOL_SCHEMAS
from dispatcher import dispatch
from guardrails import redact
from injection import scan_text
import audit

SYSTEM_PROMPT = (
    "You are a security operations assistant. "
    "Use the tools when needed. Be brief."
)


def run_agent(user_message, max_steps=5):
    trace_id = str(uuid.uuid4())[:8]
    state = {"tickets": 0}

    clean_message, pii_found = redact(user_message)
    injection_hits = scan_text(clean_message)
    audit.log(trace_id, "user_input", {
        "text": clean_message,
        "pii_redacted": pii_found,
        "injection_flags": injection_hits,
    })
    if injection_hits:
        audit.log(trace_id, "input_blocked", {"matched": injection_hits})
        return "Request blocked: it looks like an attempt to override my instructions."

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": clean_message},
    ]

    for step in range(max_steps):
        response = chat(messages, tools=TOOL_SCHEMAS)
        audit.log(trace_id, "llm_call", {
            "returned_model": response.model,
            "tokens": response.usage.total_tokens if response.usage else None,
        })
        message = response.choices[0].message

        if not message.tool_calls:
            answer = message.content or "(model returned no text)"
            audit.log(trace_id, "final_answer", {"text": answer})
            return answer

        messages.append(message)

        for call in message.tool_calls:
            name = call.function.name
            args = json.loads(call.function.arguments)
            print(f"  -> tool requested: {name} {args}")
            audit.log(trace_id, "tool_requested", {"tool": name, "args": args})

            result = dispatch(trace_id, name, args, state)

            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": json.dumps(result),
            })

    audit.log(trace_id, "stopped", {"reason": "max_steps"})
    return "Stopped: too many steps."


if __name__ == "__main__":
    print(run_agent("What is our password policy?"))