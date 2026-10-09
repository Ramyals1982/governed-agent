import re

OVERRIDE_PATTERNS = [
    r"ignore (all |any |your |the )*(previous |prior |above )*instructions",
    r"disregard (all |any |your |the )*(previous |prior |above )*(instructions|rules)",
    r"you are now\b",
    r"reveal (your |the )*(system )?prompt",
    r"new instructions\s*:",
    r"forget (what|everything|all)\b.{0,40}\b(told|instructed|said)",
    r"\b(act|respond|behave)\b.{0,20}\bwithout (any )?(limits|restrictions|rules)",
    r"\boverride (your |the |all )*(rules|instructions|safety|policy|policies)",
]

TOOL_ONLY_PATTERNS = [
    r"system note",
    r"note to (the )?assistant",
    r"after answering",
    r"\b(email|send|forward)\b.{0,60}@",
    r"\bwhen you (finish|are done|have finished)\b",
    r"\b(forward|send|email)\s+(every|all|each)\b",
    r"\bat\b.{0,30}\bdot\b",
]

USER_RULES = [re.compile(p, re.IGNORECASE) for p in OVERRIDE_PATTERNS]
TOOL_RULES = [re.compile(p, re.IGNORECASE) for p in OVERRIDE_PATTERNS + TOOL_ONLY_PATTERNS]


def scan_text(text, rules=USER_RULES):
    return [rule.pattern for rule in rules if rule.search(text)]


def sanitize_tool_result(result):
    if not isinstance(result, list):
        return result, []

    cleaned, removed = [], []
    for item in result:
        if not isinstance(item, str):
            cleaned.append(item)
            continue
        kept = []
        for sentence in re.split(r"(?<=[.!?])\s+", item):
            if scan_text(sentence, TOOL_RULES):
                removed.append(sentence)
            else:
                kept.append(sentence)
        if kept:
            cleaned.append(" ".join(kept))

    if removed and not cleaned:
        cleaned = ["[content withheld: possible prompt injection]"]
    return cleaned, removed