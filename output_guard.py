"""C7: output guard. Checks text that is about to LEAVE the agent - the answer to the
user and the body of an outbound email - for secrets and personal data.

This is the control that was missing in Phase 3 (findings F-DISC and F-EMAIL-BODY): the
agent retrieved a confidential incident report and repeated an API key to the user, and
would have emailed it out. C1 only cleans the user's INPUT; nothing checked the OUTPUT.

Two uses:
  scan(text)      -> (redacted_text, findings)   for the answer to the user (redact, let the rest through)
  is_sensitive(t) -> bool                         for outbound email bodies (block the whole send)

Limit: this matches secret and PII PATTERNS. It does not understand confidential prose.
"""
import re

import guardrails

# Obvious machine secrets. Kept deliberately narrow so normal policy text is not flagged
# (for example "api-gateway" or "api_key_rotation" must pass).
SECRET_PATTERNS = [
    # Vendor-style keys: sk-..., pk-..., rk-... followed by a long token. Case-sensitive.
    ("API_KEY", re.compile(r"\b(?:sk|pk|rk)[-_][A-Za-z0-9\-_]{8,}\b")),
    # Assignments such as api_key=abc12345 or API-KEY: abc12345
    ("API_KEY", re.compile(r"\bapi[_-]?key\s*[:=]\s*\S{8,}", re.IGNORECASE)),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("BEARER", re.compile(r"\bBearer\s+[A-Za-z0-9\-_.]{10,}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
]

REDACTION = "[REDACTED]"


def scan(text):
    """Redact secrets and PII from text meant for the user. Returns (clean_text, findings)."""
    if not isinstance(text, str):
        return text, []

    findings = []
    clean = text
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(clean):
            findings.append(label)
            clean = pattern.sub(REDACTION, clean)

    # Reuse the PII detectors from C1 (phone, PAN, Aadhaar, card, etc.).
    clean, pii = guardrails.redact(clean)
    findings.extend(pii)

    return clean, sorted(set(findings))


def is_sensitive(text):
    """True if text carries a secret or PII - used to block an outbound email body."""
    _, findings = scan(text)
    return bool(findings)
