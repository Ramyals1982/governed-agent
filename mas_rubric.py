"""MAS AIRM Section 4 - LOCKED 2LoD scoring rubric.

OWNERSHIP: this file belongs to the Second Line (CCOR). First-line developers must not
edit it. Enforce that with CODEOWNERS / branch protection (or ship it as a separately
owned package). Any change to this file changes rubric_sha256(), which invalidates every
existing 2LoD approval, so a quiet edit cannot be used to re-score an approved system.

The calibration below is a placeholder. Replace the tables and thresholds with your
institution's approved methodology before relying on the tiers.

Scores are 1-5 per dimension: Impact, Complexity, Reliance.
"""
import ast
import hashlib
from pathlib import Path

RUBRIC_VERSION = "2LoD-MAS-S4-v1"

# Tiers that must hold a valid 2LoD approval before the agent may start.
# MAS AIRM s4: only LOW materiality may use "Basic Governance"; MEDIUM and HIGH need 2LoD sign-off.
APPROVAL_REQUIRED_TIERS = {"MEDIUM", "HIGH"}

# Board risk appetite: the highest RESIDUAL tier that may go live. Set by the Board / 2LoD, not by the builder.
# Editing this changes rubric_sha256(), which voids every earlier approval.
BOARD_RISK_APPETITE_MAX_RESIDUAL = "MEDIUM"

# Mitigations the code verifies on every boot. All must hold for residual to be one tier below inherent.
REQUIRED_MITIGATIONS = ("output_guard_on_answers", "output_guard_on_email", "human_approval_enforced",
                        "kill_switch_owner_assigned", "red_team_evidence")

FINANCIAL_IMPACT = {"NONE": 1, "ADVISORY": 2, "TRANSACTIONAL": 4}
DATA_SENSITIVITY = {"PUBLIC": 1, "INTERNAL": 2, "CONFIDENTIAL_PII": 4}
ARCHITECTURE_COMPLEXITY = {"RULE_BASED": 1, "RAG_LLM": 2, "AUTONOMOUS_AGENT": 4}
OVERSIGHT_RELIANCE = {"FULL_HUMAN_REVIEW": 1, "EXCEPTION_ONLY": 3, "AUTONOMOUS": 5}
RISK_TIERS = ("LOW", "MEDIUM", "HIGH")

# What each tool can DO, classified by the second line - not by the developer.
CAPABILITY_IMPACT = {"READ_ONLY": 1, "INTERNAL_WRITE": 2, "EXTERNAL_COMM": 3, "EXTERNAL_ACTION": 4}
TOOL_CAPABILITY = {
    "search_policies": "READ_ONLY",
    "create_ticket": "INTERNAL_WRITE",
    "send_email": "EXTERNAL_COMM",
}
# A tool the second line has not classified is scored as the worst case until it is.
UNCLASSIFIED_CAPABILITY = "EXTERNAL_ACTION"

# Evidence found in a tool's own source that it reaches outside the process.
RISKY_MODULES = {"smtplib", "requests", "httpx", "urllib", "http", "socket", "subprocess",
                 "os", "shutil", "ftplib", "paramiko", "boto3"}

INTERNAL_MODEL_PROVIDERS = {"internal", "self-hosted", "on-prem"}


def rubric_sha256():
    """Hash of this file plus policy/evidence_policy.yaml (line endings normalised) - pinned into every approval."""
    data = Path(__file__).read_bytes().replace(b"\r\n", b"\n")
    # The evidence policy (how fresh and how sufficient the evidence must be) is part of the locked rubric.
    policy = Path(__file__).resolve().parent / "policy" / "evidence_policy.yaml"
    if policy.is_file():
        data += b"\n--evidence_policy--\n" + policy.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def classify_tools(tool_names, tool_functions, tools_source):
    """Return {tool_name: capability}. Table lookup, escalated by risky-module evidence."""
    risky_funcs = set()
    try:
        tree = ast.parse(tools_source)
        aliases = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] in RISKY_MODULES:
                        aliases.add((a.asname or a.name).split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in RISKY_MODULES:
                    aliases.update(a.asname or a.name for a in node.names)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(isinstance(n, ast.Name) and n.id in aliases for n in ast.walk(node)):
                    risky_funcs.add(node.name)
    except SyntaxError:
        risky_funcs = set(tool_names)  # unreadable source: assume the worst

    caps = {}
    for name in tool_names:
        cap = TOOL_CAPABILITY.get(name, UNCLASSIFIED_CAPABILITY)
        fn = tool_functions.get(name)
        if getattr(fn, "__name__", name) in risky_funcs:
            cap = "EXTERNAL_ACTION"
        caps[name] = cap
    return caps


def is_third_party_model(model_provider):
    return str(model_provider).strip().lower() not in INTERNAL_MODEL_PROVIDERS


def score(profile, tool_caps, third_party_model):
    """Deterministic Impact / Complexity / Reliance from objective attributes."""
    fin = profile["financial_impact_tier"]
    sens = profile["data_sensitivity"]
    arch = profile["architecture_type"]
    oversight = profile["human_oversight_mode"]

    impact = max([FINANCIAL_IMPACT[fin], DATA_SENSITIVITY[sens]]
                 + [CAPABILITY_IMPACT[c] for c in tool_caps.values()])
    if profile["customer_facing"]:
        impact = max(impact, 3)
    if fin == "TRANSACTIONAL" and sens == "CONFIDENTIAL_PII":
        impact = 5

    complexity = ARCHITECTURE_COMPLEXITY[arch]
    if third_party_model:
        complexity += 1
    if len(tool_caps) >= 5:
        complexity += 1
    complexity = min(complexity, 5)

    reliance = OVERSIGHT_RELIANCE[oversight]
    if arch == "AUTONOMOUS_AGENT" and oversight != "FULL_HUMAN_REVIEW":
        reliance += 1
    reliance = min(reliance, 5)

    return {"impact": impact, "complexity": complexity, "reliance": reliance}


def residual_tier(inherent, mitigations):
    """Residual = inherent lowered by ONE tier, and only when every required mitigation is verified."""
    order = ["LOW", "MEDIUM", "HIGH"]
    missing = [m for m in REQUIRED_MITIGATIONS if not mitigations.get(m)]
    if missing:
        return inherent, missing
    return order[max(order.index(inherent) - 1, 0)], []


def within_appetite(residual):
    order = ["LOW", "MEDIUM", "HIGH"]
    return order.index(residual) <= order.index(BOARD_RISK_APPETITE_MAX_RESIDUAL)


def tier(scores, profile):
    total = sum(scores.values())
    t = "LOW" if total <= 6 else "MEDIUM" if total <= 10 else "HIGH"
    if scores["impact"] == 5:
        return "HIGH"
    # 2LoD policy: an autonomous agent touching client PII is never below HIGH.
    if profile["architecture_type"] == "AUTONOMOUS_AGENT" and \
            profile["data_sensitivity"] == "CONFIDENTIAL_PII":
        return "HIGH"
    if t == "LOW" and (scores["impact"] >= 4 or scores["reliance"] == 5):
        return "MEDIUM"
    return t
