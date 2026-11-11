"""Fail the build if secrets or local state are about to be committed.

Checks every tracked file (git ls-files), or every file under the folder when it is not a git checkout:
  * no private key files (*.pem other than the 2LoD PUBLIC key), no PRIVATE_PEM, no .env
  * no local databases (*.db): audit.db holds agent traffic
  * no private key blocks or known credential shapes inside any text file

Usage: python scripts/check_repo_hygiene.py [folder]     exit 0 = clean, 1 = findings
"""
import re
import subprocess
import sys
from pathlib import Path

ALLOWED_FILES = {"mas_2lod_public.pem"}
FORBIDDEN_NAMES = [(re.compile(r"\.pem$", re.I), "key file"), (re.compile(r"^PRIVATE_PEM$"), "private key file"),
                   (re.compile(r"\.db$", re.I), "local database"), (re.compile(r"^\.env$"), ".env file"),
                   (re.compile(r"_private\.", re.I), "private key file")]
_BEGIN = "-----" + "BEGIN "
CONTENT_PATTERNS = [
    (re.compile(re.escape(_BEGIN) + r"(?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bsk-or-v1-[A-Za-z0-9]{20,}"), "OpenRouter API key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
]
# Fake keys that appear in the red-team and wiring tests on purpose (AWS's documented example, and an obvious placeholder).
ALLOWED_SNIPPETS = ("AKIAIOSFODNN7EXAMPLE", "AKIAABCDEFGHIJKLMNOP")
SKIP_DIRS = {".git", "venv", ".venv", "__pycache__", ".pytest_cache", "node_modules"}
SELF = Path(__file__).name


def list_files(root):
    root = Path(root)
    if (root / ".git").exists():
        try:
            out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
            return [root / p for p in out.decode().split("\0") if p]
        except (OSError, subprocess.CalledProcessError):
            pass
    return [p for p in root.rglob("*") if p.is_file() and not (set(p.relative_to(root).parts) & SKIP_DIRS)]


def scan(root="."):
    findings = []
    for path in list_files(root):
        if path.name in ALLOWED_FILES:
            continue
        for pattern, label in FORBIDDEN_NAMES:
            if pattern.search(path.name):
                findings.append((str(path), label))
        if path.name == SELF or path.suffix in {".png", ".jpg", ".zip", ".pyc"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern, label in CONTENT_PATTERNS:
            for m in pattern.finditer(text):
                if not any(a in m.group(0) for a in ALLOWED_SNIPPETS):
                    findings.append((str(path), label))
    return findings


def main(argv=None):
    root = (argv or sys.argv[1:] or ["."])[0]
    findings = scan(root)
    for path, label in findings:
        print(f"FOUND {label}: {path}")
    print("repo hygiene:", "FAIL" if findings else "clean")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
