"""Two-minute demo of the MAS Section 4 gate. Runs in a throw-away copy; nothing in your repo changes.

  python demo.py            run straight through
  python demo.py --pause    wait for Enter between acts (for presenting)

Act 1  an under-declared system is blocked          (effective challenge)
Act 2  an honest declaration still needs sign-off   (separation of duties)
Act 3  the 2LoD approves and the agent may start
Act 4  45 days later the evidence has expired       (the approval is still valid; the gate still stops)
Act 5  fresh evidence is recorded and it starts again

Evidence in this demo is a labelled synthetic fixture, not a real red-team run.
"""
import contextlib
import datetime as dt
import io
import shutil
import sys
import tempfile
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import evidence  # noqa: E402
import resgister  # noqa: E402
import support_fixtures  # noqa: E402
from resgister import MASComplianceError  # noqa: E402

PAUSE = "--pause" in sys.argv
T0 = dt.datetime(2026, 11, 10, 9, 0, tzinfo=dt.timezone.utc)


def day(n):
    return T0 + dt.timedelta(days=n)


def act(title):
    if PAUSE:
        input("\n[Enter] ")
    print("\n" + "=" * 78 + "\n" + title + "\n" + "=" * 78)


def say(text):
    print("  " + text)


def attempt(base, now):
    """Try to start the agent exactly as agent.py does, and print what happens."""
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            a = resgister.gate_check(base_dir=base, now=now)
        say(f"-> AGENT STARTS   inherent {a['computed_tier']}, residual {a['residual_tier']}")
        return True
    except MASComplianceError as err:
        text = str(err)
        say("-> AGENT REFUSES TO START")
        for line in textwrap.wrap(text, 88):
            say("   " + line)
        return False


def main():
    base = Path(tempfile.mkdtemp())
    try:
        for name in ("tools.py", "dispatcher.py", "approval.py", "agent.py", "llm.py", "manifest.yaml"):
            shutil.copy(HERE / name, base / name)
        support_fixtures.record_fixture_evidence(base, now=T0)
        key = base / "ccor_private.pem"
        resgister.generate_keys(key, base / resgister.PUBLIC_KEY_FILE)
        manifest = (base / "manifest.yaml").read_text(encoding="utf-8")
        honest = manifest

        act("ACT 1. The builder under-declares: 'LOW risk' for an autonomous agent that can send email")
        (base / "manifest.yaml").write_text(manifest.replace("declared_inherent_risk: HIGH", "declared_inherent_risk: LOW"), encoding="utf-8")
        attempt(base, day(0))
        say("The builder claimed LOW. The 2LoD rubric reads the code, scores it, and disagrees. The claim is logged as")
        say("2LoD_EFFECTIVE_CHALLENGE_FAILED in the audit chain.")

        act("ACT 2. Honest declaration. It is registered, but HIGH materiality needs the Second Line")
        (base / "manifest.yaml").write_text(honest, encoding="utf-8")
        resgister.register(base_dir=base)
        say("1LoD registered the system in the AI inventory for this exact manifest + tools hash.")
        attempt(base, day(0))

        act("ACT 3. The 2LoD (VP_CCOR) reviews and signs. Only they hold the private key")
        approval_id = resgister.approve("VP_CCOR", key, base_dir=base, now=day(0))
        say(f"Ed25519 approval #{approval_id} written, bound to the manifest, tools and rubric hashes, valid 90 days.")
        attempt(base, day(1))

        act("ACT 4. Day 45. The approval is still valid, but the red-team evidence is older than its 30-day limit")
        for item in evidence.evaluate(base, day(45)):
            if item["id"] == "redteam":
                say(f"evidence '{item['id']}': {item['status']} - {item['reason']}")
        attempt(base, day(45))
        say("No one had to notice. Residual risk went back up to HIGH, above the Board appetite, so it stopped.")

        act("ACT 5. The builder re-runs the red-team tests and records fresh evidence. No new approval is needed")
        evidence.record(base, "redteam", now=day(46))
        say("evidence record written (artifact hash, time, producer).")
        attempt(base, day(46))

        print("\nDone. Audit chain:", resgister.audit_integrity(base, base / "audit.db")["chain"]["status"])
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
