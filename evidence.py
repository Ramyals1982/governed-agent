"""Evidence register with expiry: automated sufficiency judgement for the MAS Section 4 gate.

The builder produces evidence (a red-team run, a test run). The 2LoD owns policy/evidence_policy.yaml,
which says how fresh the evidence must be and what counts as sufficient. This module compares the two.

Status of each required item:
  ACCEPTED        record present, artifact unchanged, thresholds met, inside its validity window
  NEEDS_REVIEW    everything else is fine but the evidence is older than max_age_days (it expired)
  NEEDS_EVIDENCE  no record yet
  REJECTED        artifact missing or changed since it was recorded, or thresholds not met

Design points:
  * Metrics are recomputed from the artifact on every check. The numbers in the record are for display only.
  * The validity WINDOW comes from the policy (max_age_days), so the builder cannot lengthen it by editing
    the record. The start date (produced_at) is self-reported by the record.
  * Limit: records are not signed. Anyone who can write evidence/ can write an artifact and a matching
    record with today's date. In production the CI pipeline signs the record (docs/PATH_TO_PRODUCTION.md).

CLI:
  python evidence.py status [--strict | --all] [--json] [--as-of 2026-12-01T00:00:00+00:00]
    --strict  exit 1 unless every item that blocks the gate is ACCEPTED (what CI and the daily watch use)
    --all     exit 1 unless every item, including informational ones, is ACCEPTED
  python evidence.py record <item-id>
"""
import argparse
import datetime as dt
import getpass
import hashlib
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

import mas_rubric

ACCEPTED, NEEDS_REVIEW, NEEDS_EVIDENCE, REJECTED = "ACCEPTED", "NEEDS_REVIEW", "NEEDS_EVIDENCE", "REJECTED"
POLICY_PATH = Path(mas_rubric.__file__).resolve().parent / "policy" / "evidence_policy.yaml"
_CLOCK_SKEW = dt.timedelta(minutes=5)


class EvidenceError(Exception):
    pass


def _utcnow():
    return dt.datetime.now(dt.timezone.utc)


def _aware(ts):
    ts = dt.datetime.fromisoformat(ts) if isinstance(ts, str) else ts
    return ts if ts.tzinfo else ts.replace(tzinfo=dt.timezone.utc)


def load_policy(policy_path=None):
    path = Path(policy_path or POLICY_PATH)
    if not path.is_file():
        raise EvidenceError(f"evidence policy not found: {path.name}")
    policy = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    items = policy.get("items")
    if not isinstance(items, list) or not items:
        raise EvidenceError("evidence policy has no items")
    for it in items:
        for key in ("id", "kind", "artifact", "record", "max_age_days"):
            if key not in it:
                raise EvidenceError(f"evidence policy item {it.get('id', '?')} is missing '{key}'")
    return policy


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


# ------------------------------------------------------------------ artifact parsers (metrics are recomputed)
def parse_redteam_markdown(path):
    cases = attacks = caught = benign = false_pos = 0
    layers = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 5 or not cells[0].isdigit() or cells[2] not in ("attack", "benign"):
            continue
        cases += 1
        layers.add(cells[1])
        if cells[2] == "attack":
            attacks += 1
            caught += cells[4] == "CAUGHT"
        else:
            benign += 1
            false_pos += cells[4] == "FALSE POSITIVE"
    return {"cases": cases, "attacks": attacks, "caught": caught, "missed": attacks - caught,
            "catch_rate": round(caught / attacks, 4) if attacks else 0.0,
            "benign": benign, "false_positives": false_pos, "layers": sorted(layers)}


def parse_junit(path):
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    total = lambda a: sum(int(s.get(a, 0)) for s in suites)  # noqa: E731
    return {"tests": total("tests"), "failures": total("failures") + total("errors"), "skipped": total("skipped")}


PARSERS = {"redteam_markdown": parse_redteam_markdown, "junit": parse_junit}


def _sufficiency(metrics, req):
    """List of reasons the metrics fall short of the policy's requirements (empty = sufficient)."""
    why = []
    if "min_attacks" in req and metrics["attacks"] < req["min_attacks"]:
        why.append(f"only {metrics['attacks']} attack cases (need {req['min_attacks']})")
    if "min_catch_rate" in req and metrics["catch_rate"] < req["min_catch_rate"]:
        why.append(f"catch rate {metrics['catch_rate']:.0%} below {req['min_catch_rate']:.0%}")
    if "max_false_positives" in req and metrics["false_positives"] > req["max_false_positives"]:
        why.append(f"{metrics['false_positives']} benign requests wrongly blocked")
    if "layers" in req:
        absent = [layer for layer in req["layers"] if layer not in metrics["layers"]]
        if absent:
            why.append("no test cases for: " + ", ".join(absent))
    if "min_tests" in req and metrics["tests"] < req["min_tests"]:
        why.append(f"only {metrics['tests']} tests (need {req['min_tests']})")
    if "max_failures" in req and metrics["failures"] > req["max_failures"]:
        why.append(f"{metrics['failures']} failing tests")
    return why


# ------------------------------------------------------------------ evaluation
def _evaluate_item(base, item, now):
    out = {"id": item["id"], "title": item.get("title", item["id"]), "controls": item.get("controls", []),
           "blocks_gate": bool(item.get("blocks_gate", False)), "max_age_days": item["max_age_days"],
           "status": None, "reason": "", "produced_at": None, "expires_at": None, "age_days": None, "metrics": None}
    record_path, artifact_path = base / item["record"], base / item["artifact"]
    if not record_path.is_file():
        out.update(status=NEEDS_EVIDENCE, reason=f"no record: run the producer, then python evidence.py record {item['id']}")
        return out
    try:
        rec = json.loads(record_path.read_text(encoding="utf-8"))
        produced = _aware(rec["produced_at"])
    except (ValueError, KeyError, TypeError):
        out.update(status=REJECTED, reason="record is unreadable")
        return out
    expires = produced + dt.timedelta(days=item["max_age_days"])
    out.update(produced_at=produced.isoformat(), expires_at=expires.isoformat(),
               age_days=round((now - produced).total_seconds() / 86400, 1))
    if not artifact_path.is_file():
        out.update(status=REJECTED, reason=f"artifact {item['artifact']} is missing")
        return out
    if _sha256(artifact_path) != rec.get("artifact_sha256"):
        out.update(status=REJECTED, reason="artifact changed after it was recorded (hash mismatch)")
        return out
    if produced > now + _CLOCK_SKEW:
        out.update(status=REJECTED, reason="record is dated in the future")
        return out
    try:
        metrics = PARSERS[item["kind"]](artifact_path)
    except Exception as err:  # unreadable or wrong-format artifact
        out.update(status=REJECTED, reason=f"artifact could not be parsed: {type(err).__name__}")
        return out
    out["metrics"] = metrics
    short = _sufficiency(metrics, item.get("requires") or {})
    if short:
        out.update(status=REJECTED, reason="insufficient: " + "; ".join(short))
    elif now >= expires:
        out.update(status=NEEDS_REVIEW, reason=f"expired {expires.date()} (older than {item['max_age_days']} days)")
    else:
        out.update(status=ACCEPTED, reason=f"valid until {expires.date()}")
    return out


def evaluate(base_dir=".", now=None, policy_path=None):
    base, now = Path(base_dir), _aware(now) if now else _utcnow()
    return [_evaluate_item(base, it, now) for it in load_policy(policy_path)["items"]]


def gate_status(base_dir=".", now=None, policy_path=None):
    """(ok, reasons) for the items that block the gate. Fails closed if the policy cannot be read."""
    try:
        items = evaluate(base_dir, now, policy_path)
    except EvidenceError as err:
        return False, [str(err)]
    bad = [f"{i['id']}: {i['status']} ({i['reason']})" for i in items if i["blocks_gate"] and i["status"] != ACCEPTED]
    return not bad, bad


# ------------------------------------------------------------------ recording
def _producer():
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return "github-actions:%s run %s" % (os.environ.get("GITHUB_REPOSITORY", "?"), os.environ.get("GITHUB_RUN_ID", "?"))
    try:
        return "local:" + getpass.getuser()
    except Exception:
        return "local"


def record(base_dir, item_id, now=None, policy_path=None):
    """Fingerprint the artifact now and write its evidence record. Refuses an artifact that fails the thresholds."""
    base = Path(base_dir)
    item = next((i for i in load_policy(policy_path)["items"] if i["id"] == item_id), None)
    if item is None:
        raise EvidenceError(f"unknown evidence item '{item_id}'")
    artifact = base / item["artifact"]
    if not artifact.is_file():
        raise EvidenceError(f"{item['artifact']} not found. Run its producer first.")
    metrics = PARSERS[item["kind"]](artifact)
    short = _sufficiency(metrics, item.get("requires") or {})
    if short:
        raise EvidenceError("not recorded, evidence is insufficient: " + "; ".join(short))
    produced = _aware(now) if now else _utcnow()
    rec = {"id": item_id, "controls": item.get("controls", []), "artifact": item["artifact"],
           "artifact_sha256": _sha256(artifact), "produced_at": produced.isoformat(),
           "valid_until_informational": (produced + dt.timedelta(days=item["max_age_days"])).isoformat(),
           "producer": _producer(), "git_commit": os.environ.get("GITHUB_SHA"), "metrics": metrics}
    path = base / item["record"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return rec


# ------------------------------------------------------------------ CLI
def main(argv=None):
    p = argparse.ArgumentParser(description="Evidence register with expiry")
    sub = p.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("status", help="show the status of every required evidence item")
    st.add_argument("--strict", action="store_true", help="exit 1 unless every item that blocks the gate is ACCEPTED")
    st.add_argument("--all", action="store_true", help="exit 1 unless every item, informational ones included, is ACCEPTED")
    st.add_argument("--json", action="store_true")
    st.add_argument("--as-of", help="evaluate at this ISO timestamp instead of now (for demos and what-if checks)")
    rc = sub.add_parser("record", help="record the current artifact as evidence")
    rc.add_argument("item")
    args = p.parse_args(argv)
    try:
        if args.cmd == "record":
            rec = record(".", args.item)
            print(f"recorded {rec['id']}: {rec['artifact']} sha256 {rec['artifact_sha256'][:16]}, by {rec['producer']}")
            return 0
        items = evaluate(".", args.as_of)
    except EvidenceError as err:
        print("ERROR:", err)
        return 2
    if args.json:
        print(json.dumps(items, indent=2))
    else:
        for i in items:
            gate = "blocks gate" if i["blocks_gate"] else "informational"
            print(f"{i['status']:<15} {i['id']:<12} ({gate}) {i['reason']}")
    watched = items if args.all else [i for i in items if i["blocks_gate"]]
    return 1 if (args.strict or args.all) and any(i["status"] != ACCEPTED for i in watched) else 0


if __name__ == "__main__":
    sys.exit(main())
