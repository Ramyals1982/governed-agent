# MAS Section 4 gate: how it works

Module 1 of a MAS AI Risk Management alignment. This is a reference implementation for a demo agent, not a certified compliance product. The calibration in `mas_rubric.py` is a placeholder that your institution would replace with its approved methodology.

## What the gate checks (every start, fail closed)

`agent.py` calls `resgister.gate_check()` before anything else. It raises `MASComplianceError` and the agent does not run unless all of these hold:

| # | Check | Blocked when |
|---|-------|--------------|
| 1 | Kill-switch | A kill-switch is active (lifting it needs the 2LoD key) |
| 2 | Objective intake | `mas_use_case_profile` in `manifest.yaml` is missing or invalid |
| 3 | Shadow capability | The tools in `tools.py` do not match `declared_tool_count` or the declared tools. `tools.py` may not import local modules, since the approval hash would not cover them |
| 4 | Shadow model | The `MODEL` in `llm.py` differs from `model.name` in the manifest |
| 5 | Oversight challenge | The declared `human_oversight_mode` differs from what `approval.py` and `dispatcher.py` really enforce |
| 6 | Effective challenge | The 2LoD rubric computes a different tier from `declared_inherent_risk` (logged as `2LoD_EFFECTIVE_CHALLENGE_FAILED`) |
| 7 | Residual risk | Residual risk is above the Board appetite (`BOARD_RISK_APPETITE_MAX_RESIDUAL` in `mas_rubric.py`) |
| 8 | Inventory | The agent is not registered for the current `manifest.yaml` + `tools.py` hashes |
| 9 | 2LoD sign-off | The tier is MEDIUM or HIGH and there is no valid, unexpired, Ed25519-signed approval for these hashes and this rubric version |
| 10 | 2LoD rejection | The 2LoD flagged an effective-challenge failure on this exact hash |

**Inherent and residual risk.** The inherent tier comes from the rubric (Impact, Complexity, Reliance, each 1 to 5). Residual risk is one tier lower only when the code verifies all of: output guard on answers, output guard on email, human approval enforced, kill-switch owner assigned, and red-team evidence present. If any is missing, residual equals inherent, and for a HIGH system that is above the appetite, so it does not start. Removing a control after sign-off therefore blocks the next start.

**Only LOW qualifies for basic governance.** MEDIUM and HIGH both need 2LoD sign-off.

## Who does what (separation of duties)

```powershell
# 1LoD (the builder): declare the facts in manifest.yaml, produce current evidence, then register
# (registering is refused until red-team evidence is ACCEPTED: python redteam.py; python evidence.py record redteam)
python resgister.py

# 2LoD (once): create the keypair. Keep ccor_private.pem with the 2LoD, outside the repo.
python resgister.py --gen-keys ccor_private.pem      # also writes mas_2lod_public.pem (commit this one)

# 2LoD: review, then sign off the current hashes
python resgister.py --status
python resgister.py --approve --reviewer VP_CCOR --key-file ccor_private.pem
```

Any change to `manifest.yaml` or `tools.py` voids the registration and the approval, and any change to `mas_rubric.py` voids the approval. The builder registers again; the 2LoD signs again. The repository holds only the public key, so the builder cannot forge an approval. Approvals expire after 90 days. Use an Ed25519 key (RSA keys from `openssl` are rejected). Do not commit `ccor_private.pem`; `.gitignore` already excludes `*.pem` except the public key.

## Evidence register with expiry

The gate treats the red-team run as evidence that can go stale. `policy/evidence_policy.yaml` (2LoD-owned, and part of the hash that every approval pins) lists each required item, its maximum age and what counts as sufficient: at least 20 attack cases, a catch rate of at least 90%, no benign request wrongly blocked, and cases for every layer including the output guard.

| Status | Meaning |
|---|---|
| `ACCEPTED` | Recorded, artifact unchanged, thresholds met, inside its window |
| `NEEDS_REVIEW` | Fine, but older than `max_age_days` |
| `NEEDS_EVIDENCE` | No record yet |
| `REJECTED` | Artifact missing or changed since it was recorded, or thresholds not met |

```powershell
python redteam.py                  # produce the evidence
python evidence.py record redteam  # fingerprint it (refused if insufficient)
python evidence.py status          # what the gate will see; add --strict to fail on anything not ACCEPTED
```

Metrics are recomputed from the artifact on every check. The record is not signed, so someone who can write `evidence/` can forge it; CI-signed evidence is the production answer ([limits](LIMITATIONS.md)). Until you run the two commands above, the gate reports `NEEDS_EVIDENCE` and the agent will not start.

## Audit evidence (C6)

- Each audit row stores the hash of the previous row, so editing or deleting an old row breaks the chain.
- Each day the 2LoD can sign a Merkle root over that day's events. Signed roots chain to each other, so a whole-chain rebuild is caught if the old root was kept.
- `python resgister.py --verify-audit` checks the chain and every seal. `--seal-day YYYY-MM-DD --reviewer NAME --key-file KEY` seals a day, and `--export-day YYYY-MM-DD` writes a write-once evidence pack into `ccor-audit-artifacts/`.
- An auditor can verify a pack offline with `python audit_chain.py verify-pack ccor-audit-artifacts YYYY-MM-DD`.
- The existing `audit.db` rows from before the upgrade are sealed under a genesis row the first time the new code opens the file.

## 2LoD console

`streamlit run ccor_dashboard.py` shows five sections: the asset registry and boot status (`APPROVED`, `PENDING_2LOD_APPROVAL`, `BLOCKED_CHALLENGE_FAILED`, `NOT_REGISTERED`, `KILL_SWITCH_ACTIVE`), declaration versus code introspection, control readiness, the 2LoD actions (approve, reject, kill-switch, each a hash-chained event), and the audit chain with Merkle roots. The console is a convenience over `resgister.py`; the startup gate does not depend on it.

## What this does not do

- The approval covers `manifest.yaml` and `tools.py` by hash. Other code (for example `dispatcher.py` and `agent.py`) is checked for specific controls on every start, but not hashed, so a change that keeps those checks passing is not detected.
- Whoever can edit the repository can also edit `agent.py` to skip the gate. The gate is strong against honest mistakes and a builder under-declaring risk, not against a determined insider; production needs the gate enforced by the deployment pipeline.
- The rubric is a placeholder calibration. The Board appetite is a constant in code, not a signed policy.
- MAS Sections 5.x (data lineage, fairness, agentic boundaries, continuous monitoring) are not implemented here.
