# CI and branch protection

The workflows and CODEOWNERS file do nothing until GitHub is set to enforce them. These settings are on the repository's Settings page and cannot be set from code.

## Workflows

| File | Runs | Purpose |
|---|---|---|
| `.github/workflows/ci.yml` job `governance-tests` | every push and pull request | Repo hygiene (no keys, databases or credentials), then the gate, audit chain, evidence and output-guard wiring tests |
| `ci.yml` job `evidence-freshness` | every push and pull request | Fails when required evidence is missing, insufficient or expired |
| `ci.yml` job `dependency-audit` | every push and pull request | Reports known vulnerabilities in `requirements.txt`. Informational, it does not fail the build |
| `.github/workflows/evidence-watch.yml` | daily at 03:17 UTC | Re-evaluates evidence and opens one issue labelled `evidence-expired` while anything is not current |

Actions are pinned to major versions. In production, pin them to full commit SHAs.

## Settings to turn on (Settings, Branches, add a rule for `main`)

1. Require a pull request before merging.
2. Require approvals: 1.
3. **Require review from Code Owners.** This is what makes `CODEOWNERS` binding.
4. Require status checks to pass: `MAS governance tests and repo hygiene`. Add `Evidence is current and sufficient` if you want an expired-evidence repository to block every merge.
5. Do not allow bypassing the above settings, and block force pushes.

## Making the separation real

`CODEOWNERS` assigns every path to the repository owner so it works for a single person. For a real split, create a second GitHub account or a team for the 2LoD, put it on the 2LoD lines (`mas_rubric.py`, `policy/`, `mas_2lod_public.pem`, `resgister.py`, `evidence.py`, `audit_chain.py`, `scripts/`, `.github/`), and keep the builder out of that team. The private signing key stays with the 2LoD, outside the repository.

## Refreshing evidence

```
python redteam.py                          # writes evidence/redteam_results.md
python evidence.py record redteam          # fingerprints it; refuses if it is insufficient
python -m pytest -q --junitxml=evidence/pytest_junit.xml
python evidence.py record unit-tests
python evidence.py status                  # what the gate will see
```
