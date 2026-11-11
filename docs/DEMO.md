# Two-minute demo

Run `python demo.py --pause` (press Enter between acts) or `python demo.py` to run straight through. It works in a throw-away copy, so your repository, keys and `audit.db` are untouched. The evidence in the demo is a labelled synthetic fixture.

| Act | You say | The screen shows |
|---|---|---|
| 1 | "The builder says this agent is low risk. It can send email on its own." | `AGENT REFUSES TO START`: the declared tier is LOW but the locked rubric computes HIGH. The claim is logged as `2LoD_EFFECTIVE_CHALLENGE_FAILED` |
| 2 | "An honest declaration still needs the Second Line." | Registered in the inventory, and still refused: HIGH needs a signed approval |
| 3 | "The 2LoD reviews and signs with a key the builder does not hold." | `AGENT STARTS`: inherent HIGH, residual MEDIUM, because the mitigations are verified from the code |
| 4 | "Forty-five days later nobody has done anything. The approval is still valid." | The red-team evidence is `NEEDS_REVIEW`. The agent refuses to start because residual risk rose back to HIGH |
| 5 | "The builder re-runs the tests and records fresh evidence. No new approval needed." | `AGENT STARTS` again. Audit chain `INTACT` |

## The point to land

The control is not the document. It is that the agent will not run if the evidence behind the approval has gone stale, and nobody had to remember.

## If asked

- **Can the builder fake the evidence?** Today, yes, if they can write the evidence folder. That is limit 6 in `LIMITATIONS.md`. The production answer is CI-signed evidence (`PATH_TO_PRODUCTION.md`).
- **Can an insider remove the gate?** Yes, it lives in the repository. Production enforcement belongs in the pipeline and deploy platform.
- **Is this MAS-compliant?** No. It implements Section 4 on a demo agent and shows how the checks run.
