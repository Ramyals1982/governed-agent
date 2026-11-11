# Control mapping: MAS AIRM, US model risk guidance, NIST AI RMF

Read [LIMITATIONS.md](LIMITATIONS.md) first. This is my interpretation, not a regulator's or auditor's.

**Which US guidance.** SR 11-7 (2011) was superseded by SR 26-2 on 17 April 2026 (Federal Reserve, OCC and FDIC). A law-firm summary reports that generative and agentic AI are outside its scope, so the right-hand reading is by analogy: how a bank's model risk practice would extend to an AI agent. SR 26-2 principles used below: overall risk is inherent risk combined with materiality; validation has three parts (conceptual soundness, outcomes analysis, ongoing monitoring); effective challenge needs expertise, independence and standing; roles and accountability are documented.

**MAS.** Section 4 is implemented (identification, inventory, risk materiality assessment). Sections 5 and 6 (lifecycle controls, capabilities and infrastructure) are not, except where an older control happens to support them.

| What the control does | Where | MAS AIRM | US model risk (SR 26-2 / SR 11-7) | NIST AI RMF 1.0 | Not covered |
|---|---|---|---|---|---|
| AI inventory: the agent must be registered for its exact manifest + tools hash, or it does not start | `resgister.py` `registration_state`, gate check 8 | S4 inventory | Model inventory | GOVERN 1.6 inventory mechanisms | Inventory of data and third-party components beyond the model |
| Risk materiality: Impact, Complexity and Reliance computed from the code by a locked rubric; builder's claim challenged | `mas_rubric.py`, gate check 6 | S4 materiality assessment | Inherent risk combined with materiality | GOVERN 1.3 level of risk management; MAP 5.1 likelihood and magnitude of impact | Rubric calibration is a placeholder |
| Inherent vs residual risk, residual within Board appetite, residual lowered only by verified mitigations | `residual_tier`, gate check 7 | S4 residual risk and appetite | Risk-based, proportionate oversight | GOVERN 1.3 | Appetite is a constant, not a signed policy |
| Independent sign-off: Ed25519-signed 2LoD approval bound to hashes; MEDIUM and HIGH need it; four-eyes; 90-day expiry | `approve`, `find_active_approval` | S4 control-function approval | Effective challenge (independence, standing) | GOVERN 2.1 roles and responsibilities | Reviewer expertise cannot be tested by code |
| Shadow capability, shadow model and oversight-mode challenges | `introspect_tools`, `verify_model_binding`, `introspect_oversight` | S4 accurate identification | Model change control | MANAGE 4.1 post-deployment monitoring | Model drift behind the same name |
| Evidence with expiry: red-team results must be recorded, unchanged, sufficient and current, or the agent stops | `evidence.py`, `policy/evidence_policy.yaml` | S5 lifecycle testing (partial) | Ongoing monitoring; validation | MEASURE 2.7 security and resilience evaluated; MANAGE 4.1 post-deployment monitoring | Evidence is unsigned; one test suite only |
| Kill-switch: anyone can activate; only the 2LoD key releases | `activate_kill_switch`, `release_kill_switch` | S4 control-function authority | Limits on model use | MANAGE 2.4 supersede, disengage or deactivate | No automatic trigger |
| Tool policy and human approval (C4, C5) | `dispatcher.py`, `approval.py` | S4 Reliance dimension | Use controls | GOVERN 3.2 human-AI roles | Approval fatigue |
| Input and output guards (C1, C2, C3, C7) | `guardrails.py`, `injection.py`, `output_guard.py` | S5 lifecycle controls (partial) | Implementation controls | MEASURE 2.7; MEASURE 2.10 privacy risk | Pattern-based only |
| Tamper-evident audit log: hash chain, signed daily Merkle roots, evidence packs, offline verifier | `audit_chain.py` | Record-keeping | Documentation; audit trail | GOVERN 1.4 transparent processes | No external anchor yet |
| Separation of duties in the repository: 2LoD owns rubric, policy, gate and key | `.github/CODEOWNERS`, branch protection | S4 designated control function | Governance roles and accountability | GOVERN 2.1 | Simulated with one person |

NIST subcategory wording was checked against the AI RMF core page. MAS section numbers beyond 4, and any US clause reference, should be checked against the primary text before you quote them.
