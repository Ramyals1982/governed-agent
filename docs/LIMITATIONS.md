# Limits first

This repository is a reference implementation on a demo agent with mocked tools. It shows how regulatory expectations can become checks that run, not that a firm is compliant. Read these before anything else.

## What this is not

1. **Not validated on real data or by an independent party.** The agent, tools and attack cases are small and were written by the same person who wrote the controls. The red-team numbers measure known phrasings, and one known gap is shown on purpose.
2. **Not a calibrated methodology.** The scoring tables in `mas_rubric.py` and the Board risk appetite (`BOARD_RISK_APPETITE_MAX_RESIDUAL`) are placeholders. A firm would replace them with its approved methodology and a signed policy.
3. **Separation of duties is simulated.** One person plays both lines here. The design supports a real split (the builder never holds the private key), but this repository does not prove it. A real split needs two principals and separate key custody.

## Where the controls can be bypassed

4. **The gate lives in the repository it protects.** Anyone who can edit `agent.py` can remove the gate call. The gate stops mistakes and a builder who under-declares risk. It does not stop a determined insider. Enforcement belongs in the deployment pipeline (see `PATH_TO_PRODUCTION.md`).
5. **The approval hash covers `manifest.yaml`, `tools.py`, `mas_rubric.py` and the evidence policy.** Other code, such as `dispatcher.py` and `agent.py`, is checked for specific controls on every start but is not hashed, so a change that keeps those checks passing is not detected.
6. **Evidence is not signed.** Metrics are recomputed from the artifact, and the validity window comes from the 2LoD-owned policy. But the start date is written by an unsigned record, so someone who can write `evidence/` can forge a fresh one. In production the CI pipeline signs it.
7. **The audit log is tamper-evident, not tamper-proof.** SQLite triggers and the hash chain make edits detectable, and signed daily Merkle roots catch a rebuilt chain, but only if the exported evidence packs are kept where the agent cannot write. Events after the last seal rely on the local clock until the next anchor. There is no external timestamp authority yet.
8. **Tool results are logged raw**, so `audit.db` can hold unredacted data. Treat it as sensitive.
9. **The output guard (C7) matches secret and PII patterns.** It does not understand confidential prose or detect wrong answers.

## Scope of the regulation

10. **Only MAS AIRM Section 4 (identification, inventory, risk materiality) is implemented.** Lifecycle controls and capabilities and infrastructure (Sections 5 and 6) are not, beyond the controls that already existed.
11. **The framework mapping is interpretive.** It is my reading, not a regulator's or auditor's. The MAS structure and dates come from law-firm summaries of the final guidelines (published 7 October 2026, Sections 3 and 4 expected from 7 October 2027). Check them against the MAS text before quoting.
12. **US model risk guidance changed in April 2026.** SR 11-7 was superseded by SR 26-2, and a summary reports that generative and agentic AI are outside its scope. This repository therefore maps to it by analogy, as a way to show how a bank's model risk practices would extend to an AI agent, not as a statement of what the guidance requires.

## Limits of the original agent controls

13. **Injection checks are regex patterns** and miss paraphrases. One missed case is shown on purpose in the results.
14. **Names and postal addresses are not redacted.** Email addresses are deliberately left visible so the policy can judge the recipient.
15. **Human approval by CLI prompt can be rushed** (approval fatigue), so approval is limited to one narrow case.
16. **Interrupted runs can leave requests in the log with no recorded outcome.**
17. **Third-party and free-tier models can change behaviour behind the same name.** The model name in `llm.py` is checked against the manifest at every start, but the provider can still change what sits behind it.
18. **The evidence is a small test set and a handful of agent runs.** It is not a security assessment.
