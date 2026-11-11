# Path to production

Read [LIMITATIONS.md](LIMITATIONS.md) first. This document says what would change to run these controls in a bank. None of it is built here. Each row names the weakness it closes. The patterns are common supply-chain and change-control practice (signed build provenance, protected approvals, policy-as-code, write-once storage); they are not a description of any one firm's internals.

## The principle

Today the gate runs inside the application it governs, on one machine, with a key in a file. In production the controls move to places the builder cannot edit: the pipeline, the key service, the deployment platform and the evidence store. The code in this repository becomes the fact collector and the reference for what the checks are.

## What changes

| Area | Today | Production | Closes |
|---|---|---|---|
| **Signing key** | PEM file the 2LoD runs by hand | Key in a KMS or HSM. Only a protected 2LoD approval step in CI can use it, through workload identity, with no key file anywhere. Rotation and revocation list defined | Key theft; manual process |
| **Approvals** | Rows in a local `audit.db` | Signed attestation files stored with the release. The verifier needs no database, so CI, deploy and runtime all check the same artifact | A runner or server has no `audit.db` |
| **What an approval covers** | Hash of `manifest.yaml` + `tools.py` | The build artifact digest (container image), SBOM, manifest, tools, policy bundle and model version, with build provenance attached | Unhashed code (limit 5) |
| **Evidence** | Unsigned record next to the file | CI produces the evidence and signs the record. Expiry and sufficiency come from the 2LoD policy. Missing or stale evidence blocks the release | Forged or self-dated evidence (limit 6) |
| **Policy** | Python tables in `mas_rubric.py` | Rego policy bundle, signed and versioned, with decision logs and unit tests. Python collects facts; the policy decides. Exceptions are recorded risk acceptances with an expiry and an approver | Hard-coded decisions; manual sufficiency judgement |
| **Manifest authorization** | `dispatcher.py` has a hard-coded tool list | Allowed tools and limits read from the signed manifest. The manifest becomes the security boundary, so it is verified before it is read | Drift between declaration and enforcement |
| **Enforcement point** | The agent calls the gate at start | Deploy-time admission check refuses an unattested release. A runtime policy check repeats every few minutes, so expiry and the kill-switch take effect while the process runs | An insider editing `agent.py`; long-running processes (limit 4) |
| **Audit log** | One SQLite file, sealed by hand | Events stream to an external append-only sink as they happen. A scheduled job seals each period and anchors the chain head with an RFC 3161 timestamp, stored in write-once storage (for example object lock) | The unanchored tail, below |
| **Inventory** | `manifest_registered` events | A registry of record changed only by reviewed pull request: register, change, retire. A material change forces re-scoring. Reviews are scheduled; retirement revokes approvals | Stale inventory |
| **Dashboards** | Local Streamlit app | A read-only web service with single sign-on and roles. It maps controls to MAS, ISO 42001 and NIST, shows inherent vs residual risk, evidence freshness and unanchored-tail age, and exports audit packs. Engineers keep the CLI | CLI-only for compliance staff |
| **Operating model** | One person | Named 2LoD team with key custody, a break-glass procedure, response times for expired evidence, and an independent check that the controls themselves still work | Simulated separation (limit 3) |

## The unanchored tail

A hash chain proves order and detects edits made before the last anchor. Entries written after the last anchor rely on the local clock and on whoever can write the file, until the next anchor covers them. That window can be made small and visible but not zero, unless every event is written to an external system before the action proceeds.

Options, in increasing cost:

1. **Anchor on events that matter.** Seal and timestamp on every merge, release and approval, and on a schedule. The window is the schedule interval.
2. **Stream to an external sink.** Events leave the machine within seconds. The window is the stream delay, and the verifier reports the age of the last anchored event.
3. **Write before acting, for high-materiality systems.** The agent does not run a risky action until its audit event is acknowledged externally. If the sink is down, the agent fails closed. This is a business decision about availability against assurance.

## Order I would build it in

1. CI, CODEOWNERS, hygiene checks, evidence freshness (done in this repository).
2. Portable approvals and signed evidence records.
3. KMS-held key and a protected approval step.
4. Anchoring and the external sink.
5. Policy bundle and decision logs.
6. Deploy-time admission, then runtime re-checks.
7. Inventory registry of record and the GRC dashboard.

## What I would not build in a proof of concept

A KMS, timestamp authority or admission controller cannot be demonstrated honestly without real infrastructure and a second person. The design above is the deliverable; claiming more would overstate it.
