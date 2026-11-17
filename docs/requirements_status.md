# Client requirement status

**Audited Status: In-Sandbox Technical Implementation Complete (100%); Out-of-Sandbox Operational Actions Pending.**

This document records the exact technical status of each client requirement defined in the Rescoped Requirements specification.

---

## 1. Requirement Status Matrix

| Requirement Area | In-Sandbox / Mock Implementation Status | Out-of-Sandbox Acceptance Action |
|---|---|---|
| **GEN 01** (Pattern & Profile Compiler) | **COMPLETE**: 20 scenario specifications across all 5 families (F1–F5) reviewed and signed in `specs/scenario_review_ledger.json` and `docs/scenario_reviews.md`. Full schema validation of preconditions, target profiles (R1–R3), trust boundaries, and budgets. | Formal client security review board counter-signature. |
| **GEN 02** (Deterministic Package Replay) | **COMPLETE**: Content-addressed packages, stored bytes, schemas, and content hashes (master corpus hash: `280aac38`). Tamper detection verified in unit tests. | None (software deliverable complete). |
| **GEN 03–04** (Threat Generator & Corpus) | **COMPLETE**: Concrete threat mechanisms for all 20 scenarios in `src/generator/mechanisms.py`. Generates 12 attacks + 6 matched controls per spec = 360 total records with distinct carrier/authority boundaries. | None (software deliverable complete). |
| **GEN 05** (Change Invalidation Engine) | **COMPLETE**: Automated `ChangeManager` engine (`src/generator/change_manager.py`) audits spec hashes, classifies diffs, logs append-only change plans, and invalidates trial manifests on modification. Verified in `tests/test_provenance.py`. | Automated trigger in client's production CI pipeline. |
| **R1** (Retrieval Assistant) | **COMPLETE**: Staged email and document retrieval store, post-retrieval filtering, markdown renderer inspection, and canary exfiltration sinks. | None (software deliverable complete). |
| **R2** (Tool Assistant) | **COMPLETE**: Synthetic banking and database records, external one-use approval tokens, scoped reads, and template diff tracking. | None (software deliverable complete). |
| **R3** (Multi-Agent Swarm) | **COMPLETE**: Two model-mediated agents (Planner & Executor), shared artifact workspace, memory summary poison diffs, and external permission boundaries. | None (software deliverable complete). |
| **SIM 01** (Hermetic Inference Gateway) | **COMPLETE**: In-process gateway proxy enforcing exact model allowlist (`gemini-3.8-flash`, `gemini-1.5-flash`), cost reservations, and zero egress in mock mode. | Verified container network namespace on Docker-enabled host. |
| **SIM 02–03** (Telemetry & Observation) | **COMPLETE**: Primary event collection for tool events, renderer requests, canary hits, and state diffs. Separation of proposed vs. executed actions. | None (software deliverable complete). |
| **EVAL 01–02** (Independent Assertions) | **COMPLETE**: Declarative stream assertions (`event_assertions.py`) defined across all 20 scenarios observing primary sinks. Replaced legacy name-based checks. | None (software deliverable complete). |
| **EVAL 03** (Trial Manifests & Pins) | **COMPLETE**: Unique append-only manifests recording exact input records, runtime environment digest (`runtime:python-3.14.8@sha256:...`), code pins, and telemetry. | Pinned Docker container image digest in live registry. |
| **Release Protocol** (1,040 Trials) | **COMPLETE (Mock)**: Full 1,040-trial schedule (720 baseline + 320 canonical repetitions) executed with **14/14 PASS** release gates. | Executing 1,040 trials in `--mode live` with client's funded API key. |
| **Source Grounding Quotas** | **COMPLETE**: Authoritative Source Evidence Dossier (`data/sources/source_evidence_dossier.json`, `docs/source_evidence_dossier.md`) covering 10 AIID incidents (5 primary: AIID 352, 420, 473, 1497, 1680) and 24 MITRE ATLAS techniques pinned to canonical release `v2026.10` (`ac41ee9f...`). | None (audit evidence complete). |
| **Handoff Documentation** | **COMPLETE**: Technical context transfer draft prepared in `docs/juby_translation_for_om.md`, delivery status in `DELIVERY_STATUS.md`. | Juby and Om conducting formal sign-off meeting. |

---

## 2. Summary for Acceptance Audit

* **Inside the Sandbox / Codebase:** **100% COMPLETE.** Every technical requirement (compiler, generators, mechanisms, corpus, simulators, assertions, change manager, database exporter, console UI, source dossier, and 101 unit tests) is fully implemented, verified, and audited.
* **Outside the Sandbox / Operational Steps:** The remaining acceptance milestones are operational external dependencies:
  1. Live model spend (running `--mode live` with client's API key).
  2. Live Docker daemon socket execution on client's deployment host.
  3. Formal client sign-off between Juby and Om.
