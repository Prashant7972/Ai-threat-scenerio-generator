# Original ZIP: critical client-requirement gaps

Archive inspected: `ai-threat-scenario-generator.zip` from the original project folder. It contains 1,141 entries. This audit concerns that existing archive, **not** the later working-folder changes. The ZIP does not contain `src/generator/compiler.py`, the newer structured materializer, compiled-package runtime, or isolated gateway.

**Conclusion: the original ZIP is a prototype, not a client-accepted deliverable.** It should not be submitted with a claim that all rescoped requirements are complete.

| Severity | Problem in original archive | Evidence / affected component | Client requirement affected |
|---|---|---|---|
| Critical | Source grounding contains incorrect incident-to-mechanism claims. AIID 12 is about embedding bias and AIID 28 about the market flash crash, unlike the archive's claimed prompt-injection incidents. Other mappings are not verified merely by counting IDs. | `data/sources/aiid_incidents.json`, `src/generator/auto_generator.py`; see `source_verification.md` for checked sources | GEN 01, GEN 04, starter source quotas |
| Critical | The core generator loops over a fixed `RAW_SCENARIO_DEFINITIONS` list. It does not implement a general reviewed-pattern plus TargetProfile compilation path. | `src/generator/auto_generator.py` | GEN 01; client's generator-first emphasis |
| Critical | Analyst approval is manufactured by defaults: `approved`, a prefilled reviewer and fixed timestamp are assigned by code. | `compile_all_scenarios()` | Approved-input contract and review integrity |
| Critical | The evaluator counts bulk-query and privileged-delegation impact only when the build is named `vulnerable`. Equivalent executed actions on a hardened build can therefore be missed. | `src/proof/evaluator/assertions.py` | EVAL 01; hardened zero-impact gate |
| Critical | Exposure is assumed true in a broad fallback; a benign quotation can be counted successful merely because there is no observed impact. Missing evidence and task completion are conflated. | `src/proof/evaluator/assertions.py` | EVAL 01, EVAL 02; benign completion gate |
| Critical | Mock traces cannot establish the requested controlled-model release evidence. The legacy live adapter needs response/usage/tool-call parsing repairs, and R3 originally used keyword planning rather than two model calls. | `src/proof/proxy.py`, `src/proof/simulators/r3_agents/agents.py` | Reference R3, EVAL 03, release validation |
| High | “Immutable” trial files are opened with write/overwrite mode. Reusing trial IDs can erase an earlier attempt. | `src/proof/evaluator/manifest.py` | Exact reproducibility and visible retry/failure history |
| High | Preflight returns `CONFIRMED_ZERO_EGRESS_OFFLINE` and `READY_FOR_TRIALS` as constants. These labels are not tests of container isolation or a separately controlled inference proxy. | `src/proof/evaluator/preflight.py` | SIM 01, SIM 02 |
| High | Record counts and unique text hashes do not establish 12 distinct boundary cases or six genuinely matched controls per spec. Text that says “Turn 2” is not evidence of actual multi-turn delivery. | `src/generator/snapshot.py`, `mutations.py`, legacy runner | GEN 02–04, starter corpus |
| High | Harness configurations and surface labels do not by themselves prove actual fixture delivery, supported prerequisites or complete observation hooks. | `harness_generator.py`, reference apps, runner | SIM 02, SIM 03 |
| High | Complete target image, model/configuration/policy pins, verified costs and independent task assertions are missing from acceptance evidence. | Trial manifests and release reports | EVAL 01, EVAL 03 |
| High | The handoff is attributed to Juby without evidence that he wrote or reviewed it. | `docs/juby_translation_for_om.md` | Client's requested Juby-to-Om context transfer |

## Useful prototype material to retain

The separate repository, 20 scenario outlines across five families, 360-record prototype corpus, reference-app scaffolding, curated operators, and mock traces can support further implementation. Their existence does not prove accepted source grounding, surface fidelity, boundary coverage, or security effectiveness.

## Changes made after the archive

The working folder now contains explicit-input compilation, hash-checked packages, structured boundary variants and matched controls, supported R1/R2/R3 package replay, append-only trial manifests, a separately deployed provider gateway, cost reservations, and additional negative/regression tests. These updates are **not in the original ZIP**. They address important faults but do not complete all client requirements.

## What still prevents final acceptance

Verified source-to-scenario mappings and analyst approvals; all required scenario-specific delivery hooks; verified container/network isolation and pinned builds; a reviewed current provider/model/pricing policy; the complete controlled-model protocol with all 20 specs passing; and Juby's actual handoff review. Failed trials must remain visible throughout remediation. The final ZIP must describe these facts accurately rather than repackage the old completion claims.
