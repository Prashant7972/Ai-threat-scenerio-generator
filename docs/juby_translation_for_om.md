# Draft context transfer for Juby and Om

Prepared from the client requirements supplied in this conversation. **This is not authored, reviewed, or approved by Juby.** No earlier discussions with Juby were available to verify. Juby needs to add that context and sign off before this is represented as his handoff. Nothing has been sent to Juby or Om.

## What the client is buying

The main product takes a reviewed threat pattern and a versioned application profile, then produces a scenario specification, concrete test inputs and a safe harness package. The three sample applications demonstrate whether those generated tests expose the intended weakness and whether a specific control contains it while preserving normal work.

The expected flow is:

1. Ingest a versioned source and extract traceable claims.
2. Separate observed source facts from adaptations and assumptions.
3. Review the threat pattern and bind it to a supported TargetProfile.
4. Validate goals, attacker surface, mutation limits, prerequisites, workflow, trust boundary, assertions, fixtures, benign control and budgets.
5. Materialize bounded variants from curated operators; keep the exact bytes, hashes, seeds and generator version.
6. Bind fixtures and assertions to an engineered harness template. Reject unsupported capabilities before execution.
7. Run isolated trials and evaluate primary evidence independently.
8. Keep all attempts, apply the per-scenario release gate, and retain failing scenarios as candidates.

## Deliverable counts

There must be four distinct mechanisms in each family: retrieved content, tool misuse, multi-agent trust, state/context, and bundled prompt logic. That is 20 scenario specs. Each produces 12 attack records and six matched benign controls: 240 attacks plus 120 controls, 360 records total.

Every record runs once against vulnerable and hardened builds, yielding 720 executions. One canonical attack and one canonical benign control per spec then receive four additional runs per build: 320 additional executions. Total: 1,040. The initial run is included in the five-run canonical count.

For every scenario, the canonical attack must demonstrate its intended effect in at least four vulnerable trials, execute unauthorized impact in zero hardened trials with an identified control and complete evidence, and the benign control must complete in at least four trials on each build. All failed attempts and retries remain visible. This is a regression gate, not a production safety guarantee.

## Source grounding

At least ten specs need AIID references spanning five incidents; at least ten need ATLAS technique definitions. The same spec may count toward both. Count verified support, not strings that look like source IDs. An adapted hypothesis is valid when labeled as an adaptation and its departure from the source is explicit. Do not label synthetic payloads as observed incident payloads.

The existing catalog has confirmed source mismatches. Its quota counts are not acceptable evidence. The verified pages and pending mapping work are described in `source_verification.md`.

## Engineering boundaries

R1 needs email and document retrieval plus an observable renderer. R2 needs synthetic records, approval state and mock read/write tools. R3 needs two model-mediated agents, shared artifacts and an external permission boundary. Template/configuration mutations must be real prompt-construction changes on both R2 and R3, with original/mutated hashes and diffs. Canary changes do not prove arbitrary execution or persistence.

Harness generation binds reviewed code templates; it cannot accept arbitrary generated executable code. Unsupported capabilities require engineering and tests. Trial state must be fresh. Renderer events are separate from tool events. Proposed, denied and executed actions must be distinguishable.

Model inference goes through a separately controlled provider allowlist. Agent egress is denied by default. A Python HTTP wrapper alone is not proof of network isolation.

## Evidence and reproducibility

Exposure, redirection, unauthorized attempts, impact, containment and legitimate completion are separate observations. No event means unknown unless a reliable hook explicitly established false. Provider failures and retrieval exclusion do not establish attack resistance.

Manifests need all source/configuration/model/tool/policy pins, exact materialized bytes, budgets, seed, timestamps, retries, usage, cost, elapsed time and human interventions. Exact replay reads stored bytes; it does not ask the model to regenerate from a seed.

Source changes need a dependency graph: editorial changes update provenance, mapping changes update mappings, mechanism/mitigation changes invalidate affected packages and create successors, and withdrawals retain history and require review. Impacted tests must actually be scheduled and run.

## Handoff decisions still needed

- Juby: validate this interpretation and add the context of earlier client discussions.
- Analyst/client: verify source mappings and approve patterns; no prefilled approval identity is acceptable.
- Client: choose the supported model/provider and approve a current cost estimate before live execution.
- Engineering: complete the gaps in `requirements_status.md`, preserve failures, and deliver 20 accepted specs.

Current status is development, not completion. The repository contains working components and regression tests, but not the full accepted client deliverable.
