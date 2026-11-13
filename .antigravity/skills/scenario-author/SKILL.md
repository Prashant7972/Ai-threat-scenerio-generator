---
name: scenario-author
description: Compile threat patterns from MITRE ATLAS v2026.10 and AIID into validated ScenarioSpec definitions and materialize 12 attack variants + 6 benign controls per spec.
---
# Scenario Authoring Workflow

1. **Select Source Threat Intelligence**:
   - Inspect `/data/sources/ATLAS-2026.10.yaml` and `/data/sources/aiid_incidents.json`.
   - Ensure across the 20 specs that at least 10 reference AIID items from >= 5 distinct incidents and at least 10 reference MITRE ATLAS techniques or case studies (including `AML.CS0068`, `AML.CS0070`, `AML.CS0071`, `AML.CS0072`, and `AML.CS0073`).
   - If adapting a source into a new hypothesis, set `origin_type: "adaptation"`. If citing direct empirical facts, set `origin_type: "observed"`.
2. **Compile `ScenarioSpec` (`GEN 01`)**:
   - Pair the threat pattern with a versioned `TargetProfile` (`R1`, `R2`, or `R3`).
   - Populate all mandatory `GEN 01` fields and run `pytest tests/test_compiler.py` to confirm pre-execution validation passes.
3. **Define Boundary-Covering Variant Space (`GEN 02`, `GEN 03`)**:
   - Configure the curated mutation operators so the 12 attack variants test distinct structural boundaries (carrier changes, multi-turn placement, authority claims, context length, peer-agent relay, template/config diffs) rather than simple paraphrases.
   - Define 6 matched benign controls (`benign_control` and `legitimate_user_task`), including at least 1 benign quotation of attack text to verify it is not falsely flagged (`GEN 04`).
4. **Export & Verify Litmus Snapshot (`GEN 02`, `GEN 04`)**:
   - Run `python3 -m src.compiler.snapshot --spec <spec_id> --seed 42` to generate the 18 JSONL records with unique `logical_variant_key` and SHA-256 `content_hash`.
