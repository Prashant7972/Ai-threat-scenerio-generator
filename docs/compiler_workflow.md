# Explicit-input compiler workflow

`src.generator.compiler.compile_pattern(pattern, profile, input_root)` takes two JSON objects. `pattern` has exactly `scenario` and `evidence`. The scenario contains all MinimumScenarioContract fields plus `workflow_stages` and `trust_boundary`. `attacker_access.surface` must equal the `injection_surface` enum value. Review must explicitly provide `approved`, a nonempty reviewer and a timezone-qualified timestamp. Never supply approval merely to bypass validation.

Each evidence entry contains `record_id`, `revision`, `locator`, `claim_ids`, `snapshot_uri` and `sha256`. References must match record/revision/locator and source facts must resolve to claim IDs. Snapshot paths and fixtures must be local to the input directory. Absolute paths, traversal, escaping symlinks and hash mismatches are rejected. Evidence hashing verifies bytes, not the truth of the claim.

TargetProfile fields are `id`, `version`, `capabilities`, `surfaces` (surface to allowed operator list), `predicates` (predicate to boolean), and `builds` (vulnerable/hardened SHA-256 pins). A pin must identify an actual build artifact; the compiler checks its syntax but does not build or verify an image. Every precondition must resolve true and the target must support the selected reviewed harness capabilities.

`build_package` materializes 18 structured boundary records and returns a SHA-256 directory under the chosen output root. `manifest.json` lists the hash of each file. `inputs/` contains source snapshots and synthetic fixtures. Original fixture URIs are relative to that directory. Source and schema files are included under the package. Existing package files cannot be silently overwritten.

Use generator id `boundary_carrier_v1`, version `1.0.0`, empty parameters, selection method `full_factorial`, and dimensions:

```json
{"authority": ["none", "claimed_system"], "carrier": ["plain", "email", "json"], "stage": [0, 1]}
```

This generator requires `authority_claims`, `carrier_changes`, and `multi_turn_placement` in the declared mutation scope. It materializes 12 attacks (2 authority modes x 3 carriers x 2 workflow stages) and six controls sharing task, fixtures, carrier and placement. Every attack points to its matched control. The payload bytes contain the complete structured workflow inputs, rather than merely writing “Turn 2” in one prompt. Unsupported generator versions, parameters, dimensions or scopes are rejected.

The R1 package runner delivers the two retrieval stages through separate model calls, preserves carrier structure and prior outputs, observes renderer requests, and can check `benign_control.expected_task_outcome.output_contains` independently. It reads stored bytes without calling the generator and rejects package tampering before execution. R2/R3 package replay is explicitly unsupported and rejected before model invocation. Other mechanism-specific generators still need implementation.

```bash
python3 -m src.proof.evaluator.package_runner --package /path/to/packages/SHA256 \
  --record-id RECORD_ID --build hardened --output /path/to/trial-manifests
```

This CLI is mock development mode. A passing record is not release acceptance.

The regression tests in `tests/test_strict_compiler.py` demonstrate the input shape using synthetic test-only approvals. They are not approved client patterns and must not be presented as such.
