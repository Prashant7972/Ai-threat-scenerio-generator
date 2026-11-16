# Scenario compiler and generator

**Status: development candidate, not a client-accepted release.** The generator is the product. Reference applications and evaluations exist to test the usefulness of its generated scenarios and harness packages.

This is a separate Git repository. No live model validation or client acceptance is claimed. Historical reports and the legacy 360-record corpus contain unverified source mappings and must not be used as acceptance evidence.

## Start here

- [Client requirement status](docs/requirements_status.md)
- [Critical gaps in the original ZIP](docs/original_zip_audit.md)
- [Draft context transfer for Juby and Om](docs/juby_translation_for_om.md)
- [Compiler input and output contract](docs/compiler_workflow.md)
- [Source verification notes](docs/source_verification.md)
- [Controlled inference deployment](deployment/README.md)
- [Compiled release-validation protocol](docs/compiled_release_protocol.md)

## Local checks

Python 3.10+ is required. Install `requirements.txt` in a virtual environment, then run:

```bash
python3 -m pytest tests/ -q
python3 -m src.generator.cli --verify
python3 -m src.proof.evaluator.runner --mode mock
```

The corpus verification command verifies legacy counts and payload integrity only. It does not verify incident support or approve a release. The mock suite deliberately returns a nonzero exit code when release gates fail. Every invocation stores its own results under `reports/runs/<session_id>/`, retaining all attempts.

## Compile explicit inputs

```bash
python3 -m src.generator.cli \
  --pattern /path/to/input/pattern.json \
  --target-profile /path/to/input/target-profile.json \
  --output /path/to/packages
```

The input must include an actual analyst approval, versioned target capabilities, machine-checkable predicates, hashed local fixtures and evidence, explicit workflow stages, and a trust boundary. The compiler validates these bindings and rejects inconsistent inputs before materialization. It does not decide whether a source claim is true or impersonate an analyst.

Each content-addressed package stores scenario JSON, target profile, harness configuration, corpus bytes, input fixtures/evidence, JSON schemas and the generator source. Reusing a package verifies the stored bytes; altered content is rejected. Generated content is data, never executed as shell scripts or Python.

## Current limitations

The legacy catalog is hard-coded, includes confirmed incorrect AIID mappings, and uses placeholder fixture references. Its mutation wrappers do not establish boundary coverage. The strict compiler now uses a structured carrier/placement generator with twelve attack cases and six paired controls. It requires authority, carrier and staged-placement mutation permissions. A separate R1 package runner replays the staged inputs from stored bytes. Compiled R2 tool-response/template and R3 peer/artifact/summary/template routing is now available. Twenty mechanism templates now include structured email/document/split inputs, long context, remembered instructions, configuration redirects and trigger-dependent local canaries. These templates have materialization tests; useful live behavior for all twenty has not been demonstrated.

The live Gemini response parser has offline unit tests for content, tool calls, refusal and failures. No external provider run has been performed. The old pricing registry is unverified; do not use its dates or rates as a current vendor quote. A separately controlled gateway and internal-only trial-network deployment are implemented. Container isolation and image pins remain unverified because Docker socket access is denied. Independent task checks for every scenario and full structured surface routing remain incomplete.

Passing unit tests or a mock trace is not evidence that all 20 scenarios meet the release gate. See the status matrix for the remaining work. The accompanying ZIP is a development candidate containing source, tests, documentation and historical evidence. Read DELIVERY_STATUS.md before treating any legacy report as acceptance.
