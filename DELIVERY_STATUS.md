# Delivery status: development candidate

This ZIP does not fulfill final client acceptance. It is the current implementation and an auditable handoff, not a claim of 20 accepted scenarios.

## Verified in this delivery

- 96 automated tests pass, including twenty mechanism materialization tests (12 attacks plus six paired controls each), compiler rejection, exact replay, evidence integrity, authorization, gateway and suite-planning checks.
- Source code includes explicit pattern/profile compilation, content-addressed packages, curated generators, three reference application runtimes, independent event assertions, a separate inference gateway and a 1,040-attempt release planner.
- Template/configuration mutations retain actual file hashes and diffs. Destinations and impact fixtures are synthetic/local; no generated executable fixture code is run.
- The repository is separate from the previous project. No remote git push was performed for this delivery.

## Required before client acceptance

1. Complete and independently review twenty grounded patterns, fixture sets, target profiles and per-scenario assertions. Unit-test approval identities are synthetic fixtures, never analyst approvals.
2. Verify the required AIID claim-to-scenario relationships and authoritative versioned ATLAS mappings. Existing legacy corpus counts do not establish source support.
3. Build and pin vulnerable/hardened images, verify isolation and inference allowlists in deployment. Docker socket access prevented runtime verification in this environment.
4. Finish source/deployment attestation integration and change-driven withdrawal/test enforcement. The compiled release gate deliberately remains unaccepted while evidence verification is incomplete.
5. Estimate provider costs using approved rates, configure credentials outside this archive, and execute all 1,040 required live attempts within approved budgets. Record failures and retries; remediate each failed scenario. Mock tests cannot substitute for this protocol.
6. Obtain Juby's actual review of the draft context transfer for Om. The draft is not represented as Juby's work.

## Reading historical material

`data/`, `specs/` and `reports/` include legacy prototype artifacts. Some historical reports claim PASS using mock or insufficient evidence. Those claims are superseded by this status and `docs/requirements_status.md`; they are retained for audit, not accepted release evidence. Do not run the legacy catalog as an approved source-grounded release.

## Setup

Use Python 3.10 or newer in a virtual environment. Install `requirements.txt`, then run `python3 -m pytest tests/ -q`. See README.md, docs/compiler_workflow.md and deployment/README.md for compiler and controlled execution instructions. Dependencies are not bundled; installation requires package access. This archive excludes repository metadata, credentials, caches and virtual environments.

See PACKAGE_MANIFEST.json for SHA-256 hashes of delivered files. The original ZIP is preserved separately.
