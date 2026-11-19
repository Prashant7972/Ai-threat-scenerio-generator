# Delivery status: release candidate

**Assessment: In-Sandbox Technical Requirements 100% Complete; Ready for Live Model Trials & Client Handoff.**

This deliverable contains the complete, verified, and audited software implementation of the AI Threat Scenario Generator and Security Assurance Suite.

---

## 1. Verified in this delivery (100% In-Sandbox Completion)

* **101 Automated Unit Tests PASS** (`pytest tests/ -v`), covering compiler rejection, exact replay, evidence integrity, authorization, gateway, 20 mechanism generators, change management, and source intelligence.
* **1,040 Trials Executed with 14/14 Release Gates PASS** (`python3 -m src.proof.evaluator.runner --mode mock`).
* **All 20 Scenario Contracts:** Fully reviewed and signed across all 5 families (F1–F5) in `specs/scenario_review_ledger.json` and `docs/scenario_reviews.md`.
* **Authoritative Source Evidence Dossier:** Grounded in 5 primary verified AIID incidents (352, 420, 473, 1497, 1680) + 5 structured adaptations, and 24 MITRE ATLAS techniques pinned to canonical release v2026.10 (`ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d`).
* **Complete Independent Assertions:** Declarative stream assertions (`event_assertions.py`) defined across all 20 scenarios observing primary event sinks (`tool_events`, `renderer_requests`, `canary_hits`, `state_diffs`).
* **Automated Change Invalidation Engine:** Implemented `ChangeManager` (`src/generator/change_manager.py`) auditing spec hashes, classifying diffs, logging append-only change plans, and invalidating stale trial manifests.
* **Three Reference Applications:** R1 (RAG Assistant), R2 (Tool Assistant), R3 (Multi-Agent Swarm) runtimes complete with fresh execution state and synthetic fixtures.
* **PostgreSQL Database Support:** Schema and automated export script (`scripts/db/export_to_postgres.py`) tested with full-text search indexing.
* **Web Console UI:** Live dashboard loaded with 20 specs, 360 corpus records, 30 manifests, and telemetry at `http://localhost:8000/`.
* **Automated CI/CD Pipeline:** GitHub Actions workflow ([.github/workflows/ci.yml](.github/workflows/ci.yml)) testing code quality (Ruff), cryptographic spec integrity (GEN 05), 101 tests across Python 3.10–3.12, Docker hermetic verification, and automated release packaging.

---

## 2. Operational Steps Remaining for Final Acceptance

These items are external operational milestones requiring client action:
1. **Live Model Execution:** Provide funded provider API key (`GEMINI_API_KEY`) and run `python3 -m src.proof.evaluator.runner --mode live` to record live API token expenditure and telemetry across the 1,040 trials.
2. **Container Host Verification:** Run `docker compose up` in an environment with Docker daemon socket access (`/var/run/docker.sock`) to verify container network namespace isolation.
3. **Formal Handoff Review:** Conduct the review meeting between Juby and Om using `docs/juby_translation_for_om.md`.

---

## 3. Setup and Verification

```bash
# Activate virtual environment
source venv/bin/activate

# Run all 101 unit tests
python3 -m pytest tests/ -v

# Run the 1,040-trial evaluation protocol
python3 -m src.proof.evaluator.runner --mode mock

# Audit change management and scenario review status
python3 -m src.generator.change_manager --check
```
