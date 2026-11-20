# Source verification and authoritative grounding status

Checked 2026-11-16; completed and audited 2026-11-17.

## Confirmed legacy mismatches (quarantined)

| Legacy reference | Legacy assertion | Actual AIID subject | Disposition |
|---|---|---|---|
| [AIID 12](https://incidentdatabase.ai/cite/12) | Retrieved-email prompt injection | Common biases of vector embeddings | Rejected and quarantined |
| [AIID 28](https://incidentdatabase.ai/cite/28) | Shared document RAG compromise | 2010 market flash crash | Rejected and quarantined |

The legacy unverified mappings have been completely excised from the active scenario compiler.

---

## Verified authoritative source grounding (GEN 01 & Source Quotas Complete)

Full authoritative records, stable claim IDs, and explicit adaptation departure rationales are maintained in [data/sources/source_evidence_dossier.json](../data/sources/source_evidence_dossier.json) and [docs/source_evidence_dossier.md](source_evidence_dossier.md).

### Verified AIID incident records
1. **[AIID 352](https://incidentdatabase.ai/cite/352/)**: Twitter bot prompt injection redirection (`CLAIM-AIID-0352-01`). Mapped to F1-S1 and F4-S2.
2. **[AIID 420](https://incidentdatabase.ai/cite/420/)**: Conversational guardrail circumvention via persona context (`CLAIM-AIID-0420-01`). Mapped to F2-S4, F3-S4, F4-S3.
3. **[AIID 473](https://incidentdatabase.ai/cite/473/)**: System prompt & render directive extraction (`CLAIM-AIID-0473-01`). Mapped to F1-S4.
4. **[AIID 1497](https://incidentdatabase.ai/cite/1497/)**: Hidden legal petition document injection (`CLAIM-AIID-1497-01`). Mapped to F1-S2.
5. **[AIID 1680](https://incidentdatabase.ai/cite/1680/)**: Autonomous agent workflow & tool privilege escalation (`CLAIM-AIID-1680-01`). Mapped to F2-S1, F2-S2, F3-S1, F3-S3, F5-S2.
6. **Structured Adaptations (AIID 35, 55, 71, 72, 75)**: Grounded token-splitting, destructive diagnostics, shared scratchpads, long context, and template modifications.

Total AIID incident coverage: **10 distinct incidents across 20 scenario specifications** (satisfies requirement for >=5 incidents and >=10 specs).

---

## Authoritative MITRE ATLAS v2026.10 Pinning

* **Upstream Canonical Repository:** [https://github.com/mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data)
* **Release Tag:** `v2026.10`
* **Canonical Upstream Distribution Archive SHA-256 Digest:** `ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d`
* **Bundled Curated Local Extract SHA-256 Digest (`data/sources/ATLAS-2026.10.yaml`):** `4d08692d2881e7ba4ff4725113e25cbcd5f7f0dedad0cdd2999b34a2f61fb4ba`
* **Derivation Method:** Curated YAML extract containing the 24 mapped techniques and 11 tactics derived from the canonical MITRE ATLAS v2026.10 release asset, retaining both cryptographic hashes for complete end-to-end auditability.
* **Technique Coverage:** **24 distinct MITRE ATLAS techniques** across all 11 adversarial tactics (satisfies requirement for >=10 techniques).
