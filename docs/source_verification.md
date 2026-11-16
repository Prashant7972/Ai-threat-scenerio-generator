# Source verification and quarantine

Checked 2026-11-16. These are source-verification notes, not analyst approval of scenario adaptations. The legacy source catalog and its derived snapshots are not accepted evidence.

## Confirmed legacy mismatches

| Legacy reference | Legacy assertion | Actual AIID subject | Disposition |
|---|---|---|---|
| [AIID 12](https://incidentdatabase.ai/cite/12) | Retrieved-email prompt injection | Common biases of vector embeddings | Reject this incident-to-mechanism claim |
| [AIID 28](https://incidentdatabase.ai/cite/28) | Shared document RAG compromise | 2010 market flash crash | Reject this incident-to-mechanism claim |

The remaining legacy AIID entries have not been individually verified and must not count toward acceptance quotas. The local `ATLAS-2026.10.yaml` is a small hand-maintained file, not a verified copy of the official release; matching its version string does not establish authenticity.

## Verified source discovery for replacement work

| Item | Source-supported fact, paraphrased | Adaptation limits |
|---|---|---|
| [AIID 352](https://incidentdatabase.ai/cite/352/) | A GPT-3 Twitter bot was redirected by users to produce attacker-chosen text. | Does not establish peer-agent compromise or renderer disclosure. Such scenarios would be explicit hypotheses. |
| [AIID 420](https://incidentdatabase.ai/cite/420/) | Users reported circumventing ChatGPT filters, including through persona-based prompts. | Does not establish persistent memory poisoning, delegated authorization or a financial tool attack. |
| [AIID 473](https://incidentdatabase.ai/cite/473/) | Early Bing testers used prompt injection to disclose initial instructions. | Does not establish CRM extraction or email-mediated exfiltration. |
| [AIID 1497](https://incidentdatabase.ai/cite/1497/) | Hidden instructions in a legal petition reportedly sought to influence Galileu's analysis; the system reportedly detected and blocked them. | Supports document-instruction delivery; no evidence here for split-document success or data disclosure. |
| [AIID 1680](https://incidentdatabase.ai/cite/1680/) | A Cline issue-triage and cache-poisoning chain reportedly led to unauthorized package publication. | Supports investigating untrusted workflow inputs and authority boundaries; synthetic configuration/canary adaptations are not replications of the complete chain. |

These five discovered incidents are not automatically mapped to ten specs to satisfy a quota. Source claims, adaptation rationales and reviewer approval still need to be recorded for each mapping.

## Authoritative ATLAS source

[MITRE's atlas-data repository](https://github.com/mitre-atlas/atlas-data) identifies its distributed YAML as authoritative. [The v2026.10 release](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.10) is available for pinning. Its reported asset SHA-256 is `ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d` for the listed `ATLAS-2026.10.yaml` asset; verify the downloaded asset against the published digest before treating it as the taxonomy snapshot.

The official [ATLAS site](https://atlas.mitre.org/) identifies AML.T0051 as LLM Prompt Injection. Exact sub-technique mappings and release definitions still require checking against the authoritative downloaded bytes. A network download from this execution environment failed with a DNS-resolution error; no official YAML was silently substituted or fabricated.

## Required next steps

Obtain immutable source records, assign stable claim IDs, preserve source revision/locator and exact snapshot hashes, record scenario-specific adaptation rationales, and obtain analyst review. Count incident/technique coverage only after those steps. The compiler's hash checks prevent changed bytes from going unnoticed, but they cannot prove that an incident supports a claimed mechanism.
