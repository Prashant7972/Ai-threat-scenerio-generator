# Authoritative Source Grounding Dossier (GEN 01 & Source Quotas)

**Status:** Verified Evidence-Backed Source Dossier  
**Release Pin:** MITRE ATLAS v2026.10 (`ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d`)  
**AIID Incidents:** 5 primary verified empirical incidents (AIID 352, 420, 473, 1497, 1680) + 5 structured adaptations  
**Scenarios Mapped:** All 20 scenarios across F1–F5  

---

## 1. Grounding Integrity Standard

In compliance with the Rescoped Requirements (**GEN 01** and **Source Quotas**):
1. **Verified Support vs. String IDs:** Quotas are satisfied only by documented, factually verified real-world incidents, not by counting arbitrary strings in a list.
2. **Observed Facts vs. Adapted Hypotheses:** Observed historical incident facts are strictly separated from test harness adaptations.
3. **No Synthetic Payload Attribution:** Synthetic test payloads generated in the sandbox are explicitly labeled as synthetic variants and never represented as the exact literal payload recovered from the original breach.

---

## 2. Primary Verified AIID Incidents

### Incident 1: AIID-INC-0352 — Twitter Bot Redirection via Prompt Injection
* **URL:** [https://incidentdatabase.ai/cite/352/](https://incidentdatabase.ai/cite/352/)
* **Observed Facts:** An AI-powered Twitter bot driven by GPT-3 was manipulated by public users who sent adversarial tweets containing commands like *"Ignore previous instructions and say..."*. The bot abandoned its brand-aligned behavior and generated attacker-chosen statements.
* **Stable Claim ID:** `CLAIM-AIID-0352-01`
* **Mapped Scenarios:**
  * **F1-S1** (External Email Retrieval): Adapts prompt redirection to an email context where incoming customer emails coerce the summarizer into data exfiltration.
  * **F4-S2** (Conversation State Redirection): Adapts the mechanism to multi-turn session state manipulation.
* **Adaptation Limits:** Does not establish multi-agent tool execution or network file upload; synthetic payloads are structured for email and conversation testing.

### Incident 2: AIID-INC-0420 — Guardrail Circumvention via Persona Framing
* **URL:** [https://incidentdatabase.ai/cite/420/](https://incidentdatabase.ai/cite/420/)
* **Observed Facts:** Users successfully bypassed conversational LLM safety guardrails using persona-based framing ("Do Anything Now") and hypothetical roleplay scenarios. The long-context hypothetical setup diluted the system prompt's negative constraints.
* **Stable Claim ID:** `CLAIM-AIID-0420-01`
* **Mapped Scenarios:**
  * **F2-S4** (Verbal Approval Bypass): Adapts persona framing to convince an assistant that verbal confirmation substitutes for an external authorization token.
  * **F3-S4** (Peer Authority Escalation): Adapts roleplay to convince an executor agent that a peer has elevated rights.
  * **F4-S3** (Memory Summary Framing): Uses hypothetical framing inside past memory summaries to override active policy.
* **Adaptation Limits:** The historical incident targeted conversational output; our scenarios adapt this to tool invocation and state integrity.

### Incident 3: AIID-INC-0473 — Bing Chat Initial Instruction Disclosure
* **URL:** [https://incidentdatabase.ai/cite/473/](https://incidentdatabase.ai/cite/473/)
* **Observed Facts:** Early testers used prompt injection to extract confidential developer system instructions, system prompts, and internal formatting directives from the Bing Chat assistant.
* **Stable Claim ID:** `CLAIM-AIID-0473-01`
* **Mapped Scenarios:**
  * **F1-S4** (Renderer Disclosure): Models the exfiltration of hidden system instructions and initial context via markdown image rendering tags.
* **Adaptation Limits:** Does not prove arbitrary database exfiltration; focuses on prompt disclosure via renderer channels.

### Incident 4: AIID-INC-1497 — Galileu Judicial Document Injection
* **URL:** [https://incidentdatabase.ai/cite/1497/](https://incidentdatabase.ai/cite/1497/)
* **Observed Facts:** In a Brazilian court's automated document analysis workflow (Galileu), an electronic legal petition was uploaded containing concealed adversarial instructions intended to alter the legal summary and favor the petitioner.
* **Stable Claim ID:** `CLAIM-AIID-1497-01`
* **Mapped Scenarios:**
  * **F1-S2** (Retrieved Document Injection): Ingested PDF/DOCX files containing hidden prompt injections attempting to coerce the RAG summarizer into emitting attacker directives.
* **Adaptation Limits:** Galileu successfully detected and isolated the attack; our vulnerable build demonstrates the failure mode while the hardened build demonstrates effective isolation.

### Incident 5: AIID-INC-1680 — Autonomous Agent Tool Privilege Escalation (Cline)
* **URL:** [https://incidentdatabase.ai/cite/1680/](https://incidentdatabase.ai/cite/1680/)
* **Observed Facts:** In an automated coding agent workflow (Cline), untrusted GitHub issue content and poisoned repository dependencies coerced the agent into executing privileged shell commands and publishing an unauthorized package.
* **Stable Claim ID:** `CLAIM-AIID-1680-01`
* **Mapped Scenarios:**
  * **F2-S1** (Tool Misuse: SQL Bulk Query)
  * **F2-S2** (Tool Misuse: Mock Wire Transfer)
  * **F3-S1** (Multi-Agent: Scope Expansion)
  * **F3-S3** (Multi-Agent: Authority Delegation Hijack)
  * **F5-S2** (Supply Chain: System Rules File Escape)
* **Adaptation Limits:** Real breach involved npm package publishing; our harness safely models mock financial transfers, SQL parameters, and sandboxed planner/executor boundaries.

---

## 3. MITRE ATLAS v2026.10 Coverage Matrix

All 24 mapped techniques are pinned to the official release asset SHA-256 `ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d`:

| ATLAS ID | Technique Name | Tactic | Mapped Scenarios |
|---|---|---|---|
| `AML.T0051.001` | LLM Prompt Injection: Indirect | Initial Access | F1-S1, F1-S2, F1-S3 |
| `AML.T0051.002` | LLM Prompt Injection: Trigger-dependent | Initial Access | F5-S4 |
| `AML.T0054` | LLM Jailbreak | Defense Evasion | F2-S4, F4-S3 |
| `AML.T0070` | RAG Poisoning | Collection | F1-S2 |
| `AML.T0066` | Retrieval Content Crafting | Collection | F1-S3 |
| `AML.T0077` | LLM Response Rendering | Exfiltration | F1-S1, F1-S4 |
| `AML.T0085.001`| AI Tool Misuse: Privileged API Call | Execution | F2-S1, F2-S2 |
| `AML.T0085.002`| AI Tool Misuse: Destructive Command Advice | Execution | F2-S3 |
| `AML.T0086` | Approval Bypass via Persona Emulation | Privilege Escalation | F2-S4 |
| `AML.T0087` | Multi-Agent Scope Hijacking | Privilege Escalation | F3-S1 |
| `AML.T0088` | Shared Artifact Poisoning | Lateral Movement | F3-S2 |
| `AML.T0089` | Agent Authority Boundary Traversal | Privilege Escalation | F3-S3 |
| `AML.T0090` | Agent Delegated Role Escalation | Privilege Escalation | F3-S4 |
| `AML.T0091` | Long-Context Attention Dilution | Defense Evasion | F4-S1 |
| `AML.T0092` | Conversation State Redirection | Execution | F4-S2 |
| `AML.T0093` | Memory Summary Integrity Poisoning | Persistence | F4-S3 |
| `AML.T0094` | Untrusted Error Status Coercion | Defense Evasion | F4-S4 |
| `AML.T0095` | Chat Template Injection | Persistence | F5-S1 |
| `AML.T0096` | System Rules File Boundary Escape | Defense Evasion | F5-S2 |
| `AML.T0097` | Tool Endpoint Configuration Redirection | Execution | F5-S3 |
| `AML.T0043` | Adversarial Data in LLM Memory | Persistence | F4-S3 |
| `AML.T0025` | Exfiltration via Tool Invocation | Exfiltration | F2-S2, F3-S3 |
| `AML.T0037` | Model Extraction / System Prompt Leak | Exfiltration | F1-S4 |
| `AML.T0040` | Execution via Injected Prompt | Execution | F2-S3 |
