# Upstream Threat Intelligence Provenance Report
## Source Grounding
- **MITRE ATLAS**: Release `v2026.10` (data format `v6.1.0`), pinned locally at `data/sources/ATLAS-2026.10.yaml`
- **AI Incident Database (AIID)**: Curated records pinned locally at `data/sources/aiid_incidents.json`

## Scenario Mappings to Threat Catalog
| Spec ID | Family | Target | Origin Type | Grounded ATLAS Techniques & AIID Incidents |
| :--- | :---: | :---: | :---: | :--- |
| F1-S1 | F1 | R1 | observed | AML.CS0024, AML.CS0059, AML.T0051.001, AIID-INC-0012 |
| F1-S2 | F1 | R1 | observed | AML.CS0035, AML.T0070, AIID-INC-0028 |
| F1-S3 | F1 | R1 | adaptation | AML.CS0025, AML.T0066 |
| F1-S4 | F1 | R1 | observed | AML.CS0029, AML.T0077, AIID-INC-0044 |
| F2-S1 | F2 | R2 | observed | AML.CS0037, AML.T0085.001, AIID-INC-0067 |
| F2-S2 | F2 | R2 | observed | AML.CS0026, AML.T0053, AIID-INC-0089 |
| F2-S3 | F2 | R2 | adaptation | AML.CS0070, AML.CS0055, AML.T0102 |
| F2-S4 | F2 | R2 | adaptation | AML.CS0073, AML.CS0068, AIID-INC-0103 |
| F3-S1 | F3 | R3 | adaptation | AML.CS0071, AML.T0118.001, AIID-INC-0118 |
| F3-S2 | F3 | R3 | adaptation | AML.CS0071, AML.T0118.000 |
| F3-S3 | F3 | R3 | adaptation | AML.CS0069, AML.T0124, AIID-INC-0118 |
| F3-S4 | F3 | R3 | adaptation | AML.CS0068, AML.CS0073, AML.M0037, AIID-INC-0103 |
| F4-S1 | F4 | R3 | adaptation | AML.T0080.001, AML.T0054 |
| F4-S2 | F4 | R3 | observed | AML.CS0072, AML.T0131, AIID-INC-0177 |
| F4-S3 | F4 | R3 | observed | AML.CS0040, AML.CS0066, AML.T0080.001, AIID-INC-0134 |
| F4-S4 | F4 | R3 | adaptation | AML.CS0053, AML.T0110.002 |
| F5-S1 | F5 | R2 | observed | AML.CS0064, AML.T0018.003 |
| F5-S2 | F5 | R3 | observed | AML.CS0041, AML.CS0049, AIID-INC-0155 |
| F5-S3 | F5 | R2 | adaptation | AML.CS0054, AML.T0081 |
| F5-S4 | F5 | R3 | adaptation | AML.CS0038, AML.T0051.002 |
