# Framework mappings

Verified 2026-11-24 against the official sources below.

| Scenario | OWASP LLM 2025 | OWASP Agentic 2026 | MITRE ATLAS 2026.10 | MITRE ATT&CK |
|---|---|---|---|---|
| S01 | LLM01, LLM06 | ASI01, ASI03 | AML.T0051.001, AML.T0053 | T1098 |
| S02 | LLM01, LLM02, LLM05 | ASI01 | AML.T0070, AML.T0051.001, AML.T0085.000, AML.T0086 (fetch variant) | T1567 |
| S03 | LLM06 | ASI03 | AML.T0053 | T1098, T1078 |
| S04 | LLM03, LLM01 | ASI04 | AML.T0110, AML.T0010.005 | T1195, T1567 |
| S05 | LLM02 | ASI03 | AML.T0098, AML.T0055 | T1552, T1078.004 |

## Always cite the year

OWASP also publishes a [2026 list](https://genai.owasp.org/top-10-for-llm-applications-2026/) with different numbers. **LLM06 is Excessive Agency in 2025 and Unbounded Consumption in 2026.** This repo pins 2025. The 2026 page does not say whether it is final.

| Risk | 2025 | 2026 |
|---|---|---|
| Prompt Injection | LLM01 | LLM01 |
| Sensitive Information Disclosure | LLM02 | LLM02 |
| Supply Chain | LLM03 | LLM04 |
| Improper Output Handling | LLM05 | LLM10 |
| Excessive Agency | LLM06 | LLM03 |

## ID choices

| Considered | Used | Why |
|---|---|---|
| AML.T0057 LLM Data Leakage (S02) | AML.T0085.000, AML.T0086 | Not present in ATLAS 2026.10 (2026-10-28). The changelog moves it to AML.T0085.002, conversation context, which does not describe a RAG read |
| AML.T0010 "ML Supply Chain Compromise" (S04) | AML.T0010.005, AML.T0110 | T0010 is now named Supply Chain Compromise. The sub-technique and Tool Poisoning fit better |
| LLM07 (S05) | Dropped | The system prompt does not leak in this scenario |

## Names and sources

| ID | Official name | Verified |
|---|---|---|
| LLM01, LLM02, LLM03, LLM05, LLM06 (2025) | Prompt Injection; Sensitive Information Disclosure; Supply Chain; Improper Output Handling; Excessive Agency | yes, [genai.owasp.org](https://genai.owasp.org/llm-top-10/) |
| ASI01, ASI03, ASI04 (2026) | Agent Goal Hijack; Identity and Privilege Abuse; Agentic Supply Chain Vulnerabilities | yes, [genai.owasp.org](https://genai.owasp.org/top-10-for-agentic-applications-2026/) |
| AML.T0051.001 | LLM Prompt Injection: Indirect | yes, ATLAS data |
| AML.T0053 | AI Agent Tool Invocation | yes, ATLAS data |
| AML.T0070 | RAG Poisoning | yes, ATLAS data |
| AML.T0085.000 | Data from AI Services: RAG Databases | yes, ATLAS data |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | yes, ATLAS data |
| AML.T0110 | AI Agent Tool Poisoning | yes, ATLAS data |
| AML.T0010.005 | Supply Chain Compromise: AI Agent Tool | yes, ATLAS data |
| AML.T0098 | AI Agent Tool Credential Harvesting | yes, ATLAS data |
| AML.T0055 | Unsecured Credentials | yes, ATLAS data |
| T1098 | Account Manipulation | yes, [attack.mitre.org](https://attack.mitre.org/techniques/T1098/) |
| T1078, T1078.004 | Valid Accounts; Cloud Accounts | yes, [attack.mitre.org](https://attack.mitre.org/techniques/T1078/004/) |
| T1195 | Supply Chain Compromise | yes, [attack.mitre.org](https://attack.mitre.org/techniques/T1195/) |
| T1552 | Unsecured Credentials | yes, [attack.mitre.org](https://attack.mitre.org/techniques/T1552/) |
| T1567 | Exfiltration Over Web Service | yes, [attack.mitre.org](https://attack.mitre.org/techniques/T1567/) |

ATLAS source: `dist/v6/ATLAS-2026.10.yaml` in [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data). The older `dist/ATLAS.yaml` is frozen at 5.6.0 and marked deprecated.
