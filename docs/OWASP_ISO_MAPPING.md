# Mapping the original controls to OWASP, NIST AI RMF and ISO

Controls C1 to C8 against the OWASP Top 10 for LLM Applications, NIST AI RMF functions and ISO 27001 / 42001 references. ISO references for C2 and C3 are my interpretation (no dedicated clause). For the MAS AIRM, US model risk and NIST subcategory mapping of the governance controls, see [CONTROL_MAPPING.md](CONTROL_MAPPING.md).

| Control | OWASP Top 10 for LLM Applications | NIST AI RMF function | ISO 42001 / ISO 27001 reference |
|---------|-----------------------------------|----------------------|---------------------------------|
| C1 PII redaction | Sensitive Information Disclosure (LLM06) | Manage | ISO 27001: A.8.11 Data masking, A.5.34 Privacy and protection of PII, A.8.12 Data leakage prevention. ISO 42001: A.7.3 Data management, A.7.6 Data preparation |
| C2 Input injection check | Prompt Injection (LLM01) | Measure, Manage | No dedicated clause. Related (interpretation): ISO 27001: A.8.8 Management of technical vulnerabilities, A.8.25 Secure development life cycle, A.8.28 Secure coding. ISO 42001: A.7.7 AI system design and development |
| C3 Tool output scan | Prompt Injection (Indirect) (LLM01) | Measure, Manage | No dedicated clause. Same related controls as C2 |
| C4 Tool policy | Excessive Agency (LLM08) | Govern, Manage | ISO 27001: A.5.15 Access control, A.8.3 Information access restriction, A.8.12 Data leakage prevention. ISO 42001: A.9.4 Intended use of the AI system |
| C5 Human approval | Excessive Agency (LLM08) | Manage | ISO 27001: A.8.12 Data leakage prevention. ISO 42001: A.9.2 Processes for responsible use |
| C7 Output guard | Sensitive Information Disclosure (LLM06), Insecure Output Handling (LLM02) | Manage | ISO 27001: A.8.12 Data leakage prevention, A.8.11 Data masking |
| C8 MAS Section 4 gate | Excessive Agency (LLM08) (governs what may run at all) | Govern | MAS AI Risk Management Guidelines, Section 4 (AI identification, inventory, risk materiality) |
| C6 Audit log | Mitigates Insecure Output Handling (LLM02) and Insecure Plugin Design (LLM07)* | Govern, Measure, Manage | ISO 27001: A.8.15 Logging. ISO 42001: A.6.2.8 Recording of event logs |

*\*Note: While standard OWASP Top 10 includes Logging & Monitoring, the LLM-specific Top 10 does not have a dedicated logging category. The audit log serves as the primary compensating control for LLM02 and LLM07.*
