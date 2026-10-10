# Threat Model

**Assets:** agent trust boundary, mock fintech settlement data, permitted actions, dummy canary and audit integrity.

**Adversary:** controls low-trust content in merchant email, web pages, uploaded documents and tool results. The adversary does **not** control the trusted application instruction plane, code, authorization table or user identity.

**Attacker objective:** redirect the task; falsely claim elevated role; get the agent to attempt an unauthorized mock refund, email or synthetic secret disclosure; manipulate answer context.

**Defense:** source provenance, normalization, risky-pattern/local statistical ML/optional hosted AI classification, dispositions, deterministic role-and-origin authorization, never-allow secret action, bounded workflow and audit.

**Protected invariants:** low-trust content cannot confer permission; tool gate always runs; no actual external business tools; output cannot expose real secrets because none are provided.

**Known vulnerabilities/gaps:** paraphrased attacks may evade patterns; model-based instruction following is only optional and not security-hardened; prompt injection can exploit cross-turn state in sophisticated agents; multi-tenant auth, rate limits, audit access controls, KMS, real approval signatures, secure PDF sandboxing and OCR are not implemented. A hostile web-facing deployment would be unsafe.

**Testing:** category pattern tests, role matrix tests, known benign quotation test, unauthorized mock effect checks, input upload cases, and an 80-case synthetic holdout with test definitions separated by attack-phrase variants.
