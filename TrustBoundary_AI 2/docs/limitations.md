# Important Limitations & Honest Judging Statement

1. **Offline detector** is a small development-set-trained ML/heuristic hybrid. This is a demonstration of a security architecture, **not** an independently validated prompt-injection defense.
2. **Optional LLM** can be configured for additional advisory category labels, but it was not called or externally validated in the generated offline benchmark. LLM disagreement/false negatives are foreseeable.
3. **Scripted baseline** intentionally models an unsafe executor. Its attack success rate must NEVER be presented as a measured failure rate of GPT, Claude, Gemini or any other actual LLM.
4. **Agentic maturity:** three bounded components coordinate automatically with tools and incident summaries. In offline mode, orchestration is workflow logic, not autonomous high-level LLM planning.
5. **Synthetic dataset:** small and templated; data and rules share design assumptions. A strong result is only a regression smoke test. No claim of real-world generalization is justified.
6. **D2 / D3:** high reliability on these tests alone cannot validate D2 generally. D3 is not claimed; image OCR and complex scanned PDFs are absent.
7. **Parsing:** uploads limited to 5 MB; PDF extracted text only, first 25 pages; HTML parser is illustrative and not a hardened sanitizer.
8. **Security:** local demo has no authentication, request limits, tenant isolation, SIEM integration, immutable audit logs or production human approval service. Run locally, not as an open internet application.
9. **Sensitive content:** do not paste real customer data, genuine API keys or production merchant records. Optional LLM mode transmits content to the model provider.
10. **Business impact:** expected loss reduction, risk rates, labor cost and platform spending are adjustable assumptions—not an empirical result.
11. **Competition:** participants should confirm whether AI-generated content is allowed and disclose AI assistance under current rules. Working artifact does not guarantee judging outcomes.
