# TrustBoundary v1.6.0 — Verified public release

- Public source, FastAPI app, frontend, tests, reports, README, DOCX/code ingestion and v1.6 normalization are uploaded at repository root: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security.
- Fresh-checkout GitHub Actions source and media commits **passed**, with 146 automated tests in the v1.6 suite. The latest screenshot and cleanup commits have their own CI checks; confirm each run before claiming the final HEAD is green.
- The v1.6 pitch PDF/PPTX and 2m27 narrated **screenshot walkthrough** are published. This video depicts real local UI screenshots but is not a live interaction recording.
- Provisional maturity: F3–D1 only. A previously authored 40-case challenge detects **7/20 attacks (35% recall)**; this is poor generalization. The 50-business-email set has 2/50 false positives (4%).
- External public prompt-injection benchmark runner is present but has **not** successfully run against downloaded public data.
- OpenAI BYOK Settings works in mocked tests and falls back offline. **A real live provider call remains unverified.** Revoke the API key previously pasted in conversation and use a newly issued private credential.
- Historical version test totals 63/70/82/100/112/124 refer to earlier releases; 146 is the current v1.6 local result.
- Git history was scanned using a local high-confidence pattern script within successful CI; dedicated gitleaks audit not performed.
- **No Unstop submission or receipt is confirmed.** Any final portal action remains with the participant.
