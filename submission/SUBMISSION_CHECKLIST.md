# TrustBoundary submission checklist — v1.5.0

- [x] Public GitHub source at repository root; verify every v1.4 file and artifact after publication.
- [x] Working local prototype with synthetic fintech workflow and deterministic tool authorization.
- [x] Historical 42-case corpus, original evaluator and **pre-fix** baseline CSV/metrics preserved; compare against post-fix results.
- [x] Added a separate 60-case authored challenge set; see tests/unseen_20261010.json and distinct report.
- [x] Proposed self-rating remains **F3–D1**. Neither synthetic suite shows production security or independently verified D2 reliability.
- [x] PDF and PPTX pitch deck published and hash-verified to v1.4 with both adversarial and template metrics.
- [x] 2–4 minute synthetic-narration demo published and hash-verified to v1.4; recommend participant's own recorded narration.
- [x] Public repository contains v1.4 source, case-level corpus/reports, PPTX/PDF and reconstructed narrated MP4. Git blob SHA checks passed; GitHub video assembly workflow completed successfully.
- [x] Fresh-checkout GitHub Actions workflow installed dependencies, passed 112 tests and reproduced historical/current case metrics: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/actions/runs/38033073702
- [ ] Independently verify file access in a signed-out browser (not available through the current verification interface).
- [x] Hosted OpenAI protocol, invalid output, false-positive and timeout/401/429/503 fallback validated with local mocks.
- [ ] Live OpenAI HTTP requests/false-positive rate remain **UNVERIFIED** without user-supplied API key; run `scripts/evaluate_openai_live.py` privately.
- [ ] Deploy reachable hosted demo if specifically required; the prototype currently runs locally only.
- [ ] Unstop competition portal submission and receipt are deliberately **out of scope** of this work, per participant request.
- [ ] Confirm contest disclosure/originality/participant rules.

**Older 55, 63, 70 and 82 test results are historical v0.9–v1.2.1 releases, not the current suite.**
**Event deadline in original documentation: October 11, 2026 23:59 IST.**

**Current v1.4 metrics:** 112 local automated tests; historical 42-case 58.3% recall; feedback-informed prior 60-case retest 100%; newly authored 40-case challenge 35% recall (7/20), 1/20 benign false positive. Do not confuse older 63/70/82/100 suites with v1.4.

**Publish status:** GitHub repository and three primary submission assets verified against local Git hashes; GitHub Actions CI successful. Real OpenAI validation and signed-out browser checks remain unverified.

- [x] v1.5: Settings mode selector and per-visitor personal key (memory-only), connection test and clear-key controls committed to GitHub.
- [x] Offline default and API fallback; synthetic/mocked connection and per-visitor isolation tests included in 124-test suite.
- [ ] Live OpenAI call: requires a newly rotated secret entered privately in Settings; the previously exposed key must not be reused.
- [ ] v1.5 UI demo recording / pitch screenshot refresh, if presentation is to feature BYOK; existing assets remain v1.4 demonstrations.
