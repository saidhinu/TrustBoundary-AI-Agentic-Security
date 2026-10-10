# TrustBoundary submission checklist — v1.4.0

- [x] Public GitHub source at repository root; verify every v1.4 file and artifact after publication.
- [x] Working local prototype with synthetic fintech workflow and deterministic tool authorization.
- [x] Historical 42-case corpus, original evaluator and **pre-fix** baseline CSV/metrics preserved; compare against post-fix results.
- [x] Added a separate 60-case authored challenge set; see tests/unseen_20261010.json and distinct report.
- [x] Proposed self-rating remains **F3–D1**. Neither synthetic suite shows production security or independently verified D2 reliability.
- [x] PDF and PPTX pitch deck updated locally to v1.4 with both adversarial and template metrics.
- [x] 2–4 minute synthetic-narration demo updated locally to v1.4; recommend participant's own recorded narration.
- [ ] Verify playback/download of actual judge-accessible repository, video and deck hyperlinks (prefer browser signed-out test).
- [x] Hosted OpenAI protocol, invalid output, false-positive and timeout/401/429/503 fallback validated with local mocks.
- [ ] Live OpenAI HTTP requests/false-positive rate remain **UNVERIFIED** without user-supplied API key; run `scripts/evaluate_openai_live.py` privately.
- [ ] Deploy reachable hosted demo if specifically required; the prototype currently runs locally only.
- [ ] Submit links to official Unstop event from the registered participant account and **retain a confirmation receipt**.
- [ ] Confirm contest disclosure/originality/participant rules.

**Older 55, 63, 70 and 82 test results are historical v0.9–v1.2.1 releases, not the current suite.**
**Event deadline in original documentation: October 11, 2026 23:59 IST.**

**Current v1.4 metrics:** 112 local automated tests; historical 42-case 58.3% recall; feedback-informed prior 60-case retest 100%; newly authored 40-case challenge 35% recall (7/20), 1/20 benign false positive. Do not confuse older 63/70/82/100 suites with v1.4.
