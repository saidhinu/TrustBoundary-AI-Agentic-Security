# TrustBoundary v1.6 — Release verification checklist

- [x] Local working FastAPI/UI source and offline-first detector.
- [x] 146 local automated tests including Unicode/encoding and Word/code ingestion tests.
- [x] Original historical 42-case baseline retained at 58.3% recall (14/24).
- [x] Reviewed 42-case known retest at 100% (24/24); 60-case known retest at 100% (30/30); neither is independent.
- [x] Previously authored 40-case challenge remains at 35% (7/20); false-positive 1/20.
- [x] 50 additional business emails measured: 2/50 false positives (4%).
- [x] GroupKFold synthetic-family ML-only evaluation script/report; 135/135 recall, not external validation.
- [x] DOCX, PY, JS and Unicode inspection paths added and regression tested.
- [x] PDF/PPTX v1.6 regenerated, based on latest evidenced results.
- [x] Local v1.6 screenshots, 10-slide deck and 2m27 screenshot walkthrough generated; GitHub verification remains pending.
- [ ] v1.6 screenshot/video evidence and updated media checked from a signed-out browser.
- [ ] GitHub source commit and fresh-checkout CI for v1.6 verified (previous v1.5 GitHub runs do not count).
- [ ] Public deepset official test split evaluated: pin-and-download script exists; download unavailable in build environment.
- [ ] Live OpenAI model run: NOT verified (requires a newly generated secret; exposed key must be revoked).
- [ ] Full Git history scanned with a dedicated gitleaks scan; pending external runner.
- [ ] Complete authenticated human review, originality statements and competition portal submission.

## Historical notes

v1.2.1 had 82 tests; v1.3 had 100; v1.4 had 112; v1.5 had 124. These are historical release counts. v1.6 currently has 146 local passing tests. Keep these distinct from benchmark case counts.

Deadline according to event brief: 11 October 2026, 23:59 IST. No Unstop submission has been made or confirmed in this workflow.
