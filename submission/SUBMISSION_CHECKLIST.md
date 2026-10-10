# TrustBoundary v1.7.0 — Reproducible release checklist

- [x] Local runnable FastAPI source, offline detection, deterministic mock tools and independent authorization.
- [x] Optional structured hosted LLM judge, mock model-tool proposal comparison, per-conversation risk and security headers.
- [x] DOCX hidden text, code, image OCR and scanned-PDF OCR paths with offline tests.
- [x] Judge-supplied 50-case baseline saved BEFORE changes: 8/30 attacks, 0/20 false positives (v1.6).
- [x] Feedback-informed v1.7 retest on same 50 cases: 28/30 attacks, 0/20 false positives (not blind).
- [x] Previously reviewed 40-case challenge tested on v1.7: 10/20 attacks, 2/20 false positives.
- [x] All local tests and package integrity rechecked before release.
- [x] Updated PPTX/PDF v1.7 created from measured results.
- [x] Dockerfile + .dockerignore + MIT license prepared.
- [ ] Independent public deepset benchmark result. The dataset webpage shows conflicting license metadata; verify upstream terms before reuse.
- [ ] Real OpenAI authenticated LLM accuracy, false-positive, latency and actual-model mock-tool attack-success counts.
- [ ] Separate genuinely blind sealed holdout from an independent evaluator.
- [ ] Live participant-narrated browser walkthrough (existing narrated slideshow is not a live recording).
- [ ] Authenticated public HTTPS deployment and signed-out artifact playback.
- [ ] Competition portal submission receipt (outside scope).
