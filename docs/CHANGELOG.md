# Changelog

## v1.7.0 — 10 October 2026 (experimental)
- Added structure-based offline security signals for agent-directed override, role impersonation, tool misuse, secrets, multi-stage manipulation and untrusted knowledge poisoning.
- Added strict-schema hosted OpenAI semantic judge returning instruction intent, category labels, evidence excerpt and confidence; advisory only. **No live OpenAI request was performed in this release.**
- Added optional real-model tool-call proposal comparison (requires private BYOK). Protected mock execution applies trusted task matching, RBAC and provenance; unprotected proposal execution is synthetic only.
- Added in-memory per-conversation decaying role/action risk (single-process, not identity-bound), Tesseract OCR for PNG/JPEG and image-only PDFs, and security response headers.
- Added Dockerfile, MIT license, tests and developer-cohort reports.
- Judge-authored set post-change score was 28/30 (93.3%) with 0/20 benign flagged, **after these cases became development examples**; not out-of-sample evidence. Previously published 40-case challenge scored 10/20 (50%) with 2/20 false positives on v1.7.
- Original v1.6 judge set baseline was 8/30 (26.7%), 0/20 false alerts. Do not conflate these releases.

## v1.6.0 (historical)
- Added Unicode normalization, URL/ROT13/base64 decoding, Word hidden text and source-code ingestion, grouped cross-validation (synthetic only), 146 automated tests, CSS/UI release consistency. Previously published 40-case challenge 7/20 (35%) recall.

## v1.5.0 (historical)
- Optional per-tab private OpenAI BYOK Settings, provider error handling, offline fallback. 124 tests. Hosted provider not independently exercised.

## v1.4.0 (historical)
- Published original case-level evaluation reports, CI verification and v1.4 deck/video. 112 tests. A new 40-case challenge produced 35% recall.

## v1.3.0 (historical)
- 100 tests. 60-case feedback-informed baseline and case-level reports.

## v1.2.1 and earlier (historical)
- Quotation activation and sanitizer fail-closed fixes; 82 tests in v1.2.1, 70 in v1.2, 63 in v1.1. Early synthetic template-family benchmark is not independent generalization proof.
