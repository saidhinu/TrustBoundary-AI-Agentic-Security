# TrustBoundary AI v1.5 source status (10 October 2026)

**Source:** public GitHub repository: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security. Check commit and root-level file availability after every publication.

**Locally and on fresh GitHub Actions checkout verified:** 124 tests passed (v1.5 current); 112 passed in v1.4 historical release; deterministic offline smoke checks; historical v1.2.1 42-case reproduction 14 TP/10 FN/1 FP/17 TN; reviewer-informed known-case 60-case retest 30 TP; newly authored 40-case challenge 7 TP/13 FN/1 FP/19 TN. This is not production-ready or independently blind testing.

**Claim:** provisional F3-D1 only. Live hosted LLM requests remain unverified; an API key previously shared in conversation is considered exposed and was not used. Visitors can supply their own replacement key transiently via Settings for connection testing. Mocked success/error/timeout/fallback behavior is tested. Video narration is synthesized and not a human recording.

**Presentation:** v1.4 PPTX, PDF and 152.5-second narrated MP4 published to GitHub; Git object hashes match local files. GitHub Actions video assembly completed successfully.

**Unstop:** intentionally excluded from this work by user request; do not claim a submission or receipt.

**CI verification:** https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/actions/runs/38033073702 — success, including historical 42-case replay and new 40-case reproduction. Live hosted OpenAI remains unverified without private credentials. Signed-out browser inspection was not available; repository visibility is public.

**v1.5 BYOK:** Offline hybrid detection remains default with no API key. Settings allows each visitor to select OpenAI assisted, enter a personal key in browser tab memory, test it, and run scans via the backend. Keys are not saved in source, browser storage, or application database. Mock HTTP success/error/quota/timeout/fallback and cross-visitor isolation tests passed. The deck and demo remain v1.4 materials and do not show the Settings UI. Existing 40-case generalization results remain weak; do not claim a production-grade firewall.
