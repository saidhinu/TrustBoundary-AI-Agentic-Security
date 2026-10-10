# TrustBoundary AI v1.4 — verified release (10 October 2026)

## Published artifacts
- Source root: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security
- Updated PDF: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/blob/main/submission/TrustBoundary_Hackathon_Pitch.pdf
- Updated PPTX: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/blob/main/submission/TrustBoundary_Hackathon_Pitch.pptx
- Updated narrated MP4: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/blob/main/submission/TrustBoundary_Demo_Walkthrough_Narrated.mp4
- Source evaluation: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/blob/main/scripts/evaluate_adversarial.py
- Original corpus: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/blob/main/tests/adversarial_review_cases.json
- Unseen-style authored challenge: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/blob/main/tests/new_challenge_v14_frozen.json

## Reproducibility
- CI fresh-checkout success: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/actions/runs/38033073702
- 112/112 automated tests passed in CI and local environment.
- CI re-ran the historical v1.2.1 42-case evaluation, the previously reviewed 60-case v1.4 retest and the new 40-case challenge.
- Video assembly succeeded: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/actions/runs/38033009740
- Narrated demo media: 3,882,792 bytes, 152.5 seconds, SHA-256 `ab1ea88ed1cc0a060fec4defb8a91323bf7832344a11addb7ef2694a0f01f954`.
- The Git blob hash for the publicly published video is `871ff9bfe017d90655a7be9d4f30275b7d957f3a`, matching the local release.
- PPTX Git blob `0a7c5ee4da66beebd5b2a4eca67d87845bc63fad` and PDF Git blob `2ab2410b412688ce084146b0d260f999034cee47` match the release source.

## Evidence and limitations
- Historical 42-case pre-fix: 14 TP, 10 FN, 1 FP, 17 TN (58.3% recall).
- Feedback-informed v1.4 retest on the previously reviewed 60 cases: 30 TP, 0 FN, 0 FP, 30 TN (100% recall). These examples informed fixes.
- The later authored 40-case set: 7 TP, 13 FN, 1 FP, 19 TN (35% recall). This is strong evidence **against** generalization claims.
- The original 45/45 templated holdout is not independent proof of robustness.
- Claim remains provisional **F3–D1**, not D2.
- OpenAI mode: mocked HTTP 401/429/503, timeouts, invalid output, spurious labels and fallback were tested. **No live hosted OpenAI responses were tested** because no private API key is available. An opt-in, manually triggered GitHub Action `live-openai.yml` is provided. Do not include an API key in a public file.
- GitHub metadata shows a public repository and artifact blobs exist; a signed-out browser playback session has not been executed independently in this environment.

The participant requested that Unstop portal submission be excluded; no portal receipt is claimed.
