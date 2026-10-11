# GitHub publishing and reproducibility — v1.7

The expected public structure is rooted at `trustboundary/`, `web/`, `tests/`, `scripts/`, `reports/`, `docs/`, and `submission/`; do not place application files under a nested project folder.

1. Verify code and reproducibility artifacts at `https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security`.
2. Run `python -m pip install -r requirements.txt` and `python -m pytest -q` from a fresh clone.
3. Run `bash scripts/reproduce_baseline_v121.sh` and inspect `docs/adversarial_review.md`.
4. Check the PDF, PPTX, and [participant's final voice-over MOV](https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/blob/main/submission/Tustboundary_Voiceover%20Demo_Final.mov) via signed-out browser links. The previous synthetic-voice MP4 was removed from `main`. Verify browser/MOV playback independently and provide an MP4 transcode if needed.
5. Never commit API credentials, customer data, local SQLite databases, or `.env`.

The application is a synthetic prototype. The optional hosted OpenAI classifier was tested with mocks only. The official Unstop portal is deliberately outside this release workflow by user request.
