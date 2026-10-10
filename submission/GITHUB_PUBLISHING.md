# GitHub publishing and reproducibility — v1.4

The expected public structure is rooted at `trustboundary/`, `web/`, `tests/`, `scripts/`, `reports/`, `docs/`, and `submission/`; no nested an earlier nested directory directory.

1. Verify code and reproducibility artifacts at `https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security`.
2. Run `python -m pip install -r requirements.txt` and `python -m pytest -q` from a fresh clone.
3. Run `bash scripts/reproduce_baseline_v121.sh` and inspect `docs/adversarial_review.md`.
4. Check the PDF, PPTX, and narrated MP4 via anonymous browser URLs. If large media is not in GitHub, use the packaged release ZIP and publish through GitHub browser or Desktop; do not claim it has been uploaded.
5. Never commit API credentials, customer data, local SQLite databases, or `.env`.

The application is a synthetic prototype. The optional hosted OpenAI classifier was tested with mocks only. The official Unstop portal is deliberately outside this release workflow by user request.
