# TrustBoundary release status — 9 October 2026

**Public repository is still incomplete:** the runnable application and test files are not yet committed to `main`.

The current, locally tested version is **v1.2.0**, and the self-declared hackathon grid level is **F3–D1** (not D2). The updated ZIP is available in the project owner's ChatGPT conversation. Reported local results: **70 automated tests passed**, including added reviewer-feedback tests. These do not establish robust defense against unseen attacks.

v1.2 changes:
- Quote exemption is restricted to explicitly educational quoted spans; instructions outside quotes remain inspectable.
- Additional detections for the previously missed `expired directives` and `transfer the entire balance` paraphrases.
- SANITIZE retains conservatively vetted safe sentences for data-only downstream display; QUARANTINE withholds source content.
- Health endpoint reports v1.2.0 and the UI displays v1.2 / F3–D1.

**To finish publication:** extract `TrustBoundary_AI_Reviewer_Fixes_v1_2.zip` and upload the contents of its `TrustBoundary_AI` folder to the repository root. Ensure `trustboundary/`, `web/`, `tests/`, `docs/`, `scripts/`, `reports/` and `submission/` are included. Do not upload `.env`, database files, `__pycache__/` or other generated runtime data. Verify a fresh clone with `python -m pytest -q` and `python -m uvicorn trustboundary.api:app --port 8000`.

**Hackathon submission on Unstop is separate and has not been confirmed.**
