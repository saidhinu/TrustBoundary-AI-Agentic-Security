# GitHub publication status

**Partial publication only (9 October 2026).**

The project README, `.gitignore`, and `requirements.txt` have been uploaded. **The source package, demo media, and hackathon submission assets have not yet been committed to this repository.** This public repository is not yet runnable.

The complete local release is available in the original ChatGPT conversation as `TrustBoundary_AI_Submission_Package.zip`. To complete publication, extract the ZIP and use GitHub’s **Add file → Upload files** to upload the **contents of the `TrustBoundary_AI` folder** to the repository root. Preserve the directories `trustboundary/`, `web/`, `tests/`, `docs/`, `reports/`, `scripts/`, and `submission/`. The video is about 4.7 MB, well below GitHub's 100 MB per-file maximum.

After upload, run `pip install -r requirements.txt && pytest -q` and `python -m uvicorn trustboundary.api:app --port 8000` locally. Ensure no `.env`, real credential or user data is published. Official hackathon submission on Unstop is a separate action and is not complete.
