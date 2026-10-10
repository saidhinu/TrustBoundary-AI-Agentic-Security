# GitHub publishing checklist — TrustBoundary AI v1.2

Repository: https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security

**As of this package's creation, the public repository does not contain the project source. Do not link it as a working proof until you verify a fresh clone.**

Upload the CONTENTS of the `TrustBoundary_AI` folder to the repository root; replace the stale root README and UPLOAD_STATUS.md. Keep the directories `trustboundary/`, `web/`, `tests/`, `docs/`, `scripts/`, `reports/`, and `submission/`. GitHub's browser upload may limit number of files; Git on a machine is recommended.

Preferred command-line route after extracting this ZIP:

```bash
cd TrustBoundary_AI
git init
git remote add origin https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security.git
git fetch origin
git checkout -b main origin/main
git add .
git commit -m 'Publish TrustBoundary v1.2 runnable source and reviewer fixes'
git push origin main
```

If remote tracking setup fails, clone repository to an empty directory, then copy the `TrustBoundary_AI` contents into it and run `git add`, `git commit`, `git push`. Do **not** publish `.env`, real payment data, secrets, local `data/*.sqlite3` or `__pycache__`.

Verify fresh clone in clean Python environment:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python -m uvicorn trustboundary.api:app --host 127.0.0.1 --port 8000
```

Expected tests: 70 passed. Verify `/health` includes `1.2.0`, UI says `v1.2` / `F3–D1`, and the two revised bypass probes return QUARANTINE. Then inspect deck and demo video before submitting on Unstop.
