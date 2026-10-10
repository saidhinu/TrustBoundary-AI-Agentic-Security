# TrustBoundary AI v1.6.0 — Agentic Prompt-Injection Firewall

[![Verify source](https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/actions/workflows/verify-source.yml/badge.svg)](https://github.com/saidhinu/TrustBoundary-AI-Agentic-Security/actions/workflows/verify-source.yml)

**ET × Accenture AI Hackathon 2026 · Problem 2 · provisional F3–D1.** Maintainer: Dhinesh Babu Venkatesan.

TrustBoundary is an **offline-first, synthetic enterprise security prototype**. It examines low-trust email, text, PDF, HTML, API payloads, Word documents and code for prompt-injection attempts. It prevents untrusted source content from authorizing mock tools via an independent, deterministic policy gate. It is **not production-grade security software** and is **not a fully autonomous LLM agent**.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
python -m uvicorn trustboundary.api:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. `/health` returns the centrally declared version from `trustboundary/__init__.py`. The app and its evaluations run **without an OpenAI key**.

Optional: In the browser's **Settings**, select **OpenAI-assisted**, enter your **own private** `OPENAI_API_KEY`, test the connection and enable it for this tab. The key is held in tab memory and sent via a request header to the local server; it is not persisted by the app. Hosted model validation is **not claimed** until a genuine live request succeeds. **Never share or commit credentials.** The deterministic tool-authorization gate remains active in both modes. Do not expose this demo unprotected on the public internet.

## Architecture

`Trusted task` + `untrusted document/email/API` → **canonicalization** (NFKC, selected confusables, zero-width characters, encoding candidates) → **inspection** (9 rule categories, contextual signals, local TF-IDF classifier, optional OpenAI) → **ALLOW / SANITIZE / QUARANTINE / ESCALATE** → bounded **mock settlement agent** → **independent tool authorization (RBAC + provenance + explicit approval)** → **metadata-only trace and incident/evaluation components**.

`authorize()` never delegates permission decisions to the LLM or external content. The deliberately vulnerable before/after reference is a **scripted simulator, not an attacked real LLM**. See [architecture](docs/architecture.md), [threat model](docs/threat_model.md) and [evaluation methods](docs/evaluation_method.md).

## Results — different cohorts, different claims

| Cohort and date | Attacks caught | Benign false alerts | Attack recall | Interpretation |
|---|---:|---:|---:|---|
| Original templated synthetic holdout (v1.5) | 45/45 | 0/35 | 100% | Narrow patterns; **not independent** |
| Reviewer-authored 42-case **historical pre-fix** (v1.2.1) | 14/24 | 1/18 | 58.3% | Preserved frozen baseline |
| Same 42 cases after known fixes (v1.6) | 24/24 | 1/18 | 100% | **Feedback-informed regression**, not unseen |
| Previously reviewed 60-case set (v1.6) | 30/30 | 1/30 | 100% | Known-case retest |
| New 40-case challenge authored for v1.4, rerun v1.6 | 7/20 | 1/20 | **35.0%** | Generalization is still weak |
| 50 additional realistic benign emails (v1.6) | N/A | **2/50** | N/A | 4% benign false-positive rate |
| Local ML only, 5-fold **template-family grouped** CV | 135/135 | 0/105 | 100% | **Still synthetic**, classifier-only, not end-to-end |
| deepset public test split (116 examples) | **Not run here** | **Not run** | — | Reproducible script ready; external number must not be invented |

Results in `reports/` and case lists in `tests/`. Run `python scripts/evaluate_adversarial.py --corpus tests/new_challenge_v14_frozen.json --name verify_40` and `python scripts/evaluate_groupcv.py`. `scripts/evaluate_public.py --download` downloads the public `deepset/prompt-injections` test parquet (pin/SHA256 checked; run with `pip install pandas pyarrow`), then computes recall and FPR **without training on that data**. The dataset page says Apache-2.0 while some metadata says CC-BY-4.0; verify attribution and license before redistribution. We do **not** redistribute the dataset.

**External test caveat:** Deepset contains direct user prompts, while this prototype primarily protects against instructions embedded in low-trust retrieved content. Even a measured score would be out-of-domain evidence, not a claim of high real-world reliability.

## Input types and limits

- Text: email, HTML (including hidden, script, comments), Markdown, JSON/API, TXT.
- PDF: digitally extracted text only. Image-only PDFs are explicitly rejected.
- DOCX: body, headers, footers, comments, hidden `w:vanish` runs (via OOXML text inspection). Macros never run.
- Python/JavaScript: source text including comments and docstrings; code is not imported or executed.
- PNG/JPEG/OCR, robust multimodal defense, authenticated multi-turn session storage and validated real financial tools are **not implemented**.

File ingestion is capped at 5 MB. Normalization and decoding are bounded; obfuscated language can still evade detection. The public demo must not receive private user records.

## Limitations and guardrails

- **Known generalization failure:** 13 of 20 attacks were missed in the 40-case challenge, despite strong synthetic and feedback-regression scores. Rule IDs and optional signals are not a replacement for genuine semantic robustness.
- Tool denial and classifier accuracy are different metrics. A missed injection can still leak as **untrusted content**, even if mock tool authorization blocks actions.
- The local model uses synthetic development fixtures and does not prove production security. Hosted OpenAI classification remains optional, advisory, potentially billable and **unverified in a real authenticated run**.
- Offline benchmark results are produced without calling OpenAI. The user-controlled BYOK browser Settings are for a **local/private HTTPS-trusted deployment**, not an invitation to share keys in a public multi-tenant server.
- Agent orchestration and human approval are bounded demonstrations, with no real money movement or outbound messages.

## AI assistance

AI coding assistants were used in this project workflow for scaffolding, draft code, regression tests, documentation and initial slide/video production. The product choice, independent authorization principle, intentionally limited F3–D1 claim, and disclosure of negative evaluation results are documented here for participant review. **Participants should verify every statement, run the scripts themselves, and describe their own actual contributions accurately.** We do not claim that any human review, live testing, or signing-off has happened unless it is recorded.

## Roadmap

1. Run the pinned external benchmark from a network-enabled machine and publish its full confusion matrix.
2. Evaluate actual OpenAI calls with a **fresh, uncompromised key**, with costs, timeouts and false-positive rates.
3. Replace brittle rules with a tested semantic detector on distinct attack sources, strengthen safe-content extraction and human review, and repeat blind red-team evaluation.
4. Add authenticated multitenant controls, rate limits, real key isolation and independent safety reviews before any production rollout.

## Project resources

- [README](README.md) · [Change history](docs/CHANGELOG.md) · [Security documentation](docs/architecture.md) · [Known weaknesses](docs/adversarial_review.md)
- [Reproducible evaluation scripts](scripts/) · [Case-level reports](reports/) · [Regression tests](tests/)
- [Pitch PDF](submission/TrustBoundary_Hackathon_Pitch.pdf) · [Editable slides](submission/TrustBoundary_Hackathon_Pitch.pptx) · [Narrated demo video](submission/TrustBoundary_Demo_Walkthrough_Narrated.mp4)

**Release status:** Public repository and local ZIP are separate publication surfaces; GitHub `main` and CI must be checked after this release is pushed. Unstop competition submission is separate and is not claimed here.
