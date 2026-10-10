# TrustBoundary AI v1.7.0 — Provenance Before Permission

An **experimental agentic prompt-injection firewall** for the ET × Accenture AI Hackathon. Its strongest safety property is independent **tool authorization**: untrusted emails, webpages, PDFs, Word documents, OCR images, API responses and code comments can contain data, but cannot grant an AI agent new privileges. No real money, emails, credentials or customer data are used.

**Positioning: provisional F3–D1**, based on category implementations and tests; not proven D2 reliability or production security. This is not a deployed, hardened payment service.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
uvicorn trustboundary.api:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 and visit **Attack Lab**. The app is fully usable offline. To use live AI detection, use **Settings** to supply a *private, newly generated* OpenAI key for that browser tab. The key is not persisted; requests to the local backend must be on a trusted connection. The **model tool-call comparison** is optional and also requires a key. The offline scripted comparison is explicitly labeled scripted and does not claim actual LLM compromise.

With Docker (Tesseract included):

```bash
docker build -t trustboundary:1.7 .
docker run --rm -p 127.0.0.1:7860:7860 trustboundary:1.7
```

In the Docker configuration, BYOK is disabled to avoid collecting visitors' keys on an unauthenticated deployment. Do not expose this demo to the public Internet without authentication, a reverse-proxy rate limiter, HTTPS and a security review. A publicly hosted demo URL has **not** been verified.

## Architecture

```text
Authorized user task ---------> Task planner ------------------------------+
                                                                          |
Untrusted source --> Fold/decode/OCR --> Rules + structural signals + ML --+--> Disposition
                                               |      optional LLM judge -->+--> QUARANTINE / SANITIZE / ALLOW
                                                                          |
                                     Bounded mock workflow / optional model tool proposals
                                                                          |
                              Independent tool authorization (RBAC + provenance + approval)
                                                                          |
                                          Synthetic execution + audit metadata
```

The hosted **LLM judge** produces strict structured fields for instruction intent, nine-category taxonomy, short evidence span and confidence. Its output is advisory only. The `authorize()` policy is outside the LLM. **Offline remains the default**; unavailable or timed-out hosted calls fall back to local classification. A separate optional model-tool demo calls the model twice (control and protected) and records actual mock tool proposals; no real payments or mail occur. Without a key, no real-model attack rate is measured.

## Measured offline results

| Corpus / purpose | TP | FN | FP | TN | Attack recall | False-positive rate |
|---|---:|---:|---:|---:|---:|---:|
| Historical reviewer set, original v1.2.1 | 14 | 10 | 1 | 17 | 58.3% | 5.6% |
| Judge-authored 50-case set on v1.6 (before inspection) | 8 | 22 | 0 | 20 | 26.7% | 0.0% |
| **Same judge set after v1.7 development** (NOT blind) | 28 | 2 | 0 | 20 | 93.3% | 0.0% |
| Earlier 40-case challenge on v1.7 | 10 | 10 | 2 | 18 | 50.0% | 10.0% |

These numbers are **different cohorts and versions**, not comparable independent benchmarks. The judge set was used to guide improvements; its post-change score is **development regression evidence**, not out-of-sample generalization. The 40-case set was also known from previous reviews. A newly sealed, independently authored holdout is **not yet available**. The narrow template-family synthetic benchmark must never be presented as production accuracy. See `reports/` and `scripts/evaluate_adversarial.py` for case-level evidence.

## Input and tool safety

- OCR PNG/JPEG and image-only PDFs require Tesseract (and PyMuPDF for scanned PDFs). OCR can misread faint or adversarial images; the extraction is not an OCR security guarantee.
- Uploaded Word source includes hidden runs, header, footer and comment text. Upload files are size limited to 5 MB; images are pixel capped.
- `/scan` accepts an optional `conversation_id` for **ephemeral single-process** risk accumulation. This is a demo aid, not authenticated identity or production multi-turn defense.
- The sample synthetic workflow restricts business actions to user-authorized settlement IDs and mock read/ticket tools. A model or retrieved document cannot bypass RBAC/provenance rules. Privileged actions require separate approval; no real approval identity system exists.
- JSON output never includes users' keys. The public Docker preset disables BYOK by default. Request logs, observability, CORS, deployment authentication and provider data retention must be reviewed before deployment.

## Limitations and roadmap

The detector still misses unfamiliar paraphrases and may reject legitimate support messages. There is no proven D2 generalization, no independent live OpenAI accuracy number, no verified public dataset score, no production isolation, no persistent identity-bound conversation store, and no live hosted demo URL. Next steps are external dataset and sealed-holdout testing, audited human approvals, stronger document isolation, and secure cloud hosting.

Reproducibility: `python scripts/evaluate_adversarial.py --corpus evaluation_inputs/judge_v16_dev_after_review.json --name judge_v17_replay`. The historical v1.6 result is **preserved in a separate report**, not recalculated using a different detector. For the public dataset runner, see `scripts/evaluate_public.py`; no downloaded dataset is bundled and its license must be checked (Hugging Face card and embedded metadata differ).

## AI assistance

I used ChatGPT to help draft prototype source code, tests, UI text, architecture documents, slides and synthetic examples. The product choice, the independent `authorize()` gate, provisional F3–D1 scope and the decision to publish negative evaluation results are my product decisions. AI assistance does not replace a manual code/security review. **I have not certified production safety or claimed that hosted-model results were run without a verified API execution.**

## Files

- `trustboundary/` application, `web/` dashboard, `tests/` regression tests
- `scripts/` replay and evaluation tools, `reports/` actual measured outcomes
- `docs/CHANGELOG.md` historical releases and `docs/` technical limitations
- `submission/` pitch deck and prior narrated walkthrough; see its metadata for the precise version shown

Licensed under [MIT](LICENSE). All data and tool effects are synthetic. Participation and final Unstop form submission are separate from publishing this repository.
