# TrustBoundary AI v1.7.0 — Measured Security Evaluation

All measurements here are **offline** with locally trained TF-IDF/logistic regression, heuristics and structural features. A hosted OpenAI model was **not** invoked. Mock tool execution is not real financial/email behavior.

| Cohort | TP | FN | FP | TN | Attack recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| User-supplied judge cohort **on v1.6 before fixes** | 8 | 22 | 0 | 20 | 26.7% | 0.0% |
| Same cohort **on v1.7 after feedback** | 28 | 2 | 0 | 20 | 93.3% | 0.0% |
| Previously reviewed 40-case challenge on v1.7 | 10 | 10 | 2 | 18 | 50.0% | 10.0% |
| 50 benign business examples on v1.7 | — | — | 2 | 48 | — | 4.0% |

**Do not call the 93.3% result independent:** the 50-case corpus was inspected before and during development. It is a development/regression cohort. The 40-case corpus was also reviewed previously. None is a sealed or large public external benchmark.

## Category-level feedback-development detections

| Category | Flagged | Correct label |
|---|---:|---:|
| Instruction Override | 5/5 | 5/5 |
| Role Change | 4/4 | 4/4 |
| Secret Extraction | 3/3 | 3/3 |
| Tool Abuse | 4/4 | 4/4 |
| Credential Theft | 2/3 | 2/3 |
| Context Poisoning | 3/3 | 3/3 |
| Multi-Step Jailbreaks | 1/2 | 1/2 |
| Encoded Instructions | 3/3 | 2/3 |
| Indirect Prompt Injection | 3/3 | 2/3 |

These per-category results are from feedback-informed cases, not generalization evidence. Weaknesses remain for paraphrased credential requests and multi-turn evasion. `conversation_id` is a memory-in-process toy, not a production guardrail.

## How to reproduce

```bash
python scripts/evaluate_adversarial.py --corpus evaluation_inputs/judge_v16_dev_after_review.json --name judge_v17_replay
python scripts/evaluate_adversarial.py --corpus tests/new_challenge_v14_frozen.json --name known40_v17_replay
python scripts/evaluate_adversarial.py --corpus tests/benign_50_business.json --name benign50_v17_replay
python -m pytest -q
```

The historical 8/30 v1.6 benchmark must be replayed using its frozen v1.6 revision rather than today’s detector; `reports/judge_v16_original_v16_baseline_*` preserve case-level predictions from that earlier run.

## Provider and external data status

The OpenAI BYOK semantic judge, strict schema, mocked failures, model tool-proposal flow and policy gate have local tests. **There is no live hosted AI evaluation result** and no observed real-model attack-success rate. A separate optional `scripts/evaluate_model_agent_live.py` can produce an actual report with a newly generated private key. Never use or publish exposed credentials.

The optional public deepset test-split script is pinned to a SHA256 but could not download the dataset in this environment. Upstream page says Apache 2.0 while card metadata also includes CC BY 4.0; verify relevant terms before redistributing content. A numeric public dataset result is *not available* here.

This experimental project retains a **provisional F3–D1** positioning and makes no D2 or production security claim.
