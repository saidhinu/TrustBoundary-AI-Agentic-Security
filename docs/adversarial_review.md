> **v1.6 update (10 October 2026):** Following Unicode/encoding normalization and contextual signal additions, the earlier v1.4 40-case challenge still detects **7/20 attacks** with **1/20 benign false positive**. A separate 50-business-email control has **2/50 false positives**. Synthetic-family grouped 5-fold CV of the ML component is 135/135 TP and 0/105 FP, but is **not an external benchmark**. The public deepset test runner is prepared but has **not been executed** in the offline build. See `reports/new_challenge_v16_retest_metrics.json`, `reports/benign_50_v16_metrics.json`, `reports/synthetic_groupkfold.json`, and `scripts/evaluate_public.py`. These additions do not establish D2 reliability.

# TrustBoundary AI v1.4: Adversarial evaluation and reproducibility

**Date:** 10 October 2026. **Scope:** synthetic, manually authored, feedback-informed. **Maturity:** provisional F3–D1. These are NOT independently blind evaluations or production guarantees.

| Dataset / detector | Attacks detected | Attack misses | Benign false positives | Recall |
|---|---:|---:|---:|---:|
| Historical 42 cases, v1.2.1 (immutable baseline) | 14/24 | 10 | 1/18 | **58.3%** |
| Same 42 cases, v1.4 (feedback-informed) | 24/24 | 0 | 0/18 | **100%** |
| Previously reviewed 60 cases, v1.3 (frozen original) | 10/30 | 20 | 2/30 | **33.3%** |
| Same 60 cases, v1.4 (feedback-informed) | 30/30 | 0 | 0/30 | **100%** |
| Newly authored 40 cases, v1.4 first evaluation | 7/20 | **13** | **1/20** | **35.0%** |

The improved performance on prior sets reflects targeted rule updates informed by those sets. **The newest 40-case evaluation is the more credible limitation signal.** This classifier remains brittle against unseen language; actual unauthorized tool execution and attack detection are separate measurements. The independent mock authorization gate blocked protected mock tool abuse but this is not a security certification.

## Files and commands

- **Frozen 42-case corpus:** `tests/adversarial_review_cases.json`
- **Historical v1.2.1 confusion matrix and individual verdicts:** `reports/adversarial_baseline_v121_metrics.json`, `reports/adversarial_baseline_v121_cases.csv`
- **Reusable evaluator:** `scripts/evaluate_adversarial.py`
- **Historical commit replay:** `bash scripts/reproduce_baseline_v121.sh` (uses the exact earlier Git commit)
- **Frozen 60-case corpus:** `tests/unseen_20261010.json`
- **v1.3 output:** `reports/unseen_20261010_v13_metrics.json`, corresponding cases CSV
- **Feedback-informed v1.4 result on 60:** `reports/frozen_v13_challenge_retest_v14_metrics.json` and `_cases.csv`
- **Post-update 40-case corpus:** `tests/new_challenge_v14_frozen.json`
- **First-evaluation results for 40 cases:** `reports/new_challenge_v14_initial_metrics.json` and `_cases.csv`

```
python -m pytest -q
bash scripts/reproduce_baseline_v121.sh
python scripts/evaluate_adversarial.py --corpus tests/unseen_20261010.json --name manual_60_retest
python scripts/evaluate_adversarial.py --corpus tests/new_challenge_v14_frozen.json --name manual_40_first_eval
```

`evaluate_adversarial.py` recomputes actual detector and mock-policy outcomes. Baseline metrics must be computed with the original v1.2.1 version; do not run the newer detector and label the results the historical baseline. The 40-case sample was authored after the v1.4 rules were written and scored once before further tuning.

## OpenAI mode

The OpenAI API classifier is optional and only advisory; deterministic tool authorization never follows its instructions. There is no live credential in the repository and no actual OpenAI request was verified. Mock tests include 401, 429, 503, invalid JSON/category responses, false positives, and timeout/fallback. To perform an authenticated (potentially billable) run, configure a private `OPENAI_API_KEY` and run `python scripts/evaluate_openai_live.py --max-cases 10`. Distinguish confirmed LLM responses from automatic offline fallback in the output.

## Known issues

13/20 malicious examples in the new 40-case challenge were missed. Contextual intent rules remain brittle and can be bypassed by different phrasing, multilingual text, adversarial formatting, or embedding. One benign control was flagged. HTML text handling preserves raw markup for security, but reliable contextual trust and safe-content extraction require more validation. This demonstration should not be deployed with sensitive customer data or production tool credentials.
