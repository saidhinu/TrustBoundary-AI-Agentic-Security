# Reproducible Evaluation Methodology

## Corpus

The synthetic fixture generator produces 180 adversarial examples (20 per each of 9 attack types), 120 benign examples and 20 quoted/ambiguous examples. Every fourth example is held out (80 held out, 240 development). Attack training/testing split is by **text variant index**; benign examples are superficially reworded using reference IDs. The dataset is *not* equivalent to an independently sourced distribution, and the regex rules were built with awareness of these attack families.

## Exact metrics

- TP: malicious sample flagged by the offline heuristic + locally trained ML detector.
- FP: benign/ambiguous sample flagged.
- Recall = TP/(TP+FN); Precision = TP/(TP+FP); FPR = FP/(TN+FP).
- F1 = 2PR/(P+R).
- Protected attack success = forbidden effect actually executed via mock tools / adversarial examples.
- Baseline attack success = forbidden effect issued by intentionally vulnerable **scripted** sandbox / adversarial examples.
- Task utility = valid settlement read and support ticket draft generated / attempted tasks.
- P95 latency = sorted measured offline scanner times at the 95th percentile.

## Caveats

A 100% offline test set result is not credible proof against unconstrained novel attacks, multi-turn injections or unsafe real LLM tool calls. The baseline is intentionally insecure and scripted, not a representative model-based baseline. Synthetic canaries have no real information value, and actual incident losses are not measured. All business impact calculations must be labeled hypothetical.

## Regenerate

```bash
python -m pytest -q
python -c 'from trustboundary.evaluation import evaluate; evaluate("heldout")'
```

The dashboard reads `reports/metrics.json` and `reports/evaluation.csv` generated from actual runs. Re-run `POST /evaluate` to update numbers. Coverage by category and error CSV files are included.
