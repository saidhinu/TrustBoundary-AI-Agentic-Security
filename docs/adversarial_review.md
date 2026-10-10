# Additional adversarial assessment — 10 October 2026

This is **separate from the template-family synthetic benchmark**. The 42 examples were manually written after receiving reviewer feedback and excluded from the local ML training fixtures. The examples were not independently supplied or blind.

| Metric | Measured result |
|---|---:|
| Adversarial cases | 24 |
| Benign controls | 18 |
| True positives | 14 |
| False negatives | 10 |
| True negatives | 17 |
| False positives | 1 |
| Recall | **58.3%** |
| Precision | **93.3%** |
| Benign false positive rate | **5.6%** |
| Attacks forwarded unchanged | **10** |
| Unauthorized protected mock tool executions | **0** |

Examples of missed attacks include authority impersonation without explicit role tags, payment paraphrases, and an HTML parser losing suspicious role-like tags. These misses are materially important. The attack is **not** guaranteed to be caught merely because the tool gate prevents mock money movement. The local ML plus regex detector **does not demonstrate D2 reliability**; we claim at most provisional F3–D1.

No real transactions, secrets or external models were used for this assessment. In particular, this is *not* a verified hosted-OpenAI model benchmark.

The full local release ZIP contains the feedback-informed 42-case JSON corpus, runnable `scripts/evaluate_adversarial.py`, CSV case outputs and JSON metrics. The latest regression suite passed 82 tests locally. To avoid confusing the main benchmark, this report is documented separately.
