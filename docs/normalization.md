# Normalization hardening — v1.6

- The original source text remains in the frontend input and a source SHA-256 is computed from original bytes.
- `fold()` is applied only to detection candidates. It uses Unicode NFKC, a bounded list of Cyrillic/Greek lookalikes and zero-width removals, and rejoins only known high-signal spaced tokens; this is not multilingual confusable normalization.
- `variants()` explores URL-unquote, Base64, hexadecimal and marked ROT13 payloads with depth <=2, 32 candidate bound and size limits. It never executes decoded text.
- The quote mask is applied to individual quoted spans next to reporting cues. Activation instructions outside quotes prevent exemption.
- Signal groups use a deterministic score and conjunction thresholds, **not semantic LLM reasoning**. The 40-case challenge still has 35% attack recall.
- `safe_segments()` is conservative: any high-risk content without a demonstrably safe subset is quarantined, not forwarded unchanged.
- Rule IDs `PI-OVR-001`, etc., identify lexical matches; IDs do not prove comprehensive category coverage.

See `tests/test_normalization.py`, `tests/test_v14_safety.py` and `reports/new_challenge_v16_retest_metrics.json`.
