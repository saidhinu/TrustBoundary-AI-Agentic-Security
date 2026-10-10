# Recorded Demo and Live Judge Walkthrough (3 minutes)

**00:00–00:25 — Problem:** A payment-support AI agent reads low-trust merchant messages and could be tricked into unauthorized mock actions. The business request is just to check ST-2048 and draft a ticket.

**00:25–01:20 — Attack Lab:** Select the **Forged system message** scenario. Show `source_type=email`, run *before/after*. State clearly that the control is a deliberately vulnerable *scripted* sandbox, not a measured real LLM. Protected instance blocks external-origin `issue_refund`, still completes the authorized ticket flow.

**01:20–01:50 — Input reliability:** Select the encoded attack, inspect its classification, and explain source provenance and encoded extraction. Mention that this detector is heuristic in offline mode; optional LLM is advisory.

**01:50–02:20 — EGO evaluation:** Open evaluation cockpit. Show held-out sample count, confusion matrix, per-class recognition, benign task completion, zero forbidden mock executions, p95 scan time, and benchmark limitations. Demonstrate that metrics are actually produced by the test runner.

**02:20–02:45 — Audit and architecture:** Open audit timeline and architecture. Explain deterministic tool authorization is separate from natural language classifier; security does not depend on the model's claimed confidence.

**02:45–03:00 — Business value:** Open impact simulator and show editable assumptions (hypothetical only). State the intended value: allow trusted AI agents to act within enforceable permissions with measurable safety and utility.

**Closing:** "TrustBoundary doesn't just ask if a prompt looks malicious. It enforces what an agent may do, and shows the evidence." 
