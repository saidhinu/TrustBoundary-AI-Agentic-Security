#!/usr/bin/env bash
set -euo pipefail
# Reproduce historical v1.2.1 results using the exact old detector and the
# NOW-PUBLISHED corpus/evaluator. Requires git history and Python dependencies.
ROOT="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
cleanup(){ git -C "$ROOT" worktree remove --force "$WORK" >/dev/null 2>&1 || true; }
trap cleanup EXIT
BASELINE="752e9e4ddfbddb874f69913a8f9a66b88bef5b99"
git -C "$ROOT" cat-file -e "$BASELINE^{commit}"
git -C "$ROOT" worktree add --detach "$WORK" "$BASELINE" >/dev/null
mkdir -p "$WORK/tests" "$WORK/scripts"
cp "$ROOT/tests/adversarial_review_cases.json" "$WORK/tests/"
cp "$ROOT/scripts/evaluate_adversarial.py" "$WORK/scripts/"
(
  cd "$WORK"
  export PYTHONPATH="$WORK"
  python scripts/evaluate_adversarial.py --corpus tests/adversarial_review_cases.json --name historical_v121_reproduction
)
cat "$WORK/reports/historical_v121_reproduction_metrics.json"
