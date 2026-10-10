#!/usr/bin/env bash
# Publish the extracted v1.7 release from an authenticated Mac Git checkout.
# Usage: bash scripts/publish_v17_mac.sh /absolute/path/to/TrustBoundary-AI-Agentic-Security
set -euo pipefail
if [ "$#" -ne 1 ]; then echo 'Usage: bash scripts/publish_v17_mac.sh /path/to/existing/git/repo' >&2;exit 2; fi
TARGET="$1"
SOURCE="$(cd "$(dirname "$0")/.." && pwd)"
if [ ! -d "$TARGET/.git" ]; then echo 'ERROR: target is not a cloned Git repository.' >&2;exit 2;fi
if ! git -C "$TARGET" remote get-url origin | grep -Fq 'saidhinu/TrustBoundary-AI-Agentic-Security';then
 echo 'ERROR: target remote is not the expected TrustBoundary repository.' >&2;exit 2
fi
if [ -n "$(git -C "$TARGET" status --porcelain)" ]; then echo 'ERROR: repo has uncommitted changes. Commit/stash first.' >&2;exit 2;fi
rsync -av --exclude='.git' --exclude='.env' --exclude='.venv' --exclude='__pycache__' --exclude='.pytest_cache' --exclude='data/' "$SOURCE/" "$TARGET/"
cd "$TARGET"
python3 -m pytest -q
git add -A
git diff --cached --stat
printf '\nReview changes then press Enter to commit and push, or Ctrl-C to abort.\n'
read -r _
git commit -m 'Release TrustBoundary AI v1.7: semantic judge, OCR, multi-turn, model-tool mock sandbox'
git push origin main
printf 'Published: %s\n' "$(git rev-parse --short HEAD)"
