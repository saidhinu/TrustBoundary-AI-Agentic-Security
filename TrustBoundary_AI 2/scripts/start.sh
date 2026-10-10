#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m uvicorn trustboundary.api:app --host 127.0.0.1 --port "${PORT:-8000}"
