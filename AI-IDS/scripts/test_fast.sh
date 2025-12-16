#!/usr/bin/env bash
set -euo pipefail

# Set LINT_STRICT=0 to run tests even if lint/type checks fail.
LINT_STRICT="${LINT_STRICT:-1}"

echo "Python version:"
python -V

echo "=== Ruff (lint) ==="
if command -v ruff >/dev/null 2>&1; then
  if [[ "$LINT_STRICT" == "1" ]]; then
    # Auto-format first so the check phase only fails for non-formatting issues
    ruff format .
    ruff check .
    ruff format --check .
  else
    ruff format . || true
    ruff check . || true
    ruff format --check . || true
  fi
else
  echo "ruff not found, skipping."
fi

echo "=== mypy (type check) ==="
if command -v mypy >/dev/null 2>&1; then
  if [[ "$LINT_STRICT" == "1" ]]; then
    mypy --ignore-missing-imports AI-IDS/anomaly_detector.py AI-IDS/packet_processor.py AI-IDS/main.py
  else
    mypy --ignore-missing-imports AI-IDS/anomaly_detector.py AI-IDS/packet_processor.py AI-IDS/main.py || true
  fi
else
  echo "mypy not found, skipping."
fi

echo "=== pytest (unit tests) ==="
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p sprint_artifacts
pytest -m "unit" -ra -vv --durations=10 | tee sprint_artifacts/pytest_unit.txt
