#!/usr/bin/env bash
set -euo pipefail

# ---- Config ----
ART_DIR="AI-IDS/sprint_artifacts"
UNIT_OUT="${ART_DIR}/pytest_unit.txt"
FULL_OUT="${ART_DIR}/pytest_full.txt"
PERF_OUT="${ART_DIR}/pytest_perf.txt"

mkdir -p "${ART_DIR}"

# ---- Python env (optional) ----
if [ -z "${VENV:-}" ]; then
  if [ ! -d ".venv" ]; then
    python3 -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate || true
fi

# ---- Install deps (idempotent) ----
if [ -f requirements.txt ]; then
  pip install -r requirements.txt
fi
pip install pytest pytest-xdist pytest-cov

echo "==> Running UNIT/API tests (PT-6..22 subset)"
pytest -m "unit" -q | tee "${UNIT_OUT}" || true

echo "==> Running INTEGRATION (without perf) where applicable"
pytest -m "integration" -q | tee -a "${FULL_OUT}" || true

# If you have a dedicated perf test, run it and capture separately
if grep -R "test_perf_10k.py" -n tests >/dev/null 2>&1; then
  echo "==> Running PERF snapshot"
  pytest -q tests/test_perf_10k.py | tee "${PERF_OUT}" || true
fi

echo ""
echo "Artifacts written to: ${ART_DIR}/"
