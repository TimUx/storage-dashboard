#!/usr/bin/env bash
# Storage Dashboard – Test-Runner (lokal & CI-tauglich).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export SECRET_KEY="${SECRET_KEY:-pytest-cli-secret-key-32bytes!}"
export DATABASE_URL="${DATABASE_URL:-sqlite://}"
export SSL_VERIFY="${SSL_VERIFY:-false}"

PIP="${PIP:-python3 -m pip}"
PYTEST=(python3 -m pytest)

if [[ "${1:-}" == "--install" ]]; then
  shift
  $PIP install -r requirements.txt -r requirements-dev.txt
fi

MARKER="${MARKER:-}"
COV="${COV:-0}"
# Parallele Ausführung: JOBS=auto setzt -n auto (benötigt pytest-xdist).
JOBS="${JOBS:-0}"

ARGS=(tests/ -v --tb=short)
if [[ -n "$MARKER" ]]; then
  ARGS+=(-m "$MARKER")
fi
if [[ "$COV" == "1" ]]; then
  ARGS+=(--cov=app --cov-config=.coveragerc --cov-report=term-missing --cov-report=html:htmlcov)
fi
if [[ "$JOBS" != "0" ]]; then
  ARGS+=(-n "$JOBS")
fi

exec "${PYTEST[@]}" "${ARGS[@]}" "$@"
