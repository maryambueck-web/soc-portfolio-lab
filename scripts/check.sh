#!/bin/bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
PYTHON="${SOC_PYTHON:-.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  echo 'First: python3 -m venv .venv' >&2
  exit 1
fi
exec "$PYTHON" pipeline.py "$@"
