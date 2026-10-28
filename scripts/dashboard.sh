#!/bin/bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
exec .venv/bin/python -m streamlit run app.py --server.address 127.0.0.1
