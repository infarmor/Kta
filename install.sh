#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
.venv/bin/pip install -q -U pip
.venv/bin/pip install -q -r requirements.txt
chmod +x kta
echo "Done. Connect and unlock your iPhone, tap Trust, then run: ./kta run"
