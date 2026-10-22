#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sha256sum -c strix-main.sha256 --quiet
echo "strix-main: zero changes verified"
