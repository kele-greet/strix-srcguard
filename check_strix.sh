#!/usr/bin/env bash
# Verify that the local strix-main checkout is untouched.
# In the public repository there is no strix-main next to this repo, so the check is skipped.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d ../strix-main ]; then
  echo "strix-main: not present (public repo) — nothing to compare"
  exit 0
fi
if [ ! -f ../strix-main.sha256 ]; then
  echo "strix-main: present but ../strix-main.sha256 missing — skipping"
  exit 0
fi
(cd .. && sha256sum -c strix-main.sha256 --quiet)
echo "strix-main: zero changes verified"
