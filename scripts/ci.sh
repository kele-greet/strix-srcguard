#!/usr/bin/env bash
# Local/CI gate: unit tests, source-integrity (when the Strix checkout exists),
# and a secret-shaped-token scan. Integration tests are excluded here because
# they need a privileged nft helper; they are run on the lab host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/uv-cache}"

echo "== unit tests =="
uv run --project "$ROOT" pytest -q -k 'not Integration'

echo "== source integrity =="
if [ -f "$ROOT/../strix-main.sha256" ] && [ -d "$ROOT/../strix-main" ]; then
  "$ROOT/check_strix.sh"
else
  echo "strix-main checkout not present; skipping zero-diff check (CI checkout is srcguard-only)"
fi

echo "== dnsguard build =="
if command -v gcc >/dev/null 2>&1; then
  "$ROOT/scripts/build_dnsguard.sh"
else
  echo "gcc not installed; skipping static dnsguard build"
fi

echo "== secret scan =="
if grep -RInE 'sk-[A-Za-z0-9]{20,}' \
  --exclude-dir=.git --exclude-dir=.venv --exclude-dir=p0-gate \
  --exclude-dir=__pycache__ --exclude='*.pyc' .; then
  echo "ERROR: secret-shaped token found" >&2
  exit 1
fi
echo "no secret-shaped tokens"

echo "CI OK"
