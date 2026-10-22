#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/bin"
gcc -O2 -static -Wall -Wextra -o "$ROOT/bin/srcguard-dnsguard" "$ROOT/srcguard/dnsguard/dnsguard.c"
file "$ROOT/bin/srcguard-dnsguard"
