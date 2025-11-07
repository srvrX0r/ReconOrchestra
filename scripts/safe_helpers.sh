#!/usr/bin/env bash
set -euo pipefail

# Safe helper to redact tokens from JSON artifacts (simple example)
redact_file() {
  infile="$1"
  outfile="${2:-$infile.redacted}"
  jq 'del(.. | .authorization? // empty) 
      | del(.. | .cookie? // empty)
      | del(.request?.body? // empty)
      | del(.response?.body? // empty)' "$infile" > "$outfile"
  echo "Wrote redacted file to $outfile"
}

if [ "${1:-}" = "redact" ]; then
  redact_file "$2" "$3"
else
  echo "Usage: $0 redact <input.json> [output.json]"
fi
