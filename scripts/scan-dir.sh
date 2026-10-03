#!/usr/bin/env bash
# Scan every *.zip in a directory and print one tab-separated line per plugin,
# followed by verdict totals on stderr. Useful for measuring how a rules change
# affects the whole registry before relying on it.
#
#   scripts/scan-dir.sh <dir> [scanner-binary] > results.tsv
set -euo pipefail

dir="${1:?usage: scan-dir.sh <dir> [scanner-binary]}"
scanner="${2:-$(dirname "$0")/../target/release/plugin_scanner}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

printf 'file\trecommendation\trisk\tcomplete\thigh_or_critical_rules\n'
pass=0 review=0 block=0 error=0
shopt -s nullglob
for zip in "$dir"/*.zip; do
  # Exit code 1 never happens without --fail-on; 2 means unreadable.
  if ! json="$("$scanner" scan "$zip" --json 2>/dev/null)"; then
    printf '%s\terror\t-\t-\t-\n' "$(basename "$zip")"
    error=$((error + 1))
    continue
  fi
  line="$(jq -r '[
      .verdict.recommendation,
      (.verdict.risk // "none"),
      (.verdict.complete | tostring),
      ([.findings[] | select(.severity == "high" or .severity == "critical") | .id] | unique | join(","))
    ] | @tsv' <<<"$json")"
  printf '%s\t%s\n' "$(basename "$zip")" "$line"
  case "${line%%$'\t'*}" in
    pass) pass=$((pass + 1)) ;;
    review) review=$((review + 1)) ;;
    block) block=$((block + 1)) ;;
  esac
done

echo "pass=$pass review=$review block=$block error=$error" >&2
