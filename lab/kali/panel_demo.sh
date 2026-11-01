#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: ./panel_demo.sh vulnerable|hardened [--with-llm]" >&2
  exit 2
fi

profile="$1"
case "$profile" in
  vulnerable|hardened) ;;
  *) echo "Profile must be vulnerable or hardened" >&2; exit 2 ;;
esac

with_llm="${2:-}"
if [[ -n "$with_llm" && "$with_llm" != "--with-llm" ]]; then
  echo "Optional second argument must be --with-llm" >&2
  exit 2
fi

python3 recon_check.py --expected-profile "$profile"
python3 run_suite.py --repetitions 1 --output "reports/panel-${profile}"

if [[ "$with_llm" == "--with-llm" ]]; then
  python3 model_probe.py
fi

echo
echo "Panel run saved under: reports/panel-${profile}/"
echo "Run once for each profile, then compare the two results.json files with compare_runs.py."
if [[ "$with_llm" == "--with-llm" ]]; then
  echo "Exploratory model traces are separate under model_reports/ and are not benchmark metrics."
fi
