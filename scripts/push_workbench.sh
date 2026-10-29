#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
bundle=".workbench/adaptaes-ready.bundle"
if [[ ! -f "$bundle" ]]; then
  printf 'Prepared bundle is missing: %s\n' "$bundle" >&2
  exit 1
fi
git fetch "$bundle" feat/research-lab-experiments
git push origin FETCH_HEAD:refs/heads/feat/research-lab-experiments
printf '\nPushed. Review PR: https://github.com/ayatinkering/AdaptAES-Proj/pull/3\n'
