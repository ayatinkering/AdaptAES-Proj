#!/usr/bin/env bash
# Run in a regular Ubuntu terminal, outside the restricted assistant environment.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

# Match only this user's Python module server on the default port.
mapfile -t server_pids < <(pgrep -u "$(id -u)" -f '(^|/)(python3|python3[.][0-9]+) -m api[.]server( --port 8000)?$' || true)
if ((${#server_pids[@]})); then
  printf 'Stopping the previous AdaptAES server…\n'
  kill -- "${server_pids[@]}"
  sleep 0.5
fi
printf 'Starting the updated API at http://127.0.0.1:8000/\n'
exec python3 -m api.server --port 8000
