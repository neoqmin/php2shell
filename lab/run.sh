#!/usr/bin/env bash
# Runs both checkers against every lab site and collects the results in lab/out/.
#   remote: php2shell_remote.py from this machine against http://127.0.0.1:<port>/
#   host:   php2shell_host.py inside each container (read-only), fed the remote JSON
# Usage: ./run.sh            (PYTHON=python on Windows Git Bash)
set -u
export MSYS_NO_PATHCONV=1  # keep container paths like /tmp intact under Git Bash
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
OUT=out
rm -rf "$OUT" && mkdir -p "$OUT"

docker compose up -d --build || exit 2

printf '%-28s %-6s %-26s %-8s %s\n' SITE PORT REMOTE HOST_RC HOST_SUMMARY | tee "$OUT/summary.txt"
for svc in $(docker compose config --services); do
  port=$(docker compose port "$svc" 80 | sed 's/.*://')
  for _ in $(seq 1 30); do
    curl -fs -o /dev/null "http://127.0.0.1:$port/" && break
    sleep 1
  done

  "$PY" ../php2shell_remote.py "http://127.0.0.1:$port/" --json > "$OUT/$svc.remote.json"
  remote=$("$PY" -c 'import json,sys; r=json.load(open(sys.argv[1], encoding="utf-8")); print(r["status"], r.get("detected_version") or "-")' "$OUT/$svc.remote.json")

  docker cp ../php2shell_host.py "$svc:/tmp/php2shell_host.py" >/dev/null
  docker cp "$OUT/$svc.remote.json" "$svc:/tmp/remote.json" >/dev/null
  # php2shell_host.py needs Python 3.7+; Ubuntu 18.04 ships 3.6 and needs the python3.8 package.
  py=$(docker exec "$svc" sh -c 'for p in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do command -v $p && break; done')
  output=$(docker exec "$svc" "$py" /tmp/php2shell_host.py --remote-json /tmp/remote.json \
           --out /tmp/php2shell_report 2>&1)
  hrc=$?
  echo "$output" > "$OUT/$svc.host.txt"
  summary=$(echo "$output" | head -1)
  docker cp "$svc:/tmp/php2shell_report" "$OUT/$svc" >/dev/null 2>&1

  printf '%-28s %-6s %-26s %-8s %s\n' "$svc" "$port" "$remote" "$hrc" "$summary" | tee -a "$OUT/summary.txt"
done

echo "결과: $(pwd)/$OUT  (정리: docker compose down)"
