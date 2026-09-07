#!/usr/bin/env bash
# One-shot orchestration of the OPTIONAL live LocalStack scenario.
set -euo pipefail
here="$(dirname "$0")"; root="$here/../.."
echo "[*] Starting LocalStack (needs ~1 GB RAM)..."
docker compose -f "$here/docker-compose.localstack.yml" up -d
sleep 8
bash "$here/setup.sh"
bash "$here/attack.sh"
python "$here/collect.py"
echo "[*] Running detections over live-confirmed telemetry..."
python "$root/automation/normalize/normalize.py"
python "$root/automation/detect/run_sigma.py"
echo "[*] Tear down: docker compose -f $here/docker-compose.localstack.yml down"
