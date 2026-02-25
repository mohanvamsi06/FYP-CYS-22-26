#!/usr/bin/env bash
# Collect Tetragon logs and save to shared volume for dashboard

OUTPUT_FILE="/output/runtime_alerts.json"
NAMESPACE="tetragon"

echo "[+] Starting Tetragon log collection..."

# Clear existing file
> "$OUTPUT_FILE"

# Stream Tetragon logs and append to file
kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/name=tetragon --follow --tail=1000 2>/dev/null | while read -r line; do
  # Only save JSON lines (Tetragon events)
  if echo "$line" | jq -e . >/dev/null 2>&1; then
    echo "$line" >> "$OUTPUT_FILE"
  fi
done
