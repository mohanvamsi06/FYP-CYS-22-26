#!/usr/bin/env bash
# Collect Tetragon logs and save to shared volume for dashboard

OUTPUT_FILE="/output/runtime_alerts.json"
NAMESPACE="tetragon"

echo "[+] Starting Tetragon log collection..."

# Clear existing file
> "$OUTPUT_FILE"

# Stream Tetragon logs and extract JSON events.
# Tetragon log lines look like:
#   time="..." level=info msg="..." node_name="..." event={"process_kprobe":...}
# OR the entire line is raw JSON (when --export-file-perm is used).
# We handle both: try to parse the whole line as JSON first,
# then fall back to extracting the last {...} object on the line.
kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/name=tetragon --follow --tail=1000 2>/dev/null | while IFS= read -r line; do
  # Skip empty lines
  [ -z "$line" ] && continue

  # Try the whole line as JSON first (raw export mode)
  if echo "$line" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    echo "$line" >> "$OUTPUT_FILE"
    continue
  fi

  # Fall back: extract the JSON object from a structured log line.
  # Tetragon structured logs embed the event as the last JSON blob.
  json_part=$(echo "$line" | grep -oP '\{.*\}' | tail -1)
  if [ -n "$json_part" ]; then
    if echo "$json_part" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
      echo "$json_part" >> "$OUTPUT_FILE"
    fi
  fi
done
