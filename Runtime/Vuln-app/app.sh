#!/bin/bash

COUNT=50

echo "[*] DoS test app starting"
echo "[*] Count per test: $COUNT"
echo "[*] PID: $$"
echo

############################################
# 1) Fork / clone storm (finite)
############################################
echo "[1/4] Fork / clone test ($COUNT times)"
for i in $(seq 1 "$COUNT"); do
  sh -c "true" &
done
wait
echo "[✓] Fork test completed"
echo

############################################
# 2) Outbound connect flood (finite)
############################################
echo "[2/4] Connect flood test ($COUNT times)"
for i in $(seq 1 "$COUNT"); do
  nc -z -w 1 1.1.1.1 80 >/dev/null 2>&1
done
echo "[✓] Connect test completed"
echo

############################################
# 3) Accept flood (finite)
############################################
echo "[3/4] Accept flood test ($COUNT times)"

# Start listener
nc -l -p 9999 >/dev/null 2>&1 &
SERVER_PID=$!

sleep 1

for i in $(seq 1 "$COUNT"); do
  nc 127.0.0.1 9999 >/dev/null 2>&1
done

kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null

echo "[✓] Accept test completed"
echo

############################################
# 4) File descriptor exhaustion (finite)
############################################
echo "[4/4] File descriptor test ($COUNT times)"
for i in $(seq 1 "$COUNT"); do
  exec {fd}</etc/passwd
  echo "[*] Opened FD $fd"
done

echo "[✓] FD test completed"
echo

echo "[*] All DoS tests completed successfully"
