#!/usr/bin/env bash
set -euo pipefail

RULE_DIR="./k8s-security/rules"
BASE_DIR="./k8s-security"

echo "[+] Removing Tetragon and related resources..."

# Check kubectl
if ! command -v kubectl >/dev/null 2>&1; then
  echo "[-] kubectl not found."
  exit 1
fi

# Remove dashboard job
echo "[+] Removing dashboard deployment..."
kubectl delete deployment k8s-security-dashboard -n default --ignore-not-found=true
kubectl delete service k8s-security-dashboard -n default --ignore-not-found=true

if [ -f "$BASE_DIR/job.yaml" ]; then
  kubectl delete -f "$BASE_DIR/job.yaml" --ignore-not-found=true
fi

# Remove TracingPolicies
echo "[+] Removing TracingPolicies..."
if [ -d "$RULE_DIR" ]; then
  kubectl delete -f "$RULE_DIR" --ignore-not-found=true
fi

# Uninstall Tetragon via Helm
echo "[+] Uninstalling Tetragon..."
if command -v helm >/dev/null 2>&1; then
  helm uninstall tetragon -n tetragon --ignore-not-found 2>/dev/null || true
fi

# Delete tetragon namespace
echo "[+] Deleting tetragon namespace..."
kubectl delete namespace tetragon --ignore-not-found=true --timeout=60s || true

# Clean up downloaded files
echo "[+] Cleaning up downloaded files..."
if [ -d "$BASE_DIR" ]; then
  rm -rf "$BASE_DIR"
  echo "    Removed $BASE_DIR directory"
fi

echo
echo "[✓] Cleanup complete!"
echo
