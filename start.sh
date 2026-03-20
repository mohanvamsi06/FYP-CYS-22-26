#!/usr/bin/env bash
set -euo pipefail

RULE_DIR="./k8s-security/rules"
BASE_DIR="./k8s-security"

echo "[+] Installing Tetragon..."

# Check kubectl
if ! command -v kubectl >/dev/null 2>&1; then
  echo "[-] kubectl not found."
  exit 1
fi

# Install Helm if missing
if ! command -v helm >/dev/null 2>&1; then
  echo "[+] Helm not found. Installing Helm..."
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# Prepare directories
mkdir -p "$RULE_DIR"

# Add Cilium Helm repo
echo "[+] Adding Cilium Helm repo..."
helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
helm repo update

# Create tetragon namespace
echo "[+] Creating tetragon namespace (if not exists)..."
kubectl create namespace tetragon --dry-run=client -o yaml | kubectl apply -f -

# Check if Tetragon CRDs exist from previous installation
if kubectl get crd tracingpolicies.cilium.io >/dev/null 2>&1; then
  echo "[!] Found existing Tetragon CRDs. Adding Helm metadata..."
  
  for crd in tracingpolicies.cilium.io tracingpoliciesnamespaced.cilium.io; do
    if kubectl get crd "$crd" >/dev/null 2>&1; then
      kubectl label crd "$crd" app.kubernetes.io/managed-by=Helm --overwrite
      kubectl annotate crd "$crd" meta.helm.sh/release-name=tetragon --overwrite
      kubectl annotate crd "$crd" meta.helm.sh/release-namespace=tetragon --overwrite
    fi
  done
  
  echo "[✓] CRDs patched with Helm metadata"
fi

# Install Tetragon
echo "[+] Installing Tetragon via Helm..."
helm upgrade --install tetragon cilium/tetragon \
  --namespace tetragon \
  --set tetragon.exporter.enabled=true \
  --set tetragon.exporter.stdout.enabled=true \
  --create-namespace

echo "[+] Waiting for Tetragon pods (max ~2 min)..."
kubectl rollout status ds/tetragon -n tetragon --timeout=120s || true

if kubectl get crd tracingpolicies.cilium.io >/dev/null 2>&1; then
  echo "[!] Patching Tetragon CRDs with Helm metadata..."
  for crd in $(kubectl get crd -o name | grep cilium.io); do
    kubectl label "$crd" app.kubernetes.io/managed-by=Helm --overwrite
    kubectl annotate "$crd" meta.helm.sh/release-name=tetragon meta.helm.sh/release-namespace=tetragon --overwrite
  done
fi

# ------------------------------------------------------------------
# WAIT FOR CRDs
# ------------------------------------------------------------------
echo "[+] Waiting for TracingPolicy CRD..."
helm upgrade tetragon cilium/tetragon -n tetragon --install --force --set crds.installMethod=helm
TIMEOUT=120
ELAPSED=0
until kubectl get crd tracingpolicies.cilium.io >/dev/null 2>&1; do
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "[-] Timeout waiting for TracingPolicy CRD after ${TIMEOUT}s"
    echo "[!] Checking Tetragon pod status..."
    kubectl get pods -n tetragon
    echo "[!] Checking CRDs..."
    kubectl get crd | grep -i tetragon || echo "No Tetragon CRDs found"
    echo "[!] Checking Tetragon logs..."
    kubectl logs -n tetragon -l app.kubernetes.io/name=tetragon --tail=50 || true
    exit 1
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
  if [ $((ELAPSED % 10)) -eq 0 ]; then
    echo "    ... still waiting (${ELAPSED}s elapsed)"
  fi
done

echo "[✓] Tetragon CRDs detected."

# ------------------------------------------------------------------
# Download rules
# ------------------------------------------------------------------
echo "[+] Downloading Tetragon rules..."

BASE_URL="https://raw.githubusercontent.com/mohanvamsi06/FYP-CYS-22-26/main/Runtime/Tracepoints"

# DoS detection
wget -q -O "$RULE_DIR/bind-detect.yaml"        "$BASE_URL/bind-detect.yaml"
wget -q -O "$RULE_DIR/dos-accept-detect.yaml"  "$BASE_URL/dos-accept-detect.yaml"
wget -q -O "$RULE_DIR/dos-clone-detect.yaml"   "$BASE_URL/dos-clone-detect.yaml"
wget -q -O "$RULE_DIR/dos-connect-detect.yaml" "$BASE_URL/dos-connect-detect.yaml"
wget -q -O "$RULE_DIR/dos-fd-detect.yaml"      "$BASE_URL/dos-fd-detect.yaml"

# File & permission monitoring
wget -q -O "$RULE_DIR/rt-chmod.yaml"                  "$BASE_URL/rt-chmod.yaml"
wget -q -O "$RULE_DIR/rt-chown.yaml"                  "$BASE_URL/rt-chown.yaml"
wget -q -O "$RULE_DIR/rt-security-file-open.yaml"     "$BASE_URL/rt-security-file-open.yaml"
wget -q -O "$RULE_DIR/rt-security-inode-rename.yaml"  "$BASE_URL/rt-security-inode-rename.yaml"
wget -q -O "$RULE_DIR/rt-security-inode-unlink.yaml"  "$BASE_URL/rt-security-inode-unlink.yaml"

# Process execution
wget -q -O "$RULE_DIR/rt-execve.yaml"              "$BASE_URL/rt-execve.yaml"
wget -q -O "$RULE_DIR/rt-security-bprm-check.yaml" "$BASE_URL/rt-security-bprm-check.yaml"

# Network
wget -q -O "$RULE_DIR/rt-security-socket-connect.yaml" "$BASE_URL/rt-security-socket-connect.yaml"

# Namespace & container escape
wget -q -O "$RULE_DIR/rt-setns.yaml"   "$BASE_URL/rt-setns.yaml"
wget -q -O "$RULE_DIR/rt-unshare.yaml" "$BASE_URL/rt-unshare.yaml"

# Enforcement (disabled by default - uncomment to enable active SIGKILL enforcement)
# wget -q -O "$RULE_DIR/sigkill-policies.yaml" "$BASE_URL/sigkill-policies.yaml"

echo "[+] Applying all TracingPolicies..."
kubectl apply -f "$RULE_DIR"

kubectl get tracingpolicy

# ------------------------------------------------------------------
# Dashboard Deployment
# ------------------------------------------------------------------
echo "[+] Deploying dashboard..."

wget -q -O "$BASE_DIR/job.yaml" \
https://raw.githubusercontent.com/mohanvamsi06/FYP-CYS-22-26/main/job.yaml

kubectl apply -f "$BASE_DIR/job.yaml"

echo "[+] Waiting for dashboard to be ready (may take a few mins on first run)..."
kubectl rollout status deployment/k8s-security-dashboard -n default --timeout=300s || {
  echo "[!] Rollout timed out. Checking pod status..."
  kubectl get pods -n default -l app=k8s-security-dashboard
  kubectl describe pod -n default -l app=k8s-security-dashboard | tail -30
  echo "[!] The pod may still be pulling the image. Wait a moment and re-run:"
  echo "    kubectl rollout status deployment/k8s-security-dashboard -n default"
  echo "    minikube service k8s-security-dashboard --url"
  exit 1
}

echo
echo "[✓] Setup complete!"
echo
echo "Access the dashboard at: "
minikube service k8s-security-dashboard --url
echo
