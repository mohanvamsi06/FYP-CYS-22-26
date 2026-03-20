# Compliance — CIS Kubernetes Benchmark v1.11

This document describes the automated CIS Benchmark v1.11 compliance checks performed by the Compliance component of this project.

---

## Overview

The compliance scanner runs as a Kubernetes Job on the control plane node. It reads the CIS Benchmark control definitions from YAML files, executes audit commands directly on the host (via `hostPID`, `hostNetwork`, and mounted host paths), evaluates each result, and writes a JSON report to `/var/tmp/results/results.json` — a shared hostPath volume accessible to the Dashboard.

### How It Works

1. The Dashboard triggers a scan via the "Run Scan" button (POST `/api/scan/start`)
2. A Kubernetes Job is created — the `mohanvamsi06/fyp:master_node` container runs on the control plane node
3. The container executes `main.py`, which iterates over all YAML control files in `cis-1.11/`
4. For each check, the audit command is run via `subprocess` (with `/proc`-based fallbacks for minimal environments)
5. The output is evaluated against the test conditions defined in the YAML
6. Results are written to `/output/results.json` (mapped to `/var/tmp/results/results.json` on the host)
7. The Dashboard polls `/api/scan/status` and loads results when the job completes

### Result Statuses

| Status | Meaning |
|--------|---------|
| PASS | Audit output satisfies the test condition |
| FAIL | Audit output does not satisfy the test condition |
| WARN | Manual check, or output could not be parsed |
| ERROR | Exception during evaluation |

### Test Operators

| Operator | Description |
|----------|-------------|
| `bitmask` | File permission check — actual permissions must be ≤ expected (e.g. 600) |
| `eq` | Exact equality |
| `has` | String contains value |
| `nothave` | String does not contain value |
| `gte` | Numeric greater-than-or-equal |
| `valid_elements` | All actual values must be in the allowed set |
| `set: true/false` | Flag presence/absence check |

---

## Section 1 — Control Plane Security Configuration

### 1.1 Control Plane Node Configuration Files

Checks file permissions and ownership of critical Kubernetes manifest and config files on the control plane node.

| ID | Description | Type | Expected |
|----|-------------|------|----------|
| 1.1.1 | kube-apiserver.yaml permissions | Automated | ≤ 600 |
| 1.1.2 | kube-apiserver.yaml ownership | Automated | root:root |
| 1.1.3 | kube-controller-manager.yaml permissions | Automated | ≤ 600 |
| 1.1.4 | kube-controller-manager.yaml ownership | Automated | root:root |
| 1.1.5 | kube-scheduler.yaml permissions | Automated | ≤ 600 |
| 1.1.6 | kube-scheduler.yaml ownership | Automated | root:root |
| 1.1.7 | etcd.yaml permissions | Automated | ≤ 600 |
| 1.1.8 | etcd.yaml ownership | Automated | root:root |
| 1.1.9 | CNI config file permissions | Manual | ≤ 600 |
| 1.1.10 | CNI config file ownership | Manual | root:root |
| 1.1.11 | etcd data directory permissions | Automated | ≤ 700 |
| 1.1.12 | etcd data directory ownership | Automated | etcd:etcd |
| 1.1.13 | admin.conf / super-admin.conf permissions | Automated | ≤ 600 |
| 1.1.14 | admin.conf / super-admin.conf ownership | Automated | root:root |
| 1.1.15 | scheduler.conf permissions | Automated | ≤ 600 |
| 1.1.16 | scheduler.conf ownership | Automated | root:root |
| 1.1.17 | controller-manager.conf permissions | Automated | ≤ 600 |
| 1.1.18 | controller-manager.conf ownership | Automated | root:root |
| 1.1.19 | /etc/kubernetes/pki/ ownership | Automated | root:root |
| 1.1.20 | PKI certificate file permissions (*.crt) | Manual | ≤ 644 |
| 1.1.21 | PKI key file permissions (*.key) | Manual | ≤ 600 |

### 1.2 API Server

Checks kube-apiserver process arguments for security-relevant flags.

| ID | Description | Type | Expected |
|----|-------------|------|----------|
| 1.2.1 | `--anonymous-auth` | Manual | false |
| 1.2.2 | `--token-auth-file` | Automated | not set |
| 1.2.3 | `DenyServiceExternalIPs` admission plugin | Manual | enabled |
| 1.2.4 | `--kubelet-client-certificate` and `--kubelet-client-key` | Automated | both set |
| 1.2.5 | `--kubelet-certificate-authority` | Automated | set |
| 1.2.6 | `--authorization-mode` not AlwaysAllow | Automated | does not contain AlwaysAllow |
| 1.2.7 | `--authorization-mode` includes Node | Automated | contains Node |
| 1.2.8 | `--authorization-mode` includes RBAC | Automated | contains RBAC |
| 1.2.9 | `EventRateLimit` admission plugin | Manual | enabled |
| 1.2.10 | `AlwaysAdmit` admission plugin | Automated | not set |
| 1.2.11 | `AlwaysPullImages` admission plugin | Manual | enabled |
| 1.2.12 | `ServiceAccount` admission plugin | Automated | not disabled |
| 1.2.13 | `NamespaceLifecycle` admission plugin | Automated | not disabled |
| 1.2.14 | `NodeRestriction` admission plugin | Automated | enabled |
| 1.2.15 | `--profiling` | Automated | false |
| 1.2.16 | `--audit-log-path` | Automated | set |
| 1.2.17 | `--audit-log-maxage` | Automated | ≥ 30 |
| 1.2.18 | `--audit-log-maxbackup` | Automated | ≥ 10 |
| 1.2.19 | `--audit-log-maxsize` | Automated | ≥ 100 |
| 1.2.20 | `--request-timeout` | Manual | appropriate value |
| 1.2.21 | `--service-account-lookup` | Automated | true |
| 1.2.22 | `--service-account-key-file` | Automated | set |
| 1.2.23 | `--etcd-certfile` and `--etcd-keyfile` | Automated | both set |
| 1.2.24 | `--tls-cert-file` and `--tls-private-key-file` | Automated | both set |
| 1.2.25 | `--client-ca-file` | Automated | set |
| 1.2.26 | `--etcd-cafile` | Automated | set |
| 1.2.27 | `--encryption-provider-config` | Manual | set |
| 1.2.28 | Encryption provider type | Manual | aescbc, kms, or secretbox |
| 1.2.29 | TLS cipher suites | Manual | strong ciphers only |
| 1.2.30 | `--service-account-extend-token-expiration` | Automated | false |

### 1.3 Controller Manager

Checks kube-controller-manager process arguments.

| ID | Description | Type | Expected |
|----|-------------|------|----------|
| 1.3.1 | `--terminated-pod-gc-threshold` | Manual | set |
| 1.3.2 | `--profiling` | Automated | false |
| 1.3.3 | `--use-service-account-credentials` | Automated | true |
| 1.3.4 | `--service-account-private-key-file` | Automated | set |
| 1.3.5 | `--root-ca-file` | Automated | set |
| 1.3.6 | `RotateKubeletServerCertificate` feature gate | Automated | not false |
| 1.3.7 | `--bind-address` | Automated | 127.0.0.1 or not set |

### 1.4 Scheduler

Checks kube-scheduler process arguments.

| ID | Description | Type | Expected |
|----|-------------|------|----------|
| 1.4.1 | `--profiling` | Automated | false |
| 1.4.2 | `--bind-address` | Automated | 127.0.0.1 or not set |

---

## Section 2 — Etcd Node Configuration

Checks etcd process arguments for TLS and certificate authentication settings.

| ID | Description | Type | Expected |
|----|-------------|------|----------|
| 2.1 | `--cert-file` and `--key-file` | Automated | both set |
| 2.2 | `--cert-file` and `--key-file` (duplicate check) | Automated | both set |
| 2.3 | `--client-cert-auth` | Automated | true |
| 2.4 | `--auto-tls` | Automated | false or not set |
| 2.5 | `--peer-cert-file` and `--peer-key-file` | Automated | both set |
| 2.6 | `--peer-client-cert-auth` | Automated | true |
| 2.7 | `--peer-auto-tls` | Automated | false or not set |
| 2.8 | `--trusted-ca-file` (unique CA for etcd) | Manual | set |

---

## Section 3 — Control Plane Configuration

### 3.1 Authentication and Authorization

| ID | Description | Type |
|----|-------------|------|
| 3.1.1 | Client certificate authentication not used for users | Manual |
| 3.1.2 | Service account token authentication not used for users | Manual |
| 3.1.3 | Bootstrap token authentication not used for users | Manual |

### 3.2 Logging

| ID | Description | Type | Expected |
|----|-------------|------|----------|
| 3.2.1 | `--audit-policy-file` is set | Manual | set |
| 3.2.2 | Audit policy covers key security concerns | Manual | review required |

---

## Section 4 — Worker Node Security Configuration

### 4.1 Worker Node Configuration Files

Checks file permissions and ownership of kubelet and kube-proxy config files on worker nodes.

| ID | Description | Type | Expected |
|----|-------------|------|----------|
| 4.1.1 | kubelet service file permissions | Automated | ≤ 600 |
| 4.1.2 | kubelet service file ownership | Automated | root:root |
| 4.1.3 | kube-proxy kubeconfig permissions | Manual | ≤ 600 |
| 4.1.4 | kube-proxy kubeconfig ownership | Manual | root:root |
| 4.1.5 | kubelet.conf permissions | Automated | ≤ 600 |
| 4.1.6 | kubelet.conf ownership | Automated | root:root |
| 4.1.7 | CA file permissions | Manual | ≤ 644 |
| 4.1.8 | CA file ownership | Manual | root:root |
| 4.1.9 | kubelet config.yaml permissions | Automated | ≤ 600 |
| 4.1.10 | kubelet config.yaml ownership | Automated | root:root |

### 4.2 Kubelet

Checks kubelet process arguments and config file settings.

| ID | Description | Type | Expected |
|----|-------------|------|----------|
| 4.2.1 | `--anonymous-auth` | Automated | false |
| 4.2.2 | `--authorization-mode` not AlwaysAllow | Automated | Webhook |
| 4.2.3 | `--client-ca-file` | Automated | set |
| 4.2.4 | `--read-only-port` | Manual | 0 or not set |
| 4.2.5 | `--streaming-connection-idle-timeout` | Manual | not 0 |
| 4.2.6 | `--make-iptables-util-chains` | Automated | true or not set |
| 4.2.7 | `--hostname-override` | Manual | not set |
| 4.2.8 | `--event-qps` | Manual | ≥ 0 |
| 4.2.9 | `--tls-cert-file` and `--tls-private-key-file` | Manual | both set |
| 4.2.10 | `--rotate-certificates` | Automated | true or not set |
| 4.2.11 | `RotateKubeletServerCertificate` | Manual | not false |
| 4.2.12 | TLS cipher suites | Manual | strong ciphers only |
| 4.2.13 | `--pod-max-pids` | Manual | set |
| 4.2.14 | `--seccomp-default` | Manual | set |
| 4.2.15 | `--IPAddressDeny` | Manual | any |

### 4.3 kube-proxy

| ID | Description | Type | Expected |
|----|-------------|------|----------|
| 4.3.1 | `--metrics-bind-address` bound to localhost | Automated | 127.0.0.1 or not set |

---

## Section 5 — Kubernetes Policies

### 5.1 RBAC and Service Accounts

| ID | Description | Type |
|----|-------------|------|
| 5.1.1 | cluster-admin role used only where required | Manual (automated audit) |
| 5.1.2 | Minimize access to secrets | Manual |
| 5.1.3 | Minimize wildcard use in Roles and ClusterRoles | Manual (automated audit) |
| 5.1.4 | Minimize access to create pods | Manual |
| 5.1.5 | Default service accounts not actively used | Manual (automated audit) |
| 5.1.6 | Service Account Tokens only mounted where necessary | Manual (automated audit) |
| 5.1.7 | Avoid use of system:masters group | Manual |
| 5.1.8 | Limit Bind, Impersonate, Escalate permissions | Manual |
| 5.1.9 | Minimize access to create persistent volumes | Manual |
| 5.1.10 | Minimize access to proxy sub-resource of nodes | Manual |
| 5.1.11 | Minimize access to CSR approval sub-resource | Manual |
| 5.1.12 | Minimize access to webhook configuration objects | Manual |
| 5.1.13 | Minimize access to service account token creation | Manual |

### 5.2 Pod Security Standards

| ID | Description | Type |
|----|-------------|------|
| 5.2.1 | At least one active policy control mechanism | Manual |
| 5.2.2 | Minimize admission of privileged containers | Manual (automated audit) |
| 5.2.3 | Minimize containers sharing host PID namespace | Manual (automated audit) |
| 5.2.4 | Minimize containers sharing host IPC namespace | Manual (automated audit) |
| 5.2.5 | Minimize containers sharing host network namespace | Manual (automated audit) |
| 5.2.6 | Minimize containers with allowPrivilegeEscalation | Manual (automated audit) |
| 5.2.7 | Minimize root containers | Manual |
| 5.2.8 | Minimize containers with NET_RAW capability | Manual |
| 5.2.9 | Minimize containers with added capabilities | Manual (automated audit) |
| 5.2.10 | Minimize containers with capabilities assigned | Manual |
| 5.2.11 | Minimize Windows HostProcess containers | Manual |
| 5.2.12 | Minimize HostPath volumes | Manual |
| 5.2.13 | Minimize containers using HostPorts | Manual |

### 5.3 Network Policies and CNI

| ID | Description | Type |
|----|-------------|------|
| 5.3.1 | CNI supports NetworkPolicies | Manual |
| 5.3.2 | All namespaces have NetworkPolicies defined | Manual |

### 5.4 Secrets Management

| ID | Description | Type |
|----|-------------|------|
| 5.4.1 | Prefer Secrets as files over environment variables | Manual |
| 5.4.2 | Consider external secret storage | Manual |

### 5.5 Extensible Admission Control

| ID | Description | Type |
|----|-------------|------|
| 5.5.1 | Configure ImagePolicyWebhook admission controller | Manual |

### 5.6 General Policies

| ID | Description | Type |
|----|-------------|------|
| 5.6.1 | Use namespaces for administrative boundaries | Manual |
| 5.6.2 | seccomp profile set to docker/default | Manual |
| 5.6.3 | Apply SecurityContext to Pods and Containers | Manual |
| 5.6.4 | Default namespace not used | Manual |

---

## Running a Scan

From the Dashboard, navigate to the Compliance tab and click "Run Scan". The scan runs as a Kubernetes Job on the control plane node and typically completes in under a minute. Results are displayed automatically when the job finishes.

To trigger a scan manually:

```bash
kubectl apply -f - <<'EOF'
apiVersion: batch/v1
kind: Job
metadata:
  name: cis-k8s-audit
spec:
  template:
    spec:
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
      - key: "node-role.kubernetes.io/control-plane"
        operator: "Exists"
        effect: "NoSchedule"
      - operator: "Exists"
      hostPID: true
      hostNetwork: true
      serviceAccountName: audit-runner
      restartPolicy: Never
      containers:
        - name: check
          image: mohanvamsi06/fyp:master_node
          imagePullPolicy: Always
          volumeMounts:
            - name: kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
            - name: etcd
              mountPath: /var/lib/etcd
              readOnly: true
            - name: output
              mountPath: /output
      volumes:
        - name: kubernetes
          hostPath:
            path: /etc/kubernetes
        - name: etcd
          hostPath:
            path: /var/lib/etcd
        - name: output
          hostPath:
            path: /var/tmp/results
            type: DirectoryOrCreate
EOF
```

View raw results:

```bash
cat /var/tmp/results/results.json | jq '.[] | {id: .check_id, status: .status, reason: .reason}'
```
