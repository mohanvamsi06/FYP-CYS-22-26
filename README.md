# K8s Security Dashboard — FYP

A Kubernetes security monitoring platform that combines **CIS Benchmark v1.11 compliance auditing** with **real-time runtime threat detection** via Tetragon eBPF tracing.

---

## What It Does

```
┌─────────────────────────────────────────────────────────┐
│                    Dashboard (Flask)                    │
│         http://<node-ip>:30500                          │
│   ┌──────────────────┐   ┌──────────────────────────┐  │
│   │  Compliance Tab  │   │      Runtime Tab         │  │
│   │  CIS Benchmark   │   │  Tetragon eBPF Alerts    │  │
│   │  PASS/FAIL/WARN  │   │  Severity / Event Type   │  │
│   └──────────────────┘   └──────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
         │                            │
         ▼                            ▼
┌─────────────────┐        ┌──────────────────────┐
│  Compliance Job │        │  Tetragon DaemonSet  │
│  (K8s Job)      │        │  15 TracingPolicies  │
│  Runs on        │        │  kprobes + tracepoints│
│  control plane  │        └──────────────────────┘
│  Writes JSON to │
│  /var/tmp/results│
└─────────────────┘
```

**Compliance** — triggers a Kubernetes Job that runs CIS Benchmark v1.11 checks directly on the control plane node (file permissions, API server flags, etcd config, RBAC, Pod Security). Results are written to a shared hostPath volume and displayed in the dashboard.

**Runtime** — Tetragon eBPF policies monitor syscalls and LSM hooks cluster-wide in real time: process execution, file operations, namespace escapes, network activity, DoS indicators. Alerts are streamed to the dashboard with severity classification.

---

## Prerequisites

- [Minikube](https://minikube.sigs.k8s.io/) (or any Kubernetes cluster)
- `kubectl` configured and pointing at your cluster
- `helm` (installed automatically by `start.sh` if missing)
- `wget`, `curl`
- Linux kernel 5.10+ (kernel 6.x recommended for full tracepoint support)

---

## Start

```bash
curl -fsSL https://raw.githubusercontent.com/mohanvamsi06/FYP-CYS-22-26/main/start.sh | bash
```

This will:
1. Install Tetragon via Helm
2. Apply all 15 runtime tracing policies
3. Deploy the dashboard
4. Print the dashboard URL

---

## Remove

```bash
curl -fsSL https://raw.githubusercontent.com/mohanvamsi06/FYP-CYS-22-26/main/remove.sh | bash
```

This will remove all TracingPolicies, uninstall Tetragon, delete the dashboard deployment, and clean up downloaded files.

---

## Documentation

- [Runtime Policies](runtime.md) — all 15 active Tetragon tracing policies, hook types, severity levels, and changes made
- [Compliance Checks](compliance.md) — full CIS Benchmark v1.11 check reference, how the scanner works, and how to trigger a scan
