# Runtime Security Integration

## Architecture Overview

This dashboard integrates Tetragon runtime security monitoring with compliance scanning for comprehensive Kubernetes security.

### Components

1. **Tetragon** - eBPF-based runtime security monitoring
   - Deployed via Helm in `tetragon` namespace
   - Monitors syscalls and kernel events via TracingPolicies
   - Exports events to stdout as JSON

2. **TracingPolicies** - Define what to monitor
   - Located in `Runtime/Tracepoints/`
   - Monitor: execve, openat, bind, chmod, ptrace, setuid, etc.
   - Some policies enforce SIGKILL on privilege escalation attempts

3. **Dashboard** - Flask web application
   - Two pages: Compliance and Runtime
   - Reads compliance results from `/var/tmp/results/results.json`
   - Reads runtime alerts from `/var/tmp/results/runtime_alerts.json`

4. **Tetragon Log Collector** - Sidecar container
   - Runs alongside dashboard in the same pod
   - Streams Tetragon logs via `kubectl logs`
   - Filters JSON events and writes to shared volume

### Data Flow

```
Tetragon Pods (tetragon namespace)
    ↓ (emit JSON events to stdout)
kubectl logs (collector sidecar)
    ↓ (filter & write)
/var/tmp/results/runtime_alerts.json (shared hostPath volume)
    ↓ (read)
Dashboard Flask App
    ↓ (serve via API)
Runtime Web UI
```

### API Endpoints

- `GET /runtime` - Runtime security page
- `GET /api/runtime/alerts` - Fetch all runtime alerts (last 1000)
- `GET /api/runtime/stats` - Get aggregated statistics

### Alert Severity Classification

- **Critical**: setuid, capset, sigkill events (privilege escalation)
- **High**: DOS attempts, bind operations
- **Medium**: execve, ptrace (process execution/debugging)
- **Low**: Other syscalls (openat, chmod, etc.)

### Deployment

The `job.yaml` deploys a pod with two containers:

1. **dashboard** - Main Flask application
2. **tetragon-collector** - Streams logs to shared volume

Both containers mount `/var/tmp/results` from the host.

### Event Types Monitored

From TracingPolicies in `Runtime/Tracepoints/`:

- `bind-detect.yaml` - Network binding attempts
- `dos-*-detect.yaml` - DOS attack patterns (accept, clone, connect, fd)
- `rt-execve.yaml` - Process execution
- `rt-openat.yaml` - File open operations
- `rt-chmod.yaml` - Permission changes
- `rt-chown.yaml` - Ownership changes
- `rt-ptrace.yaml` - Process debugging
- `rt-security-*.yaml` - Security subsystem hooks
- `rt-*-module.yaml` - Kernel module operations
- `rt-setns.yaml`, `rt-unshare.yaml` - Namespace operations
- `sigkill-policies.yaml` - Enforces SIGKILL on privilege escalation

### Features

- Real-time alert viewing with auto-refresh
- Filtering by severity, process name, event type
- Statistics dashboard showing top processes and event types
- Detailed JSON view of each alert
- Severity-based color coding

### Notes

- The collector uses `kubectl logs --follow` so it requires appropriate RBAC
- Alerts are stored as newline-delimited JSON (NDJSON)
- Only the last 1000 alerts are kept in memory for performance
- The dashboard reads the entire file on each request (suitable for moderate volumes)
