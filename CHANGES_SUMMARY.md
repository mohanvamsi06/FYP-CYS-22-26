# Runtime Security Dashboard - Changes Summary

## Overview

Added a new Runtime Security page to the dashboard that displays real-time alerts from Tetragon, similar to how the Compliance page displays CIS benchmark results.

## Changes Made

### 1. Dashboard Backend (`Dashboard/app.py`)

Added:
- `RUNTIME_LOGS_PATH` constant pointing to `/var/tmp/results/runtime_alerts.json`
- `/runtime` route serving the runtime security page
- `/api/runtime/alerts` endpoint returning parsed Tetragon events
- `/api/runtime/stats` endpoint providing aggregated statistics:
  - Total alerts count
  - Breakdown by event type (top 10)
  - Breakdown by process (top 10)
  - Breakdown by severity (critical/high/medium/low)

### 2. Runtime Security Page (`Dashboard/templates/runtime.html`)

New template featuring:
- Summary cards showing total alerts and counts by severity
- Top event types and processes panels
- Recent alerts list with:
  - Severity-based color coding
  - Timestamp display
  - Process and event type information
  - Expandable JSON details
- Filtering capabilities:
  - Text search (process name, event type)
  - Severity filter dropdown
- Auto-refresh toggle (5-second interval)
- Manual refresh button

### 3. Base Template Updates (`Dashboard/templates/base.html`)

- Added "Runtime" navigation link
- Updated page title to "K8s Security Dashboard"
- Added JavaScript to:
  - Highlight active navigation based on current path
  - Update page title dynamically per page

### 4. Job Configuration (`job.yaml`)

Added sidecar container `tetragon-collector`:
- Uses `bitnami/kubectl:latest` image
- Streams Tetragon logs via `kubectl logs -n tetragon --follow`
- Filters JSON events (lines starting with `{`)
- Writes to `/output/runtime_alerts.json` on shared volume
- Shares the same hostPath volume as dashboard container

### 5. Supporting Files

Created:
- `Dashboard/collect_tetragon_logs.sh` - Standalone script version of log collector
- `Dashboard/RUNTIME_INTEGRATION.md` - Comprehensive architecture documentation

## How It Works Together

1. **Tetragon** monitors runtime security events via TracingPolicies deployed by `start.sh`
2. **Collector sidecar** streams Tetragon pod logs and writes JSON events to shared volume
3. **Dashboard** reads the JSON file and serves it via REST API
4. **Runtime UI** fetches data, classifies severity, and displays alerts with filtering

## Severity Classification Logic

- **Critical**: setuid, capset, sigkill (privilege escalation attempts)
- **High**: DOS patterns, bind operations (network threats)
- **Medium**: execve, ptrace (process execution/debugging)
- **Low**: Other syscalls (file operations, etc.)

## Event Types Monitored

Based on TracingPolicies in `Runtime/Tracepoints/`:
- Process execution (execve)
- File operations (openat, chmod, chown)
- Network operations (bind, connect, accept)
- Security operations (ptrace, setuid, capset)
- Namespace operations (setns, unshare)
- Kernel module operations (init_module, delete_module)
- DOS detection patterns

## Deployment Notes

- Both containers run in the same pod with shared volume
- Requires RBAC permissions for kubectl to read Tetragon logs
- Uses existing `audit-runner` ServiceAccount with cluster-admin role
- Logs are stored as newline-delimited JSON (NDJSON)
- Dashboard limits display to last 1000 alerts for performance

## Testing Recommendations

1. Deploy with updated `job.yaml`
2. Verify Tetragon is running: `kubectl get pods -n tetragon`
3. Check collector is writing logs: `ls -lh /var/tmp/results/runtime_alerts.json`
4. Access dashboard and navigate to Runtime page
5. Trigger some events (exec into pods, create files, etc.)
6. Verify alerts appear in the UI

## Future Enhancements

- Persistent storage for historical alerts
- Alert aggregation and deduplication
- Custom alert rules and notifications
- Integration with external SIEM systems
- Performance optimization for high-volume environments
