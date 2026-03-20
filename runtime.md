# Runtime Tracepoints — Policy Documentation

Tetragon `TracingPolicy` resources for runtime security monitoring on Kubernetes.
Tested against Tetragon **1.6.0** on kernel **6.12**.

---

## Policy Types

Two hook mechanisms are used:

- **Tracepoint** (`spec.tracepoints`) — static hooks baked into the kernel at syscall boundaries (`sys_enter_*`). Stable across kernel versions.
- **Kprobe** (`spec.kprobes`) — dynamic hooks on internal kernel functions. More flexible but function names can vary by architecture. `syscall: false` means the target is an internal kernel function, not a syscall entrypoint.

---

## Severity Levels

| Level | Meaning |
|---|---|
| **Critical** | Direct container escape, namespace manipulation, file deletion/rename at kernel level |
| **High** | DoS vectors, network abuse, binary execution gating, fd exhaustion |
| **Medium** | Process execution, permission/ownership changes, file open monitoring |
| **Low** | Everything else not matched above |

---

## Active Policies

### DoS Detection

| File | Policy Name | Hook | Severity | Purpose |
|---|---|---|---|---|
| `bind-detect.yaml` | `bind-detect` | tracepoint `sys_enter_bind` | High | Detects socket bind calls — port binding activity |
| `dos-accept-detect.yaml` | `dos-accept-detect` | tracepoint `sys_enter_accept` | High | Detects incoming connection acceptance |
| `dos-clone-detect.yaml` | `dos-clone-detect` | tracepoint `sys_enter_clone` | High | Detects process/thread spawning — fork bomb indicator |
| `dos-connect-detect.yaml` | `dos-connect-detect` | tracepoint `sys_enter_connect` | High | Detects outbound connection attempts |
| `dos-fd-detect.yaml` | `dos-fd-detect` | kprobe `fd_install` | High | Detects file descriptor creation — covers all open/socket/pipe calls |

### File & Permission Monitoring

| File | Policy Name | Hook | Severity | Purpose |
|---|---|---|---|---|
| `rt-chmod.yaml` | `chmod-monitoring` | tracepoints `sys_enter_fchmodat` + `sys_enter_chmod` | Medium | Detects permission changes via both modern (`fchmodat`) and legacy (`chmod`) syscalls |
| `rt-chown.yaml` | `chown-monitoring` | tracepoints `sys_enter_fchownat` + `sys_enter_chown` | Medium | Detects ownership changes via both modern (`fchownat`) and legacy (`chown`) syscalls |
| `rt-security-file-open.yaml` | `rt-security-file-open-15` | kprobe `security_file_open` | Medium | Detects all file open operations at the LSM layer |
| `rt-security-inode-rename.yaml` | `rt-security-inode-rename-18` | kprobe `security_inode_rename` | Critical | Detects file/directory renames at the LSM layer |
| `rt-security-inode-unlink.yaml` | `rt-security-inode-unlink-19` | kprobe `security_inode_unlink` | Critical | Detects file deletions at the LSM layer |

### Process Execution

| File | Policy Name | Hook | Severity | Purpose |
|---|---|---|---|---|
| `rt-execve.yaml` | `rt-execve-01` | kprobe `__x64_sys_execve` | Medium | Detects all process executions |
| `rt-security-bprm-check.yaml` | `rt-security-bprm-check-16` | kprobe `security_bprm_check` | High | Detects binary execution checks at the LSM layer — fires before a binary runs |

### Network

| File | Policy Name | Hook | Severity | Purpose |
|---|---|---|---|---|
| `rt-security-socket-connect.yaml` | `rt-security-socket-connect-17` | kprobe `security_socket_connect` | High | Detects socket connection attempts at the LSM layer |

### Namespace & Container Escape

| File | Policy Name | Hook | Severity | Purpose |
|---|---|---|---|---|
| `rt-setns.yaml` | `rt-setns-11` | kprobe `__x64_sys_setns` | Critical | Detects namespace switching — container escape indicator |
| `rt-unshare.yaml` | `rt-unshare-05` | kprobe `__x64_sys_unshare` | Critical | Detects namespace unsharing — container escape indicator |

### Enforcement (not applied by default)

| File | Policy Name | Severity | Purpose |
|---|---|---|---|
| `sigkill-policies.yaml` | `enforce-priv-escape` | Critical | SIGKILLs processes attempting `setuid`, `capset`, `unshare`, or `mount` — active enforcement, not just detection |

---

## Changes Made

The following changes were made to the original policy files to make them compatible with Tetragon 1.6.0:

### Fixed — Invalid `matchActions` placement
`matchActions` at the top-level kprobe was not valid. Moved inside `selectors[]` or removed entirely (bare kprobes without selectors post all events by default).

Affected: `rt-execve`, `rt-setns`, `rt-unshare`, `rt-security-bprm-check`, `rt-security-file-open`, `rt-security-inode-rename`, `rt-security-inode-unlink`, `rt-security-socket-connect`

### Fixed — Invalid type names
`unsigned long`, `long`, `unsigned int` are not valid Tetragon arg types. Replaced with `uint64`, `int64`, `uint32`.

Affected: `rt-bpf` (removed), `rt-ptrace` (removed), `rt-init-module` (removed)

### Fixed — Unsupported `"In"` operator
The `"In"` operator does not exist in Tetragon. Originally in `rt-delete-module` — file removed.

### Fixed — Architecture-specific syscall names
`execve`, `setns`, `unshare` as plain kprobe names did not fire on this kernel. Updated to use the architecture-prefixed internal syscall wrappers: `__x64_sys_execve`, `__x64_sys_setns`, `__x64_sys_unshare`.

### Fixed — Overly restrictive path selectors
`rt-chmod` and `rt-chown` originally only matched paths under `/tmp/`, `/dev/shm/`, `/etc/`, etc. Selectors removed so all chmod/chown activity is captured. Both now also cover the modern `fchmodat`/`fchownat` variants alongside the legacy syscalls.

### Removed — Duplicate policy
`rt-openat.yaml` was a duplicate of `rt-security-file-open.yaml` — both hooked `security_file_open`. The misnamed file was deleted.

### Removed — Non-firing policies
The following policies were removed as they could not be triggered in this environment:

- `rt-bpf.yaml` — `sys_enter_bpf` not triggered by normal cluster activity
- `rt-delete-module.yaml` — `sys_enter_delete_module` not triggered
- `rt-init-module.yaml` — `sys_enter_init_module` / `sys_enter_finit_module` not triggered
- `rt-ptrace.yaml` — `sys_enter_ptrace` not triggered by normal cluster activity

### Dashboard — Updated severity mapping
`Dashboard/app.py` severity classification updated to cover all active policy event/function names:
- **Critical**: `setns`, `unshare`, `security_inode_unlink`, `security_inode_rename`, `setuid`, `capset`, `mount`
- **High**: `clone`, `accept`, `connect`, `bind`, `security_socket_connect`, `fd_install`, `security_bprm_check`
- **Medium**: `execve`, `chmod`, `fchmodat`, `chown`, `fchownat`, `security_file_open`

### Dashboard — Included event types
`INCLUDED_EVENT_TYPES` default updated from `process_tracepoint` only to `process_tracepoint,process_kprobe` so kprobe-based policies (execve, setns, unshare, file_open, etc.) are visible in the dashboard.
