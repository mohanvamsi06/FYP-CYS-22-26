# Runtime Tracepoints — Policy Documentation

Tetragon `TracingPolicy` resources for runtime security monitoring on Kubernetes.
Tested against Tetragon **1.6.0** on kernel **6.12**.

---

## Policy Types

Two hook mechanisms are used:

- **Tracepoint** (`spec.tracepoints`) — static hooks baked into the kernel at syscall boundaries (`sys_enter_*`). Stable across kernel versions.
- **Kprobe** (`spec.kprobes`) — dynamic hooks on internal kernel functions. More flexible but function names can vary by architecture. `syscall: false` means the target is an internal kernel function, not a syscall entrypoint.

---

## Active Policies

### DoS Detection

| File | Policy Name | Hook | Purpose |
|---|---|---|---|
| `bind-detect.yaml` | `bind-detect` | tracepoint `sys_enter_bind` | Detects socket bind calls — port binding activity |
| `dos-accept-detect.yaml` | `dos-accept-detect` | tracepoint `sys_enter_accept` | Detects incoming connection acceptance |
| `dos-clone-detect.yaml` | `dos-clone-detect` | tracepoint `sys_enter_clone` | Detects process/thread spawning — fork bomb indicator |
| `dos-connect-detect.yaml` | `dos-connect-detect` | tracepoint `sys_enter_connect` | Detects outbound connection attempts |
| `dos-fd-detect.yaml` | `dos-fd-detect` | kprobe `fd_install` | Detects file descriptor creation — covers all open/socket/pipe calls |

### File & Permission Monitoring

| File | Policy Name | Hook | Purpose |
|---|---|---|---|
| `rt-chmod.yaml` | `chmod-monitoring` | tracepoints `sys_enter_fchmodat` + `sys_enter_chmod` | Detects permission changes via both modern (`fchmodat`) and legacy (`chmod`) syscalls |
| `rt-chown.yaml` | `chown-monitoring` | tracepoints `sys_enter_fchownat` + `sys_enter_chown` | Detects ownership changes via both modern (`fchownat`) and legacy (`chown`) syscalls |
| `rt-security-file-open.yaml` | `rt-security-file-open-15` | kprobe `security_file_open` | Detects all file open operations at the LSM layer |
| `rt-security-inode-rename.yaml` | `rt-security-inode-rename-18` | kprobe `security_inode_rename` | Detects file/directory renames at the LSM layer |
| `rt-security-inode-unlink.yaml` | `rt-security-inode-unlink-19` | kprobe `security_inode_unlink` | Detects file deletions at the LSM layer |

### Process Execution

| File | Policy Name | Hook | Purpose |
|---|---|---|---|
| `rt-execve.yaml` | `rt-execve-01` | kprobe `__x64_sys_execve` | Detects all process executions |
| `rt-security-bprm-check.yaml` | `rt-security-bprm-check-16` | kprobe `security_bprm_check` | Detects binary execution checks at the LSM layer — fires before a binary runs |

### Network

| File | Policy Name | Hook | Purpose |
|---|---|---|---|
| `rt-security-socket-connect.yaml` | `rt-security-socket-connect-17` | kprobe `security_socket_connect` | Detects socket connection attempts at the LSM layer |

### Namespace & Container Escape

| File | Policy Name | Hook | Purpose |
|---|---|---|---|
| `rt-setns.yaml` | `rt-setns-11` | kprobe `__x64_sys_setns` | Detects namespace switching — container escape indicator |
| `rt-unshare.yaml` | `rt-unshare-05` | kprobe `__x64_sys_unshare` | Detects namespace unsharing — container escape indicator |

### Enforcement (not applied by default)

| File | Policy Name | Purpose |
|---|---|---|
| `sigkill-policies.yaml` | `enforce-priv-escape` | SIGKILLs processes attempting `setuid`, `capset`, `unshare`, or `mount` — active enforcement, not just detection |

