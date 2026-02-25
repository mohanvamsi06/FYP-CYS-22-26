# Dashboard Access Guide

## Architecture Changes

The dashboard has been converted from a Job to a Deployment + Service for continuous operation.

## What Changed

### Before (Job)
- Ran once and completed
- No network access
- Had to be manually restarted

### After (Deployment + Service)
- Runs continuously
- Exposed via NodePort on port 30500
- Auto-restarts on failure
- Includes Tetragon log collector sidecar

## Accessing the Dashboard

### 1. Get your node IP

```bash
kubectl get nodes -o wide
```

Look for the INTERNAL-IP or EXTERNAL-IP column.

### 2. Access the dashboard

```
http://<node-ip>:30500
```

### Pages Available

- **Compliance**: `http://<node-ip>:30500/compliance`
  - View CIS Kubernetes benchmark results
  - Run compliance scans on-demand
  
- **Runtime Security**: `http://<node-ip>:30500/runtime`
  - View Tetragon runtime alerts
  - Filter by severity, process, event type
  - Auto-refresh capability

## Deployment Details

### Resources Created

1. **ServiceAccount**: `audit-runner` (with cluster-admin access)
2. **Deployment**: `k8s-security-dashboard` (1 replica)
3. **Service**: `k8s-security-dashboard` (NodePort 30500)

### Containers in Pod

1. **dashboard** - Flask web application
   - Port: 5000
   - Image: mohanvamsi06/fyp:v0.0.1
   - Mounts: /output → /var/tmp/results (hostPath)

2. **tetragon-collector** - Log collector sidecar
   - Streams Tetragon logs via kubectl
   - Writes to: /output/runtime_alerts.json
   - Waits for Tetragon pods to be ready

## Useful Commands

### Check dashboard status
```bash
kubectl get deployment k8s-security-dashboard -n default
kubectl get pods -l app=k8s-security-dashboard -n default
```

### View dashboard logs
```bash
# Dashboard container
kubectl logs -l app=k8s-security-dashboard -c dashboard -n default

# Tetragon collector container
kubectl logs -l app=k8s-security-dashboard -c tetragon-collector -n default
```

### Check service
```bash
kubectl get service k8s-security-dashboard -n default
```

### Port forward (alternative access method)
```bash
kubectl port-forward deployment/k8s-security-dashboard 5000:5000 -n default
```
Then access at: `http://localhost:5000`

### Restart dashboard
```bash
kubectl rollout restart deployment/k8s-security-dashboard -n default
```

### Check shared volume
```bash
# SSH to control plane node
ls -lh /var/tmp/results/
cat /var/tmp/results/runtime_alerts.json | head -n 5
```

## Troubleshooting

### Dashboard pod not starting
```bash
kubectl describe pod -l app=k8s-security-dashboard -n default
```

### No runtime alerts showing
1. Check Tetragon is running: `kubectl get pods -n tetragon`
2. Check collector logs: `kubectl logs -l app=k8s-security-dashboard -c tetragon-collector`
3. Verify file exists: Check `/var/tmp/results/runtime_alerts.json` on control plane node

### Compliance scan not working
1. Ensure compliance job YAML is available in container
2. Check RBAC permissions for audit-runner ServiceAccount
3. View job status: `kubectl get job cis-k8s-audit -n default`

### Cannot access via NodePort
1. Check firewall rules allow port 30500
2. Verify service: `kubectl get svc k8s-security-dashboard -n default`
3. Try port-forward as alternative
4. Check if using hostNetwork: true (dashboard uses host networking)

## Security Notes

- Dashboard runs with cluster-admin privileges (required for compliance scanning)
- Uses hostPID and hostNetwork for access to node resources
- Scheduled on control plane node only (nodeSelector)
- Tolerates control plane taints

## Updating the Dashboard

After making changes to Dashboard code:

1. Build new image: `docker build -t mohanvamsi06/fyp:v0.0.2 Dashboard/`
2. Push: `docker push mohanvamsi06/fyp:v0.0.2`
3. Update image in job.yaml
4. Apply: `kubectl apply -f job.yaml`
5. Restart: `kubectl rollout restart deployment/k8s-security-dashboard`
