#!/bin/bash

NAMESPACE="default"

echo "=== Cleaning up audit-runner RBAC resources ==="

# ServiceAccount
for sa in audit-runner; do
    if kubectl get sa "$sa" -n "$NAMESPACE" >/dev/null 2>&1; then
        echo "Deleting ServiceAccount: $sa in namespace $NAMESPACE"
        kubectl delete sa "$sa" -n "$NAMESPACE"
    else
        echo "ServiceAccount $sa not found"
    fi
done

# ClusterRoles
for cr in audit-runner-impersonate; do
    if kubectl get clusterrole "$cr" >/dev/null 2>&1; then
        echo "Deleting ClusterRole: $cr"
        kubectl delete clusterrole "$cr"
    else
        echo "ClusterRole $cr not found"
    fi
done

# ClusterRoleBindings
for crb in audit-runner-binding audit-runner-impersonate-binding; do
    if kubectl get clusterrolebinding "$crb" >/dev/null 2>&1; then
        echo "Deleting ClusterRoleBinding: $crb"
        kubectl delete clusterrolebinding "$crb"
    else
        echo "ClusterRoleBinding $crb not found"
    fi
done

echo "=== Cleanup completed successfully ==="
