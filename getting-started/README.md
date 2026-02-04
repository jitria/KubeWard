# Getting Started with KubeWard

This guide walks you through deploying KubeWard in your Kubernetes cluster.

## Prerequisites

Before you begin, ensure you have:

- A Kubernetes cluster (v1.24+)
- `kubectl` configured to access your cluster
- Nodes with Linux kernel 5.15+ and eBPF/BTF support
- containerd as the container runtime

## Quick Start

### 1. Deploy KubeWard

```bash
kubectl apply -f ../deployments/kubeward.yaml
```

### 2. Verify Deployment

```bash
# Check if KubeWard pod is running
kubectl get pods -n kubeward

# Check logs
kubectl logs -n kubeward -l app=kubeward
```

### 3. Apply a Monitoring Policy

Create a KubeWard CRD to attach kprobe/kretprobe hooks:

```yaml
apiVersion: kubeward.kubeward/v1
kind: KubeWard
metadata:
  name: monitor-policy
spec:
  kprobe:
    - name: "sys_openat"
    - name: "sys_connect"
    - name: "sys_execve"
  kretprobe:
    - name: "sys_openat"
    - name: "sys_connect"
```

```bash
kubectl apply -f monitor-policy.yaml
```

### 4. Deploy a Test Pod

```bash
kubectl run ubuntu-test --image=ubuntu -- sleep 3600
```

### 5. View Syscall Events

```bash
kubectl logs -f -n kubeward deployment/kubeward
```

## Configuration

KubeWard can be configured via environment variables in the Deployment:

```yaml
env:
- name: CRI_SOCKET
  value: "unix:///run/containerd/containerd.sock"
```

## Troubleshooting

### Pod not starting

Check if the node has required capabilities:
```bash
kubectl describe pod -n kubeward <pod-name>
```

### No events collected

1. Verify the KubeWard CRD is applied
2. Check if containers are discovered by containerd handler
3. Review KubeWard logs for errors

## Next Steps

- Configure additional syscall hooks via CRD
- Monitor specific namespaces or pods
- Analyze syscall patterns for security insights
