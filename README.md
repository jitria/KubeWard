# KubeWard

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.23-blue.svg)](https://golang.org/)
[![BPF](https://img.shields.io/badge/BPF-eBPF-green.svg)](https://ebpf.io/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.24+-326CE5.svg)](https://kubernetes.io/)
[![containerd](https://img.shields.io/badge/containerd-v1.7+-575757.svg)](https://containerd.io/)

KubeWard is an eBPF-based container activity analysis system that monitors system calls within containers using kprobe/kretprobe hooks to provide real-time visibility into container behavior for Kubernetes environments.

## Features

- **eBPF Syscall Monitoring**: Kernel-level syscall hooking via kprobe/kretprobe with minimal overhead
- **9 Syscall Categories**: File ops, network, process management, FD ops, memory, signals, timers, user/group, system info
- **Dynamic Probe Attachment**: Attach/detach probes at runtime via Kubernetes CRD
- **Container-Aware Filtering**: Only monitors containers registered in the eBPF container_map
- **Kubernetes Native**: Deployed as a privileged Pod with CRD-based configuration
- **Auto Container Discovery**: Polls containerd for container lifecycle events (create/delete)

## Deployment

### Prerequisites

- Kubernetes cluster (v1.24+)
- Linux kernel 5.15+ with eBPF and BTF support
- containerd as the container runtime

### Quick Start

```bash
kubectl apply -f deployments/kubeward.yaml
```

See the [Getting Started](getting-started/) guide for detailed instructions.

### Build from Source

```bash
make build
```

### Docker Build

```bash
make docker
```

## Development

### Prerequisites

- Go 1.23+
- Clang 14+ / LLVM 14+
- Linux headers (`linux-headers-$(uname -r)`)
- `bpftool`, `iproute2`

### Project Structure

```
KubeWard/
├── main.go                 # Entry point
├── core/                   # Core lifecycle orchestration
├── config/                 # Configuration management
├── types/                  # Shared type definitions
├── log/                    # Structured logging (zap)
├── BPF/                    # eBPF monitoring engine
│   ├── monitor.go          # Go-side event handler
│   └── cfile/
│       └── monitor.c       # eBPF C program (kprobe/kretprobe)
└── k8s/                    # Kubernetes integration
    ├── k8s.go              # API client initialization
    ├── crd.go              # CRD watcher
    └── containerd.go       # Container runtime integration
```

### Configuration

KubeWard can be configured via environment variables in the Deployment:

| Variable | Default | Description |
|----------|---------|-------------|
| `CRI_SOCKET` | Auto-detect | Path to containerd socket |
| `--procfsMount` | `/proc` | Path to the proc filesystem mount |

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**Copyright 2024 [BOANLab](https://boanlab.com) @ DKU**
