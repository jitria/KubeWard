// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 BOANLab @ DKU

package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/containerd/containerd/api/services/containers/v1"
	pt "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/typeurl/v2"
	"google.golang.org/grpc"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	kwBPF "KubeWard/BPF"
	kwconfig "KubeWard/config"
	kwlog "KubeWard/log"
	kwtypes "KubeWard/types"
)

// ContainerdHandler manages the gRPC connection to containerd and tracks active containers.
type ContainerdHandler struct {
	conn       *grpc.ClientConn
	client     pb.ContainersClient
	taskClient pt.TasksClient

	containerdCtx context.Context
	dockerCtx     context.Context

	Containers     map[string]kwtypes.Container
	ContainersLock *sync.RWMutex

	Wg sync.WaitGroup
}

// ContainerdH is the global ContainerdHandler instance.
var ContainerdH *ContainerdHandler

const (
	DEFAULT_MAX_RECV_SIZE = 16 << 20
)

// init registers OCI runtime-spec type URLs for containerd API communication.
func init() {
	const prefix = "types.containerd.io"
	major := strconv.Itoa(specs.VersionMajor)

	typeurl.Register(&specs.Spec{}, prefix, "opencontainers/runtime-spec", major, "Spec")
	typeurl.Register(&specs.Process{}, prefix, "opencontainers/runtime-spec", major, "Process")
}

// NewContainerdHandler initializes the ContainerdHandler by establishing a gRPC connection.
func (ch *ContainerdHandler) NewContainerdHandler() {
	var err error
	ContainerdH = &ContainerdHandler{}

	dialTarget := kwconfig.GlobalConfig.CRISocket
	if !strings.HasPrefix(dialTarget, "unix://") {
		dialTarget = "unix://" + dialTarget
	}
	ContainerdH.conn, err = grpc.Dial(dialTarget, grpc.WithInsecure())
	if err != nil {
		kwlog.Errf("ContainerdHandler: failed to connect to CRI socket: %v", err)
	}

	ContainerdH.client = pb.NewContainersClient(ContainerdH.conn)
	ContainerdH.taskClient = pt.NewTasksClient(ContainerdH.conn)

	ContainerdH.containerdCtx = namespaces.WithNamespace(context.Background(), "k8s.io")
	ContainerdH.dockerCtx = namespaces.WithNamespace(context.Background(), "moby")

	ContainerdH.Containers = make(map[string]kwtypes.Container)
	ContainerdH.ContainersLock = &sync.RWMutex{}

	kwlog.Print("ContainerdHandler: initialized Containerd Handler")
}

// close shuts down the gRPC connection to containerd.
func (ch *ContainerdHandler) close() error {
	if ch.conn != nil {
		err := ch.conn.Close()
		if err != nil {
			kwlog.Errf("ContainerdHandler: failed to close gRPC connection: %v", err)
			return err
		}
	}
	return nil
}

// getContainerInfo retrieves metadata about a container from containerd.
func (ch *ContainerdHandler) getContainerInfo(ctx context.Context, containerID string) (kwtypes.Container, error) {
	req := pb.GetContainerRequest{ID: containerID}
	res, err := ch.client.Get(ctx, &req)
	if err != nil {
		kwlog.Errf("ContainerdHandler: failed to get container %s: %v", containerID, err)
		return kwtypes.Container{}, err
	}

	container := kwtypes.Container{
		ContainerID:   res.Container.ID,
		ContainerName: res.Container.ID,
		NamespaceName: "Unknown",
		EndPointName:  "Unknown",
		Labels:        res.Container.Labels,
	}

	if val, ok := container.Labels["io.kubernetes.container.name"]; ok {
		container.ContainerName = val
	}

	if val, ok := container.Labels["io.kubernetes.container.image"]; ok {
		container.ContainerImage = val
	}

	if _, ok := container.Labels["io.kubernetes.pod.namespace"]; ok {
		if val, ok := container.Labels["io.kubernetes.pod.namespace"]; ok {
			container.NamespaceName = val
		}
		if val, ok := container.Labels["io.kubernetes.pod.name"]; ok {
			container.EndPointName = val
		}
	} else if val, ok := container.Labels["kubearmor.io/namespace"]; ok {
		container.NamespaceName = val
	} else {
		container.NamespaceName = "container_namespace"
	}

	// Resolve PID and MNT namespace IDs
	taskReq := pt.ListPidsRequest{ContainerID: container.ContainerID}
	if taskRes, err := ch.taskClient.ListPids(ctx, &taskReq); err == nil {
		if len(taskRes.Processes) == 0 {
			kwlog.Warnf("ContainerdHandler: no processes found for container %s", containerID)
			return container, nil
		}

		pid := strconv.Itoa(int(taskRes.Processes[0].Pid))

		if data, err := os.Readlink(filepath.Join(kwconfig.GlobalConfig.ProcFsMount, pid, "/ns/pid")); err == nil {
			if _, err := fmt.Sscanf(data, "pid:[%d]\n", &container.NsKey.PidNs); err != nil {
				kwlog.Warnf("ContainerdHandler: unable to get PidNS (%s, %s, %s)", containerID, pid, err.Error())
			}
		}

		if data, err := os.Readlink(filepath.Join(kwconfig.GlobalConfig.ProcFsMount, pid, "/ns/mnt")); err == nil {
			if _, err := fmt.Sscanf(data, "mnt:[%d]\n", &container.NsKey.MntNs); err != nil {
				kwlog.Warnf("ContainerdHandler: unable to get MntNS (%s, %s, %s)", containerID, pid, err.Error())
			}
		}
	}

	return container, nil
}

// GetContainerdContainers lists all containers from both Docker and Containerd namespaces.
func (ch *ContainerdHandler) GetContainerdContainers() map[string]context.Context {
	var err error
	var containerList *pb.ListContainersResponse
	containers := make(map[string]context.Context)

	req := pb.ListContainersRequest{}

	if containerList, err = ch.client.List(ch.dockerCtx, &req, grpc.MaxCallRecvMsgSize(DEFAULT_MAX_RECV_SIZE)); err == nil {
		for _, container := range containerList.Containers {
			containers[container.ID] = ch.dockerCtx
		}
	}

	if containerList, err = ch.client.List(ch.containerdCtx, &req, grpc.MaxCallRecvMsgSize(DEFAULT_MAX_RECV_SIZE)); err == nil {
		for _, container := range containerList.Containers {
			containers[container.ID] = ch.containerdCtx
		}
	}

	return containers
}

// GetNewContainerdContainers returns only newly discovered containers.
func (ch *ContainerdHandler) GetNewContainerdContainers(currentContainers map[string]context.Context) map[string]context.Context {
	newContainers := make(map[string]context.Context)

	for containerID, ctx := range currentContainers {
		if _, exists := ch.Containers[containerID]; !exists {
			newContainers[containerID] = ctx
		}
	}

	return newContainers
}

// GetDeletedContainerdContainers returns IDs of containers that have been removed from containerd.
func (ch *ContainerdHandler) GetDeletedContainerdContainers(currentContainers map[string]context.Context) []string {
	var deletedIDs []string

	for existingID := range ch.Containers {
		if _, exists := currentContainers[existingID]; !exists {
			deletedIDs = append(deletedIDs, existingID)
		}
	}

	return deletedIDs
}

// updateContainerdContainer dispatches container lifecycle actions.
func (ch *ContainerdHandler) updateContainerdContainer(ctx context.Context, containerID, action string) bool {
	switch action {
	case "start":
		return ch.handleContainerStart(ctx, containerID)
	case "destroy":
		return ch.handleContainerDestroy(containerID)
	default:
		kwlog.Warnf("ContainerdHandler: unknown action %s for container %s", action, containerID)
		return false
	}
}

// handleContainerStart adds a new container to the tracking map.
func (ch *ContainerdHandler) handleContainerStart(ctx context.Context, containerID string) bool {
	container, err := ch.getContainerInfo(ctx, containerID)
	if err != nil {
		return false
	}

	if container.ContainerID == "" {
		return false
	}

	ch.ContainersLock.Lock()
	defer ch.ContainersLock.Unlock()

	existingContainer, exists := ch.Containers[container.ContainerID]
	if !exists {
		ch.Containers[container.ContainerID] = container
	} else if existingContainer.NsKey.PidNs == 0 && existingContainer.NsKey.MntNs == 0 {
		existingContainer.NsKey = container.NsKey
		ch.Containers[container.ContainerID] = existingContainer
	} else {
		return false
	}

	return true
}

// handleContainerDestroy removes a container from the tracking map.
func (ch *ContainerdHandler) handleContainerDestroy(containerID string) bool {
	ch.ContainersLock.Lock()
	_, exists := ch.Containers[containerID]
	if !exists {
		ch.ContainersLock.Unlock()
		return false
	}
	delete(ch.Containers, containerID)
	ch.ContainersLock.Unlock()

	return true
}

// MonitorContainerdEvents continuously polls containerd for container lifecycle changes.
func (ch *ContainerdHandler) MonitorContainerdEvents(stopCh chan struct{}) {
	ch.Wg.Add(1)
	defer ch.Wg.Done()

	kwlog.Print("ContainerdHandler: started monitoring Containerd events")

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			ch.close()
			kwlog.Print("ContainerdHandler: done clean")
			return

		case <-ticker.C:
			containers := ch.GetContainerdContainers()

			newContainers := ch.GetNewContainerdContainers(containers)
			deletedIDs := ch.GetDeletedContainerdContainers(containers)

			if len(newContainers) > 0 {
				for containerID, ctx := range newContainers {
					if !ch.updateContainerdContainer(ctx, containerID, "start") {
						kwlog.Warnf("ContainerdHandler: failed to start container %s", containerID)
						continue
					}

					container, err := ch.getContainerInfo(ctx, containerID)
					if err != nil {
						kwlog.Warnf("ContainerdHandler: failed to get container info for %s: %v", containerID, err)
						continue
					}

					nskey := kwtypes.NsKey{
						PidNs: container.NsKey.PidNs,
						MntNs: container.NsKey.MntNs,
					}

					kwBPF.AddNsToContainer(nskey, container)
					kwlog.Printf("ContainerdHandler: added container %s with NsKey %+v", containerID, nskey)
				}
			}

			if len(deletedIDs) > 0 {
				for _, containerID := range deletedIDs {
					ch.ContainersLock.RLock()
					container, exists := ch.Containers[containerID]
					ch.ContainersLock.RUnlock()

					if exists {
						nskey := kwtypes.NsKey{
							PidNs: container.NsKey.PidNs,
							MntNs: container.NsKey.MntNs,
						}

						kwBPF.DeleteNsToContainer(nskey)
						kwlog.Printf("ContainerdHandler: removed container %s with NsKey %+v from containerMap", containerID, nskey)
					}

					if !ch.updateContainerdContainer(context.TODO(), containerID, "destroy") {
						kwlog.Warnf("ContainerdHandler: failed to destroy container %s", containerID)
						continue
					}
				}
			}
		}
	}
}
