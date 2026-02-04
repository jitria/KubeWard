// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 BOANLab @ DKU

package core

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	kwBPF "KubeWard/BPF"
	kwk8s "KubeWard/k8s"
	kwlog "KubeWard/log"
)

// GetOSSigChannel creates and returns a channel that receives OS termination signals.
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

const ()

// kubeWardHandlerType holds the global state for the KubeWard service.
type kubeWardHandlerType struct {
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// KubeWardH is the global KubeWard service handler instance.
var KubeWardH kubeWardHandlerType

// KubeWard initializes all components and runs the service until termination signal.
func KubeWard() {
	var err error
	sigChan := GetOSSigChannel()

	if err = makeKubeWardHandler(); err != nil {
		kwlog.Errf("fail to KubeWardHandler : %s", err)
		return
	}
	kwlog.Printf("KubeWardHandler: success make KubeWardHandler")

	kwk8s.InitK8sClient()
	kwlog.Printf("KubeWardH: success make k8sHandler")

	kwk8s.ContainerdH.NewContainerdHandler()
	kwlog.Printf("KubeWardHandler: success make containerdHandler")

	KubeWardH.wg.Add(1)
	go func() {
		defer KubeWardH.wg.Done()
		kwBPF.MonitorH.IniteBPF(KubeWardH.stopCh)
	}()
	kwlog.Printf("KubeWardHandler: success attach eBPF code for monitoring")

	time.Sleep(3 * time.Second)
	kwlog.Printf("KubeWardHandler: done sleeping")

	KubeWardH.wg.Add(1)
	go func() {
		defer KubeWardH.wg.Done()
		kwk8s.ContainerdH.MonitorContainerdEvents(KubeWardH.stopCh)
	}()
	kwlog.Printf("KubeWardHandler: success make containerdHandler")

	KubeWardH.wg.Add(1)
	go func() {
		defer KubeWardH.wg.Done()
		kwk8s.Crd(KubeWardH.stopCh)
	}()
	kwlog.Printf("KubeWardHandler: success apply crd")

	<-sigChan

	destroyKubeWard()
}

// makeKubeWardHandler initializes the stop channel and WaitGroup.
func makeKubeWardHandler() error {

	KubeWardH.stopCh = make(chan struct{})
	KubeWardH.wg = sync.WaitGroup{}

	return nil
}

// destroyKubeWard performs graceful shutdown of all goroutines.
func destroyKubeWard() {
	close(KubeWardH.stopCh)
	KubeWardH.wg.Wait()
	kwlog.Printf("KubeWardH: success clean")
}
