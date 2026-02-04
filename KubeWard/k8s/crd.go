// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 BOANLab @ DKU

package k8s

import (
	kwBPF "KubeWard/BPF"
	kwtypes "KubeWard/types"

	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// Crd starts a shared informer that watches KubeWard CRD instances and dynamically attaches/detaches eBPF probes.
func Crd(stopCh chan struct{}) {
	dynClient := K8sH.DynClient

	gvr := schema.GroupVersionResource{
		Group:    "kubeward.kubeward",
		Version:  "v1",
		Resource: "kubewards",
	}

	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return dynClient.Resource(gvr).Namespace("").List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return dynClient.Resource(gvr).Namespace("").Watch(context.TODO(), options)
		},
	}

	informer := cache.NewSharedInformer(
		lw,
		&unstructured.Unstructured{},
		0,
	)

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			u := obj.(*unstructured.Unstructured)
			updateAttach(u)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			u := newObj.(*unstructured.Unstructured)
			updateAttach(u)
		},
		DeleteFunc: func(obj interface{}) {
			u := obj.(*unstructured.Unstructured)
			deleteAttach(u)
		},
	})

	go informer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, informer.HasSynced) {
		fmt.Println("Timed out waiting for caches to sync")
		return
	}

	<-stopCh
}

// updateAttach parses the CRD spec and attaches the specified kprobe/kretprobe hooks.
func updateAttach(u *unstructured.Unstructured) {
	spec, found, err := unstructured.NestedMap(u.Object, "spec")
	if err != nil || !found {
		fmt.Printf("Failed to find spec: %v\n", err)
		return
	}

	var myResourceSpec kwtypes.MyResourceSpec
	specData, err := json.Marshal(spec)
	if err != nil {
		fmt.Printf("Failed to marshal spec to JSON: %v\n", err)
		return
	}

	err = json.Unmarshal(specData, &myResourceSpec)
	if err != nil {
		fmt.Printf("Failed to unmarshal spec to struct: %v\n", err)
		return
	}

	kwBPF.MonitorH.AttacheBPFProgram(myResourceSpec)
}

// deleteAttach detaches all currently attached eBPF probes when the CRD is deleted.
func deleteAttach(u *unstructured.Unstructured) {
	kwBPF.MonitorH.DetacheBPFProgram()
}
