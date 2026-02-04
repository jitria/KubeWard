// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 BOANLab @ DKU

package k8s

import (
	"os"
	"path/filepath"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8sHandler holds the Kubernetes API client connections.
type K8sHandler struct {
	config    *rest.Config
	ClientSet *kubernetes.Clientset
	DynClient *dynamic.DynamicClient
}

// K8sH is the global Kubernetes handler instance.
var K8sH K8sHandler

// InitK8sClient initializes the Kubernetes client using in-cluster config or kubeconfig file.
func InitK8sClient() (*kubernetes.Clientset, error) {
	if err := initLocalAPIClient(); err != nil {
		return nil, err
	}

	return K8sH.ClientSet, nil
}

// initLocalAPIClient creates the REST config and initializes both ClientSet and DynClient.
func initLocalAPIClient() error {
	// Try in-cluster config first (when running inside a Pod)
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig file
		kubeconfig := os.Getenv("HOME") + "/.kube/config"
		if _, statErr := os.Stat(filepath.Clean(kubeconfig)); statErr != nil {
			return statErr
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return err
		}
	}

	K8sH.ClientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	K8sH.DynClient, err = dynamic.NewForConfig(config)
	if err != nil {
		return err
	}

	return nil
}
