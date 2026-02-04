// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 BOANLab @ DKU

package config

import (
	kwlog "KubeWard/log"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the global runtime configuration for KubeWard.
type Config struct {
	CRISocket   string
	ProcFsMount string
}

// GlobalConfig is the singleton configuration instance used across all packages.
var GlobalConfig Config

// Configuration parameter names
const (
	ConfigCRISocket   string = "criSocket"
	ConfigProcFsMount string = "procfsMount"
)

// readCmdLineParams parses command-line flags and registers them with viper.
func readCmdLineParams() {
	criSocket := flag.String(ConfigCRISocket, "", "path to CRI socket (format: unix:///path/to/file.sock)")
	procFsMount := flag.String(ConfigProcFsMount, "/proc", "Path to the BPF filesystem to use for storing maps")

	flags := []string{}
	flag.VisitAll(func(f *flag.Flag) {
		kv := fmt.Sprintf("%s:%v", f.Name, f.Value)
		flags = append(flags, kv)
	})

	flag.Parse()

	viper.SetDefault(ConfigCRISocket, *criSocket)
	viper.SetDefault(ConfigProcFsMount, *procFsMount)
}

// LoadConfig loads configuration from CLI flags, environment variables, and auto-detection.
func LoadConfig() error {
	readCmdLineParams()
	viper.AutomaticEnv()

	GlobalConfig.CRISocket = os.Getenv("CRI_SOCKET")
	if GlobalConfig.CRISocket == "" {
		GlobalConfig.CRISocket = viper.GetString(ConfigCRISocket)
	}

	if GlobalConfig.CRISocket != "" && !strings.HasPrefix(GlobalConfig.CRISocket, "unix://") {
		return fmt.Errorf("CRI socket must start with 'unix://' (%s is invalid)", GlobalConfig.CRISocket)
	}

	if GlobalConfig.CRISocket == "" {
		detectedSocket := GetCRISocket()
		if detectedSocket != "" {
			GlobalConfig.CRISocket = detectedSocket
			kwlog.Printf("Auto-detected CRI_SOCKET: %s", GlobalConfig.CRISocket)
		} else {
			return fmt.Errorf("CRI socket not provided and auto-detection failed")
		}
	}

	GlobalConfig.ProcFsMount = viper.GetString(ConfigProcFsMount)

	kwlog.Printf("Final Configuration [%+v]", GlobalConfig)

	return nil
}

// ContainerRuntimeSocketMap maps container runtime names to their possible socket paths.
var ContainerRuntimeSocketMap = map[string][]string{
	"containerd": {
		"/var/snap/microk8s/common/run/containerd.sock",
		"/run/k3s/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
	},
}

// GetCRISocket auto-detects the CRI socket by checking well-known paths.
func GetCRISocket() string {
	for k := range ContainerRuntimeSocketMap {
		for _, candidate := range ContainerRuntimeSocketMap[k] {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	return ""
}
