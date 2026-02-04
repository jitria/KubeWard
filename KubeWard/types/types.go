// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 BOANLab @ DKU

package types

// Container holds metadata about a monitored container.
type Container struct {
	ContainerID    string `json:"containerID"`
	ContainerName  string `json:"containerName"`
	ContainerImage string `json:"containerImage"`

	NamespaceName string            `json:"namespaceName"`
	EndPointName  string            `json:"endPointName"`
	Labels        map[string]string `json:"labels"`

	NsKey  NsKey  `json:"nskey"`
	Status string `json:"status,omitempty"`
}

// NsKey represents a unique Linux namespace identifier using PID and MNT namespace IDs.
type NsKey struct {
	PidNs uint32
	MntNs uint32
}

// Kprobe defines a kprobe hook specification from the KubeWard CRD.
type Kprobe struct {
	Name string `json:"name,omitempty"`
}

// Kretprobe defines a kretprobe hook specification from the KubeWard CRD.
type Kretprobe struct {
	Name string `json:"name,omitempty"`
}

// MyResourceSpec represents the spec field of a KubeWard CRD instance.
type MyResourceSpec struct {
	Kprobe    []Kprobe    `json:"kprobe,omitempty"`
	Kretprobe []Kretprobe `json:"kretprobe,omitempty"`
}
