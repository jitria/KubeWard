// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 BOANLab @ DKU

package main

import (
	kwcfg "KubeWard/config"
	"KubeWard/core"
	kwlog "KubeWard/log"
)

func main() {
	if err := kwcfg.LoadConfig(); err != nil {
		kwlog.Errf("Failed to load config: %v", err)
		return
	}

	core.KubeWard()
}
