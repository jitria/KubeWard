.PHONY: all generate build docker clean deploy undeploy

MODULE_DIR := KubeWard
PROG_NAME := KubeWard
IMAGE_NAME := boanlab/kubeward
TAG := v1.0

all: generate build

## eBPF code generation
generate:
	cd $(MODULE_DIR) && go generate ./BPF/...

## Build binary
build:
	cd $(MODULE_DIR) && go build -o ../bin/$(PROG_NAME) .

## Docker image
docker:
	docker build -t $(IMAGE_NAME):$(TAG) -f deployments/Dockerfile .

## Deploy to Kubernetes
deploy:
	kubectl apply -f deployments/kubeward.yaml

## Undeploy from Kubernetes
undeploy:
	kubectl delete -f deployments/kubeward.yaml

## Cleanup
clean:
	rm -rf bin/
	cd $(MODULE_DIR) && go clean
	docker rmi $(IMAGE_NAME):$(TAG) 2>/dev/null || true
