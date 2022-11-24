OS ?= $(shell go env GOOS)
ARCH ?= $(shell go env GOARCH)

IMAGE_NAME := "andersmic/cert-manager-webhook-dnsservices"
IMAGE_TAG := "0.1.0"

OUT := $(shell pwd)/_out

KUBE_VERSION=1.21.2


$(shell mkdir -p "$(OUT)")
export TEST_ASSET_ETCD=_out/kubebuilder/bin/etcd
export TEST_ASSET_KUBE_APISERVER=_out/kubebuilder/bin/kube-apiserver
export TEST_ASSET_KUBECTL=_out/kubebuilder/bin/kubectl

.DEFAULT_GOAL := build

test: _out/kubebuilder
	go test -v .

_out/kubebuilder:
	curl -fsSL https://go.kubebuilder.io/test-tools/$(KUBE_VERSION)/$(OS)/$(ARCH) -o kubebuilder-tools.tar.gz
	mkdir -p _out/kubebuilder
	tar -xvf kubebuilder-tools.tar.gz
	mv kubebuilder/bin _out/kubebuilder/
	rm kubebuilder-tools.tar.gz
	rm -R kubebuilder

clean: clean-kubebuilder

clean-kubebuilder:
	rm -Rf _out/kubebuilder

build:
	docker build --rm -t "${IMAGE_NAME}:${IMAGE_TAG}" -t "${IMAGE_NAME}:latest" .

release: build
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: rendered-manifest.yaml

rendered-manifest.yaml:
	helm template \
			--set image.repository=$(IMAGE_NAME) \
			--set image.tag=$(IMAGE_TAG) \
			deploy/example-webhook > "$(OUT)/rendered-manifest.yaml"
