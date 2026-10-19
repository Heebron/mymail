GO ?= go
UPX ?= upx
REGISTRY ?= nexus.thepratts.info/pratt-registry
IMAGE ?= pratt/mymail
IMAGE_TAG := $(REGISTRY)/$(IMAGE)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf 'devel')
BUILT_ON ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

BINARIES := mymail mymail-send mymail-password
UPX_FLAGS ?= --best --lzma

.PHONY: all build image push compress test vet fmt clean

all: build

build: $(BINARIES)

image:
	docker build --build-arg VERSION="$(VERSION)" --build-arg BUILT_ON="$(BUILT_ON)" --tag $(IMAGE_TAG) .

push: image
	docker push $(IMAGE_TAG)

mymail:
	GOWORK=off $(GO) build -ldflags "-X main.version=$(VERSION) -X main.builtOn=$(BUILT_ON)" -o $@ ./cmd/mymail

mymail-send:
	GOWORK=off $(GO) build -o $@ ./cmd/mymail-send

mymail-password:
	GOWORK=off $(GO) build -o $@ ./cmd/mymail-password

compress: build
	@command -v $(UPX) >/dev/null 2>&1 || { echo "error: $(UPX) is required for compression" >&2; exit 1; }
	$(UPX) $(UPX_FLAGS) $(BINARIES)

test:
	GOWORK=off $(GO) test -race ./...

vet:
	GOWORK=off $(GO) vet ./...

fmt:
	GOWORK=off $(GO) fmt ./...

clean:
	rm -f $(BINARIES)