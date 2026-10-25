GO ?= go
UPX ?= upx
REGISTRY ?= nexus.thepratts.info/pratt-registry
IMAGE ?= pratt/mymail
IMAGE_TAG := $(REGISTRY)/$(IMAGE)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf 'devel')
BUILT_ON ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
MYMAIL_TEST_SENDER ?= test-sender@example.test
MYMAIL_TEST_USERNAME ?= test-user
MYMAIL_TEST_ADDRESS ?= test-user@mail.example.test
DIST_DIR ?= dist

BINARIES := mymail mymail-send mymail-password
UPX_FLAGS ?= --best --lzma

.PHONY: all build image push compress windows mac raspberry-pi risc-v test vet fmt clean

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

windows:
	@mkdir -p $(DIST_DIR)/windows
	GOWORK=off GOOS=windows GOARCH=amd64 $(GO) build -ldflags "-X main.version=$(VERSION) -X main.builtOn=$(BUILT_ON)" -o $(DIST_DIR)/windows/mymail.exe ./cmd/mymail
	GOWORK=off GOOS=windows GOARCH=amd64 $(GO) build -o $(DIST_DIR)/windows/mymail-send.exe ./cmd/mymail-send
	GOWORK=off GOOS=windows GOARCH=amd64 $(GO) build -o $(DIST_DIR)/windows/mymail-password.exe ./cmd/mymail-password

mac:
	@mkdir -p $(DIST_DIR)/mac
	GOWORK=off GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "-X main.version=$(VERSION) -X main.builtOn=$(BUILT_ON)" -o $(DIST_DIR)/mac/mymail ./cmd/mymail
	GOWORK=off GOOS=darwin GOARCH=amd64 $(GO) build -o $(DIST_DIR)/mac/mymail-send ./cmd/mymail-send
	GOWORK=off GOOS=darwin GOARCH=amd64 $(GO) build -o $(DIST_DIR)/mac/mymail-password ./cmd/mymail-password

raspberry-pi:
	@mkdir -p $(DIST_DIR)/raspberry-pi
	GOWORK=off GOOS=linux GOARCH=arm GOARM=7 $(GO) build -ldflags "-X main.version=$(VERSION) -X main.builtOn=$(BUILT_ON)" -o $(DIST_DIR)/raspberry-pi/mymail ./cmd/mymail
	GOWORK=off GOOS=linux GOARCH=arm GOARM=7 $(GO) build -o $(DIST_DIR)/raspberry-pi/mymail-send ./cmd/mymail-send
	GOWORK=off GOOS=linux GOARCH=arm GOARM=7 $(GO) build -o $(DIST_DIR)/raspberry-pi/mymail-password ./cmd/mymail-password

risc-v:
	@mkdir -p $(DIST_DIR)/risc-v
	GOWORK=off GOOS=linux GOARCH=riscv64 $(GO) build -ldflags "-X main.version=$(VERSION) -X main.builtOn=$(BUILT_ON)" -o $(DIST_DIR)/risc-v/mymail ./cmd/mymail
	GOWORK=off GOOS=linux GOARCH=riscv64 $(GO) build -o $(DIST_DIR)/risc-v/mymail-send ./cmd/mymail-send
	GOWORK=off GOOS=linux GOARCH=riscv64 $(GO) build -o $(DIST_DIR)/risc-v/mymail-password ./cmd/mymail-password

compress: build
	@command -v $(UPX) >/dev/null 2>&1 || { echo "error: $(UPX) is required for compression" >&2; exit 1; }
	$(UPX) $(UPX_FLAGS) $(BINARIES)

test:
	MYMAIL_TEST_SENDER="$(MYMAIL_TEST_SENDER)" MYMAIL_TEST_USERNAME="$(MYMAIL_TEST_USERNAME)" MYMAIL_TEST_ADDRESS="$(MYMAIL_TEST_ADDRESS)" GOWORK=off $(GO) test -race ./...

vet:
	GOWORK=off $(GO) vet ./...

fmt:
	GOWORK=off $(GO) fmt ./...

clean:
	rm -f $(BINARIES)
	rm -rf $(DIST_DIR)