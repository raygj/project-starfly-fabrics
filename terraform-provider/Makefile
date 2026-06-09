.PHONY: build test testacc testacc-live fmt lint install clean

PROVIDER_NAME := terraform-provider-starfly
BUILD_DIR := bin

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(PROVIDER_NAME)

install: build
	@mkdir -p ~/.terraform.d/plugins/registry.terraform.io/starfly-fabrics/starfly/0.1.0/darwin_arm64
	cp $(BUILD_DIR)/$(PROVIDER_NAME) ~/.terraform.d/plugins/registry.terraform.io/starfly-fabrics/starfly/0.1.0/darwin_arm64/$(PROVIDER_NAME)

test:
	go test ./...

testacc:
	TF_ACC=1 go test ./... -run TestAcc -timeout 30m -count=1

testacc-live:
	bash scripts/testacc.sh

fmt:
	go fmt ./...

lint:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR) .terraform
