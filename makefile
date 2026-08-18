.PHONY: help build test clean fmt lint build-all

# Variables
BINARY_NAME=keychain-auth
VERSION?=3.2.3
BUILD_DIR=bin
GO=go
GOFMT=gofmt

help:
	@echo "keychain-auth - Build Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build the binary for current OS"
	@echo "  test        Run all tests"
	@echo "  clean       Remove build artifacts"
	@echo "  fmt         Format all Go code"
	@echo "  build-all   Check compilation across Linux, macOS, and Windows"

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/keychain-auth/
	@echo "✓ Built $(BUILD_DIR)/$(BINARY_NAME)"

test:
	@echo "Running tests..."
	$(GO) test -v ./...

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Cleaned"

fmt:
	@echo "Formatting code..."
	$(GOFMT) -w -s .
	@echo "✓ Code formatted"

build-all:
	@echo "Checking compilation across platforms..."
	@echo -n "  Linux (amd64)... "
	@GOOS=linux GOARCH=amd64 $(GO) build -o /dev/null ./cmd/keychain-auth/ && echo "✓ OK" || (echo "✗ FAILED"; exit 1)
	@echo -n "  macOS (amd64)... "
	@GOOS=darwin GOARCH=amd64 $(GO) build -o /dev/null ./cmd/keychain-auth/ && echo "✓ OK" || (echo "✗ FAILED"; exit 1)
	@echo -n "  Windows (amd64)... "
	@GOOS=windows GOARCH=amd64 $(GO) build -o /dev/null ./cmd/keychain-auth/ && echo "✓ OK" || (echo "✗ FAILED"; exit 1)
	@echo "✓ All platforms compile successfully!"
