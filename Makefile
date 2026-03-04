# xsh2scrt Makefile
# Supports macOS and Linux, amd64 and arm64 architectures

# Binary name
BINARY_NAME=xsh2scrt
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Output directory
DIST_DIR=dist

# Platforms
PLATFORMS=darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64

.PHONY: all build clean test deps help release

# Default target
all: build

# Build for current platform
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) .

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(DIST_DIR)
	rm -f $(BINARY_NAME)

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Run tests
test:
	$(GOTEST) -v ./...

# Build for all platforms
build-all: clean deps
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d'/' -f1); \
		GOARCH=$$(echo $$platform | cut -d'/' -f2); \
		OUTPUT=$(DIST_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH; \
		if [ "$$GOOS" = "windows" ]; then OUTPUT="$$OUTPUT.exe"; fi; \
		echo "Building $$platform..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH $(GOBUILD) $(LDFLAGS) -o $$OUTPUT . || exit 1; \
	done
	@echo "Build complete! Files in $(DIST_DIR)/"

# Build specific targets
build-linux-amd64:
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 .

build-linux-arm64:
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 .

build-darwin-amd64:
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 .

build-darwin-arm64:
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 .

build-windows-amd64:
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe .

# Release build (Linux amd64 + macOS arm64)
release: clean deps build-linux-amd64 build-darwin-arm64
	@echo "Release builds complete!"
	@ls -lh $(DIST_DIR)/

# Create checksums
checksums:
	@cd $(DIST_DIR) && sha256sum * > checksums.txt 2>/dev/null || shasum -a 256 * > checksums.txt
	@echo "Checksums created in $(DIST_DIR)/checksums.txt"

# GitHub release (requires gh CLI)
github-release: release checksums
	@if [ -z "$(VERSION)" ]; then echo "VERSION not set"; exit 1; fi
	gh release create $(VERSION) $(DIST_DIR)/* --title "Release $(VERSION)" --notes "Release $(VERSION)"

# Show help
help:
	@echo "Available targets:"
	@echo "  make build              - Build for current platform"
	@echo "  make build-all          - Build for all platforms"
	@echo "  make release            - Build Linux amd64 + macOS arm64"
	@echo "  make build-linux-amd64  - Build for Linux amd64"
	@echo "  make build-linux-arm64  - Build for Linux arm64"
	@echo "  make build-darwin-amd64 - Build for macOS amd64"
	@echo "  make build-darwin-arm64 - Build for macOS arm64"
	@echo "  make clean              - Clean build artifacts"
	@echo "  make test               - Run tests"
	@echo "  make deps               - Download dependencies"
	@echo "  make checksums          - Generate SHA256 checksums"
	@echo "  make github-release     - Create GitHub release"
