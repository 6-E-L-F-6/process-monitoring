# Makefile for Process Monitor

BINARY_NAME=procmon
VERSION=2.0.0
BUILD_DIR=./build
DATA_DIR=./data
LOG_DIR=./logs
DUMP_DIR=./dumps

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build clean test deps run install uninstall dirs

all: deps dirs build

build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) -v

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

dirs:
	@echo "Creating directories..."
	mkdir -p $(BUILD_DIR)
	mkdir -p $(DATA_DIR)
	mkdir -p $(LOG_DIR)
	mkdir -p $(DUMP_DIR)

run: build
	@echo "Running $(BINARY_NAME)..."
	sudo $(BUILD_DIR)/$(BINARY_NAME)

install: build
	@echo "Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	mkdir -p /var/lib/procmon
	mkdir -p /var/log/procmon
	mkdir -p /var/lib/procmon/dumps
	@echo "Installation complete!"

uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstall complete!"

# Development helpers
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

vet:
	@echo "Running go vet..."
	$(GOCMD) vet ./...

lint: fmt vet
	@echo "Linting complete!"

# Cross compilation
build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 -v

build-arm:
	@echo "Building for ARM..."
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 -v

# Database operations
db-clean:
	@echo "Cleaning database..."
	rm -f $(DATA_DIR)/procmon.db

db-backup:
	@echo "Backing up database..."
	cp $(DATA_DIR)/procmon.db $(DATA_DIR)/procmon.db.backup.$(shell date +%Y%m%d_%H%M%S)

# Export operations
export-all: build
	@echo "Exporting all processes..."
	$(BUILD_DIR)/$(BINARY_NAME) -mode export -output exports/all_processes.json

export-pid: build
	@echo "Exporting PID $(PID)..."
	$(BUILD_DIR)/$(BINARY_NAME) -mode export -pid $(PID) -output exports/process_$(PID).json

# Help
help:
	@echo "Process Monitor Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make all          - Download deps, create dirs, and build"
	@echo "  make build        - Build the binary"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make test         - Run tests"
	@echo "  make deps         - Download dependencies"
	@echo "  make run          - Build and run with sudo"
	@echo "  make install      - Install to /usr/local/bin"
	@echo "  make uninstall    - Remove from /usr/local/bin"
	@echo "  make fmt          - Format code"
	@echo "  make lint         - Run linters"
	@echo "  make db-clean     - Remove database"
	@echo "  make db-backup    - Backup database"
	@echo "  make export-all   - Export all processes"
	@echo "  make export-pid PID=1234 - Export specific PID"
