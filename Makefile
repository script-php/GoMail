.PHONY: build test clean run help

# Build variables
BINARY_NAME=gomail
RELEASE_DIR=release
BUILD_DIR=build

# Default target
help:
	@echo "GoMail Makefile targets:"
	@echo "  make build       - Build binary to release/gomail"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make run         - Run with config.dev.json"
	@echo "  make hash        - Hash a password (usage: make hash PASSWORD=test)"

# Build target
build:
	@echo "Building GoMail..."
	@mkdir -p $(RELEASE_DIR)
	@go build -o $(RELEASE_DIR)/$(BINARY_NAME) .
	@echo "✓ Built: $(RELEASE_DIR)/$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(RELEASE_DIR)/$(BINARY_NAME)
	@rm -f $(BUILD_DIR)/*
	@echo "✓ Cleaned"

# Run with dev config
run:
	@echo "Running GoMail with config.dev.json..."
	@$(RELEASE_DIR)/$(BINARY_NAME) -config $(RELEASE_DIR)/config.local.json

# Hash password
hash:
	@if [ -z "$(PASSWORD)" ]; then \
		echo "Usage: make hash PASSWORD=test"; \
		exit 1; \
	fi
	@$(RELEASE_DIR)/$(BINARY_NAME) -hash-password "$(PASSWORD)"

# Development build (for local testing)
dev-build: clean build test
	@echo "✓ Development build complete"

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@echo "✓ Formatted"

# Lint code
lint:
	@echo "Running linter..."
	@golangci-lint run ./...

# Update dependencies
deps:
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy
	@echo "✓ Dependencies updated"
