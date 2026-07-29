.PHONY: build test lint clean run docker-build

APP_NAME := landc-sso
BUILD_DIR := ./build
MAIN_PATH := ./cmd/api

# Build the binary
build:
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PATH)

# Run tests
test:
	go test -v -race -coverprofile=coverage.out ./...

# Run tests with race detection
test-race:
	go test -race -count=1 ./...

# Show test coverage
coverage:
	go tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	golangci-lint run ./...

# Run the server
run:
	go run $(MAIN_PATH)

# Build Docker image
docker-build:
	docker build -t $(APP_NAME):latest .

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

# Download dependencies
deps:
	go mod download

# Tidy modules
tidy:
	go mod tidy
