# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go project that demonstrates how to test SFTP functionality using Docker containers. It uses the `ory/dockertest` library for CI/CD-friendly container management.

## Features

1. SFTP client implementation with upload functionality
2. Docker container management using `ory/dockertest/v3`
3. **Dynamic port allocation** - automatically finds available ports to avoid conflicts
4. Automated testing with atmoz/sftp Docker image
5. **Parallel test support** - multiple tests can run concurrently safely
6. GitHub Actions CI/CD pipeline
7. Cross-platform compatibility (tested on macOS, works in GitHub Actions Ubuntu)

## Development Commands

- `go run .` - Run the main application
- `go build .` - Build the binary
- `go test ./...` - Run all tests (requires Docker)
- `go test -v -timeout=10m ./...` - Run tests with verbose output and extended timeout
- `go mod tidy` - Clean up dependencies
- `go fmt ./...` - Format Go code
- `go vet ./...` - Run Go vet for static analysis

## Dependencies

- `github.com/pkg/sftp` - SFTP client library
- `github.com/ory/dockertest/v3` - Docker container testing library
- `github.com/stretchr/testify` - Testing assertions
- `golang.org/x/crypto` - SSH and cryptographic functions

## Testing

The project uses `dockertest` instead of direct `exec.Command("docker", ...)` calls for better CI/CD compatibility:

- **Dynamic port allocation**: Uses `findAvailablePort()` to automatically find free ports
- **Parallel test safety**: Each test gets its own unique port to avoid conflicts
- **Port range support**: `findAvailablePortInRange()` for constrained environments
- Automatically pulls and manages Docker containers
- Handles port mapping and container lifecycle
- Provides retry mechanisms for service readiness
- Works seamlessly in GitHub Actions and other CI environments

### Port Allocation Methods

```go
// Find any available port (recommended)
port, err := findAvailablePort()

// Find port in specific range
port, err := findAvailablePortInRange(8000, 9000)

// Check if specific port is available
available := isPortAvailable(2222)
```

## CI/CD

GitHub Actions workflow (`.github/workflows/test.yml`) runs:
- Go tests with Docker support
- Race condition detection
- Code formatting checks
- Static analysis with `go vet`