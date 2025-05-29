# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go project that demonstrates how to test SFTP functionality using Docker containers. It uses the `ory/dockertest` library for CI/CD-friendly container management.

## Features

1. SFTP client implementation with upload functionality
2. Docker container management using `ory/dockertest/v3`
3. Automated testing with atmoz/sftp Docker image
4. GitHub Actions CI/CD pipeline
5. Cross-platform compatibility (tested on macOS, works in GitHub Actions Ubuntu)

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

- Automatically pulls and manages Docker containers
- Handles port mapping and container lifecycle
- Provides retry mechanisms for service readiness
- Works seamlessly in GitHub Actions and other CI environments

## CI/CD

GitHub Actions workflow (`.github/workflows/test.yml`) runs:
- Go tests with Docker support
- Race condition detection
- Code formatting checks
- Static analysis with `go vet`