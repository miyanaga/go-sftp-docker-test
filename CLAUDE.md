# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go project named `go-sftp-docker-test` that appears to be a testing setup for SFTP operations in a Docker environment. The project uses Go 1.22.2.

## Development Commands

Since this is a standard Go project, use these commands:

- `go run .` - Run the main application
- `go build .` - Build the binary
- `go test ./...` - Run all tests
- `go mod tidy` - Clean up dependencies
- `go fmt ./...` - Format Go code
- `go vet ./...` - Run Go vet for static analysis

## Project Structure

Currently minimal with only:
- `go.mod` - Go module definition
- `.gitignore` - Standard Go gitignore file

The project appears to be in early setup phase and may be intended for testing SFTP functionality within Docker containers.