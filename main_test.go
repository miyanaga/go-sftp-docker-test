package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sftpImage = "atmoz/sftp:latest"
	username  = "testuser"
	password  = "testpass"
)

func TestSFTPUpload(t *testing.T) {
	// Setup dockertest pool
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	// Test that we can connect to docker
	err = pool.Client.Ping()
	require.NoError(t, err)

	// Pull and start SFTP container
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "atmoz/sftp",
		Tag:          "latest",
		Cmd:          []string{fmt.Sprintf("%s:%s:1001", username, password)},
		ExposedPorts: []string{"22/tcp"},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	require.NoError(t, err)
	defer func() {
		if err := pool.Purge(resource); err != nil {
			log.Printf("Could not purge resource: %s", err)
		}
	}()

	// Get the mapped port
	hostPort := resource.GetPort("22/tcp")

	// Wait for SFTP service to be ready
	pool.MaxWait = 120 * time.Second
	err = pool.Retry(func() error {
		client := NewSFTPClient("localhost", hostPort, username, password)
		return client.Connect()
	})
	require.NoError(t, err)

	// Create upload directory and set proper permissions
	_, err = resource.Exec([]string{"mkdir", "-p", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)
	_, err = resource.Exec([]string{"chown", "testuser:users", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)

	// Create test file
	tempFile := createTempTestFile(t)
	defer os.Remove(tempFile)

	// Test SFTP upload
	sftpClient := NewSFTPClient("localhost", hostPort, username, password)
	err = sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := "upload/test-file.txt"
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	// Verify file exists in container
	verifyFileUpload(t, resource, remoteFilePath)
}

func createTempTestFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test-file.txt")

	content := "Hello, SFTP World!\nThis is a test file for SFTP upload."
	err := os.WriteFile(tempFile, []byte(content), 0644)
	require.NoError(t, err)

	return tempFile
}

func verifyFileUpload(t *testing.T, resource *dockertest.Resource, remoteFilePath string) {
	// Execute a command to check if the file exists in the container
	fullPath := fmt.Sprintf("/home/testuser/%s", remoteFilePath)
	exitCode, err := resource.Exec([]string{"test", "-f", fullPath}, dockertest.ExecOptions{})
	if err != nil || exitCode != 0 {
		// Try to list the directory contents for debugging
		_, lsErr := resource.Exec([]string{"ls", "-la", "/home/testuser/upload/"}, dockertest.ExecOptions{})
		if lsErr == nil {
			t.Logf("Listed upload directory for debugging")
		}
	}
	assert.Equal(t, 0, exitCode, "File should exist on the SFTP server")
	assert.NoError(t, err, "Exec command should succeed")
}
