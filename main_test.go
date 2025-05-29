package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sftpImage     = "atmoz/sftp:latest"
	containerName = "sftp-test-container"
	sftpPort      = "2222"
	username      = "testuser"
	password      = "testpass"
)

func TestSFTPUpload(t *testing.T) {
	// Setup SFTP container using Docker CLI
	containerID := setupSFTPContainer(t)
	defer cleanupContainer(t, containerID)

	// Wait for SFTP service to be ready
	time.Sleep(10 * time.Second)

	// Create test file
	tempFile := createTempTestFile(t)
	defer os.Remove(tempFile)

	// Test SFTP upload
	sftpClient := NewSFTPClient("localhost", sftpPort, username, password)
	err := sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := "upload/test-file.txt"
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	// Verify file exists in container
	verifyFileUpload(t, containerID, remoteFilePath)
}

func setupSFTPContainer(t *testing.T) string {
	// Pull image if not exists
	cmd := exec.Command("docker", "image", "inspect", sftpImage)
	if err := cmd.Run(); err != nil {
		t.Logf("Pulling atmoz/sftp image...")
		cmd = exec.Command("docker", "pull", sftpImage)
		require.NoError(t, cmd.Run())
	}

	// Remove existing container if exists
	exec.Command("docker", "rm", "-f", containerName).Run()

	// Start atmoz/sftp container with user configuration
	cmd = exec.Command("docker", "run", "-d",
		"--name", containerName,
		"-p", fmt.Sprintf("%s:22", sftpPort),
		sftpImage,
		fmt.Sprintf("%s:%s:1001", username, password))

	output, err := cmd.Output()
	require.NoError(t, err)

	containerID := strings.TrimSpace(string(output))
	t.Logf("Started atmoz/sftp container: %s", containerID)

	// Check container logs and directory structure for debugging
	time.Sleep(2 * time.Second)
	logCmd := exec.Command("docker", "logs", containerID)
	if logs, err := logCmd.Output(); err == nil {
		t.Logf("Container logs: %s", string(logs))
	}

	// Check directory structure and create upload directory
	lsCmd := exec.Command("docker", "exec", containerID, "ls", "-la", "/home/testuser/")
	if lsOutput, err := lsCmd.Output(); err == nil {
		t.Logf("User home directory: %s", string(lsOutput))
	}

	// Create upload directory and set proper permissions
	mkdirCmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", "/home/testuser/upload")
	mkdirCmd.Run()
	chownCmd := exec.Command("docker", "exec", containerID, "chown", "testuser:users", "/home/testuser/upload")
	chownCmd.Run()

	return containerID
}

func cleanupContainer(t *testing.T, containerID string) {
	cmd := exec.Command("docker", "rm", "-f", containerID)
	if err := cmd.Run(); err != nil {
		t.Logf("Warning: failed to remove container: %v", err)
	}
}

func createTempTestFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test-file.txt")

	content := "Hello, SFTP World!\nThis is a test file for SFTP upload."
	err := os.WriteFile(tempFile, []byte(content), 0644)
	require.NoError(t, err)

	return tempFile
}

func verifyFileUpload(t *testing.T, containerID, remoteFilePath string) {
	// Execute a command to check if the file exists in the container
	fullPath := fmt.Sprintf("/home/testuser/%s", remoteFilePath)
	cmd := exec.Command("docker", "exec", containerID, "test", "-f", fullPath)
	err := cmd.Run()
	if err != nil {
		// Try to list the directory contents for debugging
		lsCmd := exec.Command("docker", "exec", containerID, "ls", "-la", "/home/testuser/upload/")
		if lsOutput, lsErr := lsCmd.Output(); lsErr == nil {
			t.Logf("Upload directory contents: %s", string(lsOutput))
		}
	}
	assert.NoError(t, err, "File should exist on the SFTP server")
}
