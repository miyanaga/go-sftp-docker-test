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
	sftpImage     = "alpine:latest"
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
	time.Sleep(5 * time.Second)

	// Create test file
	tempFile := createTempTestFile(t)
	defer os.Remove(tempFile)

	// Test SFTP upload
	sftpClient := NewSFTPClient("localhost", sftpPort, username, password)
	err := sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := "/home/testuser/upload/test-file.txt"
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	// Verify file exists in container
	verifyFileUpload(t, containerID, remoteFilePath)
}

func setupSFTPContainer(t *testing.T) string {
	// Pull image if not exists
	cmd := exec.Command("docker", "image", "inspect", sftpImage)
	if err := cmd.Run(); err != nil {
		t.Logf("Pulling Alpine image...")
		cmd = exec.Command("docker", "pull", sftpImage)
		require.NoError(t, cmd.Run())
	}

	// Remove existing container if exists
	exec.Command("docker", "rm", "-f", containerName).Run()

	// Start Alpine container
	cmd = exec.Command("docker", "run", "-d",
		"--name", containerName,
		"-p", fmt.Sprintf("%s:22", sftpPort),
		sftpImage,
		"sleep", "infinity")

	output, err := cmd.Output()
	require.NoError(t, err)

	containerID := strings.TrimSpace(string(output))
	t.Logf("Started Alpine container: %s", containerID)

	// Install and configure SSH server in container
	setupSSHInContainer(t, containerID)

	return containerID
}

func setupSSHInContainer(t *testing.T, containerID string) {
	commands := [][]string{
		{"apk", "add", "--no-cache", "openssh"},
		{"adduser", "-D", "-s", "/bin/sh", username},
		{"sh", "-c", fmt.Sprintf("echo '%s:%s' | chpasswd", username, password)},
		{"mkdir", "-p", fmt.Sprintf("/home/%s/upload", username)},
		{"chown", fmt.Sprintf("%s:%s", username, username), fmt.Sprintf("/home/%s/upload", username)},
		{"ssh-keygen", "-A"},
		{"sed", "-i", "s/#PasswordAuthentication yes/PasswordAuthentication yes/", "/etc/ssh/sshd_config"},
		{"sed", "-i", "s/#PermitRootLogin prohibit-password/PermitRootLogin no/", "/etc/ssh/sshd_config"},
		{"/usr/sbin/sshd", "-D"},
	}

	for i, cmdArgs := range commands {
		if i == len(commands)-1 {
			// Start SSH server in background
			cmd := exec.Command("docker", "exec", "-d", containerID)
			cmd.Args = append(cmd.Args, cmdArgs...)
			require.NoError(t, cmd.Run())
		} else {
			// Run setup commands
			cmd := exec.Command("docker", "exec", containerID)
			cmd.Args = append(cmd.Args, cmdArgs...)
			if err := cmd.Run(); err != nil {
				t.Logf("Command failed: %v", cmdArgs)
				require.NoError(t, err)
			}
		}
	}

	t.Logf("SSH server configured and started")
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
	cmd := exec.Command("docker", "exec", containerID, "test", "-f", remoteFilePath)
	err := cmd.Run()
	assert.NoError(t, err, "File should exist on the SFTP server")
}
