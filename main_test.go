package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	// Find available port
	availablePort, err := findAvailablePort()
	require.NoError(t, err)
	t.Logf("Using port: %d", availablePort)

	// Setup dockertest pool
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	// Test that we can connect to docker
	err = pool.Client.Ping()
	require.NoError(t, err)

	// Pull and start SFTP container with specific port mapping
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "atmoz/sftp",
		Tag:          "latest",
		Cmd:          []string{fmt.Sprintf("%s:%s:1001", username, password)},
		ExposedPorts: []string{"22/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"22/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(availablePort)}},
		},
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

	// Use the specific port we allocated
	hostPort := strconv.Itoa(availablePort)

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

func TestSFTPUploadMultiple(t *testing.T) {
	// Test that multiple tests can run concurrently with different ports
	t.Run("Upload1", func(t *testing.T) {
		t.Parallel()
		testSFTPUploadWithPort(t, "test-file-1.txt")
	})

	t.Run("Upload2", func(t *testing.T) {
		t.Parallel()
		testSFTPUploadWithPort(t, "test-file-2.txt")
	})
}

func testSFTPUploadWithPort(t *testing.T, fileName string) {
	// Find available port
	availablePort, err := findAvailablePort()
	require.NoError(t, err)
	t.Logf("Using port: %d for %s", availablePort, fileName)

	// Setup dockertest pool
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	// Test that we can connect to docker
	err = pool.Client.Ping()
	require.NoError(t, err)

	// Pull and start SFTP container with specific port mapping
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "atmoz/sftp",
		Tag:          "latest",
		Cmd:          []string{fmt.Sprintf("%s:%s:1001", username, password)},
		ExposedPorts: []string{"22/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"22/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(availablePort)}},
		},
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

	// Use the specific port we allocated
	hostPort := strconv.Itoa(availablePort)

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

	// Create test file with unique name
	tempFile := createTempTestFileWithName(t, fileName)
	defer os.Remove(tempFile)

	// Test SFTP upload
	sftpClient := NewSFTPClient("localhost", hostPort, username, password)
	err = sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := fmt.Sprintf("upload/%s", fileName)
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	// Verify file exists in container
	verifyFileUpload(t, resource, remoteFilePath)
}

// findAvailablePort finds an available port on the local machine
func findAvailablePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}

// findAvailablePortInRange finds an available port within a specific range
func findAvailablePortInRange(start, end int) (int, error) {
	for port := start; port <= end; port++ {
		if isPortAvailable(port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available port found in range %d-%d", start, end)
}

// isPortAvailable checks if a port is available for use
func isPortAvailable(port int) bool {
	addr := fmt.Sprintf("localhost:%d", port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return true // Port is available
	}
	conn.Close()
	return false // Port is in use
}

func createTempTestFile(t *testing.T) string {
	return createTempTestFileWithName(t, "test-file.txt")
}

func createTempTestFileWithName(t *testing.T, fileName string) string {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, fileName)

	content := fmt.Sprintf("Hello, SFTP World!\nThis is a test file named %s for SFTP upload.", fileName)
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
