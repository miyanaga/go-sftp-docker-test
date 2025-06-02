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

func TestSFTPAuthenticationMethods(t *testing.T) {
	t.Run("PasswordAuth", func(t *testing.T) {
		t.Parallel()
		testSFTPPasswordAuth(t)
	})

	t.Run("RSAKeyAuth", func(t *testing.T) {
		t.Parallel()
		testSFTPRSAKeyAuth(t)
	})

	t.Run("RSAKeyWithPassphraseAuth", func(t *testing.T) {
		t.Parallel()
		testSFTPRSAKeyWithPassphraseAuth(t)
	})

	t.Run("ED25519KeyAuth", func(t *testing.T) {
		t.Parallel()
		testSFTPED25519KeyAuth(t)
	})

	t.Run("ED25519KeyWithPassphraseAuth", func(t *testing.T) {
		t.Parallel()
		testSFTPED25519KeyWithPassphraseAuth(t)
	})
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

func testSFTPPasswordAuth(t *testing.T) {
	availablePort, err := findAvailablePort()
	require.NoError(t, err)
	t.Logf("Using port: %d for password auth", availablePort)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)

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

	hostPort := strconv.Itoa(availablePort)
	pool.MaxWait = 120 * time.Second
	err = pool.Retry(func() error {
		client := NewSFTPClient("localhost", hostPort, username, password)
		return client.Connect()
	})
	require.NoError(t, err)

	_, err = resource.Exec([]string{"mkdir", "-p", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)
	_, err = resource.Exec([]string{"chown", "testuser:users", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)

	tempFile := createTempTestFileWithName(t, "password-auth-test.txt")
	defer os.Remove(tempFile)

	sftpClient := NewSFTPClient("localhost", hostPort, username, password)
	err = sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := "upload/password-auth-test.txt"
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	verifyFileUpload(t, resource, remoteFilePath)
}

func testSFTPRSAKeyAuth(t *testing.T) {
	availablePort, err := findAvailablePort()
	require.NoError(t, err)
	t.Logf("Using port: %d for RSA key auth", availablePort)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)

	keyPath := "/tmp/id_rsa_without_passphrase.pub"
	err = os.WriteFile(keyPath, []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDEOB38RnRdExaIL/b1TF60txjB99PeiqGRpA7m+7WUkji6kYUSy7ZFaYrKdKgV5UY2JGz6FvQ5+Jh7LNoLfRAVZuz5xiOmDPwvFq/T4SW70VZAyzGUtgA+5zvYWhc9P38wG6ZZ23xxp7/x4UewIPhbAzc4ti2/zNgVOrmrpvWr1RgyDffbgDt1melR6JUrv5B9vdUt6j56fFTjPUt10gR/4NoVDt24V5oXyz9+H44pjXNDhY1m+NIWOAIikggR0D7YOqlcUBdv5x09ICggedM/Kxhyw8otK7fKjBaeQDx6xLTyELHfBiAlaNU5rtutkXFr1QWvXRBWwwrmMRdTzNikORG2/UgXswXQZ2AL1Js3UAbahM3Z6BJ/hIVEXLOAkVStoxKydAMpjYD3DyOExh5lI50Mj2tw8jrDIbVi+X/bgd8ZK8DRPeoB0kbw09lUpA62lX8JWoAKVAPJ9eTqcBS6+WBXsFzBeFBLiufyALEKphYZX5NTVol+I2j1vjK0CJzpZczchX4HUGJ5HGPEQgbCMY58ektCMbh9xEI9ZTzL4+qwL3P91gC7ZzpfkTwxygumGYHysHT9TYLNRG57l5Vt9TFixgOFF9DHxBmNP1d3Hv8kBxn8CXdpNy8CgEewAvYyXt5s58Dq6UYRQYAmWz02YdTLaWkrBZeOX42Usn/iZQ== miyanaga@m4pro.local"), 0644)
	require.NoError(t, err)
	defer os.Remove(keyPath)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "atmoz/sftp",
		Tag:          "latest",
		Cmd:          []string{fmt.Sprintf("%s::1001", username)},
		ExposedPorts: []string{"22/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"22/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(availablePort)}},
		},
		Mounts: []string{fmt.Sprintf("%s:/home/%s/.ssh/keys/id_rsa.pub:ro", keyPath, username)},
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

	hostPort := strconv.Itoa(availablePort)
	pool.MaxWait = 120 * time.Second

	privateKeyPath := "keys/id_rsa_without_passphrase"
	err = pool.Retry(func() error {
		client := NewSFTPClientWithPrivateKey("localhost", hostPort, username, privateKeyPath)
		return client.Connect()
	})
	require.NoError(t, err)

	_, err = resource.Exec([]string{"mkdir", "-p", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)
	_, err = resource.Exec([]string{"chown", "testuser:users", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)

	tempFile := createTempTestFileWithName(t, "rsa-key-auth-test.txt")
	defer os.Remove(tempFile)

	sftpClient := NewSFTPClientWithPrivateKey("localhost", hostPort, username, privateKeyPath)
	err = sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := "upload/rsa-key-auth-test.txt"
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	verifyFileUpload(t, resource, remoteFilePath)
}

func testSFTPRSAKeyWithPassphraseAuth(t *testing.T) {
	availablePort, err := findAvailablePort()
	require.NoError(t, err)
	t.Logf("Using port: %d for RSA key with passphrase auth", availablePort)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)

	keyPath := "/tmp/id_rsa_with_passphrase.pub"
	pubKeyContent, err := os.ReadFile("keys/id_rsa_with_passphrase.pub")
	require.NoError(t, err)
	err = os.WriteFile(keyPath, pubKeyContent, 0644)
	require.NoError(t, err)
	defer os.Remove(keyPath)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "atmoz/sftp",
		Tag:          "latest",
		Cmd:          []string{fmt.Sprintf("%s::1001", username)},
		ExposedPorts: []string{"22/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"22/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(availablePort)}},
		},
		Mounts: []string{fmt.Sprintf("%s:/home/%s/.ssh/keys/id_rsa.pub:ro", keyPath, username)},
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

	hostPort := strconv.Itoa(availablePort)
	pool.MaxWait = 120 * time.Second

	privateKeyPath := "keys/id_rsa_with_passphrase"
	passphrase := "the-pass"
	err = pool.Retry(func() error {
		client := NewSFTPClientWithPrivateKeyAndPassphrase("localhost", hostPort, username, privateKeyPath, passphrase)
		return client.Connect()
	})
	require.NoError(t, err)

	_, err = resource.Exec([]string{"mkdir", "-p", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)
	_, err = resource.Exec([]string{"chown", "testuser:users", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)

	tempFile := createTempTestFileWithName(t, "rsa-key-passphrase-auth-test.txt")
	defer os.Remove(tempFile)

	sftpClient := NewSFTPClientWithPrivateKeyAndPassphrase("localhost", hostPort, username, privateKeyPath, passphrase)
	err = sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := "upload/rsa-key-passphrase-auth-test.txt"
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	verifyFileUpload(t, resource, remoteFilePath)
}

func testSFTPED25519KeyAuth(t *testing.T) {
	availablePort, err := findAvailablePort()
	require.NoError(t, err)
	t.Logf("Using port: %d for ED25519 key auth", availablePort)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)

	keyPath := "/tmp/id_ed25519_without_passphrase.pub"
	err = os.WriteFile(keyPath, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKxrRIHEUPFjUuzjU5mKB9D0ZX5oKyzhVsxYysufGN0 miyanaga@m4pro.local"), 0644)
	require.NoError(t, err)
	defer os.Remove(keyPath)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "atmoz/sftp",
		Tag:          "latest",
		Cmd:          []string{fmt.Sprintf("%s::1001", username)},
		ExposedPorts: []string{"22/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"22/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(availablePort)}},
		},
		Mounts: []string{fmt.Sprintf("%s:/home/%s/.ssh/keys/id_ed25519.pub:ro", keyPath, username)},
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

	hostPort := strconv.Itoa(availablePort)
	pool.MaxWait = 120 * time.Second

	privateKeyPath := "keys/id_ed25519_without_passphrase"
	err = pool.Retry(func() error {
		client := NewSFTPClientWithPrivateKey("localhost", hostPort, username, privateKeyPath)
		return client.Connect()
	})
	require.NoError(t, err)

	_, err = resource.Exec([]string{"mkdir", "-p", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)
	_, err = resource.Exec([]string{"chown", "testuser:users", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)

	tempFile := createTempTestFileWithName(t, "ed25519-key-auth-test.txt")
	defer os.Remove(tempFile)

	sftpClient := NewSFTPClientWithPrivateKey("localhost", hostPort, username, privateKeyPath)
	err = sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := "upload/ed25519-key-auth-test.txt"
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	verifyFileUpload(t, resource, remoteFilePath)
}

func testSFTPED25519KeyWithPassphraseAuth(t *testing.T) {
	availablePort, err := findAvailablePort()
	require.NoError(t, err)
	t.Logf("Using port: %d for ED25519 key with passphrase auth", availablePort)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)

	keyPath := "/tmp/id_ed25519_with_passphrase.pub"
	pubKeyContent, err := os.ReadFile("keys/id_ed25519_with_passphrase.pub")
	require.NoError(t, err)
	err = os.WriteFile(keyPath, pubKeyContent, 0644)
	require.NoError(t, err)
	defer os.Remove(keyPath)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "atmoz/sftp",
		Tag:          "latest",
		Cmd:          []string{fmt.Sprintf("%s::1001", username)},
		ExposedPorts: []string{"22/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"22/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(availablePort)}},
		},
		Mounts: []string{fmt.Sprintf("%s:/home/%s/.ssh/keys/id_ed25519.pub:ro", keyPath, username)},
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

	hostPort := strconv.Itoa(availablePort)
	pool.MaxWait = 120 * time.Second

	privateKeyPath := "keys/id_ed25519_with_passphrase"
	passphrase := "the-pass"
	err = pool.Retry(func() error {
		client := NewSFTPClientWithPrivateKeyAndPassphrase("localhost", hostPort, username, privateKeyPath, passphrase)
		return client.Connect()
	})
	require.NoError(t, err)

	_, err = resource.Exec([]string{"mkdir", "-p", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)
	_, err = resource.Exec([]string{"chown", "testuser:users", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)

	tempFile := createTempTestFileWithName(t, "ed25519-key-passphrase-auth-test.txt")
	defer os.Remove(tempFile)

	sftpClient := NewSFTPClientWithPrivateKeyAndPassphrase("localhost", hostPort, username, privateKeyPath, passphrase)
	err = sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := "upload/ed25519-key-passphrase-auth-test.txt"
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	verifyFileUpload(t, resource, remoteFilePath)
}
