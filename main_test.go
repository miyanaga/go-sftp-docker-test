package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

type AuthTestCase struct {
	name       string
	authType   string
	privateKey string
	passphrase string
	dockerCmd  []string
	mounts     []string
	fileName   string
	port       int
}

func TestSFTPAuthenticationMethods(t *testing.T) {
	testCases := []AuthTestCase{}

	// Assign available ports to each test case
	baseTestCases := []AuthTestCase{
		{
			name:      "PasswordAuth",
			authType:  "password",
			dockerCmd: []string{fmt.Sprintf("%s:%s:1001", username, password)},
			fileName:  "password-auth-test.txt",
		},
		{
			name:       "RSAKeyAuth",
			authType:   "privatekey",
			privateKey: "keys/id_rsa_without_passphrase",
			dockerCmd:  []string{fmt.Sprintf("%s::1001", username)},
			fileName:   "rsa-key-auth-test.txt",
		},
		{
			name:       "RSAKeyWithPassphraseAuth",
			authType:   "privatekey_passphrase",
			privateKey: "keys/id_rsa_with_passphrase",
			passphrase: "the-pass",
			dockerCmd:  []string{fmt.Sprintf("%s::1001", username)},
			fileName:   "rsa-key-passphrase-auth-test.txt",
		},
		{
			name:       "ED25519KeyAuth",
			authType:   "privatekey",
			privateKey: "keys/id_ed25519_without_passphrase",
			dockerCmd:  []string{fmt.Sprintf("%s::1001", username)},
			fileName:   "ed25519-key-auth-test.txt",
		},
		{
			name:       "ED25519KeyWithPassphraseAuth",
			authType:   "privatekey_passphrase",
			privateKey: "keys/id_ed25519_with_passphrase",
			passphrase: "the-pass",
			dockerCmd:  []string{fmt.Sprintf("%s::1001", username)},
			fileName:   "ed25519-key-passphrase-auth-test.txt",
		},
	}

	// Assign ports to test cases with some spacing to avoid conflicts
	basePort, err := findAvailablePort()
	require.NoError(t, err)

	for i, baseTC := range baseTestCases {
		tc := baseTC
		tc.port = basePort + i + 1 // Add spacing between ports
		testCases = append(testCases, tc)
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testSFTPAuth(t, tc)
		})
	}
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

func testSFTPAuth(t *testing.T, tc AuthTestCase) {
	t.Logf("Using port: %d for %s", tc.port, tc.name)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)

	// Setup mounts for public key authentication
	var mounts []string
	if tc.authType == "privatekey" || tc.authType == "privatekey_passphrase" {
		mounts = setupPublicKeyMounts(t, tc.privateKey)
		defer cleanupPublicKeyMounts(mounts)
	}

	runOptions := &dockertest.RunOptions{
		Repository:   "atmoz/sftp",
		Tag:          "latest",
		Cmd:          tc.dockerCmd,
		ExposedPorts: []string{"22/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"22/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(tc.port)}},
		},
	}
	if len(mounts) > 0 {
		runOptions.Mounts = mounts
	}

	resource, err := pool.RunWithOptions(runOptions, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	require.NoError(t, err)
	defer func() {
		if err := pool.Purge(resource); err != nil {
			log.Printf("Could not purge resource: %s", err)
		}
	}()

	hostPort := strconv.Itoa(tc.port)
	pool.MaxWait = 120 * time.Second

	// Wait for service to be ready with appropriate client
	err = pool.Retry(func() error {
		client := createSFTPClient(tc, "localhost", hostPort)
		return client.Connect()
	})
	require.NoError(t, err)

	// Setup upload directory
	_, err = resource.Exec([]string{"mkdir", "-p", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)
	_, err = resource.Exec([]string{"chown", "testuser:users", "/home/testuser/upload"}, dockertest.ExecOptions{})
	require.NoError(t, err)

	// Create test file
	tempFile := createTempTestFileWithName(t, tc.fileName)
	defer os.Remove(tempFile)

	// Test SFTP upload
	sftpClient := createSFTPClient(tc, "localhost", hostPort)
	err = sftpClient.Connect()
	require.NoError(t, err)
	defer sftpClient.Close()

	remoteFilePath := fmt.Sprintf("upload/%s", tc.fileName)
	err = sftpClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	verifyFileUpload(t, resource, remoteFilePath)
}

func createSFTPClient(tc AuthTestCase, host, port string) *SFTPClient {
	switch tc.authType {
	case "password":
		return NewSFTPClient(host, port, username, password)
	case "privatekey":
		return NewSFTPClientWithPrivateKey(host, port, username, tc.privateKey)
	case "privatekey_passphrase":
		return NewSFTPClientWithPrivateKeyAndPassphrase(host, port, username, tc.privateKey, tc.passphrase)
	default:
		panic(fmt.Sprintf("unsupported auth type: %s", tc.authType))
	}
}

func setupPublicKeyMounts(t *testing.T, privateKeyPath string) []string {
	pubKeyPath := privateKeyPath + ".pub"
	pubKeyContent, err := os.ReadFile(pubKeyPath)
	require.NoError(t, err)

	tempPubKeyPath := filepath.Join(os.TempDir(), fmt.Sprintf("pubkey_%d.pub", time.Now().UnixNano()))
	err = os.WriteFile(tempPubKeyPath, pubKeyContent, 0644)
	require.NoError(t, err)

	// Determine key type for mount path
	keyType := "id_rsa"
	if strings.Contains(privateKeyPath, "ed25519") {
		keyType = "id_ed25519"
	}

	return []string{fmt.Sprintf("%s:/home/%s/.ssh/keys/%s.pub:ro", tempPubKeyPath, username, keyType)}
}

func cleanupPublicKeyMounts(mounts []string) {
	for _, mount := range mounts {
		parts := strings.Split(mount, ":")
		if len(parts) > 0 {
			os.Remove(parts[0])
		}
	}
}
