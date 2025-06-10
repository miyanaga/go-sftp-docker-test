package ftp

import (
	"context"
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
	ftpUsername = "testuser"
	ftpPassword = "testpass"
)

// FTPTestPattern represents a test pattern for FTP connections
type FTPTestPattern struct {
	Name        string
	UseTLS      bool
	Port        int
	DockerImage string
	DockerTag   string
	DockerEnv   []string
}

// TestFTPTableDriven tests 2 FTP connection patterns using table-driven tests
func TestFTPTableDriven(t *testing.T) {
	// Find base port for tests
	basePort, err := findAvailablePort()
	require.NoError(t, err)

	// Define 2 connection patterns: FTP and FTPS (both using Passive mode)
	testPatterns := []FTPTestPattern{
		{
			Name:        "FTP_PassiveMode_NoEncryption",
			UseTLS:      false,
			Port:        basePort,
			DockerImage: "fauria/vsftpd",
			DockerTag:   "latest",
			DockerEnv: []string{
				fmt.Sprintf("FTP_USER=%s", ftpUsername),
				fmt.Sprintf("FTP_PASS=%s", ftpPassword),
				"PASV_ENABLE=YES",
				"PASV_MIN_PORT=21100",
				"PASV_MAX_PORT=21110",
				"PASV_ADDRESS=127.0.0.1",
				"LOCAL_UMASK=022",
			},
		},
		{
			Name:        "FTPS_PassiveMode_WithEncryption",
			UseTLS:      true,
			Port:        basePort + 1,
			DockerImage: "fauria/vsftpd",
			DockerTag:   "latest",
			DockerEnv: []string{
				fmt.Sprintf("FTP_USER=%s", ftpUsername),
				fmt.Sprintf("FTP_PASS=%s", ftpPassword),
				"PASV_ENABLE=YES",
				"PASV_MIN_PORT=21100",
				"PASV_MAX_PORT=21110",
				"PASV_ADDRESS=127.0.0.1",
				"LOCAL_UMASK=022",
				// TLS settings
				"SSL_ENABLE=YES",
				"REQUIRE_SSL_REUSE=NO",
				"FORCE_LOCAL_DATA_SSL=YES",
				"FORCE_LOCAL_LOGINS_SSL=YES",
				"SSL_TLSV1=YES",
				"SSL_SSLV2=NO",
				"SSL_SSLV3=NO",
			},
		},
	}

	for _, pattern := range testPatterns {
		pattern := pattern // capture range variable
		t.Run(pattern.Name, func(t *testing.T) {
			// Skip FTPS test for now as it requires certificate setup
			if pattern.UseTLS {
				t.Skip("Skipping FTPS test - requires certificate setup in Docker container")
			}

			// Run the test for this pattern
			runFTPPatternTest(t, pattern)
		})
	}
}

// runFTPPatternTest runs a single FTP pattern test
func runFTPPatternTest(t *testing.T, pattern FTPTestPattern) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Setup Docker container
	pool, resource := setupFTPDocker(t, pattern)
	defer func() {
		if err := pool.Purge(resource); err != nil {
			log.Printf("Could not purge resource: %s", err)
		}
	}()

	// Wait for FTP server to be ready
	err := waitForFTPServer(pool, pattern)
	require.NoError(t, err, "FTP server did not become ready in time")

	// Create FTP client
	cfg := SimpleFTPConfig{
		Host:     "localhost",
		Port:     strconv.Itoa(pattern.Port),
		Username: ftpUsername,
		Password: ftpPassword,
		UseTLS:   pattern.UseTLS,
	}
	client := NewSimpleFTPClient(cfg)

	// Test connection
	err = client.Connect()
	require.NoError(t, err, "Failed to connect to FTP server")
	defer client.Close()

	// Run test operations
	t.Run("Upload", func(t *testing.T) {
		testFTPUpload(t, client, ctx)
	})

	t.Run("List", func(t *testing.T) {
		testFTPList(t, client)
	})

	t.Run("Download", func(t *testing.T) {
		testFTPDownload(t, client, ctx)
	})

	t.Run("Delete", func(t *testing.T) {
		testFTPDelete(t, client)
	})
}

// setupFTPDocker sets up the FTP Docker container
func setupFTPDocker(t *testing.T, pattern FTPTestPattern) (*dockertest.Pool, *dockertest.Resource) {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	err = pool.Client.Ping()
	require.NoError(t, err)

	// Configure port bindings
	portBindings := map[docker.Port][]docker.PortBinding{
		"21/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(pattern.Port)}},
	}

	// Also expose passive mode ports (matching PASV_MIN_PORT and PASV_MAX_PORT)
	exposedPorts := []string{"21/tcp", "21100-21110/tcp"}
	for i := 21100; i <= 21110; i++ {
		portStr := fmt.Sprintf("%d/tcp", i)
		portBindings[docker.Port(portStr)] = []docker.PortBinding{
			{HostIP: "0.0.0.0", HostPort: strconv.Itoa(i)},
		}
	}

	// Run container
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   pattern.DockerImage,
		Tag:          pattern.DockerTag,
		Env:          pattern.DockerEnv,
		ExposedPorts: exposedPorts,
		PortBindings: portBindings,
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	require.NoError(t, err)

	return pool, resource
}

// waitForFTPServer waits for the FTP server to be ready
func waitForFTPServer(pool *dockertest.Pool, pattern FTPTestPattern) error {
	pool.MaxWait = 60 * time.Second
	return pool.Retry(func() error {
		cfg := SimpleFTPConfig{
			Host:     "localhost",
			Port:     strconv.Itoa(pattern.Port),
			Username: ftpUsername,
			Password: ftpPassword,
			UseTLS:   pattern.UseTLS,
		}
		client := NewSimpleFTPClient(cfg)
		err := client.Connect()
		if err == nil {
			client.Close()
		}
		return err
	})
}

// Test operations

func testFTPUpload(t *testing.T, client *SimpleFTPClient, ctx context.Context) {
	// Create test file
	tempFile := createTempTestFile(t)
	defer os.Remove(tempFile)

	// Upload file
	remoteFile := "test/upload.txt"
	err := client.Upload(tempFile, remoteFile)
	assert.NoError(t, err, "Failed to upload file")
}

func testFTPList(t *testing.T, client *SimpleFTPClient) {
	// List files in test directory
	files, err := client.List("test")
	require.NoError(t, err, "Failed to list files")
	assert.Len(t, files, 1, "Expected 1 file in test directory")
	assert.Equal(t, "test/upload.txt", files[0])
}

func testFTPDownload(t *testing.T, client *SimpleFTPClient, ctx context.Context) {
	// Download file
	downloadPath := filepath.Join(t.TempDir(), "downloaded.txt")
	err := client.Download("test/upload.txt", downloadPath)
	require.NoError(t, err, "Failed to download file")

	// Verify content
	content, err := os.ReadFile(downloadPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "Hello, FTP World!")
}

func testFTPDelete(t *testing.T, client *SimpleFTPClient) {
	// Delete file
	err := client.Delete("test/upload.txt")
	assert.NoError(t, err, "Failed to delete file")

	// Verify deletion
	files, err := client.List("test")
	require.NoError(t, err)
	assert.Len(t, files, 0, "Expected no files after deletion")
}

// TestSimpleFTPOperations tests basic FTP operations
func TestSimpleFTPOperations(t *testing.T) {
	// Find available port
	port, err := findAvailablePort()
	require.NoError(t, err)

	pattern := FTPTestPattern{
		Name:        "BasicFTP",
		UseTLS:      false,
		Port:        port,
		DockerImage: "bogem/ftp",
		DockerTag:   "latest",
		DockerEnv: []string{
			fmt.Sprintf("FTP_USER=%s", ftpUsername),
			fmt.Sprintf("FTP_PASS=%s", ftpPassword),
		},
	}

	runFTPPatternTest(t, pattern)
}

// Helper function to find available port
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

// createTempTestFile creates a temporary test file
func createTempTestFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test-file.txt")

	content := "Hello, FTP World!\nThis is a test file for FTP upload."
	err := os.WriteFile(tempFile, []byte(content), 0644)
	require.NoError(t, err)

	return tempFile
}
