package webdav

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
	username = "testuser"
	password = "testpass"
)

type AuthTestCase struct {
	name      string
	authType  AuthMethod
	dockerEnv []string
	fileName  string
	port      int
}

func TestWebDAVUpload(t *testing.T) {
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

	// Pull and start WebDAV container with specific port mapping
	// Using bytemark/webdav which supports Basic auth well
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "bytemark/webdav",
		Tag:        "latest",
		Env: []string{
			"AUTH_TYPE=Basic",
			fmt.Sprintf("USERNAME=%s", username),
			fmt.Sprintf("PASSWORD=%s", password),
		},
		ExposedPorts: []string{"80/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"80/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(availablePort)}},
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

	// Construct WebDAV URL
	webdavURL := fmt.Sprintf("http://localhost:%d", availablePort)

	// Wait for WebDAV service to be ready
	pool.MaxWait = 120 * time.Second
	err = pool.Retry(func() error {
		client := NewWebDAVClientBasicAuth(webdavURL, username, password)
		return client.Connect()
	})
	require.NoError(t, err)

	// Create test file
	tempFile := createTempTestFile(t)
	defer os.Remove(tempFile)

	// Test WebDAV upload
	webdavClient := NewWebDAVClientBasicAuth(webdavURL, username, password)
	err = webdavClient.Connect()
	require.NoError(t, err)
	defer webdavClient.Close()

	remoteFilePath := "/upload/test-file.txt"
	err = webdavClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	// Verify file exists in container
	verifyFileUpload(t, resource, remoteFilePath)
}

func TestWebDAVAuthenticationMethods(t *testing.T) {
	testCases := []AuthTestCase{}

	// For demonstration purposes, we'll test both auth methods with bytemark/webdav (Basic only)
	// and show how the digest auth client handles Basic auth fallback
	baseTestCases := []AuthTestCase{
		{
			name:     "BasicAuth",
			authType: AuthBasic,
			dockerEnv: []string{
				"AUTH_TYPE=Basic",
				fmt.Sprintf("USERNAME=%s", username),
				fmt.Sprintf("PASSWORD=%s", password),
			},
			fileName: "basic-auth-test.txt",
		},
		{
			name:     "DigestAuthClient_BasicServer",
			authType: AuthDigest,
			dockerEnv: []string{
				"AUTH_TYPE=Basic",
				fmt.Sprintf("USERNAME=%s", username),
				fmt.Sprintf("PASSWORD=%s", password),
			},
			fileName: "digest-client-basic-server-test.txt",
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
			testWebDAVAuth(t, tc)
		})
	}
}

func TestWebDAVUploadMultiple(t *testing.T) {
	// Test that multiple tests can run concurrently with different ports
	t.Run("Upload1", func(t *testing.T) {
		t.Parallel()
		testWebDAVUploadWithPort(t, "test-file-1.txt")
	})

	t.Run("Upload2", func(t *testing.T) {
		t.Parallel()
		testWebDAVUploadWithPort(t, "test-file-2.txt")
	})
}

func testWebDAVUploadWithPort(t *testing.T, fileName string) {
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

	// Pull and start WebDAV container with specific port mapping
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "bytemark/webdav",
		Tag:        "latest",
		Env: []string{
			"AUTH_TYPE=Basic",
			fmt.Sprintf("USERNAME=%s", username),
			fmt.Sprintf("PASSWORD=%s", password),
		},
		ExposedPorts: []string{"80/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"80/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(availablePort)}},
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

	// Construct WebDAV URL
	webdavURL := fmt.Sprintf("http://localhost:%d", availablePort)

	// Wait for WebDAV service to be ready
	pool.MaxWait = 120 * time.Second
	err = pool.Retry(func() error {
		client := NewWebDAVClientBasicAuth(webdavURL, username, password)
		return client.Connect()
	})
	require.NoError(t, err)

	// Create test file with unique name
	tempFile := createTempTestFileWithName(t, fileName)
	defer os.Remove(tempFile)

	// Test WebDAV upload
	webdavClient := NewWebDAVClientBasicAuth(webdavURL, username, password)
	err = webdavClient.Connect()
	require.NoError(t, err)
	defer webdavClient.Close()

	remoteFilePath := fmt.Sprintf("/upload/%s", fileName)
	err = webdavClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	// Verify file exists in container
	verifyFileUpload(t, resource, remoteFilePath)
}

func testWebDAVAuth(t *testing.T, tc AuthTestCase) {
	t.Logf("Using port: %d for %s", tc.port, tc.name)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)

	runOptions := &dockertest.RunOptions{
		Repository:   "bytemark/webdav",
		Tag:          "latest",
		Env:          tc.dockerEnv,
		ExposedPorts: []string{"80/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"80/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(tc.port)}},
		},
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

	webdavURL := fmt.Sprintf("http://localhost:%d", tc.port)
	pool.MaxWait = 120 * time.Second

	// Wait for service to be ready with appropriate client
	err = pool.Retry(func() error {
		client := createWebDAVClient(tc, webdavURL)
		return client.Connect()
	})
	require.NoError(t, err)

	// Create test file
	tempFile := createTempTestFileWithName(t, tc.fileName)
	defer os.Remove(tempFile)

	// Test WebDAV upload
	webdavClient := createWebDAVClient(tc, webdavURL)
	err = webdavClient.Connect()
	require.NoError(t, err)
	defer webdavClient.Close()

	remoteFilePath := fmt.Sprintf("/upload/%s", tc.fileName)
	err = webdavClient.Upload(tempFile, remoteFilePath)
	assert.NoError(t, err)

	verifyFileUpload(t, resource, remoteFilePath)
}

func createWebDAVClient(tc AuthTestCase, url string) *WebDAVClient {
	switch tc.authType {
	case AuthBasic:
		return NewWebDAVClientBasicAuth(url, username, password)
	case AuthDigest:
		return NewWebDAVClientDigestAuth(url, username, password)
	default:
		panic(fmt.Sprintf("unsupported auth type: %d", tc.authType))
	}
}

// Helper functions (same as in main_test.go)
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

func createTempTestFile(t *testing.T) string {
	return createTempTestFileWithName(t, "test-file.txt")
}

func createTempTestFileWithName(t *testing.T, fileName string) string {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, fileName)

	content := fmt.Sprintf("Hello, WebDAV World!\nThis is a test file named %s for WebDAV upload.", fileName)
	err := os.WriteFile(tempFile, []byte(content), 0644)
	require.NoError(t, err)

	return tempFile
}

func verifyFileUpload(t *testing.T, resource *dockertest.Resource, remoteFilePath string) {
	// For WebDAV, we'll check if the file exists by trying to access it
	// The bytemark/webdav image stores files in /var/lib/dav/data
	fullPath := fmt.Sprintf("/var/lib/dav/data%s", remoteFilePath)
	exitCode, err := resource.Exec([]string{"test", "-f", fullPath}, dockertest.ExecOptions{})
	if err != nil || exitCode != 0 {
		// Try to list the directory contents for debugging
		dirPath := filepath.Dir(fullPath)
		output, lsErr := resource.Exec([]string{"ls", "-la", dirPath}, dockertest.ExecOptions{})
		if lsErr == nil {
			t.Logf("Listed %s directory for debugging, exit code: %d", dirPath, output)
		}
		// Also check parent directories
		output2, lsErr2 := resource.Exec([]string{"ls", "-la", "/var/lib/dav/data/"}, dockertest.ExecOptions{})
		if lsErr2 == nil {
			t.Logf("Listed /var/lib/dav/data/ directory for debugging, exit code: %d", output2)
		}
	}
	assert.Equal(t, 0, exitCode, "File should exist on the WebDAV server")
	assert.NoError(t, err, "Exec command should succeed")
}

func TestWebDAVDigestAuthWithNginx(t *testing.T) {
	// This test demonstrates digest auth using nginx with digest auth module
	// Skip this test if you don't have a suitable nginx image with digest auth
	t.Skip("Skipping digest auth test - requires special nginx image with digest auth module")

	// Example of how you would test digest auth with a proper server:
	// 1. Use an nginx image with ngx_http_auth_digest_module
	// 2. Configure nginx with digest authentication
	// 3. Test the digest auth client against it
}
