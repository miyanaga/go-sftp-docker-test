package minio

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
	minioImage      = "minio/minio:latest"
	accessKeyID     = "minioadmin"
	secretAccessKey = "minioadmin"
	bucketName      = "test-bucket"
)

type S3TestCase struct {
	name            string
	endpoint        string
	accessKeyID     string
	secretAccessKey string
	bucketName      string
	useDocker       bool
	usePathStyle    bool
	region          string
	skipTest        bool
	setupFunc       func(*testing.T) (teardown func())
}

func TestS3Operations(t *testing.T) {
	// Find available port for MinIO
	minioPort, err := findAvailablePort()
	require.NoError(t, err)

	testCases := []S3TestCase{
		{
			name:            "MinIO_Basic",
			endpoint:        fmt.Sprintf("http://localhost:%d", minioPort),
			accessKeyID:     accessKeyID,
			secretAccessKey: secretAccessKey,
			bucketName:      bucketName,
			useDocker:       true,
			usePathStyle:    true,
			region:          "us-east-1",
		},
		{
			name:            "MinIO_CustomBucket",
			endpoint:        fmt.Sprintf("http://localhost:%d", minioPort),
			accessKeyID:     accessKeyID,
			secretAccessKey: secretAccessKey,
			bucketName:      "custom-bucket",
			useDocker:       true,
			usePathStyle:    true,
			region:          "us-east-1",
		},
		// Placeholder for real AWS S3 test
		{
			name:            "AWS_S3_Real",
			endpoint:        "", // Use default AWS endpoint
			accessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			secretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			bucketName:      os.Getenv("AWS_S3_BUCKET"),
			useDocker:       false,
			usePathStyle:    false,
			region:          "us-east-1",
			skipTest:        os.Getenv("AWS_ACCESS_KEY_ID") == "",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipTest {
				t.Skip("Skipping test - environment variables not set")
			}

			var teardown func()
			if tc.useDocker {
				teardown = setupMinIOContainer(t, minioPort)
				defer teardown()
			} else if tc.setupFunc != nil {
				teardown = tc.setupFunc(t)
				defer teardown()
			}

			// Run test operations
			testS3Operations(t, tc)
		})
	}
}

func TestS3Upload(t *testing.T) {
	// Find available port
	availablePort, err := findAvailablePort()
	require.NoError(t, err)
	t.Logf("Using port: %d", availablePort)

	// Setup MinIO container
	teardown := setupMinIOContainer(t, availablePort)
	defer teardown()

	// Create S3 client
	cfg := S3Config{
		Endpoint:        fmt.Sprintf("http://localhost:%d", availablePort),
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		BucketName:      bucketName,
		UsePathStyle:    true,
		Region:          "us-east-1",
	}
	client := NewS3Client(cfg)

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)
	defer client.Close()

	// Create test file
	tempFile := createTempTestFile(t)
	defer os.Remove(tempFile)

	// Test upload
	remoteFilePath := "upload/test-file.txt"
	err = client.Upload(ctx, tempFile, remoteFilePath)
	assert.NoError(t, err)

	// Verify file exists
	files, err := client.List(ctx, "upload/")
	require.NoError(t, err)
	assert.Contains(t, files, remoteFilePath)
}

func TestS3UploadMultiple(t *testing.T) {
	// Test that multiple tests can run concurrently with different ports
	t.Run("Upload1", func(t *testing.T) {
		t.Parallel()
		testS3UploadWithPort(t, "test-file-1.txt")
	})

	t.Run("Upload2", func(t *testing.T) {
		t.Parallel()
		testS3UploadWithPort(t, "test-file-2.txt")
	})
}

func testS3UploadWithPort(t *testing.T, fileName string) {
	// Find available port
	availablePort, err := findAvailablePort()
	require.NoError(t, err)
	t.Logf("Using port: %d for %s", availablePort, fileName)

	// Setup MinIO container
	teardown := setupMinIOContainer(t, availablePort)
	defer teardown()

	// Create S3 client
	cfg := S3Config{
		Endpoint:        fmt.Sprintf("http://localhost:%d", availablePort),
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		BucketName:      bucketName,
		UsePathStyle:    true,
		Region:          "us-east-1",
	}
	client := NewS3Client(cfg)

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)
	defer client.Close()

	// Create test file with unique name
	tempFile := createTempTestFileWithName(t, fileName)
	defer os.Remove(tempFile)

	// Test upload
	remoteFilePath := fmt.Sprintf("upload/%s", fileName)
	err = client.Upload(ctx, tempFile, remoteFilePath)
	assert.NoError(t, err)

	// Verify file exists
	files, err := client.List(ctx, "upload/")
	require.NoError(t, err)
	assert.Contains(t, files, remoteFilePath)
}

func testS3Operations(t *testing.T, tc S3TestCase) {
	ctx := context.Background()

	// Create S3 client
	cfg := S3Config{
		Endpoint:        tc.endpoint,
		AccessKeyID:     tc.accessKeyID,
		SecretAccessKey: tc.secretAccessKey,
		BucketName:      tc.bucketName,
		UsePathStyle:    tc.usePathStyle,
		Region:          tc.region,
	}
	client := NewS3Client(cfg)

	err := client.Connect(ctx)
	require.NoError(t, err)
	defer client.Close()

	// Test upload
	tempFile := createTempTestFileWithName(t, fmt.Sprintf("%s-test.txt", tc.name))
	defer os.Remove(tempFile)

	remoteFilePath := fmt.Sprintf("test/%s/upload-test.txt", tc.name)
	err = client.Upload(ctx, tempFile, remoteFilePath)
	require.NoError(t, err)

	// Test list
	files, err := client.List(ctx, fmt.Sprintf("test/%s/", tc.name))
	require.NoError(t, err)
	assert.Contains(t, files, remoteFilePath)

	// Test download
	downloadPath := filepath.Join(t.TempDir(), "downloaded.txt")
	err = client.Download(ctx, remoteFilePath, downloadPath)
	require.NoError(t, err)

	// Verify downloaded content
	originalContent, err := os.ReadFile(tempFile)
	require.NoError(t, err)
	downloadedContent, err := os.ReadFile(downloadPath)
	require.NoError(t, err)
	assert.Equal(t, originalContent, downloadedContent)

	// Test delete
	err = client.Delete(ctx, remoteFilePath)
	require.NoError(t, err)

	// Verify deletion
	files, err = client.List(ctx, fmt.Sprintf("test/%s/", tc.name))
	require.NoError(t, err)
	assert.NotContains(t, files, remoteFilePath)

	// Test multiple uploads and batch delete
	var uploadedFiles []string
	for i := 0; i < 3; i++ {
		testFile := createTempTestFileWithName(t, fmt.Sprintf("%s-batch-%d.txt", tc.name, i))
		defer os.Remove(testFile)

		remotePath := fmt.Sprintf("test/%s/batch/file-%d.txt", tc.name, i)
		err = client.Upload(ctx, testFile, remotePath)
		require.NoError(t, err)
		uploadedFiles = append(uploadedFiles, remotePath)
	}

	// Verify all files uploaded
	files, err = client.List(ctx, fmt.Sprintf("test/%s/batch/", tc.name))
	require.NoError(t, err)
	assert.Len(t, files, 3)

	// Test batch delete
	err = client.DeleteMultiple(ctx, uploadedFiles)
	require.NoError(t, err)

	// Verify batch deletion
	files, err = client.List(ctx, fmt.Sprintf("test/%s/batch/", tc.name))
	require.NoError(t, err)
	assert.Len(t, files, 0)
}

func setupMinIOContainer(t *testing.T, port int) func() {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	err = pool.Client.Ping()
	require.NoError(t, err)

	// Pull and start MinIO container
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "minio/minio",
		Tag:        "latest",
		Cmd:        []string{"server", "/data"},
		Env: []string{
			fmt.Sprintf("MINIO_ROOT_USER=%s", accessKeyID),
			fmt.Sprintf("MINIO_ROOT_PASSWORD=%s", secretAccessKey),
		},
		ExposedPorts: []string{"9000/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9000/tcp": {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(port)}},
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	require.NoError(t, err)

	// Wait for MinIO to be ready
	pool.MaxWait = 120 * time.Second
	err = pool.Retry(func() error {
		cfg := S3Config{
			Endpoint:        fmt.Sprintf("http://localhost:%d", port),
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
			BucketName:      bucketName,
			UsePathStyle:    true,
			Region:          "us-east-1",
		}
		client := NewS3Client(cfg)
		return client.Connect(context.Background())
	})
	require.NoError(t, err)

	return func() {
		if err := pool.Purge(resource); err != nil {
			log.Printf("Could not purge resource: %s", err)
		}
	}
}

// Helper functions
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

	content := fmt.Sprintf("Hello, S3 World!\nThis is a test file named %s for S3 upload.", fileName)
	err := os.WriteFile(tempFile, []byte(content), 0644)
	require.NoError(t, err)

	return tempFile
}
