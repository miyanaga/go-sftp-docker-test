package minio

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Client struct {
	endpoint        string
	accessKeyID     string
	secretAccessKey string
	bucketName      string
	usePathStyle    bool
	region          string
	client          *s3.Client
}

type S3Config struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	BucketName      string
	UsePathStyle    bool
	Region          string
}

func NewS3Client(cfg S3Config) *S3Client {
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return &S3Client{
		endpoint:        cfg.Endpoint,
		accessKeyID:     cfg.AccessKeyID,
		secretAccessKey: cfg.SecretAccessKey,
		bucketName:      cfg.BucketName,
		usePathStyle:    cfg.UsePathStyle,
		region:          cfg.Region,
	}
}

func (s *S3Client) Connect(ctx context.Context) error {
	// Create custom endpoint resolver
	customResolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			if s.endpoint != "" {
				return aws.Endpoint{
					URL:               s.endpoint,
					SigningRegion:     s.region,
					HostnameImmutable: true,
				}, nil
			}
			// Fallback to default resolution
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})

	// Create AWS config with custom endpoint
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(s.region),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(s.accessKeyID, s.secretAccessKey, ""),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create S3 client with path style if needed (for MinIO)
	s.client = s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = s.usePathStyle
	})

	// Test connection by checking if bucket exists
	_, err = s.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(s.bucketName),
	})
	if err != nil {
		// If bucket doesn't exist, try to create it
		_, createErr := s.client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(s.bucketName),
		})
		if createErr != nil {
			return fmt.Errorf("bucket check failed: %w, create failed: %w", err, createErr)
		}
	}

	return nil
}

func (s *S3Client) Upload(ctx context.Context, localFilePath, remoteFilePath string) error {
	if s.client == nil {
		return fmt.Errorf("S3 client not connected")
	}

	// Open local file
	file, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer file.Close()

	// Get file info for content length
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Ensure remote path doesn't start with /
	remoteFilePath = strings.TrimPrefix(remoteFilePath, "/")

	// Upload file
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucketName),
		Key:           aws.String(remoteFilePath),
		Body:          file,
		ContentLength: aws.Int64(fileInfo.Size()),
	})
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	return nil
}

func (s *S3Client) Download(ctx context.Context, remoteFilePath, localFilePath string) error {
	if s.client == nil {
		return fmt.Errorf("S3 client not connected")
	}

	// Ensure remote path doesn't start with /
	remoteFilePath = strings.TrimPrefix(remoteFilePath, "/")

	// Get object
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(remoteFilePath),
	})
	if err != nil {
		return fmt.Errorf("failed to get object: %w", err)
	}
	defer result.Body.Close()

	// Create local file directory if needed
	localDir := filepath.Dir(localFilePath)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create local file
	file, err := os.Create(localFilePath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer file.Close()

	// Copy content
	_, err = io.Copy(file, result.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func (s *S3Client) List(ctx context.Context, prefix string) ([]string, error) {
	if s.client == nil {
		return nil, fmt.Errorf("S3 client not connected")
	}

	// Ensure prefix doesn't start with /
	prefix = strings.TrimPrefix(prefix, "/")

	var files []string
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucketName),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range page.Contents {
			if obj.Key != nil {
				files = append(files, *obj.Key)
			}
		}
	}

	return files, nil
}

func (s *S3Client) Delete(ctx context.Context, remoteFilePath string) error {
	if s.client == nil {
		return fmt.Errorf("S3 client not connected")
	}

	// Ensure remote path doesn't start with /
	remoteFilePath = strings.TrimPrefix(remoteFilePath, "/")

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(remoteFilePath),
	})
	if err != nil {
		return fmt.Errorf("failed to delete object: %w", err)
	}

	return nil
}

func (s *S3Client) DeleteMultiple(ctx context.Context, remoteFilePaths []string) error {
	if s.client == nil {
		return fmt.Errorf("S3 client not connected")
	}

	if len(remoteFilePaths) == 0 {
		return nil
	}

	// Build delete objects
	var deleteObjects []types.ObjectIdentifier
	for _, path := range remoteFilePaths {
		path = strings.TrimPrefix(path, "/")
		deleteObjects = append(deleteObjects, types.ObjectIdentifier{
			Key: aws.String(path),
		})
	}

	_, err := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(s.bucketName),
		Delete: &types.Delete{
			Objects: deleteObjects,
			Quiet:   aws.Bool(true),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete objects: %w", err)
	}

	return nil
}

func (s *S3Client) Close() error {
	// AWS SDK client doesn't need explicit closing
	return nil
}
