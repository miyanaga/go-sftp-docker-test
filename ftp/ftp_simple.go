package ftp

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
)

// SimpleFTPClient is a simplified FTP client that only supports Passive mode
type SimpleFTPClient struct {
	host      string
	port      string
	username  string
	password  string
	useTLS    bool
	client    *ftp.ServerConn
	tlsConfig *tls.Config
}

// SimpleFTPConfig holds configuration for SimpleFTPClient
type SimpleFTPConfig struct {
	Host      string
	Port      string
	Username  string
	Password  string
	UseTLS    bool
	TLSConfig *tls.Config
}

// NewSimpleFTPClient creates a new SimpleFTPClient instance
func NewSimpleFTPClient(cfg SimpleFTPConfig) *SimpleFTPClient {
	if cfg.Port == "" {
		cfg.Port = "21"
	}

	if cfg.TLSConfig == nil && cfg.UseTLS {
		cfg.TLSConfig = &tls.Config{
			InsecureSkipVerify: true, // For testing purposes
			ServerName:         cfg.Host,
		}
	}

	return &SimpleFTPClient{
		host:      cfg.Host,
		port:      cfg.Port,
		username:  cfg.Username,
		password:  cfg.Password,
		useTLS:    cfg.UseTLS,
		tlsConfig: cfg.TLSConfig,
	}
}

// Connect establishes connection to the FTP server
func (f *SimpleFTPClient) Connect() error {
	addr := fmt.Sprintf("%s:%s", f.host, f.port)

	var conn *ftp.ServerConn
	var err error

	// Connect with timeout
	dialOptions := []ftp.DialOption{
		ftp.DialWithTimeout(30 * time.Second),
	}

	if f.useTLS {
		// For FTPS, use explicit TLS option
		dialOptions = append(dialOptions, ftp.DialWithExplicitTLS(f.tlsConfig))
	}

	conn, err = ftp.Dial(addr, dialOptions...)
	if err != nil {
		return fmt.Errorf("failed to dial FTP server: %w", err)
	}

	// Login
	err = conn.Login(f.username, f.password)
	if err != nil {
		conn.Quit()
		return fmt.Errorf("failed to login: %w", err)
	}

	// Set binary mode (TYPE I)
	err = conn.Type(ftp.TransferTypeBinary)
	if err != nil {
		conn.Quit()
		return fmt.Errorf("failed to set binary mode: %w", err)
	}

	f.client = conn
	return nil
}

// Close closes the FTP connection
func (f *SimpleFTPClient) Close() error {
	if f.client != nil {
		return f.client.Quit()
	}
	return nil
}

// Upload uploads a local file to the FTP server
func (f *SimpleFTPClient) Upload(localFilePath, remoteFilePath string) error {
	if f.client == nil {
		return fmt.Errorf("FTP client not connected")
	}

	// Open local file
	file, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer file.Close()

	// Ensure directory exists
	remoteDir := path.Dir(remoteFilePath)
	if remoteDir != "." && remoteDir != "/" {
		// Try to create directory, ignore error if it already exists
		_ = f.client.MakeDir(remoteDir)
	}

	// Upload file
	err = f.client.Stor(remoteFilePath, file)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	return nil
}

// Download downloads a file from the FTP server
func (f *SimpleFTPClient) Download(remoteFilePath, localFilePath string) error {
	if f.client == nil {
		return fmt.Errorf("FTP client not connected")
	}

	// Create local directory if needed
	localDir := path.Dir(localFilePath)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Download file
	resp, err := f.client.Retr(remoteFilePath)
	if err != nil {
		return fmt.Errorf("failed to retrieve file: %w", err)
	}
	defer resp.Close()

	// Create local file
	file, err := os.Create(localFilePath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer file.Close()

	// Copy content
	_, err = io.Copy(file, resp)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// List lists files in a directory
func (f *SimpleFTPClient) List(dirPath string) ([]string, error) {
	if f.client == nil {
		return nil, fmt.Errorf("FTP client not connected")
	}

	entries, err := f.client.List(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.Type == ftp.EntryTypeFile {
			// Build full path
			fullPath := path.Join(dirPath, entry.Name)
			fullPath = strings.TrimPrefix(fullPath, "/")
			files = append(files, fullPath)
		}
	}

	return files, nil
}

// Delete deletes a file on the FTP server
func (f *SimpleFTPClient) Delete(remoteFilePath string) error {
	if f.client == nil {
		return fmt.Errorf("FTP client not connected")
	}

	err := f.client.Delete(remoteFilePath)
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}
