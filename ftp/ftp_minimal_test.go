package ftp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFTPConnectionPatterns demonstrates the 2 FTP connection patterns
func TestFTPConnectionPatterns(t *testing.T) {
	patterns := []struct {
		Name   string
		UseTLS bool
	}{
		{
			Name:   "FTP_PassiveMode_NoEncryption",
			UseTLS: false,
		},
		{
			Name:   "FTPS_PassiveMode_WithEncryption",
			UseTLS: true,
		},
	}

	for _, pattern := range patterns {
		t.Run(pattern.Name, func(t *testing.T) {
			// Create client configuration
			cfg := SimpleFTPConfig{
				Host:     "ftp.example.com",
				Port:     "21",
				Username: "testuser",
				Password: "testpass",
				UseTLS:   pattern.UseTLS,
			}

			// Create client
			client := NewSimpleFTPClient(cfg)
			require.NotNil(t, client)

			// Verify configuration
			assert.Equal(t, "ftp.example.com", client.host)
			assert.Equal(t, "21", client.port)
			assert.Equal(t, "testuser", client.username)
			assert.Equal(t, "testpass", client.password)
			assert.Equal(t, pattern.UseTLS, client.useTLS)

			if pattern.UseTLS {
				assert.NotNil(t, client.tlsConfig, "TLS config should be set for FTPS")
			} else {
				assert.Nil(t, client.tlsConfig, "TLS config should be nil for plain FTP")
			}

			t.Logf("Pattern: %s - UseTLS: %v", pattern.Name, pattern.UseTLS)
		})
	}
}

// TestFTPClientOperations tests client operations without actual connection
func TestFTPClientOperations(t *testing.T) {
	cfg := SimpleFTPConfig{
		Host:     "localhost",
		Port:     "21",
		Username: "test",
		Password: "test",
		UseTLS:   false,
	}
	client := NewSimpleFTPClient(cfg)

	// Test operations return appropriate errors when not connected
	operations := []struct {
		Name string
		Test func(t *testing.T)
	}{
		{
			Name: "Upload",
			Test: func(t *testing.T) {
				err := client.Upload("local.txt", "remote.txt")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not connected")
			},
		},
		{
			Name: "Download",
			Test: func(t *testing.T) {
				err := client.Download("remote.txt", "local.txt")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not connected")
			},
		},
		{
			Name: "List",
			Test: func(t *testing.T) {
				_, err := client.List("/")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not connected")
			},
		},
		{
			Name: "Delete",
			Test: func(t *testing.T) {
				err := client.Delete("file.txt")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not connected")
			},
		},
	}

	for _, op := range operations {
		t.Run(op.Name, op.Test)
	}
}
