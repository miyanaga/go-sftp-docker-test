package webdav

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

type AuthMethod int

const (
	AuthBasic AuthMethod = iota
	AuthDigest
)

type WebDAVClient struct {
	url        string
	username   string
	password   string
	authMethod AuthMethod
	client     *http.Client
	// For digest auth
	realm  string
	nonce  string
	opaque string
	qop    string
	nc     int
	cnonce string
}

func NewWebDAVClientBasicAuth(url, username, password string) *WebDAVClient {
	return &WebDAVClient{
		url:        strings.TrimRight(url, "/"),
		username:   username,
		password:   password,
		authMethod: AuthBasic,
		client:     &http.Client{Timeout: 30 * time.Second},
		nc:         1,
	}
}

func NewWebDAVClientDigestAuth(url, username, password string) *WebDAVClient {
	return &WebDAVClient{
		url:        strings.TrimRight(url, "/"),
		username:   username,
		password:   password,
		authMethod: AuthDigest,
		client:     &http.Client{Timeout: 30 * time.Second},
		nc:         1,
	}
}

func (w *WebDAVClient) Connect() error {
	// Test connection with OPTIONS request
	req, err := http.NewRequest("OPTIONS", w.url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if w.authMethod == AuthBasic {
		req.SetBasicAuth(w.username, w.password)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized && w.authMethod == AuthDigest {
		// Parse digest auth challenge
		authHeader := resp.Header.Get("WWW-Authenticate")
		if err := w.parseDigestChallenge(authHeader); err != nil {
			// If it's not a digest challenge, try basic auth
			if strings.Contains(authHeader, "Basic") {
				req, err = http.NewRequest("OPTIONS", w.url, nil)
				if err != nil {
					return fmt.Errorf("failed to create request: %w", err)
				}
				req.SetBasicAuth(w.username, w.password)
				resp2, err := w.client.Do(req)
				if err != nil {
					return fmt.Errorf("failed to connect with basic auth: %w", err)
				}
				defer resp2.Body.Close()
				if resp2.StatusCode >= 400 {
					return fmt.Errorf("connection failed with status: %d", resp2.StatusCode)
				}
				return nil
			}
			return fmt.Errorf("failed to parse digest challenge: %w", err)
		}

		// Retry with digest auth
		req, err = http.NewRequest("OPTIONS", w.url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		w.setDigestAuth(req, "OPTIONS", "")
		resp2, err := w.client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect with digest auth: %w", err)
		}
		defer resp2.Body.Close()

		if resp2.StatusCode >= 400 {
			return fmt.Errorf("connection failed with status: %d", resp2.StatusCode)
		}
	} else if resp.StatusCode >= 400 {
		return fmt.Errorf("connection failed with status: %d", resp.StatusCode)
	}

	return nil
}

func (w *WebDAVClient) Upload(localFilePath, remoteFilePath string) error {
	// Read local file
	data, err := os.ReadFile(localFilePath)
	if err != nil {
		return fmt.Errorf("failed to read local file: %w", err)
	}

	// Ensure remote path starts with /
	if !strings.HasPrefix(remoteFilePath, "/") {
		remoteFilePath = "/" + remoteFilePath
	}

	// Create parent directory if needed
	parentDir := path.Dir(remoteFilePath)
	if parentDir != "/" && parentDir != "." {
		if err := w.createDirectory(parentDir); err != nil {
			return fmt.Errorf("failed to create parent directory: %w", err)
		}
	}

	// Upload file
	fullURL := w.url + remoteFilePath
	req, err := http.NewRequest("PUT", fullURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create PUT request: %w", err)
	}

	// Set authentication
	if w.authMethod == AuthBasic {
		req.SetBasicAuth(w.username, w.password)
	} else if w.authMethod == AuthDigest {
		// First request without auth to get challenge
		resp, err := w.client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			authHeader := resp.Header.Get("WWW-Authenticate")
			if err := w.parseDigestChallenge(authHeader); err != nil {
				// If it's not a digest challenge, try basic auth
				if strings.Contains(authHeader, "Basic") {
					req, err = http.NewRequest("PUT", fullURL, bytes.NewReader(data))
					if err != nil {
						return fmt.Errorf("failed to create PUT request: %w", err)
					}
					req.SetBasicAuth(w.username, w.password)
				} else {
					return fmt.Errorf("failed to parse digest challenge: %w", err)
				}
			} else {
				// Retry with digest auth
				req, err = http.NewRequest("PUT", fullURL, bytes.NewReader(data))
				if err != nil {
					return fmt.Errorf("failed to create PUT request: %w", err)
				}
				w.setDigestAuth(req, "PUT", remoteFilePath)
			}
		}
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (w *WebDAVClient) createDirectory(dirPath string) error {
	fullURL := w.url + dirPath
	req, err := http.NewRequest("MKCOL", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create MKCOL request: %w", err)
	}

	if w.authMethod == AuthBasic {
		req.SetBasicAuth(w.username, w.password)
	} else if w.authMethod == AuthDigest {
		// First request without auth to get challenge
		resp, err := w.client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			authHeader := resp.Header.Get("WWW-Authenticate")
			if err := w.parseDigestChallenge(authHeader); err != nil {
				// If it's not a digest challenge, try basic auth
				if strings.Contains(authHeader, "Basic") {
					req, err = http.NewRequest("MKCOL", fullURL, nil)
					if err != nil {
						return fmt.Errorf("failed to create MKCOL request: %w", err)
					}
					req.SetBasicAuth(w.username, w.password)
				} else {
					return fmt.Errorf("failed to parse digest challenge: %w", err)
				}
			} else {
				// Retry with digest auth
				req, err = http.NewRequest("MKCOL", fullURL, nil)
				if err != nil {
					return fmt.Errorf("failed to create MKCOL request: %w", err)
				}
				w.setDigestAuth(req, "MKCOL", dirPath)
			}
		}
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	defer resp.Body.Close()

	// 201 Created or 405 Method Not Allowed (directory already exists) are OK
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusMethodNotAllowed {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create directory with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (w *WebDAVClient) parseDigestChallenge(authHeader string) error {
	if !strings.HasPrefix(authHeader, "Digest ") {
		return fmt.Errorf("not a digest challenge")
	}

	params := make(map[string]string)
	parts := strings.Split(authHeader[7:], ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			key := kv[0]
			value := strings.Trim(kv[1], `"`)
			params[key] = value
		}
	}

	w.realm = params["realm"]
	w.nonce = params["nonce"]
	w.opaque = params["opaque"]
	w.qop = params["qop"]

	// Generate client nonce
	b := make([]byte, 16)
	rand.Read(b)
	w.cnonce = hex.EncodeToString(b)

	return nil
}

func (w *WebDAVClient) setDigestAuth(req *http.Request, method, uri string) {
	ha1 := w.md5Hash(fmt.Sprintf("%s:%s:%s", w.username, w.realm, w.password))
	ha2 := w.md5Hash(fmt.Sprintf("%s:%s", method, uri))

	nc := fmt.Sprintf("%08x", w.nc)

	var response string
	if w.qop == "auth" || w.qop == "auth-int" {
		response = w.md5Hash(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, w.nonce, nc, w.cnonce, "auth", ha2))
	} else {
		response = w.md5Hash(fmt.Sprintf("%s:%s:%s", ha1, w.nonce, ha2))
	}

	authValue := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		w.username, w.realm, w.nonce, uri, response)

	if w.qop != "" {
		authValue += fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s"`, nc, w.cnonce)
	}

	if w.opaque != "" {
		authValue += fmt.Sprintf(`, opaque="%s"`, w.opaque)
	}

	req.Header.Set("Authorization", authValue)
	w.nc++
}

func (w *WebDAVClient) md5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (w *WebDAVClient) Close() error {
	// HTTP client doesn't need explicit closing
	return nil
}
