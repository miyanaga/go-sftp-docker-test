package main

import (
	"fmt"
	"io"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type AuthMethod int

const (
	AuthPassword AuthMethod = iota
	AuthPrivateKey
	AuthPrivateKeyWithPassphrase
)

type SFTPClient struct {
	host       string
	port       string
	username   string
	password   string
	privateKey string
	passphrase string
	authMethod AuthMethod
	client     *sftp.Client
	sshConn    *ssh.Client
}

func NewSFTPClient(host, port, username, password string) *SFTPClient {
	return &SFTPClient{
		host:       host,
		port:       port,
		username:   username,
		password:   password,
		authMethod: AuthPassword,
	}
}

func NewSFTPClientWithPrivateKey(host, port, username, privateKeyPath string) *SFTPClient {
	return &SFTPClient{
		host:       host,
		port:       port,
		username:   username,
		privateKey: privateKeyPath,
		authMethod: AuthPrivateKey,
	}
}

func NewSFTPClientWithPrivateKeyAndPassphrase(host, port, username, privateKeyPath, passphrase string) *SFTPClient {
	return &SFTPClient{
		host:       host,
		port:       port,
		username:   username,
		privateKey: privateKeyPath,
		passphrase: passphrase,
		authMethod: AuthPrivateKeyWithPassphrase,
	}
}

func (s *SFTPClient) Connect() error {
	var authMethods []ssh.AuthMethod

	switch s.authMethod {
	case AuthPassword:
		authMethods = []ssh.AuthMethod{
			ssh.Password(s.password),
		}
	case AuthPrivateKey:
		key, err := os.ReadFile(s.privateKey)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	case AuthPrivateKeyWithPassphrase:
		key, err := os.ReadFile(s.privateKey)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(s.passphrase))
		if err != nil {
			return fmt.Errorf("failed to parse private key with passphrase: %w", err)
		}
		authMethods = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	default:
		return fmt.Errorf("unsupported authentication method")
	}

	config := &ssh.ClientConfig{
		User:            s.username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("%s:%s", s.host, s.port)
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to dial SSH: %w", err)
	}
	s.sshConn = conn

	client, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}
	s.client = client

	return nil
}

func (s *SFTPClient) Close() error {
	if s.client != nil {
		s.client.Close()
	}
	if s.sshConn != nil {
		return s.sshConn.Close()
	}
	return nil
}

func (s *SFTPClient) Upload(localFilePath, remoteFilePath string) error {
	if s.client == nil {
		return fmt.Errorf("SFTP client not connected")
	}

	localFile, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer localFile.Close()

	remoteFile, err := s.client.Create(remoteFilePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer remoteFile.Close()

	_, err = io.Copy(remoteFile, localFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

func main() {
	fmt.Println("SFTP Client for Docker Test")
}
