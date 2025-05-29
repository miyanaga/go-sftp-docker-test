package main

import (
	"fmt"
	"io"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type SFTPClient struct {
	host     string
	port     string
	username string
	password string
	client   *sftp.Client
	sshConn  *ssh.Client
}

func NewSFTPClient(host, port, username, password string) *SFTPClient {
	return &SFTPClient{
		host:     host,
		port:     port,
		username: username,
		password: password,
	}
}

func (s *SFTPClient) Connect() error {
	config := &ssh.ClientConfig{
		User: s.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.password),
		},
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
