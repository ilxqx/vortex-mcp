package transfer

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ilxqx/vortex-mcp/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	defaultSSHPort    = 22
	defaultSSHTimeout = 60
	maxFileSize       = 100 * 1024 * 1024 // 100MB
	bufferSize        = 32 * 1024         // 32KB
)

type UploadInput struct {
	Server     string `json:"server" jsonschema:"Pre-configured server name from VORTEX_SSH_SERVERS"`
	LocalPath  string `json:"local_path" jsonschema:"Absolute path to the local file to upload"`
	RemotePath string `json:"remote_path" jsonschema:"Absolute path for the remote destination"`
}

type UploadOutput struct {
	Message      string `json:"message" jsonschema:"Human-readable result message"`
	BytesWritten int64  `json:"bytes_written" jsonschema:"Number of bytes transferred"`
}

type DownloadInput struct {
	Server     string `json:"server" jsonschema:"Pre-configured server name from VORTEX_SSH_SERVERS"`
	RemotePath string `json:"remote_path" jsonschema:"Absolute path to the remote file to download"`
	LocalPath  string `json:"local_path" jsonschema:"Absolute path for the local destination"`
}

type DownloadOutput struct {
	Message      string `json:"message" jsonschema:"Human-readable result message"`
	BytesWritten int64  `json:"bytes_written" jsonschema:"Number of bytes transferred"`
}

func Register(s *mcp.Server) {
	mcp.AddTool(
		s,
		&mcp.Tool{
			Name:        "transfer_upload",
			Title:       "Upload File via SFTP",
			Description: "Upload a local file to a remote host via SFTP. Maximum file size is 100MB. Server must be pre-configured via VORTEX_SSH_SERVERS environment variable.",
		},
		executeUpload,
	)

	mcp.AddTool(
		s,
		&mcp.Tool{
			Name:        "transfer_download",
			Title:       "Download File via SFTP",
			Description: "Download a file from a remote host to local filesystem via SFTP. Maximum file size is 100MB. Server must be pre-configured via VORTEX_SSH_SERVERS environment variable.",
		},
		executeDownload,
	)
}

type resolvedConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	KeyFile  string
}

func resolveConfig(serverName string) (*resolvedConfig, error) {
	if serverName == "" {
		return nil, fmt.Errorf("server name is required")
	}

	serverCfg, err := config.GetServer(serverName)
	if err != nil {
		return nil, err
	}

	cfg := &resolvedConfig{
		Host:     serverCfg.Host,
		Port:     serverCfg.Port,
		User:     serverCfg.User,
		Password: serverCfg.Password,
		KeyFile:  serverCfg.KeyFile,
	}

	if cfg.Port == 0 {
		cfg.Port = defaultSSHPort
	}

	return cfg, nil
}

func executeUpload(ctx context.Context, req *mcp.CallToolRequest, input UploadInput) (*mcp.CallToolResult, UploadOutput, error) {
	if input.LocalPath == "" || input.RemotePath == "" {
		return nil, UploadOutput{}, fmt.Errorf("local_path and remote_path are required")
	}

	cfg, err := resolveConfig(input.Server)
	if err != nil {
		return nil, UploadOutput{}, err
	}

	fileInfo, err := os.Stat(input.LocalPath)
	if err != nil {
		return nil, UploadOutput{}, fmt.Errorf("local file error: %w", err)
	}
	if fileInfo.IsDir() {
		return nil, UploadOutput{}, fmt.Errorf("local_path must be a file, not a directory")
	}
	if fileInfo.Size() > maxFileSize {
		return nil, UploadOutput{}, fmt.Errorf("file too large: %d bytes (max: %d bytes)", fileInfo.Size(), maxFileSize)
	}

	client, err := dialSSH(ctx, cfg)
	if err != nil {
		return nil, UploadOutput{}, fmt.Errorf("SSH connection failed: %w", err)
	}
	defer func() { _ = client.Close() }()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return nil, UploadOutput{}, fmt.Errorf("SFTP client failed: %w", err)
	}
	defer func() { _ = sftpClient.Close() }()

	srcFile, err := os.Open(input.LocalPath)
	if err != nil {
		return nil, UploadOutput{}, fmt.Errorf("failed to open local file: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	dstFile, err := sftpClient.Create(input.RemotePath)
	if err != nil {
		return nil, UploadOutput{}, fmt.Errorf("failed to create remote file: %w", err)
	}
	defer func() { _ = dstFile.Close() }()

	buf := make([]byte, bufferSize)
	written, err := io.CopyBuffer(dstFile, srcFile, buf)
	if err != nil {
		return nil, UploadOutput{}, fmt.Errorf("upload failed: %w", err)
	}

	return nil, UploadOutput{
		Message:      fmt.Sprintf("Successfully uploaded %s to %s:%s", filepath.Base(input.LocalPath), cfg.Host, input.RemotePath),
		BytesWritten: written,
	}, nil
}

func executeDownload(ctx context.Context, req *mcp.CallToolRequest, input DownloadInput) (*mcp.CallToolResult, DownloadOutput, error) {
	if input.RemotePath == "" || input.LocalPath == "" {
		return nil, DownloadOutput{}, fmt.Errorf("remote_path and local_path are required")
	}

	cfg, err := resolveConfig(input.Server)
	if err != nil {
		return nil, DownloadOutput{}, err
	}

	client, err := dialSSH(ctx, cfg)
	if err != nil {
		return nil, DownloadOutput{}, fmt.Errorf("SSH connection failed: %w", err)
	}
	defer func() { _ = client.Close() }()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return nil, DownloadOutput{}, fmt.Errorf("SFTP client failed: %w", err)
	}
	defer func() { _ = sftpClient.Close() }()

	remoteInfo, err := sftpClient.Stat(input.RemotePath)
	if err != nil {
		return nil, DownloadOutput{}, fmt.Errorf("remote file error: %w", err)
	}
	if remoteInfo.IsDir() {
		return nil, DownloadOutput{}, fmt.Errorf("remote_path must be a file, not a directory")
	}
	if remoteInfo.Size() > maxFileSize {
		return nil, DownloadOutput{}, fmt.Errorf("file too large: %d bytes (max: %d bytes)", remoteInfo.Size(), maxFileSize)
	}

	srcFile, err := sftpClient.Open(input.RemotePath)
	if err != nil {
		return nil, DownloadOutput{}, fmt.Errorf("failed to open remote file: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	localDir := filepath.Dir(input.LocalPath)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return nil, DownloadOutput{}, fmt.Errorf("failed to create local directory: %w", err)
	}

	dstFile, err := os.Create(input.LocalPath)
	if err != nil {
		return nil, DownloadOutput{}, fmt.Errorf("failed to create local file: %w", err)
	}
	defer func() { _ = dstFile.Close() }()

	buf := make([]byte, bufferSize)
	written, err := io.CopyBuffer(dstFile, srcFile, buf)
	if err != nil {
		return nil, DownloadOutput{}, fmt.Errorf("download failed: %w", err)
	}

	return nil, DownloadOutput{
		Message:      fmt.Sprintf("Successfully downloaded %s:%s to %s", cfg.Host, input.RemotePath, input.LocalPath),
		BytesWritten: written,
	}, nil
}

// Auth priority: password > key file > SSH agent
func buildAuthMethods(cfg *resolvedConfig) ([]gossh.AuthMethod, error) {
	var auths []gossh.AuthMethod

	if cfg.Password != "" {
		auths = append(auths, gossh.Password(cfg.Password))
	}

	if cfg.KeyFile != "" {
		key, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		signer, err := gossh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key file: %w", err)
		}
		auths = append(auths, gossh.PublicKeys(signer))
	}

	if sshAgent := getSSHAgent(); sshAgent != nil {
		auths = append(auths, gossh.PublicKeysCallback(sshAgent.Signers))
	}

	if len(auths) == 0 {
		return nil, fmt.Errorf("no authentication method available (password, key_file, or SSH agent required)")
	}

	return auths, nil
}

func getSSHAgent() agent.Agent {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil
	}

	return agent.NewClient(conn)
}

func dialSSH(ctx context.Context, cfg *resolvedConfig) (*gossh.Client, error) {
	auths, err := buildAuthMethods(cfg)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(defaultSSHTimeout) * time.Second
	sshConfig := &gossh.ClientConfig{
		User:            cfg.User,
		Auth:            auths,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	dialer := net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	c, newCh, reqs, err := gossh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return gossh.NewClient(c, newCh, reqs), nil
}
