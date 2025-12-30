package transfer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ilxqx/vortex-mcp/internal/config"
	"github.com/ilxqx/vortex-mcp/internal/sshpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/sftp"
)

const (
	defaultSSHPort    = 22
	defaultSSHTimeout = 60
	maxFileSize       = 100 * 1024 * 1024 // 100MB
	bufferSize        = 32 * 1024         // 32KB
)

type UploadInput struct {
	Server     string `json:"server" jsonschema:"Name of a pre-configured SSH server. Use ssh_list_servers tool first to get available server names."`
	LocalPath  string `json:"local_path" jsonschema:"Absolute path to the local file to upload. Must be a file, not a directory."`
	RemotePath string `json:"remote_path" jsonschema:"Absolute path for the destination on the remote server. Parent directory must exist."`
}

type UploadOutput struct {
	Message      string `json:"message" jsonschema:"Human-readable success message with transfer details."`
	BytesWritten int64  `json:"bytes_written" jsonschema:"Total number of bytes transferred."`
}

type DownloadInput struct {
	Server     string `json:"server" jsonschema:"Name of a pre-configured SSH server. Use ssh_list_servers tool first to get available server names."`
	RemotePath string `json:"remote_path" jsonschema:"Absolute path to the file on the remote server. Must be a file, not a directory."`
	LocalPath  string `json:"local_path" jsonschema:"Absolute path for the local destination. Parent directories will be created if needed."`
}

type DownloadOutput struct {
	Message      string `json:"message" jsonschema:"Human-readable success message with transfer details."`
	BytesWritten int64  `json:"bytes_written" jsonschema:"Total number of bytes transferred."`
}

func Register(s *mcp.Server) {
	mcp.AddTool(
		s,
		&mcp.Tool{
			Name:        "transfer_upload",
			Title:       "Upload File via SFTP",
			Description: "Upload a local file to a remote server via SFTP. Use this tool to copy files from local machine to remote servers. Maximum file size: 100MB. Call ssh_list_servers first to get available server names.",
		},
		executeUpload,
	)

	mcp.AddTool(
		s,
		&mcp.Tool{
			Name:        "transfer_download",
			Title:       "Download File via SFTP",
			Description: "Download a file from a remote server to local machine via SFTP. Use this tool to copy files from remote servers to local filesystem. Maximum file size: 100MB. Call ssh_list_servers first to get available server names.",
		},
		executeDownload,
	)
}

func getPoolConfig(serverName string) (*sshpool.Config, *config.ServerConfig, error) {
	if serverName == "" {
		return nil, nil, fmt.Errorf("server name is required")
	}

	serverCfg, err := config.GetServer(serverName)
	if err != nil {
		return nil, nil, err
	}

	port := serverCfg.Port
	if port == 0 {
		port = defaultSSHPort
	}

	timeout := serverCfg.Timeout
	if timeout == 0 {
		timeout = defaultSSHTimeout
	}

	poolCfg := &sshpool.Config{
		Host:     serverCfg.Host,
		Port:     port,
		User:     serverCfg.User,
		Password: serverCfg.Password,
		KeyFile:  serverCfg.KeyFile,
		Timeout:  time.Duration(timeout) * time.Second,
	}

	return poolCfg, serverCfg, nil
}

func executeUpload(ctx context.Context, req *mcp.CallToolRequest, input UploadInput) (*mcp.CallToolResult, UploadOutput, error) {
	if input.LocalPath == "" || input.RemotePath == "" {
		return nil, UploadOutput{}, fmt.Errorf("local_path and remote_path are required")
	}

	poolCfg, serverCfg, err := getPoolConfig(input.Server)
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

	client, err := sshpool.Default().Get(ctx, poolCfg)
	if err != nil {
		return nil, UploadOutput{}, fmt.Errorf("SSH connection failed: %w", err)
	}

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
		Message:      fmt.Sprintf("Successfully uploaded %s to %s:%s", filepath.Base(input.LocalPath), serverCfg.Host, input.RemotePath),
		BytesWritten: written,
	}, nil
}

func executeDownload(ctx context.Context, req *mcp.CallToolRequest, input DownloadInput) (*mcp.CallToolResult, DownloadOutput, error) {
	if input.RemotePath == "" || input.LocalPath == "" {
		return nil, DownloadOutput{}, fmt.Errorf("remote_path and local_path are required")
	}

	poolCfg, serverCfg, err := getPoolConfig(input.Server)
	if err != nil {
		return nil, DownloadOutput{}, err
	}

	client, err := sshpool.Default().Get(ctx, poolCfg)
	if err != nil {
		return nil, DownloadOutput{}, fmt.Errorf("SSH connection failed: %w", err)
	}

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
		Message:      fmt.Sprintf("Successfully downloaded %s:%s to %s", serverCfg.Host, input.RemotePath, input.LocalPath),
		BytesWritten: written,
	}, nil
}
