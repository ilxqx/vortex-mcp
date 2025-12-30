package transfer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/ilxqx/vortex-mcp/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

// TransferToolTestSuite tests transfer tool registration and basic validation.
type TransferToolTestSuite struct {
	suite.Suite

	ctx           context.Context
	server        *mcp.Server
	client        *mcp.Client
	serverSession *mcp.ServerSession
	clientSession *mcp.ClientSession
}

func (s *TransferToolTestSuite) SetupSuite() {
	s.ctx = context.Background()

	s.server = mcp.NewServer(&mcp.Implementation{
		Name:    "vortex-test",
		Version: "v1.0.0",
	}, nil)

	Register(s.server)

	s.client = mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "v1.0.0",
	}, nil)

	t1, t2 := mcp.NewInMemoryTransports()

	var err error
	s.serverSession, err = s.server.Connect(s.ctx, t1, nil)
	s.Require().NoError(err, "Server should connect successfully")

	s.clientSession, err = s.client.Connect(s.ctx, t2, nil)
	s.Require().NoError(err, "Client should connect successfully")
}

func (s *TransferToolTestSuite) TearDownSuite() {
	if s.serverSession != nil {
		_ = s.serverSession.Close()
	}
	if s.clientSession != nil {
		_ = s.clientSession.Close()
	}
}

func (s *TransferToolTestSuite) getTextContent(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	if tc, ok := result.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

// TestListTools tests that transfer tools are properly registered.
func (s *TransferToolTestSuite) TestListTools() {
	s.T().Log("Testing transfer tool registration")

	tools, err := s.clientSession.ListTools(s.ctx, nil)
	s.Require().NoError(err, "ListTools should succeed")

	s.Run("UploadToolRegistered", func() {
		found := false
		for _, tool := range tools.Tools {
			if tool.Name == "transfer_upload" {
				found = true
				s.Equal("Upload File via SFTP", tool.Title, "Upload tool title should match")
				break
			}
		}
		s.True(found, "transfer_upload tool should be registered")
	})

	s.Run("DownloadToolRegistered", func() {
		found := false
		for _, tool := range tools.Tools {
			if tool.Name == "transfer_download" {
				found = true
				s.Equal("Download File via SFTP", tool.Title, "Download tool title should match")
				break
			}
		}
		s.True(found, "transfer_download tool should be registered")
	})
}

// TestUploadValidation tests upload input validation and error handling.
func (s *TransferToolTestSuite) TestUploadValidation() {
	s.T().Log("Testing upload validation")

	s.Run("ServerNotFound", func() {
		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_upload",
			Arguments: map[string]any{
				"server":      "non-existent-server",
				"local_path":  "/etc/hosts",
				"remote_path": "/home/user/test.txt",
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.True(result.IsError, "Non-existent server should return error")

		text := s.getTextContent(result)
		s.Contains(text, "not found", "Error should indicate server not found")
	})

	s.Run("NonexistentLocalFile", func() {
		config.ResetRegistry()
		config.RegisterServer(&config.ServerConfig{
			Name:     "test",
			Host:     "localhost",
			User:     "testuser",
			Password: "testpass",
		})

		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_upload",
			Arguments: map[string]any{
				"server":      "test",
				"local_path":  "/nonexistent/path/file.txt",
				"remote_path": "/home/user/test.txt",
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.True(result.IsError, "Nonexistent file should return error")
	})
}

// TestDownloadValidation tests download input validation and error handling.
func (s *TransferToolTestSuite) TestDownloadValidation() {
	s.T().Log("Testing download validation")

	s.Run("ServerNotFound", func() {
		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_download",
			Arguments: map[string]any{
				"server":      "non-existent-server",
				"remote_path": "/home/user/test.txt",
				"local_path":  "/tmp/test.txt",
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.True(result.IsError, "Non-existent server should return error")

		text := s.getTextContent(result)
		s.Contains(text, "not found", "Error should indicate server not found")
	})
}

func TestTransferToolTestSuite(t *testing.T) {
	suite.Run(t, new(TransferToolTestSuite))
}

// TransferIntegrationTestSuite tests SFTP upload and download functionality
// with a real SSH container via Testcontainers.
type TransferIntegrationTestSuite struct {
	suite.Suite

	ctx           context.Context
	server        *mcp.Server
	client        *mcp.Client
	serverSession *mcp.ServerSession
	clientSession *mcp.ClientSession
	sshContainer  *SSHContainer
	tempDir       string
}

// SSHContainer holds the SSH container configuration for testing.
type SSHContainer struct {
	testcontainers.Container
	Host     string
	Port     int
	User     string
	Password string
}

func (s *TransferIntegrationTestSuite) SetupSuite() {
	if testing.Short() {
		s.T().Skip("Skipping integration test in short mode")
	}

	s.ctx = context.Background()

	var err error
	s.tempDir, err = os.MkdirTemp("", "transfer-test-*")
	s.Require().NoError(err, "Should create temp directory")

	s.sshContainer = s.setupSSHContainer()
	s.T().Logf("SSH container started at %s:%d", s.sshContainer.Host, s.sshContainer.Port)

	s.server = mcp.NewServer(&mcp.Implementation{
		Name:    "vortex-test",
		Version: "v1.0.0",
	}, nil)

	Register(s.server)

	s.client = mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "v1.0.0",
	}, nil)

	t1, t2 := mcp.NewInMemoryTransports()

	s.serverSession, err = s.server.Connect(s.ctx, t1, nil)
	s.Require().NoError(err, "Server should connect successfully")

	s.clientSession, err = s.client.Connect(s.ctx, t2, nil)
	s.Require().NoError(err, "Client should connect successfully")
}

func (s *TransferIntegrationTestSuite) SetupTest() {
	config.ResetRegistry()
	config.RegisterServer(&config.ServerConfig{
		Name:        "test-container",
		Description: "Test SSH Container",
		Host:        s.sshContainer.Host,
		Port:        s.sshContainer.Port,
		User:        s.sshContainer.User,
		Password:    s.sshContainer.Password,
	})
}

func (s *TransferIntegrationTestSuite) TearDownSuite() {
	if s.serverSession != nil {
		_ = s.serverSession.Close()
	}
	if s.clientSession != nil {
		_ = s.clientSession.Close()
	}
	if s.sshContainer != nil {
		if err := s.sshContainer.Terminate(s.ctx); err != nil {
			s.T().Logf("Failed to terminate SSH container: %v", err)
		}
	}
	if s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir)
	}
	config.ResetRegistry()
}

func (s *TransferIntegrationTestSuite) setupSSHContainer() *SSHContainer {
	password := "testpassword123"

	req := testcontainers.ContainerRequest{
		Image:        "testcontainers/sshd:1.3.0",
		ExposedPorts: []string{"22/tcp"},
		Env: map[string]string{
			"PASSWORD": password,
		},
		WaitingFor: wait.ForAll(
			wait.ForLog("chpasswd: password for 'root' changed"),
			wait.ForListeningPort("22/tcp"),
			wait.ForExec([]string{"sh", "-c", "echo ready"}).
				WithExitCodeMatcher(func(exitCode int) bool {
					return exitCode == 0
				}),
		).WithDeadline(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(s.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	s.Require().NoError(err, "Should start SSH container")

	host, err := container.Host(s.ctx)
	s.Require().NoError(err, "Should get container host")

	mappedPort, err := container.MappedPort(s.ctx, nat.Port("22/tcp"))
	s.Require().NoError(err, "Should get mapped port")

	sshContainer := &SSHContainer{
		Container: container,
		Host:      host,
		Port:      mappedPort.Int(),
		User:      "root",
		Password:  password,
	}

	s.waitForSSHReady(sshContainer)

	return sshContainer
}

func (s *TransferIntegrationTestSuite) waitForSSHReady(container *SSHContainer) {
	sshConfig := &ssh.ClientConfig{
		User:            container.User,
		Auth:            []ssh.AuthMethod{ssh.Password(container.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", container.Host, container.Port)
	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		client, err := ssh.Dial("tcp", addr, sshConfig)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		session, err := client.NewSession()
		if err != nil {
			_ = client.Close()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		output, err := session.CombinedOutput("echo ready")
		_ = session.Close()
		_ = client.Close()

		if err == nil && strings.Contains(string(output), "ready") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	s.FailNow("SSH container did not become ready in time")
}

func (s *TransferIntegrationTestSuite) getTextContent(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	if tc, ok := result.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

// TestUpload tests SFTP upload functionality.
func (s *TransferIntegrationTestSuite) TestUpload() {
	s.T().Log("Testing SFTP upload functionality")

	s.Run("BasicUpload", func() {
		localPath := filepath.Join(s.tempDir, "upload_test.txt")
		content := "Hello, SFTP upload test!"
		err := os.WriteFile(localPath, []byte(content), 0644)
		s.Require().NoError(err, "Should create test file")

		remotePath := "/tmp/uploaded_file.txt"

		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_upload",
			Arguments: map[string]any{
				"server":      "test-container",
				"local_path":  localPath,
				"remote_path": remotePath,
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.False(result.IsError, "Upload should not return error")

		text := s.getTextContent(result)
		s.Contains(text, "Successfully uploaded", "Output should indicate success")
		s.T().Logf("Result: %s", text)

		s.verifyRemoteFileContent(remotePath, content)
	})

	s.Run("LargeFile", func() {
		localPath := filepath.Join(s.tempDir, "large_file.bin")
		content := make([]byte, 1024*1024)
		for i := range content {
			content[i] = byte(i % 256)
		}
		err := os.WriteFile(localPath, content, 0644)
		s.Require().NoError(err, "Should create large test file")

		remotePath := "/tmp/large_file.bin"

		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_upload",
			Arguments: map[string]any{
				"server":      "test-container",
				"local_path":  localPath,
				"remote_path": remotePath,
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.False(result.IsError, "Upload should not return error")

		text := s.getTextContent(result)
		var output UploadOutput
		err = json.Unmarshal([]byte(text), &output)
		s.Require().NoError(err, "Should parse output as JSON")
		s.Equal(int64(1024*1024), output.BytesWritten, "Should have written 1MB")
	})

	s.Run("NonexistentFile", func() {
		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_upload",
			Arguments: map[string]any{
				"server":      "test-container",
				"local_path":  "/nonexistent/path/file.txt",
				"remote_path": "/tmp/test.txt",
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.True(result.IsError, "Should return error for nonexistent file")
	})

	s.Run("DirectoryNotAllowed", func() {
		dirPath := filepath.Join(s.tempDir, "test_dir")
		err := os.Mkdir(dirPath, 0755)
		s.Require().NoError(err, "Should create test directory")

		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_upload",
			Arguments: map[string]any{
				"server":      "test-container",
				"local_path":  dirPath,
				"remote_path": "/tmp/test_dir",
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.True(result.IsError, "Should return error when uploading directory")

		text := s.getTextContent(result)
		s.Contains(text, "directory", "Error should mention directory")
	})
}

// TestDownload tests SFTP download functionality.
func (s *TransferIntegrationTestSuite) TestDownload() {
	s.T().Log("Testing SFTP download functionality")

	s.Run("BasicDownload", func() {
		remotePath := "/tmp/download_test.txt"
		content := "Hello, SFTP download test!"
		s.createRemoteFile(remotePath, content)

		localPath := filepath.Join(s.tempDir, "downloaded_file.txt")

		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_download",
			Arguments: map[string]any{
				"server":      "test-container",
				"remote_path": remotePath,
				"local_path":  localPath,
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.False(result.IsError, "Download should not return error")

		text := s.getTextContent(result)
		s.Contains(text, "Successfully downloaded", "Output should indicate success")
		s.T().Logf("Result: %s", text)

		downloadedContent, err := os.ReadFile(localPath)
		s.Require().NoError(err, "Should read downloaded file")
		s.Equal(content, string(downloadedContent), "Content should match")
	})

	s.Run("CreateNestedDirectory", func() {
		remotePath := "/tmp/nested_download_test.txt"
		content := "Nested directory test"
		s.createRemoteFile(remotePath, content)

		localPath := filepath.Join(s.tempDir, "nested", "dir", "downloaded.txt")

		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_download",
			Arguments: map[string]any{
				"server":      "test-container",
				"remote_path": remotePath,
				"local_path":  localPath,
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.False(result.IsError, "Should create nested directories automatically")

		downloadedContent, err := os.ReadFile(localPath)
		s.Require().NoError(err, "Should read downloaded file")
		s.Equal(content, string(downloadedContent), "Content should match")
	})

	s.Run("NonexistentRemoteFile", func() {
		localPath := filepath.Join(s.tempDir, "nonexistent_download.txt")

		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_download",
			Arguments: map[string]any{
				"server":      "test-container",
				"remote_path": "/nonexistent/path/file.txt",
				"local_path":  localPath,
			},
		})
		s.Require().NoError(err, "CallTool should succeed")
		s.True(result.IsError, "Should return error for nonexistent remote file")
	})
}

// TestRoundTrip tests upload followed by download to verify data integrity.
func (s *TransferIntegrationTestSuite) TestRoundTrip() {
	s.T().Log("Testing upload and download round trip")

	s.Run("TextFileWithUnicode", func() {
		originalContent := "Round trip test content - 测试中文内容"
		localUploadPath := filepath.Join(s.tempDir, "roundtrip_original.txt")
		err := os.WriteFile(localUploadPath, []byte(originalContent), 0644)
		s.Require().NoError(err, "Should create test file")

		remotePath := "/tmp/roundtrip.txt"

		// Upload
		result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_upload",
			Arguments: map[string]any{
				"server":      "test-container",
				"local_path":  localUploadPath,
				"remote_path": remotePath,
			},
		})
		s.Require().NoError(err, "Upload should succeed")
		s.False(result.IsError, "Upload should not return error")

		// Download
		localDownloadPath := filepath.Join(s.tempDir, "roundtrip_downloaded.txt")
		result, err = s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
			Name: "transfer_download",
			Arguments: map[string]any{
				"server":      "test-container",
				"remote_path": remotePath,
				"local_path":  localDownloadPath,
			},
		})
		s.Require().NoError(err, "Download should succeed")
		s.False(result.IsError, "Download should not return error")

		// Verify
		downloadedContent, err := os.ReadFile(localDownloadPath)
		s.Require().NoError(err, "Should read downloaded file")
		s.Equal(originalContent, string(downloadedContent), "Content should match after round trip")
	})
}

func (s *TransferIntegrationTestSuite) createRemoteFile(path, content string) {
	sshConfig := &ssh.ClientConfig{
		User:            s.sshContainer.User,
		Auth:            []ssh.AuthMethod{ssh.Password(s.sshContainer.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", s.sshContainer.Host, s.sshContainer.Port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	s.Require().NoError(err, "SSH dial should succeed")
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	s.Require().NoError(err, "SSH session should succeed")
	defer func() { _ = session.Close() }()

	cmd := fmt.Sprintf("echo -n '%s' > %s", content, path)
	err = session.Run(cmd)
	s.Require().NoError(err, "Should create remote file")
}

func (s *TransferIntegrationTestSuite) verifyRemoteFileContent(path, expectedContent string) {
	sshConfig := &ssh.ClientConfig{
		User:            s.sshContainer.User,
		Auth:            []ssh.AuthMethod{ssh.Password(s.sshContainer.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", s.sshContainer.Host, s.sshContainer.Port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	s.Require().NoError(err, "SSH dial should succeed")
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	s.Require().NoError(err, "SSH session should succeed")
	defer func() { _ = session.Close() }()

	output, err := session.CombinedOutput(fmt.Sprintf("cat %s", path))
	s.Require().NoError(err, "Should read remote file")
	s.Equal(expectedContent, string(output), "Remote file content should match")
}

func TestTransferIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(TransferIntegrationTestSuite))
}
