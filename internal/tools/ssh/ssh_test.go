package ssh

import (
	"context"
	"encoding/json"
	"fmt"
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

type SSHToolTestSuite struct {
	suite.Suite

	ctx           context.Context
	server        *mcp.Server
	client        *mcp.Client
	serverSession *mcp.ServerSession
	clientSession *mcp.ClientSession
}

func (s *SSHToolTestSuite) SetupSuite() {
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

func (s *SSHToolTestSuite) TearDownSuite() {
	if s.serverSession != nil {
		_ = s.serverSession.Close()
	}
	if s.clientSession != nil {
		_ = s.clientSession.Close()
	}
}

func (s *SSHToolTestSuite) getTextContent(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	if tc, ok := result.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func (s *SSHToolTestSuite) TestListTools() {
	tools, err := s.clientSession.ListTools(s.ctx, nil)
	s.Require().NoError(err, "ListTools should succeed")

	sshFound := false
	listFound := false
	for _, tool := range tools.Tools {
		if tool.Name == "ssh_execute" {
			sshFound = true
			s.Equal("Execute SSH Command", tool.Title, "Tool title should match")
		}
		if tool.Name == "ssh_list_servers" {
			listFound = true
		}
	}
	s.True(sshFound, "ssh_execute tool should be registered")
	s.True(listFound, "ssh_list_servers tool should be registered")
}

func (s *SSHToolTestSuite) TestServerNotFound() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "non-existent-server",
			"command": "echo hello",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.True(result.IsError, "Non-existent server should return error")

	text := s.getTextContent(result)
	s.Contains(text, "not found", "Error should indicate server not found")
}

func (s *SSHToolTestSuite) TestBlockedCommand_RmRf() {
	// Register a test server
	config.ResetRegistry()
	config.RegisterServer(&config.ServerConfig{
		Name:     "test",
		Host:     "localhost",
		User:     "testuser",
		Password: "testpass",
	})

	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "test",
			"command": "rm -rf /",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.True(result.IsError, "Blocked command should return error")

	text := s.getTextContent(result)
	s.Contains(text, "blocked", "Error should indicate command is blocked")
}

func (s *SSHToolTestSuite) TestBlockedCommand_Shutdown() {
	config.ResetRegistry()
	config.RegisterServer(&config.ServerConfig{
		Name:     "test",
		Host:     "localhost",
		User:     "testuser",
		Password: "testpass",
	})

	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "test",
			"command": "shutdown now",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.True(result.IsError, "Shutdown should be blocked")
}

func TestSSHToolTestSuite(t *testing.T) {
	suite.Run(t, new(SSHToolTestSuite))
}

type SSHIntegrationTestSuite struct {
	suite.Suite

	ctx           context.Context
	server        *mcp.Server
	client        *mcp.Client
	serverSession *mcp.ServerSession
	clientSession *mcp.ClientSession
	sshContainer  *SSHContainer
}

type SSHContainer struct {
	testcontainers.Container
	Host     string
	Port     int
	User     string
	Password string
}

func (s *SSHIntegrationTestSuite) SetupSuite() {
	if testing.Short() {
		s.T().Skip("Skipping integration test in short mode")
	}

	s.ctx = context.Background()

	// Start SSH container
	s.sshContainer = s.setupSSHContainer()
	s.T().Logf("SSH container started at %s:%d", s.sshContainer.Host, s.sshContainer.Port)

	// Setup MCP server and client
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

func (s *SSHIntegrationTestSuite) SetupTest() {
	// Register container server before each test
	config.RegisterServer(&config.ServerConfig{
		Name:        "test-container",
		Description: "Test SSH Container",
		Host:        s.sshContainer.Host,
		Port:        s.sshContainer.Port,
		User:        s.sshContainer.User,
		Password:    s.sshContainer.Password,
	})
}

func (s *SSHIntegrationTestSuite) TearDownSuite() {
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
	config.ResetRegistry()
}

func (s *SSHIntegrationTestSuite) setupSSHContainer() *SSHContainer {
	password := "testpassword123"

	req := testcontainers.ContainerRequest{
		Image:        "testcontainers/sshd:1.3.0",
		ExposedPorts: []string{"22/tcp"},
		Env: map[string]string{
			"PASSWORD": password,
		},
		WaitingFor: wait.ForAll(
			// Wait for password setup to complete
			wait.ForLog("chpasswd: password for 'root' changed"),
			// Wait for SSH port to be ready
			wait.ForListeningPort("22/tcp"),
			// Wait for SSH service to be fully operational
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
	s.Require().NoError(err, "Failed to start SSH container")

	host, err := container.Host(s.ctx)
	s.Require().NoError(err, "Failed to get container host")

	mappedPort, err := container.MappedPort(s.ctx, nat.Port("22/tcp"))
	s.Require().NoError(err, "Failed to get mapped port")

	sshContainer := &SSHContainer{
		Container: container,
		Host:      host,
		Port:      mappedPort.Int(),
		User:      "root",
		Password:  password,
	}

	// Wait for SSH to be truly ready by attempting a connection
	s.waitForSSHReady(sshContainer)

	return sshContainer
}

func (s *SSHIntegrationTestSuite) waitForSSHReady(container *SSHContainer) {
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

func (s *SSHIntegrationTestSuite) getTextContent(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	if tc, ok := result.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func (s *SSHIntegrationTestSuite) getOutput(result *mcp.CallToolResult) string {
	text := s.getTextContent(result)
	if text == "" {
		return ""
	}

	var output SSHExecuteOutput
	if err := json.Unmarshal([]byte(text), &output); err != nil {
		return text
	}
	return output.Output
}

func (s *SSHIntegrationTestSuite) TestEchoCommand() {
	// Use simple echo command that doesn't depend on external binaries
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "test-container",
			"command": "echo hello",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.False(result.IsError, "Result should not be an error")

	output := s.getOutput(result)
	s.Contains(output, "hello", "Output should contain hello")
	s.T().Logf("Output: %s", output)
}

func (s *SSHIntegrationTestSuite) TestUnameCommand() {
	// Use whoami which is more reliable across different environments
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "test-container",
			"command": "whoami",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.False(result.IsError, "Result should not be an error")

	output := s.getOutput(result)
	s.Contains(output, "root", "Output should contain root")
	s.T().Logf("Output: %s", output)
}

func (s *SSHIntegrationTestSuite) TestPipedCommand() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "test-container",
			"command": "echo 'hello world' | grep hello",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.False(result.IsError, "Result should not be an error")

	output := s.getOutput(result)
	s.Contains(output, "hello", "Output should contain 'hello'")
	s.T().Logf("Output: %s", output)
}

func (s *SSHIntegrationTestSuite) TestNonZeroExitCode() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "test-container",
			"command": "exit 42",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.False(result.IsError, "Non-zero exit should not be a protocol error")

	text := s.getTextContent(result)
	s.Contains(text, "42", "Output should contain exit code")
	s.T().Logf("Output: %s", text)
}

func (s *SSHIntegrationTestSuite) TestBlockedCommandStillBlocked() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "test-container",
			"command": "rm -rf /",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.True(result.IsError, "Blocked command should still be blocked")

	text := s.getTextContent(result)
	s.Contains(text, "blocked", "Error should indicate command is blocked")
}

func (s *SSHIntegrationTestSuite) TestTimeout() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "test-container",
			"command": "sleep 5",
			"timeout": 1, // 1 second timeout
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.True(result.IsError, "Timeout should return error")

	text := s.getTextContent(result)
	s.Contains(text, "timed out", "Error should mention timeout")
	s.T().Logf("Error: %s", text)
}

func (s *SSHIntegrationTestSuite) TestLargeOutput() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "ssh_execute",
		Arguments: map[string]any{
			"server":  "test-container",
			"command": "cat /etc/passwd",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.False(result.IsError, "Large output should work")

	output := s.getOutput(result)
	s.NotEmpty(output, "Output should not be empty")
	s.T().Logf("Output length: %d bytes", len(output))
}

func TestSSHIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(SSHIntegrationTestSuite))
}
