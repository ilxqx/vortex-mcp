package shell

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/suite"
)

type ShellToolTestSuite struct {
	suite.Suite

	ctx           context.Context
	server        *mcp.Server
	client        *mcp.Client
	serverSession *mcp.ServerSession
	clientSession *mcp.ClientSession
}

func (s *ShellToolTestSuite) SetupSuite() {
	s.ctx = context.Background()

	s.server = mcp.NewServer(&mcp.Implementation{
		Name:    "vortex-test",
		Version: "v1.0.0",
	}, nil)

	Register(s.server, 60)

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

func (s *ShellToolTestSuite) TearDownSuite() {
	if s.serverSession != nil {
		_ = s.serverSession.Close()
	}
	if s.clientSession != nil {
		_ = s.clientSession.Close()
	}
}

func (s *ShellToolTestSuite) getTextContent(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	if tc, ok := result.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func (s *ShellToolTestSuite) TestListTools() {
	tools, err := s.clientSession.ListTools(s.ctx, nil)
	s.Require().NoError(err, "ListTools should succeed")

	found := false
	for _, tool := range tools.Tools {
		if tool.Name == "shell_execute" {
			found = true
			s.Equal("Execute Shell Command", tool.Title, "Tool title should match")
			break
		}
	}
	s.True(found, "shell_execute tool should be registered")
}

func (s *ShellToolTestSuite) TestSimpleEchoCommand() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "shell_execute",
		Arguments: map[string]any{
			"command": "echo hello",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.False(result.IsError, "Result should not be an error")
	s.Require().NotEmpty(result.Content, "Result should have content")

	text := s.getTextContent(result)
	s.Contains(text, "hello", "Output should contain 'hello'")
	s.T().Logf("Output: %s", text)
}

func (s *ShellToolTestSuite) TestCommandWithExitCode() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "shell_execute",
		Arguments: map[string]any{
			"command": "exit 1",
		},
	})
	s.Require().NoError(err, "CallTool should succeed even for non-zero exit")
	s.False(result.IsError, "Result should not be a protocol error")

	text := s.getTextContent(result)
	s.T().Logf("Output: %s", text)
}

func (s *ShellToolTestSuite) TestEmptyCommand() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "shell_execute",
		Arguments: map[string]any{
			"command": "",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.True(result.IsError, "Empty command should return error")
}

func (s *ShellToolTestSuite) TestBlockedCommand_RmRf() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "shell_execute",
		Arguments: map[string]any{
			"command": "rm -rf /tmp/test",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.True(result.IsError, "Blocked command should return error")

	text := s.getTextContent(result)
	s.Contains(text, "blocked", "Error message should indicate command is blocked")
	s.T().Logf("Blocked message: %s", text)
}

func (s *ShellToolTestSuite) TestBlockedCommand_Shutdown() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "shell_execute",
		Arguments: map[string]any{
			"command": "shutdown now",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.True(result.IsError, "Shutdown command should be blocked")
}

func (s *ShellToolTestSuite) TestBlockedCommand_ForkBomb() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "shell_execute",
		Arguments: map[string]any{
			"command": ":(){ :|:& };:",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.True(result.IsError, "Fork bomb should be blocked")
}

func (s *ShellToolTestSuite) TestWorkingDirectory() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "shell_execute",
		Arguments: map[string]any{
			"command":     "pwd",
			"working_dir": "/tmp",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.False(result.IsError, "Result should not be an error")

	text := s.getTextContent(result)
	s.Contains(text, "/tmp", "Working directory should be /tmp")
	s.T().Logf("Working dir output: %s", text)
}

func (s *ShellToolTestSuite) TestPipedCommands() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "shell_execute",
		Arguments: map[string]any{
			"command": "echo 'hello world' | grep hello",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.False(result.IsError, "Piped commands should work")

	text := s.getTextContent(result)
	s.Contains(text, "hello", "Output should contain 'hello'")
}

func (s *ShellToolTestSuite) TestMultilineOutput() {
	result, err := s.clientSession.CallTool(s.ctx, &mcp.CallToolParams{
		Name: "shell_execute",
		Arguments: map[string]any{
			"command": "echo -e 'line1\\nline2\\nline3'",
		},
	})
	s.Require().NoError(err, "CallTool should succeed")
	s.False(result.IsError, "Multiline output should work")

	text := s.getTextContent(result)
	s.Contains(text, "line1", "Output should contain line1")
	s.Contains(text, "line2", "Output should contain line2")
	s.T().Logf("Multiline output: %s", text)
}

func TestShellToolTestSuite(t *testing.T) {
	suite.Run(t, new(ShellToolTestSuite))
}
