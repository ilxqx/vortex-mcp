package ssh

import (
	"context"
	"fmt"
	"time"

	"github.com/ilxqx/vortex-mcp/internal/config"
	"github.com/ilxqx/vortex-mcp/internal/security"
	"github.com/ilxqx/vortex-mcp/internal/sshpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSSHPort    = 22
	defaultSSHTimeout = 30
	maxOutputSize     = 1 << 20 // 1MB
)

type SSHExecuteInput struct {
	Server  string `json:"server" jsonschema:"Pre-configured server name from VORTEX_SSH_SERVERS"`
	Command string `json:"command" jsonschema:"Shell command to execute on the remote host"`
	Timeout int    `json:"timeout,omitempty" jsonschema:"Command timeout in seconds (default: 30)"`
}

type SSHExecuteOutput struct {
	Output   string `json:"output" jsonschema:"Combined stdout and stderr output"`
	ExitCode int    `json:"exit_code" jsonschema:"Command exit code (0 indicates success)"`
}

func Register(s *mcp.Server) {
	mcp.AddTool(
		s,
		&mcp.Tool{
			Name:        "ssh_execute",
			Title:       "Execute SSH Command",
			Description: "Execute a shell command on a remote host via SSH. Dangerous commands (rm -rf, shutdown, etc.) are blocked for safety. Server must be pre-configured via VORTEX_SSH_SERVERS environment variable.",
		},
		executeSSH,
	)

	mcp.AddTool(
		s,
		&mcp.Tool{
			Name:        "ssh_list_servers",
			Title:       "List SSH Servers",
			Description: "List all pre-configured SSH servers available for connection. Returns server name, host, and user for each configured server.",
		},
		listServers,
	)
}

type ListServersInput struct{}

type ListServersOutput struct {
	Servers []config.ServerInfo `json:"servers" jsonschema:"List of configured SSH servers"`
}

func listServers(context.Context, *mcp.CallToolRequest, ListServersInput) (*mcp.CallToolResult, ListServersOutput, error) {
	servers := config.ListServers()
	return nil, ListServersOutput{Servers: servers}, nil
}

func executeSSH(ctx context.Context, req *mcp.CallToolRequest, input SSHExecuteInput) (*mcp.CallToolResult, SSHExecuteOutput, error) {
	if input.Command == "" {
		return nil, SSHExecuteOutput{}, fmt.Errorf("command is required")
	}

	// Analyze command for potential dangers
	analysis, err := security.AnalyzeCommand(input.Command)
	if err != nil {
		return nil, SSHExecuteOutput{}, fmt.Errorf("failed to analyze command: %w", err)
	}
	if analysis.Blocked {
		return nil, SSHExecuteOutput{}, fmt.Errorf("command blocked: %s", analysis.Reason)
	}

	// Resolve connection config
	serverCfg, err := config.GetServer(input.Server)
	if err != nil {
		return nil, SSHExecuteOutput{}, err
	}

	timeout := serverCfg.Timeout
	if timeout == 0 {
		timeout = defaultSSHTimeout
	}
	if input.Timeout > 0 {
		timeout = input.Timeout
	}

	port := serverCfg.Port
	if port == 0 {
		port = defaultSSHPort
	}

	timeoutDuration := time.Duration(timeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	// Get connection from pool
	poolCfg := &sshpool.Config{
		Host:     serverCfg.Host,
		Port:     port,
		User:     serverCfg.User,
		Password: serverCfg.Password,
		KeyFile:  serverCfg.KeyFile,
		Timeout:  timeoutDuration,
	}

	client, err := sshpool.Default().Get(ctx, poolCfg)
	if err != nil {
		return nil, SSHExecuteOutput{}, fmt.Errorf("failed to get SSH connection: %w", err)
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, SSHExecuteOutput{}, fmt.Errorf("failed to create session: %w", err)
	}
	defer func() { _ = session.Close() }()

	type cmdResult struct {
		output []byte
		err    error
	}
	resultCh := make(chan cmdResult, 1)
	go func() {
		output, err := session.CombinedOutput(input.Command)
		resultCh <- cmdResult{output: output, err: err}
	}()

	var result cmdResult
	select {
	case result = <-resultCh:
		// Command completed normally
	case <-ctx.Done():
		// Timeout occurred - close session to interrupt the command
		_ = session.Close()
		// Wait for goroutine to finish to avoid leaking
		<-resultCh
		return nil, SSHExecuteOutput{}, fmt.Errorf("command timed out after %s", timeoutDuration)
	}

	output := string(result.output)
	if len(output) > maxOutputSize {
		output = output[:maxOutputSize] + "\n... (output truncated)"
	}

	sshOutput := SSHExecuteOutput{
		Output:   output,
		ExitCode: 0,
	}

	if result.err != nil {
		if exitErr, ok := result.err.(*ssh.ExitError); ok {
			sshOutput.ExitCode = exitErr.ExitStatus()
		} else {
			return nil, SSHExecuteOutput{}, fmt.Errorf("command failed: %w", result.err)
		}
	}

	return nil, sshOutput, nil
}
