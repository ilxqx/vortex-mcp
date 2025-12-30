package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ilxqx/vortex-mcp/internal/config"
	"github.com/ilxqx/vortex-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

type resolvedConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	KeyFile  string
	Timeout  int
}

func resolveConfig(serverName string, timeoutOverride int) (*resolvedConfig, error) {
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
		Timeout:  serverCfg.Timeout,
	}

	if cfg.Port == 0 {
		cfg.Port = defaultSSHPort
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultSSHTimeout
	}

	// Allow overriding timeout from input
	if timeoutOverride > 0 {
		cfg.Timeout = timeoutOverride
	}

	return cfg, nil
}

// Auth priority: password > key file > SSH agent
func buildAuthMethods(cfg *resolvedConfig) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod

	if cfg.Password != "" {
		auths = append(auths, ssh.Password(cfg.Password))
	}

	if cfg.KeyFile != "" {
		key, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key file: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}

	if sshAgent := getSSHAgent(); sshAgent != nil {
		auths = append(auths, ssh.PublicKeysCallback(sshAgent.Signers))
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
	cfg, err := resolveConfig(input.Server, input.Timeout)
	if err != nil {
		return nil, SSHExecuteOutput{}, err
	}

	timeoutDuration := time.Duration(cfg.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	// Build auth methods
	auths, err := buildAuthMethods(cfg)
	if err != nil {
		return nil, SSHExecuteOutput{}, err
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeoutDuration,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	dialer := net.Dialer{Timeout: timeoutDuration}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, SSHExecuteOutput{}, fmt.Errorf("failed to connect: %w", err)
	}

	c, newCh, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, SSHExecuteOutput{}, fmt.Errorf("SSH handshake failed: %w", err)
	}

	client := ssh.NewClient(c, newCh, reqs)
	defer func() { _ = client.Close() }()

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
		_ = client.Close()
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
