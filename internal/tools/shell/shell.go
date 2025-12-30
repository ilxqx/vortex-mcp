package shell

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ilxqx/vortex-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxOutputSize  = 1 << 20 // 1MB
	defaultTimeout = 60
)

type ShellExecuteInput struct {
	Command    string `json:"command" jsonschema:"The shell command to execute"`
	WorkingDir string `json:"working_dir,omitempty" jsonschema:"Working directory for command execution"`
	Timeout    int    `json:"timeout,omitempty" jsonschema:"Command timeout in seconds (default: 60)"`
}

type ShellExecuteOutput struct {
	Output   string `json:"output" jsonschema:"Combined stdout and stderr output"`
	ExitCode int    `json:"exit_code" jsonschema:"Command exit code (0 indicates success)"`
}

func Register(s *mcp.Server, timeout int) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	mcp.AddTool(
		s,
		&mcp.Tool{
			Name:        "shell_execute",
			Title:       "Execute Shell Command",
			Description: "Execute a shell command on the local machine. Dangerous commands (rm -rf, shutdown, etc.) are blocked for safety. Returns command output and exit code.",
		},
		func(ctx context.Context, req *mcp.CallToolRequest, input ShellExecuteInput) (*mcp.CallToolResult, ShellExecuteOutput, error) {
			return executeShell(ctx, input, timeout)
		},
	)
}

func executeShell(ctx context.Context, input ShellExecuteInput, defaultTimeoutSec int) (*mcp.CallToolResult, ShellExecuteOutput, error) {
	if strings.TrimSpace(input.Command) == "" {
		return nil, ShellExecuteOutput{}, fmt.Errorf("command is required")
	}

	analysis, err := security.AnalyzeCommand(input.Command)
	if err != nil {
		return nil, ShellExecuteOutput{}, fmt.Errorf("failed to analyze command: %w", err)
	}
	if analysis.Blocked {
		return nil, ShellExecuteOutput{}, fmt.Errorf("command blocked: %s", analysis.Reason)
	}

	timeout := defaultTimeoutSec
	if input.Timeout > 0 {
		timeout = input.Timeout
	}

	timeoutDuration := time.Duration(timeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", input.Command)
	if input.WorkingDir != "" {
		cmd.Dir = input.WorkingDir
	}

	output, err := cmd.CombinedOutput()
	outText := string(output)
	if len(outText) > maxOutputSize {
		outText = outText[:maxOutputSize] + "\n... (output truncated)"
	}

	result := ShellExecuteOutput{
		Output:   outText,
		ExitCode: 0,
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, ShellExecuteOutput{}, fmt.Errorf("command timed out after %s", timeoutDuration)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, ShellExecuteOutput{}, fmt.Errorf("command failed: %w", err)
		}
	}

	return nil, result, nil
}
