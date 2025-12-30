package shell

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ilxqx/vortex-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxOutputSize  = 1 << 20 // 1MB
	defaultTimeout = 60
)

// shellInfo contains OS-specific shell configuration
type shellInfo struct {
	shell   string
	args    []string
	syntax  string
}

// getShellInfo returns the appropriate shell for the current OS
func getShellInfo() shellInfo {
	if runtime.GOOS == "windows" {
		return shellInfo{
			shell:  "cmd.exe",
			args:   []string{"/c"},
			syntax: "Windows cmd.exe",
		}
	}
	return shellInfo{
		shell:  "/bin/sh",
		args:   []string{"-c"},
		syntax: "Unix/POSIX shell (sh/bash)",
	}
}

// buildDescription creates a dynamic tool description based on OS
func buildDescription() string {
	if runtime.GOOS == "windows" {
		return "Execute a shell command on the local Windows machine using cmd.exe. " +
			"IMPORTANT: This is a Windows system - use Windows cmd.exe syntax (e.g., 'dir' instead of 'ls', " +
			"'type' instead of 'cat', 'del' instead of 'rm', 'copy' instead of 'cp', " +
			"use backslashes '\\' for paths, use '%VAR%' for environment variables). " +
			"Dangerous commands (format, del /s /q, shutdown, etc.) are blocked for safety. " +
			"Returns combined stdout/stderr output and exit code."
	}
	return fmt.Sprintf(
		"Execute a shell command on the local %s machine using /bin/sh. "+
			"IMPORTANT: This is a Unix-like system - use POSIX shell syntax (e.g., 'ls', 'cat', 'rm', 'cp', "+
			"use forward slashes '/' for paths, use '$VAR' for environment variables). "+
			"Dangerous commands (rm -rf /, shutdown, mkfs, etc.) are blocked for safety. "+
			"Returns combined stdout/stderr output and exit code.",
		runtime.GOOS,
	)
}

type ShellExecuteInput struct {
	Command    string `json:"command" jsonschema:"The shell command to execute. Must use syntax appropriate for the target OS: Windows cmd.exe syntax on Windows (dir, type, del) or POSIX shell syntax on Unix/Linux/macOS (ls, cat, rm)."`
	WorkingDir string `json:"working_dir,omitempty" jsonschema:"Absolute path to the working directory for command execution. If not specified, uses the server's current working directory. Use OS-appropriate path separators (backslash on Windows, forward slash on Unix)."`
	Timeout    int    `json:"timeout,omitempty" jsonschema:"Command execution timeout in seconds. If the command takes longer, it will be terminated. Default is 60 seconds. Maximum recommended is 300 seconds (5 minutes)."`
}

type ShellExecuteOutput struct {
	Output   string `json:"output" jsonschema:"Combined stdout and stderr output from the command. Output is truncated to 1MB if it exceeds this limit."`
	ExitCode int    `json:"exit_code" jsonschema:"Command exit code. 0 typically indicates success, non-zero indicates an error."`
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
			Description: buildDescription(),
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

	// Analyze command for security risks
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

	// Get OS-appropriate shell
	info := getShellInfo()
	cmdArgs := append(info.args, input.Command)
	cmd := exec.CommandContext(ctx, info.shell, cmdArgs...)
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
