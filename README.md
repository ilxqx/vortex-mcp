# Vortex MCP Server

[![GitHub Release](https://img.shields.io/github/v/release/ilxqx/vortex-mcp)](https://github.com/ilxqx/vortex-mcp/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/ilxqx/vortex-mcp/test.yml?branch=main)](https://github.com/ilxqx/vortex-mcp/actions/workflows/test.yml)
[![Coverage](https://img.shields.io/codecov/c/github/ilxqx/vortex-mcp)](https://codecov.io/gh/ilxqx/vortex-mcp)
[![Go Reference](https://pkg.go.dev/badge/github.com/ilxqx/vortex-mcp.svg)](https://pkg.go.dev/github.com/ilxqx/vortex-mcp)
[![Go Report Card](https://goreportcard.com/badge/github.com/ilxqx/vortex-mcp)](https://goreportcard.com/report/github.com/ilxqx/vortex-mcp)
[![License](https://img.shields.io/github/license/ilxqx/vortex-mcp)](https://github.com/ilxqx/vortex-mcp/blob/main/LICENSE)

Vortex is a universal [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server written in Go that provides secure shell execution and file transfer capabilities for AI assistants.

## Features

- **Local Shell Execution** - Execute shell commands on the local machine with security filtering
- **Remote SSH Execution** - Execute commands on remote hosts via SSH with pre-configured servers
- **SFTP File Transfer** - Upload and download files between local and remote hosts
- **Security First** - Dangerous commands (rm -rf, shutdown, etc.) are blocked by default
- **DSN-based Configuration** - Simple URL-style server configuration via environment variables
- **Cross-platform** - Supports macOS, Linux, and Windows

## Installation

### Using Go Install

```bash
go install github.com/ilxqx/vortex-mcp/cmd/vortex@latest
```

### From Source

```bash
# Clone the repository
git clone https://github.com/ilxqx/vortex-mcp.git
cd vortex-mcp

# Build using Task
task build

# Or install to $GOPATH/bin
task install
```

### Pre-built Binaries

Download from the [Releases](https://github.com/ilxqx/vortex-mcp/releases) page.

## Configuration

### SSH Server Configuration

SSH servers are configured via the `VORTEX_SSH_SERVERS` environment variable using DSN (Data Source Name) format:

```
ssh://[user[:password]@]host[:port]?name=alias[&desc=description][&key=keyfile][&timeout=30]
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `user` | Yes | SSH username |
| `password` | No | SSH password (use key-based auth if omitted) |
| `host` | Yes | Hostname or IP address |
| `port` | No | SSH port (default: 22) |
| `name` | Yes | Server alias for tool invocation |
| `desc` | No | Human-readable description |
| `key` | No | Path to private key file (supports `~/` expansion) |
| `timeout` | No | Connection timeout in seconds (default: 30) |

**Examples:**

```bash
# Single server with password authentication
export VORTEX_SSH_SERVERS="ssh://admin:secret@192.168.1.100?name=prod"

# Single server with key-based authentication
export VORTEX_SSH_SERVERS="ssh://deploy@server.example.com?name=deploy&key=~/.ssh/deploy_key"

# Multiple servers (comma-separated)
export VORTEX_SSH_SERVERS="ssh://admin@web1.example.com?name=web1,ssh://admin@db1.example.com:2222?name=db1&key=~/.ssh/db_key"

# With optional description (no spaces)
export VORTEX_SSH_SERVERS="ssh://admin@prod.example.com?name=prod&desc=ProductionServer"
```

> **Note:** The `desc` parameter is optional. If your description contains spaces or special characters (`&`, `=`, `,`), you'll need to URL-encode them (e.g., space → `%20`). For simplicity, we recommend using names without spaces or omitting `desc` entirely.

### MCP Client Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "vortex": {
      "command": "/path/to/vortex",
      "args": ["--timeout", "60"],
      "env": {
        "VORTEX_SSH_SERVERS": "ssh://admin@server.example.com?name=myserver&key=~/.ssh/id_rsa"
      }
    }
  }
}
```

## Available Tools

### shell_execute

Execute a shell command on the local machine.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | string | Yes | The shell command to execute |
| `working_dir` | string | No | Working directory for command execution |
| `timeout` | int | No | Timeout in seconds (default: 60) |

**Returns:** `output` (string), `exit_code` (int)

### ssh_execute

Execute a command on a pre-configured remote host via SSH.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `server` | string | Yes | Pre-configured server name |
| `command` | string | Yes | Command to execute |
| `timeout` | int | No | Timeout in seconds (default: 30) |

**Returns:** `output` (string), `exit_code` (int)

### ssh_list_servers

List all pre-configured SSH servers.

**Returns:** Array of servers with `name`, `description`, `host`, and `user` fields.

### transfer_upload

Upload a local file to a remote host via SFTP.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `server` | string | Yes | Pre-configured server name |
| `local_path` | string | Yes | Absolute path to the local file |
| `remote_path` | string | Yes | Absolute path for remote destination |

**Returns:** `message` (string), `bytes_written` (int)

### transfer_download

Download a file from a remote host via SFTP.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `server` | string | Yes | Pre-configured server name |
| `remote_path` | string | Yes | Absolute path to the remote file |
| `local_path` | string | Yes | Absolute path for local destination |

**Returns:** `message` (string), `bytes_written` (int)

## Command Line Usage

```bash
# Run the server (stdio mode)
vortex

# With custom shell command timeout
vortex --timeout 120

# With debug logging
vortex --log-level debug

# Show version
vortex version

# Show help
vortex --help
```

## Security

Vortex implements security measures to prevent accidental damage:

- **Command Filtering** - Dangerous commands are blocked:
  - `rm -rf /`, `rm -rf ~`, `rm -rf *`
  - `shutdown`, `reboot`, `halt`, `poweroff`
  - `mkfs`, `dd if=`
  - Fork bombs and other destructive patterns
- **File Size Limits** - SFTP transfers are limited to 100MB
- **Output Truncation** - Command output is truncated at 1MB

## Development

### Prerequisites

- Go 1.25+
- [Task](https://taskfile.dev/) (optional, for build automation)

### Build Commands

```bash
# List all tasks
task

# Build binary
task build

# Run tests
task test

# Run tests with coverage
task test:coverage

# Format code
task fmt

# Run linter
task lint

# Clean build artifacts
task clean

# Build for all platforms
task release
```

### Project Structure

```
vortex-mcp/
├── cmd/vortex/         # Application entry point
├── internal/
│   ├── config/         # Server configuration and DSN parsing
│   ├── security/       # Command security analysis
│   └── tools/          # MCP tool implementations
│       ├── shell/      # Local shell execution
│       ├── ssh/        # Remote SSH execution
│       └── transfer/   # SFTP file transfer
├── pkg/version/        # Version information
├── Taskfile.yml        # Task automation
└── README.md
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/) - The protocol specification
- [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) - Official Go SDK for MCP
