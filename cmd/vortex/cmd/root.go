package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ilxqx/vortex-mcp/internal/tools/shell"
	"github.com/ilxqx/vortex-mcp/internal/tools/ssh"
	"github.com/ilxqx/vortex-mcp/internal/tools/transfer"
	"github.com/ilxqx/vortex-mcp/pkg/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

var (
	timeout  int
	logLevel string
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "vortex",
	Short: "Vortex MCP Server - Universal MCP server for shell, SSH, and file transfer",
	Long: `Vortex is a Model Context Protocol (MCP) server that provides tools for:
  - Executing shell commands on the local machine
  - SSH remote command execution
  - File transfer via SFTP (upload/download)

It communicates via stdio transport and can be integrated with any MCP client
such as Claude Desktop, VS Code, or Cursor.`,
	Run: runServer,
}

func init() {
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 60, "Default command timeout in seconds")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

// Version returns the version information.
func Version() string {
	return version.Version
}

func runServer(cmd *cobra.Command, args []string) {
	setupLogging()

	s := createServer()
	registerTools(s)

	slog.Info("Starting Vortex MCP Server", "version", version.Version)

	ctx := setupSignalHandler()

	if err := s.Run(ctx, &mcp.StdioTransport{}); err != nil {
		slog.Error("Server error", "error", err)
		os.Exit(1)
	}
}

func setupLogging() {
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))
}

func createServer() *mcp.Server {
	return mcp.NewServer(
		&mcp.Implementation{
			Name:    "vortex",
			Version: version.Version,
			Title:   "Vortex MCP Server",
		},
		&mcp.ServerOptions{
			Logger: slog.Default(),
		},
	)
}

func registerTools(s *mcp.Server) {
	shell.Register(s, timeout)
	ssh.Register(s)
	transfer.Register(s)
}

func setupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("Shutting down...")
		cancel()
	}()

	return ctx
}
