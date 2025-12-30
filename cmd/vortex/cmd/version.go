package cmd

import (
	"fmt"

	"github.com/ilxqx/vortex-mcp/pkg/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Long:  `Print the version, commit hash, and build time of Vortex MCP Server.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Vortex MCP Server %s\n", version.Version)
		fmt.Printf("  Commit: %s\n", version.Commit)
		fmt.Printf("  Built:  %s\n", version.BuildTime)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
