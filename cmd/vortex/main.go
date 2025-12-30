package main

import (
	"fmt"
	"os"

	"github.com/ilxqx/vortex-mcp/cmd/vortex/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
