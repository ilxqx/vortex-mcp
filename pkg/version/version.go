package version

var (
	// Version is set at build time via -ldflags "-X".
	Version = "dev"
	// Commit is the git commit hash, set at build time.
	Commit = "unknown"
	// BuildTime is the build timestamp, set at build time.
	BuildTime = "unknown"
)
