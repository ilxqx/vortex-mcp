package security

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// DangerLevel represents command danger classification.
type DangerLevel int

const (
	DangerLevelSafe    DangerLevel = iota // Safe to execute
	DangerLevelWarning                    // Warning but allowed
	DangerLevelBlocked                    // Blocked from execution
)

// forkBombPattern detects fork bomb patterns like: f(){ f|f& };f or :(){ :|:& };:
var forkBombPattern = regexp.MustCompile(`[\w:]+\s*\(\s*\)\s*\{[^}]*\|\s*[\w:]+\s*&`)

// criticalPaths are paths that should never be modified recursively or deleted
var criticalPaths = map[string]bool{
	"/":      true,
	"/bin":   true,
	"/boot":  true,
	"/dev":   true,
	"/etc":   true,
	"/home":  true,
	"/lib":   true,
	"/lib64": true,
	"/opt":   true,
	"/proc":  true,
	"/root":  true,
	"/sbin":  true,
	"/sys":   true,
	"/tmp":   true,
	"/usr":   true,
	"/var":   true,
}

// sudoFlagsWithArg are sudo flags that take an argument
var sudoFlagsWithArg = map[string]bool{
	"-u": true, "-g": true, "-C": true, "-h": true,
	"-p": true, "-r": true, "-t": true, "-T": true,
	"-U": true, "-D": true,
}

var commandCheckers = map[string]struct {
	baseLevel DangerLevel
	reason    string
	checkFn   func(args []string) DangerLevel
}{
	// File removal
	"rm": {
		baseLevel: DangerLevelSafe,
		reason:    "removes files or directories",
		checkFn:   checkRmCommand,
	},
	"rmdir": {baseLevel: DangerLevelWarning, reason: "removes directories"},

	// Disk operations - always blocked
	"mkfs":      {baseLevel: DangerLevelBlocked, reason: "formats filesystem"},
	"dd":        {baseLevel: DangerLevelBlocked, reason: "low-level disk operations"},
	"fdisk":     {baseLevel: DangerLevelBlocked, reason: "disk partitioning"},
	"parted":    {baseLevel: DangerLevelBlocked, reason: "disk partitioning"},
	"shred":     {baseLevel: DangerLevelBlocked, reason: "secure file deletion"},
	"wipefs":    {baseLevel: DangerLevelBlocked, reason: "wipes filesystem signatures"},
	"badblocks": {baseLevel: DangerLevelBlocked, reason: "disk testing can be destructive"},

	// System control - always blocked
	"shutdown": {baseLevel: DangerLevelBlocked, reason: "shuts down system"},
	"reboot":   {baseLevel: DangerLevelBlocked, reason: "reboots system"},
	"halt":     {baseLevel: DangerLevelBlocked, reason: "halts system"},
	"poweroff": {baseLevel: DangerLevelBlocked, reason: "powers off system"},
	"init":     {baseLevel: DangerLevelBlocked, reason: "changes system runlevel"},

	// Permission changes
	"chmod": {
		baseLevel: DangerLevelWarning,
		reason:    "changes file permissions",
		checkFn:   checkChmodCommand,
	},
	"chown": {
		baseLevel: DangerLevelWarning,
		reason:    "changes file ownership",
		checkFn:   checkRecursiveFlag,
	},
	"chgrp": {
		baseLevel: DangerLevelWarning,
		reason:    "changes file group",
		checkFn:   checkRecursiveFlag,
	},

	// Firewall - always blocked
	"iptables":  {baseLevel: DangerLevelBlocked, reason: "modifies firewall rules"},
	"ip6tables": {baseLevel: DangerLevelBlocked, reason: "modifies firewall rules"},
	"nft":       {baseLevel: DangerLevelBlocked, reason: "modifies firewall rules"},
	"ufw":       {baseLevel: DangerLevelBlocked, reason: "modifies firewall rules"},
	"firewalld": {baseLevel: DangerLevelBlocked, reason: "modifies firewall rules"},

	// Process control - dangerous
	"kill": {
		baseLevel: DangerLevelWarning,
		reason:    "terminates processes",
		checkFn:   checkKillCommand,
	},
	"killall": {baseLevel: DangerLevelBlocked, reason: "terminates processes by name"},
	"pkill":   {baseLevel: DangerLevelBlocked, reason: "terminates processes by pattern"},

	// Mount operations
	"mount":  {baseLevel: DangerLevelBlocked, reason: "mounts filesystems"},
	"umount": {baseLevel: DangerLevelBlocked, reason: "unmounts filesystems"},

	// Cron
	"crontab": {
		baseLevel: DangerLevelWarning,
		reason:    "modifies scheduled tasks",
		checkFn:   checkCrontabCommand,
	},

	// File operations that can be dangerous
	"truncate": {baseLevel: DangerLevelWarning, reason: "truncates files"},
	"mv": {
		baseLevel: DangerLevelSafe,
		reason:    "moves/renames files",
		checkFn:   checkMvCommand,
	},
	"cp": {
		baseLevel: DangerLevelSafe,
		reason:    "copies files",
		checkFn:   checkCpCommand,
	},

	// Code execution - potential for arbitrary code
	"eval": {baseLevel: DangerLevelBlocked, reason: "executes arbitrary code"},
}

var commandPrefixes = []struct {
	prefix string
	level  DangerLevel
	reason string
}{
	{"mkfs.", DangerLevelBlocked, "formats filesystem"},
}

type CommandAnalysis struct {
	Command     string
	DangerLevel DangerLevel
	Reason      string
	Blocked     bool
}

// AnalyzeCommand parses and analyzes a shell command for security risks.
func AnalyzeCommand(command string) (*CommandAnalysis, error) {
	if forkBombPattern.MatchString(command) {
		return &CommandAnalysis{
			Command:     command,
			DangerLevel: DangerLevelBlocked,
			Reason:      "fork bomb detected",
			Blocked:     true,
		}, nil
	}

	parser := syntax.NewParser()
	prog, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		// Unparseable commands are allowed; let the shell handle syntax errors
		return &CommandAnalysis{
			Command:     command,
			DangerLevel: DangerLevelSafe,
			Reason:      "",
			Blocked:     false,
		}, nil
	}

	analysis := &CommandAnalysis{
		Command:     command,
		DangerLevel: DangerLevelSafe,
		Blocked:     false,
	}

	syntax.Walk(prog, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			analyzeCallExpr(n, analysis)
		case *syntax.BinaryCmd:
			// Check both sides of pipes and logical operators
			analyzeBinaryCmd(n, analysis)
		case *syntax.Redirect:
			// Check dangerous redirections
			analyzeRedirect(n, analysis)
		}
		return true
	})

	return analysis, nil
}

func analyzeCallExpr(n *syntax.CallExpr, analysis *CommandAnalysis) {
	if len(n.Args) == 0 {
		return
	}

	cmdName := extractWord(n.Args[0])
	if cmdName == "" {
		return
	}

	var args []string
	for i := 1; i < len(n.Args); i++ {
		if arg := extractWord(n.Args[i]); arg != "" {
			args = append(args, arg)
		}
	}

	// Check sudo/su/doas elevation
	if cmdName == "sudo" || cmdName == "su" || cmdName == "doas" {
		checkElevatedCommand(cmdName, args, analysis)
		return
	}

	// bash -c, python -c, etc. can execute arbitrary code
	if isShellExec(cmdName, args) {
		updateAnalysis(analysis, DangerLevelBlocked, "executes arbitrary code via "+cmdName)
		return
	}

	if checker, ok := commandCheckers[cmdName]; ok {
		level := checker.baseLevel
		if checker.checkFn != nil {
			level = checker.checkFn(args)
		}
		if level > DangerLevelSafe {
			updateAnalysis(analysis, level, "command '"+cmdName+"' "+checker.reason)
		}
	}

	for _, prefix := range commandPrefixes {
		if strings.HasPrefix(cmdName, prefix.prefix) {
			updateAnalysis(analysis, prefix.level, "command '"+cmdName+"' "+prefix.reason)
		}
	}
}

// analyzeBinaryCmd detects dangerous pipe patterns like "curl | sh"
func analyzeBinaryCmd(n *syntax.BinaryCmd, analysis *CommandAnalysis) {
	if n.Op == syntax.Pipe {
		leftCmd := extractFirstCommand(n.X)
		rightCmd := extractFirstCommand(n.Y)

		// curl/wget piped to shell
		if (leftCmd == "curl" || leftCmd == "wget") &&
			(rightCmd == "sh" || rightCmd == "bash" || rightCmd == "zsh" || rightCmd == "ksh") {
			updateAnalysis(analysis, DangerLevelBlocked, "remote code execution via "+leftCmd+" | "+rightCmd)
		}
	}
}

// analyzeRedirect blocks writes to critical system paths
func analyzeRedirect(n *syntax.Redirect, analysis *CommandAnalysis) {
	if n.Op == syntax.RdrOut || n.Op == syntax.AppOut || n.Op == syntax.RdrAll {
		target := extractWord(n.Word)
		if target == "" {
			return
		}

		cleaned := filepath.Clean(target)

		// Block direct writes to block devices
		if strings.HasPrefix(cleaned, "/dev/sd") ||
			strings.HasPrefix(cleaned, "/dev/hd") ||
			strings.HasPrefix(cleaned, "/dev/nvme") ||
			cleaned == "/dev/null" {
			if cleaned != "/dev/null" {
				updateAnalysis(analysis, DangerLevelBlocked, "writes to block device "+target)
			}
			return
		}

		if cleaned == "/etc/passwd" || cleaned == "/etc/shadow" ||
			cleaned == "/etc/sudoers" || cleaned == "/etc/hosts" {
			updateAnalysis(analysis, DangerLevelBlocked, "writes to critical system file "+target)
		}
	}
}

// checkElevatedCommand analyzes the actual command being run under sudo/su/doas
func checkElevatedCommand(elevator string, args []string, analysis *CommandAnalysis) {
	subCmd, subArgs := findSubCommand(args)
	if subCmd == "" {
		return
	}

	if checker, ok := commandCheckers[subCmd]; ok {
		level := checker.baseLevel
		if checker.checkFn != nil {
			level = checker.checkFn(subArgs)
		}
		if level > DangerLevelSafe {
			updateAnalysis(analysis, level, "elevated command '"+subCmd+"' "+checker.reason)
		}
	}

	for _, prefix := range commandPrefixes {
		if strings.HasPrefix(subCmd, prefix.prefix) {
			updateAnalysis(analysis, prefix.level, "elevated command '"+subCmd+"' "+prefix.reason)
		}
	}

	if isShellExec(subCmd, subArgs) {
		updateAnalysis(analysis, DangerLevelBlocked, "elevated arbitrary code execution via "+subCmd)
	}
}

// findSubCommand extracts the actual command from sudo/su/doas arguments
func findSubCommand(args []string) (cmd string, cmdArgs []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if strings.HasPrefix(arg, "-") {
			if sudoFlagsWithArg[arg] && i+1 < len(args) {
				i++ // Skip flag argument
			}
			continue
		}

		if i < len(args) {
			return arg, args[i+1:]
		}
	}
	return "", nil
}

func checkRmCommand(args []string) DangerLevel {
	hasRecursive := false
	hasForce := false
	hasCriticalPath := false

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			if strings.Contains(arg, "r") || strings.Contains(arg, "R") {
				hasRecursive = true
			}
			if strings.Contains(arg, "f") {
				hasForce = true
			}
		} else if arg == "--recursive" {
			hasRecursive = true
		} else if arg == "--force" {
			hasForce = true
		} else if !strings.HasPrefix(arg, "-") {
			cleaned := filepath.Clean(arg)
			if criticalPaths[cleaned] || cleaned == "/" {
				hasCriticalPath = true
			}
			// Home directories are considered critical
			if strings.HasPrefix(cleaned, "/home/") && strings.Count(cleaned, "/") == 2 {
				hasCriticalPath = true
			}
		}
	}

	if hasRecursive && (hasForce || hasCriticalPath) {
		return DangerLevelBlocked
	}
	if hasCriticalPath {
		return DangerLevelBlocked
	}
	if hasRecursive {
		return DangerLevelWarning
	}
	return DangerLevelSafe
}

func checkChmodCommand(args []string) DangerLevel {
	hasRecursive := false
	hasDangerousPerm := false

	for _, arg := range args {
		if arg == "-R" || arg == "--recursive" {
			hasRecursive = true
		}
		if arg == "777" || arg == "a+rwx" || arg == "ugo+rwx" {
			hasDangerousPerm = true
		}
	}

	if hasRecursive || hasDangerousPerm {
		return DangerLevelBlocked
	}
	return DangerLevelWarning
}

func checkRecursiveFlag(args []string) DangerLevel {
	for _, arg := range args {
		if arg == "-R" || arg == "--recursive" {
			return DangerLevelBlocked
		}
	}
	return DangerLevelWarning
}

func checkKillCommand(args []string) DangerLevel {
	for _, arg := range args {
		// kill -9 -1 would kill all processes
		if arg == "-1" || arg == "-9" {
			return DangerLevelBlocked
		}
	}
	return DangerLevelWarning
}

func checkCrontabCommand(args []string) DangerLevel {
	if slices.Contains(args, "-r") {
		return DangerLevelBlocked // -r removes all crontab entries
	}
	return DangerLevelWarning
}

func checkMvCommand(args []string) DangerLevel {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			cleaned := filepath.Clean(arg)
			if criticalPaths[cleaned] {
				return DangerLevelBlocked
			}
		}
	}
	return DangerLevelSafe
}

func checkCpCommand(args []string) DangerLevel {
	hasForce := false
	hasCriticalDest := false

	for i, arg := range args {
		if arg == "-f" || arg == "--force" {
			hasForce = true
		}
		// Last non-flag argument is the destination
		if !strings.HasPrefix(arg, "-") && i == len(args)-1 {
			cleaned := filepath.Clean(arg)
			if criticalPaths[cleaned] {
				hasCriticalDest = true
			}
		}
	}

	if hasForce && hasCriticalDest {
		return DangerLevelWarning
	}
	return DangerLevelSafe
}

func isShellExec(cmd string, args []string) bool {
	shells := map[string]bool{
		"bash": true, "sh": true, "zsh": true, "ksh": true, "csh": true,
		"python": true, "python3": true, "python2": true,
		"perl": true, "ruby": true, "node": true, "php": true,
	}

	if shells[cmd] {
		for _, arg := range args {
			if arg == "-c" || arg == "-e" {
				return true
			}
		}
	}
	return false
}

func extractFirstCommand(stmt *syntax.Stmt) string {
	if stmt == nil {
		return ""
	}
	var cmdName string
	syntax.Walk(stmt, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			cmdName = extractWord(call.Args[0])
			return false
		}
		return true
	})
	return cmdName
}

func updateAnalysis(analysis *CommandAnalysis, level DangerLevel, reason string) {
	if level > analysis.DangerLevel {
		analysis.DangerLevel = level
		analysis.Reason = reason
		analysis.Blocked = level == DangerLevelBlocked
	}
}

func extractWord(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return ""
	}

	var result strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			result.WriteString(p.Value)
		case *syntax.SglQuoted:
			result.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, qpart := range p.Parts {
				if lit, ok := qpart.(*syntax.Lit); ok {
					result.WriteString(lit.Value)
				}
			}
		}
	}
	return result.String()
}
