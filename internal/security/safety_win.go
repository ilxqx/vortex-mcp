package security

import (
	"regexp"
	"strings"
)

// windowsDangerousCommands contains commands that are always blocked on Windows
var windowsDangerousCommands = map[string]string{
	"format":   "formats disk drives",
	"diskpart": "disk partitioning tool",
	"shutdown": "shuts down or restarts the system",
	"bcdedit":  "modifies boot configuration",
	"bootrec":  "repairs boot records",
	"sfc":      "system file checker can modify system files",
	"dism":     "deployment image servicing and management",
	"cipher":   "can encrypt/wipe data",
	"recover":  "recovers files from damaged disks",
}

// windowsWarningCommands contains commands that generate warnings on Windows
var windowsWarningCommands = map[string]string{
	"reg":       "modifies Windows registry",
	"regedit":   "modifies Windows registry",
	"netsh":     "modifies network configuration",
	"sc":        "modifies Windows services",
	"taskkill":  "terminates processes",
	"wmic":      "Windows management instrumentation",
	"powercfg":  "modifies power configuration",
	"icacls":    "modifies file permissions",
	"takeown":   "takes ownership of files",
	"attrib":    "changes file attributes",
	"fsutil":    "file system utility",
	"chkdsk":    "disk checking utility",
	"defrag":    "disk defragmentation",
	"cleanmgr":  "disk cleanup",
	"systemreset": "resets Windows",
}

// windowsCriticalPaths contains paths that should not be modified on Windows
var windowsCriticalPaths = []string{
	`c:\windows`,
	`c:\program files`,
	`c:\program files (x86)`,
	`c:\users`,
	`c:\programdata`,
	`%systemroot%`,
	`%windir%`,
	`%programfiles%`,
	`%programfiles(x86)%`,
	`%userprofile%`,
}

// windowsDangerousPatterns contains regex patterns for dangerous Windows commands
var windowsDangerousPatterns = []*regexp.Regexp{
	// del /s /q (recursive force delete)
	regexp.MustCompile(`(?i)\bdel\s+.*(/s|/q).*(/s|/q)`),
	// rd /s /q or rmdir /s /q (recursive directory removal)
	regexp.MustCompile(`(?i)\b(rd|rmdir)\s+.*(/s|/q).*(/s|/q)`),
	// format command with any drive
	regexp.MustCompile(`(?i)\bformat\s+[a-z]:`),
	// Deleting from root of any drive
	regexp.MustCompile(`(?i)\b(del|rd|rmdir)\s+[a-z]:\\[\s$]`),
	regexp.MustCompile(`(?i)\b(del|rd|rmdir)\s+[a-z]:\\$`),
	// PowerShell Remove-Item with -Recurse -Force
	regexp.MustCompile(`(?i)remove-item\s+.*-recurse.*-force`),
	regexp.MustCompile(`(?i)remove-item\s+.*-force.*-recurse`),
	// PowerShell dangerous cmdlets
	regexp.MustCompile(`(?i)\bstop-computer\b`),
	regexp.MustCompile(`(?i)\brestart-computer\b`),
	regexp.MustCompile(`(?i)\bclear-disk\b`),
	regexp.MustCompile(`(?i)\binitialize-disk\b`),
	// Registry manipulation patterns
	regexp.MustCompile(`(?i)\breg\s+(delete|add)\s+.*hklm`),
	regexp.MustCompile(`(?i)\breg\s+(delete|add)\s+.*hkey_local_machine`),
	// Dangerous system paths in delete commands
	regexp.MustCompile(`(?i)\b(del|rd|rmdir|remove-item)\s+.*\\windows\\`),
	regexp.MustCompile(`(?i)\b(del|rd|rmdir|remove-item)\s+.*\\system32\\`),
}

// windowsWarningPatterns contains regex patterns for warning-level Windows commands
var windowsWarningPatterns = []*regexp.Regexp{
	// Simple del or rd without /s /q
	regexp.MustCompile(`(?i)\b(del|erase)\s+`),
	regexp.MustCompile(`(?i)\b(rd|rmdir)\s+`),
	// taskkill
	regexp.MustCompile(`(?i)\btaskkill\s+`),
	// net stop/start
	regexp.MustCompile(`(?i)\bnet\s+(stop|start)\s+`),
}

func analyzeWindowsCommand(command string) *CommandAnalysis {
	analysis := &CommandAnalysis{
		Command:     command,
		DangerLevel: DangerLevelSafe,
		Blocked:     false,
	}

	cmdLower := strings.ToLower(command)
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return analysis
	}

	cmdName := strings.ToLower(parts[0])
	cmdName = strings.TrimSuffix(cmdName, ".exe")
	cmdName = strings.TrimSuffix(cmdName, ".cmd")
	cmdName = strings.TrimSuffix(cmdName, ".bat")

	if reason, blocked := windowsDangerousCommands[cmdName]; blocked {
		analysis.DangerLevel = DangerLevelBlocked
		analysis.Reason = "command '" + cmdName + "' " + reason
		analysis.Blocked = true
		return analysis
	}

	for _, pattern := range windowsDangerousPatterns {
		if pattern.MatchString(command) {
			analysis.DangerLevel = DangerLevelBlocked
			analysis.Reason = "dangerous command pattern detected"
			analysis.Blocked = true
			return analysis
		}
	}

	if strings.Contains(cmdLower, "del") || strings.Contains(cmdLower, "rmdir") ||
		strings.Contains(cmdLower, "rd ") || strings.Contains(cmdLower, "remove-item") {
		for _, path := range windowsCriticalPaths {
			if strings.Contains(cmdLower, strings.ToLower(path)) {
				analysis.DangerLevel = DangerLevelBlocked
				analysis.Reason = "attempts to delete critical system path"
				analysis.Blocked = true
				return analysis
			}
		}
	}

	if reason, warned := windowsWarningCommands[cmdName]; warned {
		analysis.DangerLevel = DangerLevelWarning
		analysis.Reason = "command '" + cmdName + "' " + reason
		return analysis
	}

	for _, pattern := range windowsWarningPatterns {
		if pattern.MatchString(command) {
			analysis.DangerLevel = DangerLevelWarning
			analysis.Reason = "potentially destructive command"
			return analysis
		}
	}

	return analysis
}
