package security

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// WindowsSecurityTestSuite tests the Windows command security analyzer
// including dangerous commands, patterns, and critical path detection.
type WindowsSecurityTestSuite struct {
	suite.Suite
}

// TestBlockedCommands tests commands that should always be blocked on Windows.
func (s *WindowsSecurityTestSuite) TestBlockedCommands() {
	s.T().Log("Testing blocked Windows commands")

	tests := []struct {
		name    string
		command string
	}{
		{"FormatDrive", "format c:"},
		{"FormatDriveWithOptions", "format d: /fs:ntfs"},
		{"Diskpart", "diskpart"},
		{"Shutdown", "shutdown /s /t 0"},
		{"ShutdownRestart", "shutdown /r"},
		{"Bcdedit", "bcdedit /set"},
		{"Cipher", "cipher /w:c:"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			analysis := analyzeWindowsCommand(tt.command)
			s.True(analysis.Blocked, "Command '%s' should be blocked", tt.command)
			s.Equal(DangerLevelBlocked, analysis.DangerLevel)
			s.T().Logf("Command: %s -> Blocked: %s", tt.command, analysis.Reason)
		})
	}
}

// TestDangerousPatterns tests dangerous command patterns on Windows.
func (s *WindowsSecurityTestSuite) TestDangerousPatterns() {
	s.T().Log("Testing dangerous Windows command patterns")

	tests := []struct {
		name    string
		command string
	}{
		{"DelRecursiveForce", "del /s /q *.*"},
		{"DelForceRecursive", "del /q /s c:\\temp"},
		{"RdRecursiveForce", "rd /s /q c:\\folder"},
		{"RmdirRecursiveForce", "rmdir /s /q folder"},
		{"DelFromRoot", "del c:\\"},
		{"RdFromRoot", "rd c:\\ /s /q"},
		{"PowerShellRemoveRecurseForce", "Remove-Item -Path c:\\test -Recurse -Force"},
		{"PowerShellRemoveForceRecurse", "Remove-Item c:\\test -Force -Recurse"},
		{"PowerShellStopComputer", "Stop-Computer"},
		{"PowerShellRestartComputer", "Restart-Computer"},
		{"RegDeleteHKLM", "reg delete HKLM\\SOFTWARE\\Test"},
		{"DelWindowsFolder", "del c:\\windows\\temp\\*"},
		{"DelSystem32", "del c:\\windows\\system32\\file.dll"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			analysis := analyzeWindowsCommand(tt.command)
			s.True(analysis.Blocked, "Command '%s' should be blocked", tt.command)
			s.Equal(DangerLevelBlocked, analysis.DangerLevel)
			s.T().Logf("Command: %s -> Blocked: %s", tt.command, analysis.Reason)
		})
	}
}

// TestCriticalPaths tests deletion of critical system paths.
func (s *WindowsSecurityTestSuite) TestCriticalPaths() {
	s.T().Log("Testing critical path protection on Windows")

	tests := []struct {
		name    string
		command string
	}{
		{"DelProgramFiles", "del \"c:\\program files\\app\""},
		{"RdProgramFilesX86", "rd \"c:\\program files (x86)\\app\""},
		{"DelUsers", "del c:\\users\\test"},
		{"RmdirProgramData", "rmdir c:\\programdata\\app"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			analysis := analyzeWindowsCommand(tt.command)
			s.True(analysis.Blocked, "Command '%s' should be blocked", tt.command)
			s.T().Logf("Command: %s -> Blocked: %s", tt.command, analysis.Reason)
		})
	}
}

// TestWarningCommands tests commands that should generate warnings.
func (s *WindowsSecurityTestSuite) TestWarningCommands() {
	s.T().Log("Testing warning-level Windows commands")

	tests := []struct {
		name    string
		command string
	}{
		{"RegQuery", "reg query HKCU"},
		{"Taskkill", "taskkill /pid 1234"},
		{"NetStop", "net stop servicename"},
		{"NetStart", "net start servicename"},
		{"Icacls", "icacls file.txt /grant user:F"},
		{"Attrib", "attrib +h file.txt"},
		{"SimpleDel", "del file.txt"},
		{"SimpleRd", "rd emptydir"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			analysis := analyzeWindowsCommand(tt.command)
			s.False(analysis.Blocked, "Command '%s' should not be blocked", tt.command)
			s.Equal(DangerLevelWarning, analysis.DangerLevel)
			s.T().Logf("Command: %s -> Warning: %s", tt.command, analysis.Reason)
		})
	}
}

// TestSafeCommands tests commands that should be allowed.
func (s *WindowsSecurityTestSuite) TestSafeCommands() {
	s.T().Log("Testing safe Windows commands")

	tests := []struct {
		name    string
		command string
	}{
		{"Dir", "dir"},
		{"DirPath", "dir c:\\temp"},
		{"DirDetailed", "dir /a /s c:\\projects"},
		{"Type", "type file.txt"},
		{"Echo", "echo hello world"},
		{"Cd", "cd c:\\users"},
		{"Copy", "copy file1.txt file2.txt"},
		{"Move", "move old.txt new.txt"},
		{"Mkdir", "mkdir newfolder"},
		{"Cls", "cls"},
		{"Set", "set PATH"},
		{"Hostname", "hostname"},
		{"Ipconfig", "ipconfig /all"},
		{"Ping", "ping localhost"},
		{"Netstat", "netstat -an"},
		{"Tasklist", "tasklist"},
		{"Whoami", "whoami"},
		{"Ver", "ver"},
		{"Systeminfo", "systeminfo"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			analysis := analyzeWindowsCommand(tt.command)
			s.False(analysis.Blocked, "Command '%s' should not be blocked", tt.command)
			s.Equal(DangerLevelSafe, analysis.DangerLevel)
			s.T().Logf("Command: %s -> Safe", tt.command)
		})
	}
}

// TestEmptyAndWhitespace tests edge cases.
func (s *WindowsSecurityTestSuite) TestEmptyAndWhitespace() {
	s.T().Log("Testing edge cases")

	s.Run("EmptyCommand", func() {
		analysis := analyzeWindowsCommand("")
		s.False(analysis.Blocked)
		s.Equal(DangerLevelSafe, analysis.DangerLevel)
	})

	s.Run("WhitespaceOnly", func() {
		analysis := analyzeWindowsCommand("   ")
		s.False(analysis.Blocked)
		s.Equal(DangerLevelSafe, analysis.DangerLevel)
	})
}

// TestCaseInsensitivity tests that command detection is case-insensitive.
func (s *WindowsSecurityTestSuite) TestCaseInsensitivity() {
	s.T().Log("Testing case insensitivity")

	tests := []struct {
		name    string
		command string
		blocked bool
	}{
		{"FormatLower", "format c:", true},
		{"FormatUpper", "FORMAT C:", true},
		{"FormatMixed", "Format C:", true},
		{"DelRecursiveMixed", "DEL /S /Q *.*", true},
		{"ShutdownMixed", "ShutDown /s", true},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			analysis := analyzeWindowsCommand(tt.command)
			s.Equal(tt.blocked, analysis.Blocked, "Command '%s' blocked status mismatch", tt.command)
		})
	}
}

func TestWindowsSecurityTestSuite(t *testing.T) {
	suite.Run(t, new(WindowsSecurityTestSuite))
}
