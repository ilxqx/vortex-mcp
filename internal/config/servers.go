package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	EnvSSHServers = "VORTEX_SSH_SERVERS"
	DefaultSSHPort = 22
	DefaultTimeout = 30
)

// ServerConfig represents a pre-configured SSH server.
type ServerConfig struct {
	Name        string
	Description string
	Host        string
	Port        int
	User        string
	Password    string
	KeyFile     string
	Timeout     int
}

var (
	serverRegistry = make(map[string]*ServerConfig)
	registryMu     sync.RWMutex
	initialized    bool
)

// ParseDSN parses an SSH DSN string.
// Format: ssh://[user[:password]@]host[:port]?name=alias[&desc=description][&key=keyfile][&timeout=30]
func ParseDSN(dsn string) (*ServerConfig, error) {
	if dsn == "" {
		return nil, fmt.Errorf("empty DSN")
	}

	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid DSN format: %w", err)
	}

	if u.Scheme != "ssh" {
		return nil, fmt.Errorf("invalid scheme: expected 'ssh', got '%s'", u.Scheme)
	}

	config := &ServerConfig{
		Port:    DefaultSSHPort,
		Timeout: DefaultTimeout,
	}

	if config.Host = u.Hostname(); config.Host == "" {
		return nil, fmt.Errorf("missing host in DSN")
	}

	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}
		config.Port = port
	}

	if u.User != nil {
		config.User = u.User.Username()
		if password, ok := u.User.Password(); ok {
			config.Password = password
		}
	}

	query := u.Query()

	if config.Name = query.Get("name"); config.Name == "" {
		return nil, fmt.Errorf("missing required parameter 'name' in DSN")
	}

	config.Description = query.Get("desc")

	if keyFile := query.Get("key"); keyFile != "" {
		if strings.HasPrefix(keyFile, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				keyFile = home + keyFile[1:]
			}
		}
		config.KeyFile = keyFile
	}

	if timeoutStr := query.Get("timeout"); timeoutStr != "" {
		timeout, err := strconv.Atoi(timeoutStr)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
		config.Timeout = timeout
	}

	return config, nil
}

func ParseServers(dsnStr string) ([]*ServerConfig, error) {
	if dsnStr == "" {
		return nil, nil
	}

	var configs []*ServerConfig
	parts := splitDSNList(dsnStr)

	for _, part := range parts {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}

		config, err := ParseDSN(part)
		if err != nil {
			return nil, fmt.Errorf("parsing DSN '%s': %w", part, err)
		}
		configs = append(configs, config)
	}

	return configs, nil
}

// splitDSNList splits by comma while respecting URL-encoded characters
func splitDSNList(dsnStr string) []string {
	var (
		result    []string
		current   strings.Builder
		inPercent int
	)

	for _, r := range dsnStr {
		if r == '%' {
			inPercent = 2
			current.WriteRune(r)
			continue
		}

		if inPercent > 0 {
			inPercent--
			current.WriteRune(r)
			continue
		}

		if r == ',' {
			result = append(result, current.String())
			current.Reset()
			continue
		}

		current.WriteRune(r)
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}

func LoadServersFromEnv() error {
	dsns := os.Getenv(EnvSSHServers)
	if dsns == "" {
		return nil
	}

	configs, err := ParseServers(dsns)
	if err != nil {
		return fmt.Errorf("loading servers from %s: %w", EnvSSHServers, err)
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	for _, config := range configs {
		serverRegistry[config.Name] = config
	}
	initialized = true

	return nil
}

func GetServer(name string) (*ServerConfig, error) {
	ensureInitialized()

	registryMu.RLock()
	defer registryMu.RUnlock()

	config, ok := serverRegistry[name]
	if !ok {
		return nil, fmt.Errorf("server '%s' not found", name)
	}

	return config, nil
}

func ListServers() []ServerInfo {
	ensureInitialized()

	registryMu.RLock()
	defer registryMu.RUnlock()

	var servers []ServerInfo
	for _, config := range serverRegistry {
		servers = append(servers, ServerInfo{
			Name:        config.Name,
			Description: config.Description,
			Host:        config.Host,
			User:        config.User,
		})
	}

	return servers
}

func ensureInitialized() {
	registryMu.RLock()
	if initialized {
		registryMu.RUnlock()
		return
	}
	registryMu.RUnlock()

	_ = LoadServersFromEnv()
}

type ServerInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Host        string `json:"host"`
	User        string `json:"user"`
}

func ResetRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	serverRegistry = make(map[string]*ServerConfig)
	initialized = false
}

func RegisterServer(config *ServerConfig) {
	registryMu.Lock()
	defer registryMu.Unlock()
	serverRegistry[config.Name] = config
	initialized = true
}
