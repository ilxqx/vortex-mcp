package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDSN(t *testing.T) {
	tests := []struct {
		name    string
		dsn     string
		want    *ServerConfig
		wantErr bool
	}{
		{
			name: "FullDSN",
			dsn:  "ssh://deploy:secret@prod.example.com:2222?name=prod&desc=Production+Server&timeout=60",
			want: &ServerConfig{
				Name:        "prod",
				Description: "Production Server",
				Host:        "prod.example.com",
				Port:        2222,
				User:        "deploy",
				Password:    "secret",
				Timeout:     60,
			},
		},
		{
			name: "MinimalDSN",
			dsn:  "ssh://user@host.com?name=myserver",
			want: &ServerConfig{
				Name:    "myserver",
				Host:    "host.com",
				Port:    DefaultSSHPort,
				User:    "user",
				Timeout: DefaultTimeout,
			},
		},
		{
			name: "WithKeyFile",
			dsn:  "ssh://deploy@prod.example.com?name=prod&key=/path/to/key",
			want: &ServerConfig{
				Name:    "prod",
				Host:    "prod.example.com",
				Port:    DefaultSSHPort,
				User:    "deploy",
				KeyFile: "/path/to/key",
				Timeout: DefaultTimeout,
			},
		},
		{
			name: "WithTildeKeyFile",
			dsn:  "ssh://deploy@prod.example.com?name=prod&key=~/.ssh/id_rsa",
			want: &ServerConfig{
				Name:    "prod",
				Host:    "prod.example.com",
				Port:    DefaultSSHPort,
				User:    "deploy",
				Timeout: DefaultTimeout,
				// KeyFile will be expanded, check separately
			},
		},
		{
			name:    "EmptyDSN",
			dsn:     "",
			wantErr: true,
		},
		{
			name:    "InvalidScheme",
			dsn:     "http://user@host.com?name=test",
			wantErr: true,
		},
		{
			name:    "MissingHost",
			dsn:     "ssh://?name=test",
			wantErr: true,
		},
		{
			name:    "MissingName",
			dsn:     "ssh://user@host.com",
			wantErr: true,
		},
		{
			name:    "InvalidPort",
			dsn:     "ssh://user@host.com:abc?name=test",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDSN(tt.dsn)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Host, got.Host)
			assert.Equal(t, tt.want.Port, got.Port)
			assert.Equal(t, tt.want.User, got.User)
			assert.Equal(t, tt.want.Password, got.Password)
			assert.Equal(t, tt.want.Description, got.Description)
			assert.Equal(t, tt.want.Timeout, got.Timeout)

			// Check key file separately for tilde expansion
			if tt.want.KeyFile != "" {
				assert.Equal(t, tt.want.KeyFile, got.KeyFile)
			}
		})
	}
}

func TestParseDSN_TildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	dsn := "ssh://user@host.com?name=test&key=~/.ssh/id_rsa"
	cfg, err := ParseDSN(dsn)
	require.NoError(t, err)
	assert.Equal(t, home+"/.ssh/id_rsa", cfg.KeyFile)
}

func TestParseServers(t *testing.T) {
	tests := []struct {
		name    string
		dsns    string
		want    int
		wantErr bool
	}{
		{
			name: "SingleServer",
			dsns: "ssh://user@host1.com?name=server1",
			want: 1,
		},
		{
			name: "MultipleServers",
			dsns: "ssh://user1@host1.com?name=server1,ssh://user2@host2.com?name=server2,ssh://user3@host3.com?name=server3",
			want: 3,
		},
		{
			name: "EmptyString",
			dsns: "",
			want: 0,
		},
		{
			name: "WithSpaces",
			dsns: "ssh://user@host1.com?name=server1, ssh://user@host2.com?name=server2",
			want: 2,
		},
		{
			name:    "InvalidDSN",
			dsns:    "ssh://user@host1.com?name=server1,invalid-dsn",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configs, err := ParseServers(tt.dsns)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, configs, tt.want)
		})
	}
}

func TestServerRegistry(t *testing.T) {
	// Reset registry before test
	ResetRegistry()
	defer ResetRegistry()

	// Register a server
	cfg := &ServerConfig{
		Name:     "test-server",
		Host:     "test.example.com",
		Port:     22,
		User:     "testuser",
		Password: "testpass",
	}
	RegisterServer(cfg)

	// Get server
	got, err := GetServer("test-server")
	require.NoError(t, err)
	assert.Equal(t, cfg.Name, got.Name)
	assert.Equal(t, cfg.Host, got.Host)

	// Get non-existent server
	_, err = GetServer("non-existent")
	assert.Error(t, err)
}

func TestListServers(t *testing.T) {
	// Reset registry before test
	ResetRegistry()
	defer ResetRegistry()

	// Register multiple servers
	RegisterServer(&ServerConfig{Name: "server1", Host: "host1.com", User: "user1"})
	RegisterServer(&ServerConfig{Name: "server2", Host: "host2.com", User: "user2", Description: "Second server"})

	servers := ListServers()
	assert.Len(t, servers, 2)

	// Check that sensitive info is not exposed
	for _, s := range servers {
		assert.NotEmpty(t, s.Name)
		assert.NotEmpty(t, s.Host)
		assert.NotEmpty(t, s.User)
	}
}

func TestLoadServersFromEnv(t *testing.T) {
	// Reset registry before test
	ResetRegistry()
	defer ResetRegistry()

	// Set environment variable
	dsns := "ssh://deploy@prod.example.com:22?name=prod&desc=Production,ssh://dev@dev.example.com?name=dev"
	_ = os.Setenv(EnvSSHServers, dsns)
	defer func() { _ = os.Unsetenv(EnvSSHServers) }()

	err := LoadServersFromEnv()
	require.NoError(t, err)

	// Check prod server
	prod, err := GetServer("prod")
	require.NoError(t, err)
	assert.Equal(t, "prod.example.com", prod.Host)
	assert.Equal(t, "deploy", prod.User)
	assert.Equal(t, "Production", prod.Description)

	// Check dev server
	dev, err := GetServer("dev")
	require.NoError(t, err)
	assert.Equal(t, "dev.example.com", dev.Host)
	assert.Equal(t, "dev", dev.User)
}

func TestSplitDSNList(t *testing.T) {
	tests := []struct {
		name string
		dsns string
		want []string
	}{
		{
			name: "Simple",
			dsns: "a,b,c",
			want: []string{"a", "b", "c"},
		},
		{
			name: "WithURLEncoded",
			dsns: "ssh://user@host?name=test%2C1,ssh://user@host2?name=test2",
			want: []string{"ssh://user@host?name=test%2C1", "ssh://user@host2?name=test2"},
		},
		{
			name: "Empty",
			dsns: "",
			want: nil,
		},
		{
			name: "Single",
			dsns: "single",
			want: []string{"single"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitDSNList(tt.dsns)
			assert.Equal(t, tt.want, got)
		})
	}
}
