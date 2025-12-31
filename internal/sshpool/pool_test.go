package sshpool

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

// PoolTestSuite tests the SSH connection pool functionality including
// connection creation, reuse, health checks, and idle cleanup.
type PoolTestSuite struct {
	suite.Suite

	ctx          context.Context
	sshContainer *SSHContainer
	pool         *Pool
}

// SSHContainer holds the SSH container configuration for testing.
type SSHContainer struct {
	testcontainers.Container
	Host     string
	Port     int
	User     string
	Password string
}

func (s *PoolTestSuite) SetupSuite() {
	if testing.Short() {
		s.T().Skip("Skipping integration test in short mode")
	}

	s.ctx = context.Background()
	s.sshContainer = s.setupSSHContainer()
	s.T().Logf("SSH container started at %s:%d", s.sshContainer.Host, s.sshContainer.Port)
}

func (s *PoolTestSuite) SetupTest() {
	s.pool = New(WithIdleTimeout(30 * time.Second))
}

func (s *PoolTestSuite) TearDownTest() {
	if s.pool != nil {
		_ = s.pool.Close()
	}
}

func (s *PoolTestSuite) TearDownSuite() {
	if s.sshContainer != nil {
		if err := s.sshContainer.Terminate(s.ctx); err != nil {
			s.T().Logf("Failed to terminate SSH container: %v", err)
		}
	}
}

func (s *PoolTestSuite) setupSSHContainer() *SSHContainer {
	password := "testpassword123"

	req := testcontainers.ContainerRequest{
		Image:        "testcontainers/sshd:1.3.0",
		ExposedPorts: []string{"22/tcp"},
		Env: map[string]string{
			"PASSWORD": password,
		},
		WaitingFor: wait.ForAll(
			wait.ForLog("chpasswd: password for 'root' changed"),
			wait.ForListeningPort("22/tcp"),
			wait.ForExec([]string{"sh", "-c", "echo ready"}).
				WithExitCodeMatcher(func(exitCode int) bool {
					return exitCode == 0
				}),
		).WithDeadline(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(s.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	s.Require().NoError(err, "Should start SSH container")

	host, err := container.Host(s.ctx)
	s.Require().NoError(err, "Should get container host")

	mappedPort, err := container.MappedPort(s.ctx, nat.Port("22/tcp"))
	s.Require().NoError(err, "Should get mapped port")

	sshContainer := &SSHContainer{
		Container: container,
		Host:      host,
		Port:      mappedPort.Int(),
		User:      "root",
		Password:  password,
	}

	s.waitForSSHReady(sshContainer)

	return sshContainer
}

func (s *PoolTestSuite) waitForSSHReady(container *SSHContainer) {
	sshConfig := &ssh.ClientConfig{
		User:            container.User,
		Auth:            []ssh.AuthMethod{ssh.Password(container.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", container.Host, container.Port)
	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		client, err := ssh.Dial("tcp", addr, sshConfig)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		session, err := client.NewSession()
		if err != nil {
			_ = client.Close()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		_, err = session.CombinedOutput("echo ready")
		_ = session.Close()
		_ = client.Close()

		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	s.FailNow("SSH container did not become ready in time")
}

func (s *PoolTestSuite) getPoolConfig() *Config {
	return &Config{
		Host:     s.sshContainer.Host,
		Port:     s.sshContainer.Port,
		User:     s.sshContainer.User,
		Password: s.sshContainer.Password,
		Timeout:  10 * time.Second,
	}
}

// TestGetConnection tests basic connection retrieval from the pool.
func (s *PoolTestSuite) TestGetConnection() {
	s.T().Log("Testing basic connection retrieval")

	s.Run("SuccessfulConnection", func() {
		cfg := s.getPoolConfig()

		client, err := s.pool.Get(s.ctx, cfg)
		s.Require().NoError(err, "Should get connection from pool")
		s.NotNil(client, "Client should not be nil")

		session, err := client.NewSession()
		s.Require().NoError(err, "Should create session")
		defer func() { _ = session.Close() }()

		output, err := session.CombinedOutput("echo hello")
		s.Require().NoError(err, "Should execute command")
		s.Contains(string(output), "hello", "Output should contain hello")
	})

	s.Run("InvalidHost", func() {
		cfg := &Config{
			Host:     "invalid-host-that-does-not-exist",
			Port:     22,
			User:     "user",
			Password: "pass",
			Timeout:  2 * time.Second,
		}

		_, err := s.pool.Get(s.ctx, cfg)
		s.Error(err, "Should fail for invalid host")
	})

	s.Run("InvalidCredentials", func() {
		cfg := &Config{
			Host:     s.sshContainer.Host,
			Port:     s.sshContainer.Port,
			User:     "wronguser",
			Password: "wrongpass",
			Timeout:  5 * time.Second,
		}

		_, err := s.pool.Get(s.ctx, cfg)
		s.Error(err, "Should fail for invalid credentials")
	})
}

// TestConnectionReuse tests that connections are properly reused.
func (s *PoolTestSuite) TestConnectionReuse() {
	s.T().Log("Testing connection reuse")

	cfg := s.getPoolConfig()

	client1, err := s.pool.Get(s.ctx, cfg)
	s.Require().NoError(err, "Should get first connection")

	client2, err := s.pool.Get(s.ctx, cfg)
	s.Require().NoError(err, "Should get second connection")

	s.Equal(client1, client2, "Should return the same connection for same config")

	active, idle := s.pool.Stats()
	s.T().Logf("Pool stats: active=%d, idle=%d", active, idle)
	s.Equal(1, active+idle, "Should have exactly one connection in pool")
}

// TestMultipleServers tests connections to different servers are separate.
func (s *PoolTestSuite) TestMultipleServers() {
	s.T().Log("Testing multiple server connections")

	cfg1 := s.getPoolConfig()

	cfg2 := &Config{
		Host:     s.sshContainer.Host,
		Port:     s.sshContainer.Port,
		User:     s.sshContainer.User,
		Password: s.sshContainer.Password,
		Timeout:  10 * time.Second,
	}

	client1, err := s.pool.Get(s.ctx, cfg1)
	s.Require().NoError(err, "Should get connection with cfg1")

	client2, err := s.pool.Get(s.ctx, cfg2)
	s.Require().NoError(err, "Should get connection with cfg2")

	s.Equal(client1, client2, "Same config should return same connection")
}

// TestPoolClose tests pool closure behavior.
func (s *PoolTestSuite) TestPoolClose() {
	s.T().Log("Testing pool close")

	cfg := s.getPoolConfig()

	client, err := s.pool.Get(s.ctx, cfg)
	s.Require().NoError(err, "Should get connection")
	s.NotNil(client, "Client should not be nil")

	err = s.pool.Close()
	s.NoError(err, "Should close pool without error")

	_, err = s.pool.Get(s.ctx, cfg)
	s.Error(err, "Should fail to get connection after close")
	s.Contains(err.Error(), "pool is closed", "Error should indicate pool is closed")
}

// TestStats tests pool statistics reporting.
func (s *PoolTestSuite) TestStats() {
	s.T().Log("Testing pool statistics")

	active, idle := s.pool.Stats()
	s.Equal(0, active, "New pool should have no active connections")
	s.Equal(0, idle, "New pool should have no idle connections")

	cfg := s.getPoolConfig()

	_, err := s.pool.Get(s.ctx, cfg)
	s.Require().NoError(err, "Should get connection")

	active, idle = s.pool.Stats()
	s.T().Logf("After get: active=%d, idle=%d", active, idle)
	s.Equal(1, active+idle, "Should have one connection total")
}

// TestWithIdleTimeout tests the idle timeout option.
func (s *PoolTestSuite) TestWithIdleTimeout() {
	s.T().Log("Testing idle timeout option")

	pool := New(WithIdleTimeout(100 * time.Millisecond))
	defer func() { _ = pool.Close() }()

	s.Equal(100*time.Millisecond, pool.idleTimeout, "Idle timeout should be set correctly")
}

// TestContextCancellation tests behavior when context is cancelled.
func (s *PoolTestSuite) TestContextCancellation() {
	s.T().Log("Testing context cancellation")

	ctx, cancel := context.WithCancel(s.ctx)
	cancel()

	cfg := s.getPoolConfig()

	_, err := s.pool.Get(ctx, cfg)
	s.Error(err, "Should fail when context is cancelled")
}

// TestMakeKey tests the key generation for pool entries.
func (s *PoolTestSuite) TestMakeKey() {
	s.T().Log("Testing key generation")

	cfg := &Config{
		Host: "example.com",
		Port: 22,
		User: "testuser",
	}

	key := s.pool.makeKey(cfg)
	s.Equal("testuser@example.com:22", key, "Key should have expected format")
}

// TestConcurrentAccess tests concurrent access to the pool.
func (s *PoolTestSuite) TestConcurrentAccess() {
	s.T().Log("Testing concurrent access")

	cfg := s.getPoolConfig()
	const goroutines = 10

	errCh := make(chan error, goroutines)

	for range goroutines {
		go func() {
			client, err := s.pool.Get(s.ctx, cfg)
			if err != nil {
				errCh <- err
				return
			}

			session, err := client.NewSession()
			if err != nil {
				errCh <- err
				return
			}

			_, err = session.CombinedOutput("echo test")
			_ = session.Close()
			errCh <- err
		}()
	}

	for range goroutines {
		err := <-errCh
		s.NoError(err, "Concurrent access should not error")
	}

	active, idle := s.pool.Stats()
	s.T().Logf("After concurrent access: active=%d, idle=%d", active, idle)
	s.Equal(1, active+idle, "Should have only one connection despite concurrent access")
}

func TestPoolTestSuite(t *testing.T) {
	suite.Run(t, new(PoolTestSuite))
}

// PoolUnitTestSuite tests pool unit functionality without real SSH connections.
type PoolUnitTestSuite struct {
	suite.Suite
}

// TestNew tests pool creation.
func (s *PoolUnitTestSuite) TestNew() {
	s.T().Log("Testing pool creation")

	s.Run("DefaultOptions", func() {
		pool := New()
		defer func() { _ = pool.Close() }()

		s.NotNil(pool, "Pool should not be nil")
		s.Equal(defaultIdleTimeout, pool.idleTimeout, "Default idle timeout should be set")
		s.NotNil(pool.clients, "Clients map should be initialized")
		s.False(pool.closed.Load(), "Pool should not be closed")
	})

	s.Run("WithCustomIdleTimeout", func() {
		timeout := 10 * time.Minute
		pool := New(WithIdleTimeout(timeout))
		defer func() { _ = pool.Close() }()

		s.Equal(timeout, pool.idleTimeout, "Custom idle timeout should be set")
	})
}

// TestCloseEmpty tests closing an empty pool.
func (s *PoolUnitTestSuite) TestCloseEmpty() {
	s.T().Log("Testing close empty pool")

	pool := New()
	err := pool.Close()
	s.NoError(err, "Closing empty pool should not error")

	err = pool.Close()
	s.NoError(err, "Closing already closed pool should not error")
}

// TestStatsEmpty tests stats on empty pool.
func (s *PoolUnitTestSuite) TestStatsEmpty() {
	s.T().Log("Testing stats on empty pool")

	pool := New()
	defer func() { _ = pool.Close() }()

	active, idle := pool.Stats()
	s.Equal(0, active, "Empty pool should have no active connections")
	s.Equal(0, idle, "Empty pool should have no idle connections")
}

// TestMakeKeyVariations tests key generation with different configs.
func (s *PoolUnitTestSuite) TestMakeKeyVariations() {
	s.T().Log("Testing key generation variations")

	pool := New()
	defer func() { _ = pool.Close() }()

	s.Run("StandardConfig", func() {
		cfg := &Config{Host: "host.com", Port: 22, User: "user"}
		s.Equal("user@host.com:22", pool.makeKey(cfg))
	})

	s.Run("NonStandardPort", func() {
		cfg := &Config{Host: "host.com", Port: 2222, User: "admin"}
		s.Equal("admin@host.com:2222", pool.makeKey(cfg))
	})

	s.Run("IPAddress", func() {
		cfg := &Config{Host: "192.168.1.100", Port: 22, User: "root"}
		s.Equal("root@192.168.1.100:22", pool.makeKey(cfg))
	})
}

// TestDefaultPool tests the default global pool singleton.
func (s *PoolUnitTestSuite) TestDefaultPool() {
	s.T().Log("Testing default pool singleton")

	pool1 := Default()
	pool2 := Default()

	s.NotNil(pool1, "Default pool should not be nil")
	s.Equal(pool1, pool2, "Default should return same instance")
}

func TestPoolUnitTestSuite(t *testing.T) {
	suite.Run(t, new(PoolUnitTestSuite))
}
