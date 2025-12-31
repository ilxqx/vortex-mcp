package sshpool

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	defaultIdleTimeout   = 5 * time.Minute
	defaultCleanInterval = 1 * time.Minute
	defaultConnTimeout   = 30 * time.Second
)

// Config holds SSH connection configuration.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	KeyFile  string
	Timeout  time.Duration
}

// Pool manages a pool of SSH connections.
type Pool struct {
	clients     *xsync.Map[string, *pooledClient]
	idleTimeout time.Duration
	closed      atomic.Bool
	closeCh     chan struct{}
	wg          sync.WaitGroup
}

type pooledClient struct {
	client   *ssh.Client
	key      string
	lastUsed atomic.Int64
	closed   atomic.Bool
}

func (pc *pooledClient) getLastUsed() time.Time {
	return time.Unix(0, pc.lastUsed.Load())
}

func (pc *pooledClient) updateLastUsed() {
	pc.lastUsed.Store(time.Now().UnixNano())
}

// Option configures the Pool.
type Option func(*Pool)

// WithIdleTimeout sets the idle timeout for connections.
func WithIdleTimeout(d time.Duration) Option {
	return func(p *Pool) {
		p.idleTimeout = d
	}
}

// New creates a new connection pool.
func New(opts ...Option) *Pool {
	p := &Pool{
		clients:     xsync.NewMap[string, *pooledClient](),
		idleTimeout: defaultIdleTimeout,
		closeCh:     make(chan struct{}),
	}

	for _, opt := range opts {
		opt(p)
	}

	p.wg.Go(p.cleaner)

	return p
}

// Get returns an SSH client for the given configuration.
// If a connection exists and is healthy, it will be reused.
func (p *Pool) Get(ctx context.Context, cfg *Config) (*ssh.Client, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("pool is closed")
	}

	key := p.makeKey(cfg)

	if pc, exists := p.clients.Load(key); exists {
		if !pc.closed.Load() && p.isHealthy(pc.client) {
			pc.updateLastUsed()
			return pc.client, nil
		}
		p.remove(key)
	}

	client, err := p.dial(ctx, cfg)
	if err != nil {
		return nil, err
	}

	pc := &pooledClient{
		client: client,
		key:    key,
	}
	pc.updateLastUsed()

	if p.closed.Load() {
		_ = client.Close()
		return nil, fmt.Errorf("pool is closed")
	}

	// Atomically store or get existing connection
	actual, loaded := p.clients.LoadOrStore(key, pc)
	if loaded {
		// Another goroutine created a connection first, use that one
		_ = client.Close()
		actual.updateLastUsed()
		return actual.client, nil
	}

	return client, nil
}

// Close closes all connections and stops the cleaner.
func (p *Pool) Close() error {
	if p.closed.Swap(true) {
		return nil // Already closed
	}
	close(p.closeCh)

	var errs []error
	p.clients.Range(func(key string, pc *pooledClient) bool {
		if pc.closed.Swap(true) {
			return true // Already closed
		}
		if err := pc.client.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing %s: %w", key, err))
		}
		return true
	})
	p.clients.Clear()

	p.wg.Wait()

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Stats returns pool statistics.
func (p *Pool) Stats() (active int, idle int) {
	now := time.Now()
	p.clients.Range(func(_ string, pc *pooledClient) bool {
		if !pc.closed.Load() {
			if now.Sub(pc.getLastUsed()) > p.idleTimeout {
				idle++
			} else {
				active++
			}
		}
		return true
	})
	return
}

func (p *Pool) makeKey(cfg *Config) string {
	return fmt.Sprintf("%s@%s:%d", cfg.User, cfg.Host, cfg.Port)
}

func (p *Pool) dial(ctx context.Context, cfg *Config) (*ssh.Client, error) {
	auths, err := p.buildAuthMethods(cfg)
	if err != nil {
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultConnTimeout
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	dialer := net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	c, newCh, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH handshake failed: %w", err)
	}

	return ssh.NewClient(c, newCh, reqs), nil
}

func (p *Pool) buildAuthMethods(cfg *Config) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod

	if cfg.Password != "" {
		auths = append(auths, ssh.Password(cfg.Password))
	}

	if cfg.KeyFile != "" {
		key, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key file: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}

	if sshAgent := p.getSSHAgent(); sshAgent != nil {
		auths = append(auths, ssh.PublicKeysCallback(sshAgent.Signers))
	}

	if len(auths) == 0 {
		return nil, fmt.Errorf("no authentication method available")
	}

	return auths, nil
}

func (p *Pool) getSSHAgent() agent.Agent {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil
	}

	return agent.NewClient(conn)
}

func (p *Pool) isHealthy(client *ssh.Client) bool {
	// Try to open a session to check if connection is still alive
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	_ = session.Close()
	return true
}

func (p *Pool) remove(key string) {
	pc, exists := p.clients.LoadAndDelete(key)
	if !exists {
		return
	}

	if pc.closed.Swap(true) {
		return // Already closed
	}
	_ = pc.client.Close()
}

func (p *Pool) cleaner() {
	ticker := time.NewTicker(defaultCleanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			p.cleanIdle()
		}
	}
}

func (p *Pool) cleanIdle() {
	if p.closed.Load() {
		return
	}

	var toRemove []string
	now := time.Now()

	p.clients.Range(func(key string, pc *pooledClient) bool {
		if !pc.closed.Load() && now.Sub(pc.getLastUsed()) > p.idleTimeout {
			toRemove = append(toRemove, key)
		}
		return true
	})

	for _, key := range toRemove {
		p.remove(key)
	}
}

// DefaultPool is the global connection pool.
var (
	defaultPool     *Pool
	defaultPoolOnce sync.Once
)

// Default returns the default global pool.
func Default() *Pool {
	defaultPoolOnce.Do(func() {
		defaultPool = New()
	})
	return defaultPool
}

// CloseDefault closes the default pool.
func CloseDefault() error {
	if defaultPool != nil {
		return defaultPool.Close()
	}
	return nil
}
