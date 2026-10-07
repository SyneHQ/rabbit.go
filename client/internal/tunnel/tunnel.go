package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TunnelConfig holds configuration for SSH tunneling
type TunnelConfig struct {
	SSHHost           string
	SSHPort           string
	SSHUser           string
	SSHKeyPath        string
	SSHKnownHostsPath string        // Defaults to ~/.ssh/known_hosts; unknown hosts fail closed.
	ConnectionTimeout time.Duration // Bounds TCP setup and SSH negotiation; defaults to 10 seconds.
	LocalPort         string
	RemoteHost        string
	RemotePort        string
	BindAddress       string
}

// Tunnel represents an SSH tunnel instance
type Tunnel struct {
	Config     TunnelConfig
	client     *ssh.Client
	listener   net.Listener
	wg         sync.WaitGroup
	stopSignal chan struct{}
	mu         sync.Mutex
	stopOnce   sync.Once
	started    bool
	stopped    bool
	active     map[net.Conn]struct{}
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewTunnel creates a new SSH tunnel instance
func NewTunnel(config TunnelConfig) (*Tunnel, error) {
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 10 * time.Second
	}
	if config.ConnectionTimeout < 0 {
		return nil, errors.New("SSH connection timeout must be positive")
	}
	if config.SSHKeyPath == "" || config.SSHKnownHostsPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("error getting home directory: %v", err)
		}
		if config.SSHKeyPath == "" {
			config.SSHKeyPath = filepath.Join(homeDir, ".ssh", "id_rsa")
		}
		if config.SSHKnownHostsPath == "" {
			config.SSHKnownHostsPath = filepath.Join(homeDir, ".ssh", "known_hosts")
		}
	}

	if config.BindAddress == "" {
		config.BindAddress = "localhost"
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Tunnel{
		ctx:        ctx,
		cancel:     cancel,
		Config:     config,
		stopSignal: make(chan struct{}),
		active:     make(map[net.Conn]struct{}),
	}, nil
}

// sshKnownHostsCallback never learns or replaces host keys automatically.
// Operators must verify host fingerprints through a trusted channel first.
func sshKnownHostsCallback(path string) (ssh.HostKeyCallback, error) {
	callback, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load SSH known_hosts: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := callback(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyError *knownhosts.KeyError
		if errors.As(err, &keyError) && len(keyError.Want) == 0 {
			return fmt.Errorf("unknown SSH host %q; verify its key and add it to %s: %w", hostname, path, err)
		}
		return fmt.Errorf("SSH host key verification failed for %q: %w", hostname, err)
	}, nil
}

// Start starts the SSH tunnel
func (t *Tunnel) Start() error {
	t.mu.Lock()
	if t.started || t.stopped {
		t.mu.Unlock()
		return errors.New("SSH tunnel already started or stopped")
	}
	t.started = true
	// Stop waits for unfinished startup as well as established stream workers.
	t.wg.Add(1)
	t.mu.Unlock()
	defer t.wg.Done()
	ctx, cancel := context.WithTimeout(t.ctx, t.Config.ConnectionTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Read private key
	key, err := os.ReadFile(t.Config.SSHKeyPath)
	if err != nil {
		return fmt.Errorf("error reading SSH key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("error parsing SSH key: %v", err)
	}

	hostKeyCallback, err := sshKnownHostsCallback(t.Config.SSHKnownHostsPath)
	if err != nil {
		return err
	}

	// Configure SSH client
	config := &ssh.ClientConfig{
		User: t.Config.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	// Publish the raw socket before SSH negotiation so Stop can interrupt a
	// peer that accepts TCP but never sends its SSH version or handshake.
	address := net.JoinHostPort(t.Config.SSHHost, t.Config.SSHPort)
	raw, err := (&net.Dialer{Timeout: t.Config.ConnectionTimeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("connect to SSH server: %w", err)
	}
	if !t.trackConnection(raw) {
		raw.Close()
		return net.ErrClosed
	}
	defer t.untrackConnection(raw)
	published := false
	defer func() {
		if !published {
			raw.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return err
	}
	stopHandshake := context.AfterFunc(ctx, func() { raw.Close() })
	sshConn, channels, requests, err := ssh.NewClientConn(raw, address, config)
	stopHandshake()
	if err != nil {
		return fmt.Errorf("negotiate SSH connection: %w", err)
	}
	client := ssh.NewClient(sshConn, channels, requests)
	if err := ctx.Err(); err != nil {
		client.Close()
		return err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		client.Close()
		return err
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(t.Config.BindAddress, t.Config.LocalPort))
	if err != nil {
		client.Close()
		return fmt.Errorf("error starting local listener: %v", err)
	}
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		listener.Close()
		client.Close()
		return net.ErrClosed
	}
	t.client = client
	t.listener = listener
	published = true
	// Register the accept loop before publishing its listener to Stop.
	t.wg.Add(1)
	t.mu.Unlock()

	fmt.Printf("SSH tunnel established:\n")
	fmt.Printf("Local port %s -> Remote %s:%s\n", t.Config.LocalPort, t.Config.RemoteHost, t.Config.RemotePort)
	fmt.Printf("Cloud server can now connect to PostgreSQL at localhost:%s\n", t.Config.LocalPort)

	// Handle connections
	go t.handleConnections()

	return nil
}

// handleConnections handles incoming connections to the tunnel
func (t *Tunnel) handleConnections() {
	defer t.wg.Done()

	for {
		select {
		case <-t.stopSignal:
			return
		default:
			// Accept connection
			local, err := t.listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				fmt.Printf("Error accepting connection: %v\n", err)
				continue
			}

			if !t.trackConnection(local) {
				local.Close()
				return
			}
			// The accept loop owns a WaitGroup slot while adding each stream.
			t.wg.Add(1)
			go func() {
				defer t.wg.Done()
				defer local.Close()
				defer t.untrackConnection(local)

				// Open connection to remote server through SSH tunnel
				remote, err := t.client.Dial("tcp", net.JoinHostPort(t.Config.RemoteHost, t.Config.RemotePort))
				if err != nil {
					fmt.Printf("Error connecting to remote server: %v\n", err)
					return
				}
				defer remote.Close()
				if !t.trackConnection(remote) {
					return
				}
				defer t.untrackConnection(remote)
				bridgeData(local, remote)
			}()
		}
	}
}

func (t *Tunnel) trackConnection(conn net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return false
	}
	t.active[conn] = struct{}{}
	return true
}

func (t *Tunnel) untrackConnection(conn net.Conn) {
	t.mu.Lock()
	delete(t.active, conn)
	t.mu.Unlock()
}

// Stop closes both endpoints of idle streams before waiting for workers.
func (t *Tunnel) Stop() error {
	t.stopOnce.Do(func() {
		t.mu.Lock()
		t.stopped = true
		t.cancel()
		close(t.stopSignal)
		listener, client := t.listener, t.client
		connections := make([]net.Conn, 0, len(t.active))
		for conn := range t.active {
			connections = append(connections, conn)
		}
		t.mu.Unlock()
		if listener != nil {
			listener.Close()
		}
		// Close the SSH transport before its channels, so a channel Close
		// cannot wait indefinitely for a peer that stopped reading SSH packets.
		if client != nil {
			client.Close()
		}
		for _, conn := range connections {
			conn.Close()
		}
		t.wg.Wait()
	})
	return nil
}

// GetRandomPort gets a random available port
func GetRandomPort() (string, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return fmt.Sprintf("%d", addr.Port), nil
}
