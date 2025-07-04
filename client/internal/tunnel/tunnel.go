package tunnel

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// TunnelConfig holds configuration for SSH tunneling
type TunnelConfig struct {
	SSHHost     string
	SSHPort     string
	SSHUser     string
	SSHKeyPath  string
	LocalPort   string
	RemoteHost  string
	RemotePort  string
	BindAddress string
}

// Tunnel represents an SSH tunnel instance
type Tunnel struct {
	Config     TunnelConfig
	client     *ssh.Client
	listener   net.Listener
	wg         sync.WaitGroup
	stopSignal chan struct{}
}

// NewTunnel creates a new SSH tunnel instance
func NewTunnel(config TunnelConfig) (*Tunnel, error) {
	if config.SSHKeyPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("error getting home directory: %v", err)
		}
		config.SSHKeyPath = filepath.Join(homeDir, ".ssh", "id_rsa")
	}

	if config.BindAddress == "" {
		config.BindAddress = "localhost"
	}

	return &Tunnel{
		Config:     config,
		stopSignal: make(chan struct{}),
	}, nil
}

// Start starts the SSH tunnel
func (t *Tunnel) Start() error {
	// Read private key
	key, err := os.ReadFile(t.Config.SSHKeyPath)
	if err != nil {
		return fmt.Errorf("error reading SSH key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("error parsing SSH key: %v", err)
	}

	// Configure SSH client
	config := &ssh.ClientConfig{
		User: t.Config.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to SSH server
	client, err := ssh.Dial("tcp", net.JoinHostPort(t.Config.SSHHost, t.Config.SSHPort), config)
	if err != nil {
		return fmt.Errorf("error connecting to SSH server: %v", err)
	}
	t.client = client

	// Start local listener
	listener, err := net.Listen("tcp", net.JoinHostPort(t.Config.BindAddress, t.Config.LocalPort))
	if err != nil {
		t.client.Close()
		return fmt.Errorf("error starting local listener: %v", err)
	}
	t.listener = listener

	fmt.Printf("SSH tunnel established:\n")
	fmt.Printf("Local port %s -> Remote %s:%s\n", t.Config.LocalPort, t.Config.RemoteHost, t.Config.RemotePort)
	fmt.Printf("Cloud server can now connect to PostgreSQL at localhost:%s\n", t.Config.LocalPort)

	// Handle connections
	t.wg.Add(1)
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

			// Handle the connection in a goroutine
			t.wg.Add(1)
			go func() {
				defer t.wg.Done()
				defer local.Close()

				// Open connection to remote server through SSH tunnel
				remote, err := t.client.Dial("tcp", net.JoinHostPort(t.Config.RemoteHost, t.Config.RemotePort))
				if err != nil {
					fmt.Printf("Error connecting to remote server: %v\n", err)
					return
				}
				defer remote.Close()

				// Copy data bidirectionally
				t.wg.Add(2)
				go func() {
					defer t.wg.Done()
					io.Copy(local, remote)
				}()
				go func() {
					defer t.wg.Done()
					io.Copy(remote, local)
				}()
			}()
		}
	}
}

// Stop stops the SSH tunnel
func (t *Tunnel) Stop() error {
	close(t.stopSignal)

	if t.listener != nil {
		t.listener.Close()
	}
	if t.client != nil {
		t.client.Close()
	}

	t.wg.Wait()
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
