package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

// TunnelClient represents a tunnel client that connects to our custom tunnel server
type TunnelClient struct {
	Config         TunnelClientConfig
	controlConn    net.Conn
	localConn      net.Conn
	wg             sync.WaitGroup
	stopSignal     chan struct{}
	tunnelID       string
	remotePort     string
	isConnected    bool
	connectionMu   sync.RWMutex
	reconnectCount int
	stopped        bool // Prevent reconnect after user shutdown
}

// TunnelClientConfig holds configuration for our custom tunnel client
type TunnelClientConfig struct {
	ServerAddress        string
	LocalPort            string
	Token                string
	MaxReconnectAttempts int           // Maximum number of reconnection attempts (0 = infinite)
	InitialRetryDelay    time.Duration // Initial delay between reconnection attempts
	MaxRetryDelay        time.Duration // Maximum delay between reconnection attempts
	HealthCheckInterval  time.Duration // Interval for health checks
	ConnectionTimeout    time.Duration // Timeout for connection attempts
}

// NewTunnelClient creates a new tunnel client instance
func NewTunnelClient(config TunnelClientConfig) (*TunnelClient, error) {
	if config.Token == "" {
		config.Token = "default"
	}

	// Set default values for reconnection parameters
	if config.MaxReconnectAttempts == 0 {
		config.MaxReconnectAttempts = 10 // 0 means infinite, but we'll use 10 as default
	}
	if config.InitialRetryDelay == 0 {
		config.InitialRetryDelay = 1 * time.Second
	}
	if config.MaxRetryDelay == 0 {
		config.MaxRetryDelay = 60 * time.Second
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 10 * time.Second
	}

	return &TunnelClient{
		Config:     config,
		stopSignal: make(chan struct{}),
	}, nil
}

// Start starts the tunnel client with automatic reconnection
func (tc *TunnelClient) Start() error {
	// Start with initial connection attempt
	tc.wg.Add(1)
	go tc.connectionManager()

	return nil
}

// connectionManager manages the tunnel connection with automatic reconnection
func (tc *TunnelClient) connectionManager() {
	defer tc.wg.Done()

	attempt := 0
	for {
		select {
		case <-tc.stopSignal:
			tc.connectionMu.Lock()
			tc.stopped = true
			tc.connectionMu.Unlock()
			return
		default:
			attempt++
			fmt.Printf("🔄 Connection attempt %d...\n", attempt)

			if err := tc.connect(); err != nil {
				fmt.Printf("❌ Connection failed: %v\n", err)

				// Check if we should stop trying
				if tc.Config.MaxReconnectAttempts > 0 && attempt >= tc.Config.MaxReconnectAttempts {
					fmt.Printf("💥 Maximum reconnection attempts (%d) reached. Stopping.\n", tc.Config.MaxReconnectAttempts)
					return
				}

				// Calculate exponential backoff delay
				delay := tc.calculateBackoffDelay(attempt)
				fmt.Printf("⏳ Waiting %v before next attempt...\n", delay)

				select {
				case <-tc.stopSignal:
					tc.connectionMu.Lock()
					tc.stopped = true
					tc.connectionMu.Unlock()
					return
				case <-time.After(delay):
					// Before retrying, check if stopped
					tc.connectionMu.RLock()
					if tc.stopped {
						tc.connectionMu.RUnlock()
						return
					}
					tc.connectionMu.RUnlock()
					continue
				}
			} else {
				// Connection successful, reset attempt counter
				attempt = 0
				tc.reconnectCount++

				if tc.reconnectCount > 1 {
					fmt.Printf("✅ Reconnected successfully! (reconnection #%d)\n", tc.reconnectCount-1)
				} else {
					fmt.Printf("✅ Connected successfully!\n")
				}

				// Start health monitoring
				tc.wg.Add(1)
				go tc.healthMonitor()

				// Wait for connection to end
				tc.waitForDisconnection()

				// Before retrying, check if stopped
				tc.connectionMu.RLock()
				if tc.stopped {
					tc.connectionMu.RUnlock()
					return
				}
				tc.connectionMu.RUnlock()
				fmt.Printf("🔌 Connection lost. Attempting to reconnect...\n")
			}
		}
	}
}

// connect establishes a connection to the tunnel server
func (tc *TunnelClient) connect() error {
	// Connect to tunnel server with timeout
	dialer := &net.Dialer{
		Timeout: tc.Config.ConnectionTimeout,
	}

	conn, err := dialer.Dial("tcp", tc.Config.ServerAddress)
	if err != nil {
		return fmt.Errorf("error connecting to tunnel server: %v", err)
	}

	// Send authentication and tunnel request
	fmt.Fprintf(conn, "%s\n", tc.Config.Token)
	fmt.Fprintf(conn, "%s\n", tc.Config.LocalPort)

	// Read response with timeout
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return fmt.Errorf("error reading server response: %v", err)
	}
	conn.SetReadDeadline(time.Time{}) // Clear deadline

	response = strings.TrimSpace(response)
	parts := strings.Split(response, ":")

	if len(parts) < 1 || parts[0] != "SUCCESS" {
		conn.Close()
		if len(parts) > 1 {
			return fmt.Errorf("tunnel creation failed: %s", strings.Join(parts[1:], ":"))
		}
		return fmt.Errorf("tunnel creation failed: %s", response)
	}

	if len(parts) < 3 {
		conn.Close()
		return fmt.Errorf("invalid server response format: %s", response)
	}

	// Update connection state
	tc.connectionMu.Lock()
	tc.controlConn = conn
	tc.tunnelID = parts[1]
	tc.remotePort = parts[2]
	tc.isConnected = true
	tc.connectionMu.Unlock()

	fmt.Printf("🎯 Tunnel established!\n")
	fmt.Printf("   Tunnel ID: %s\n", tc.tunnelID)
	fmt.Printf("   Local port %s → Remote port %s\n", tc.Config.LocalPort, tc.remotePort)
	fmt.Printf("   Access via: %s (remote port %s)\n", tc.Config.ServerAddress, tc.remotePort)

	// Start handling tunnel connections
	tc.wg.Add(1)
	go tc.handleTunnelConnections()

	return nil
}

// calculateBackoffDelay calculates exponential backoff delay
func (tc *TunnelClient) calculateBackoffDelay(attempt int) time.Duration {
	// Exponential backoff: delay = initial * 2^(attempt-1)
	delay := time.Duration(float64(tc.Config.InitialRetryDelay) * math.Pow(2, float64(attempt-1)))

	// Cap at maximum delay
	if delay > tc.Config.MaxRetryDelay {
		delay = tc.Config.MaxRetryDelay
	}

	return delay
}

// healthMonitor monitors connection health and triggers reconnection if needed
func (tc *TunnelClient) healthMonitor() {
	defer tc.wg.Done()

	ticker := time.NewTicker(tc.Config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tc.stopSignal:
			return
		case <-ticker.C:
			if !tc.isHealthy() {
				fmt.Printf("🚨 Health check failed - connection appears dead\n")
				tc.disconnect()
				return
			}
		}
	}
}

// isHealthy checks if the connection is healthy
func (tc *TunnelClient) isHealthy() bool {
	tc.connectionMu.RLock()
	conn := tc.controlConn
	connected := tc.isConnected
	tc.connectionMu.RUnlock()

	if !connected || conn == nil {
		return false
	}

	// Try to write a simple ping (this is a basic health check)
	// In a more sophisticated implementation, you might have a proper ping/pong protocol
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write([]byte{}) // Empty write to test connection
	conn.SetWriteDeadline(time.Time{})

	return err == nil
}

// waitForDisconnection waits until the connection is lost
func (tc *TunnelClient) waitForDisconnection() {
	for {
		tc.connectionMu.RLock()
		connected := tc.isConnected
		tc.connectionMu.RUnlock()

		if !connected {
			break
		}

		select {
		case <-tc.stopSignal:
			return
		case <-time.After(1 * time.Second):
			continue
		}
	}
}

// disconnect closes the current connection
func (tc *TunnelClient) disconnect() {
	tc.connectionMu.Lock()
	defer tc.connectionMu.Unlock()

	tc.isConnected = false
	if tc.controlConn != nil {
		tc.controlConn.Close()
		tc.controlConn = nil
	}
}

// handleTunnelConnections handles incoming tunnel connection requests
func (tc *TunnelClient) handleTunnelConnections() {
	defer tc.wg.Done()
	defer tc.disconnect()

	reader := bufio.NewReader(tc.controlConn)

	for {
		select {
		case <-tc.stopSignal:
			return
		default:
			// Read connection request from server
			line, err := reader.ReadString('\n')
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					fmt.Printf("📡 Control connection error: %v\n", err)
				}
				return
			}

			line = strings.TrimSpace(line)

			if line == "CONNECT" {
				// Read the connection ID
				connIDLine, err := reader.ReadString('\n')
				if err != nil {
					fmt.Printf("❌ Error reading connection ID: %v\n", err)
					return
				}

				connIDLine = strings.TrimSpace(connIDLine)
				if !strings.HasPrefix(connIDLine, "CONN_ID:") {
					fmt.Printf("⚠️ Invalid connection ID format: %s\n", connIDLine)
					continue
				}

				connID := strings.TrimPrefix(connIDLine, "CONN_ID:")
				fmt.Printf("🔗 New connection %s → local:%s\n", connID, tc.Config.LocalPort)

				// Handle this connection in a separate goroutine
				tc.wg.Add(1)
				go tc.handleDataConnection(connID)
			}
		}
	}
}

// handleDataConnection handles a data connection by establishing a new connection to the server
func (tc *TunnelClient) handleDataConnection(connID string) {
	defer tc.wg.Done()

	// Establish a new connection to the server for data transfer
	dialer := &net.Dialer{
		Timeout: tc.Config.ConnectionTimeout,
	}

	dataConn, err := dialer.Dial("tcp", tc.Config.ServerAddress)
	if err != nil {
		fmt.Printf("❌ Error connecting for data transfer: %v\n", err)
		return
	}
	defer dataConn.Close()

	// Send the connection ID to identify this data connection
	fmt.Fprintf(dataConn, "DATA:%s\n", connID)

	// Connect to local service
	localConn, err := net.Dial("tcp", net.JoinHostPort("localhost", tc.Config.LocalPort))
	if err != nil {
		fmt.Printf("❌ Error connecting to local service on port %s: %v\n", tc.Config.LocalPort, err)
		return
	}
	defer localConn.Close()

	fmt.Printf("🌉 Bridging connection %s\n", connID)

	// Copy data bidirectionally between local service and data connection
	done := make(chan struct{}, 2)
	var bytesToServer, bytesToLocal int64

	go func() {
		defer func() { done <- struct{}{} }()
		n, err := io.Copy(dataConn, localConn)
		bytesToServer = n
		if err != nil && err != io.EOF {
			fmt.Printf("⚠️ Error copying local→server: %v\n", err)
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		n, err := io.Copy(localConn, dataConn)
		bytesToLocal = n
		if err != nil && err != io.EOF {
			fmt.Printf("⚠️ Error copying server→local: %v\n", err)
		}
	}()

	// Wait for one direction to finish
	<-done
	fmt.Printf("✅ Connection %s finished (↑%d ↓%d bytes)\n", connID, bytesToServer, bytesToLocal)
}

// Stop stops the tunnel client
func (tc *TunnelClient) Stop() error {
	fmt.Printf("🛑 Stopping tunnel client...\n")
	close(tc.stopSignal)
	tc.connectionMu.Lock()
	if tc.controlConn != nil {
		// Send disconnect message to server
		tc.controlConn.Write([]byte("DISCONNECT\n"))
	}
	tc.stopped = true
	tc.connectionMu.Unlock()

	tc.disconnect()
	tc.wg.Wait()

	fmt.Printf("✅ Tunnel client stopped\n")
	return nil
}
