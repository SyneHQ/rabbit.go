package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"rabbit.go/internal/database"
	"rabbit.go/internal/middleware"

	"github.com/google/uuid"
)

// Config holds server configuration
type Config struct {
	BindAddress string
	ControlPort string
	LogLevel    string
	APIPort     string // Port for HTTP API server
}

// Server represents the tunnel server
type Server struct {
	config          Config
	controlListener net.Listener
	tunnels         map[string]*Tunnel
	pendingConns    map[string]chan net.Conn
	mu              sync.RWMutex
	stopChan        chan struct{}
	wg              sync.WaitGroup

	// Database integration
	dbService *database.Service

	// API server
	apiServer *APIServer

	// Security middleware
	securityMiddleware *middleware.SecurityMiddleware
}

// Tunnel represents an active tunnel session
type Tunnel struct {
	ID           string
	Token        string
	TeamID       string
	TokenID      string
	PortAssignID string
	LocalPort    string
	RemotePort   string
	BindAddress  string
	Client       net.Conn
	Listener     net.Listener
	CreatedAt    time.Time
	stopChan     chan struct{}
	stopOnce     sync.Once // Ensure stopChan is only closed once
	controlMu    sync.Mutex
	wg           sync.WaitGroup

	// Database tracking
	SessionID     string
	ConnectionLog string
}

// TunnelRequest represents a tunnel creation request
type TunnelRequest struct {
	Token     string `json:"token"`
	LocalPort string `json:"local_port"`
}

// TunnelResponse represents a tunnel creation response
type TunnelResponse struct {
	Success    bool   `json:"success"`
	TunnelID   string `json:"tunnel_id,omitempty"`
	RemotePort string `json:"remote_port,omitempty"`
	Error      string `json:"error,omitempty"`
}

// NewServer creates a new tunnel server
func NewServer(config Config) (*Server, error) {
	log.Println("Loading .env file")
	// Initialize database connection
	dbConfig := database.GetConfigFromEnv()
	db, err := database.NewDatabase(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	dbService := database.NewService(db)

	// Test database connection
	ctx := context.Background()
	if err := dbService.HealthCheck(ctx); err != nil {
		return nil, fmt.Errorf("database health check failed: %w", err)
	}

	log.Printf("✅ Database connection established")

	// Initialize security middleware
	securityConfig := middleware.DefaultSecurityConfig()
	securityMiddleware := middleware.NewSecurityMiddleware(securityConfig)

	server := &Server{
		config:             config,
		tunnels:            make(map[string]*Tunnel),
		pendingConns:       make(map[string]chan net.Conn),
		stopChan:           make(chan struct{}),
		dbService:          dbService,
		securityMiddleware: securityMiddleware,
	}

	// Create API server if port is specified
	if config.APIPort != "" {
		server.apiServer = NewAPIServer(dbService, config.BindAddress, config.APIPort, config.ControlPort)
		server.apiServer.onRevoke = server.revokeToken
	}

	return server, nil
}

// authenticateToken validates a token using the database and returns port assignment
func (s *Server) authenticateToken(ctx context.Context, token string) (*database.TeamToken, *database.PortAssignment, error) {
	return s.dbService.AuthenticateToken(ctx, token)
}

// Start starts the tunnel server
func (s *Server) Start() error {
	// Set global server reference
	globalServer = s

	var err error
	s.controlListener, err = controlListener(net.JoinHostPort(s.config.BindAddress, s.config.ControlPort))
	if err != nil {
		return fmt.Errorf("error starting control listener: %v", err)
	}

	log.Printf("🚀 Tunnel server started on %s:%s", s.config.BindAddress, s.config.ControlPort)
	log.Printf("🔐 Security middleware enabled")
	log.Printf("📡 Using database-based authentication")

	// Restore active connections from database
	if err := s.restoreActiveConnections(); err != nil {
		log.Printf("⚠️ Failed to restore active connections: %v", err)
	}

	// Start API server if configured
	if s.apiServer != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.apiServer.Start(); err != nil && err != http.ErrServerClosed {
				log.Printf("❌ API server error: %v", err)
			}
		}()
	}

	s.wg.Add(1)
	go s.handleControlConnections()

	return nil
}

// Stop stops the tunnel server
func (s *Server) Stop() error {
	close(s.stopChan)

	if s.controlListener != nil {
		s.controlListener.Close()
	}

	// Stop security middleware
	if s.securityMiddleware != nil {
		s.securityMiddleware.Stop()
	}

	// Stop API server
	if s.apiServer != nil {
		if err := s.apiServer.Stop(); err != nil {
			log.Printf("⚠️ Error stopping API server: %v", err)
		}
	}

	// Stop all tunnels
	s.mu.RLock()
	tunnels := make([]*Tunnel, 0, len(s.tunnels))
	for _, tunnel := range s.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	s.mu.RUnlock()
	for _, tunnel := range tunnels {
		s.stopTunnel(tunnel)
	}

	s.wg.Wait()
	return nil
}

// handleControlConnections handles incoming control connections
func (s *Server) handleControlConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopChan:
			return
		default:
			conn, err := s.controlListener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("Error accepting control connection: %v", err)
				}
				continue
			}

			// Apply security validation
			if err := s.securityMiddleware.ValidateConnection(conn); err != nil {
				log.Printf("🚫 Connection rejected from %s: %v", conn.RemoteAddr(), err)
				conn.Close()
				continue
			}

			// Wrap connection with security features
			secureConn := s.securityMiddleware.WrapConnection(conn)

			s.wg.Add(1)
			go s.handleControlConnection(secureConn)
		}
	}
}

// handleControlConnection handles a single control connection
func (s *Server) handleControlConnection(conn net.Conn) {
	defer s.wg.Done()

	log.Printf("New control connection from %s", conn.RemoteAddr())
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Simple protocol: read token and local port on separate lines
	reader := bufio.NewReader(conn)

	// Read first line to determine connection type
	firstLine, err := readControlLine(reader)
	if err != nil {
		log.Printf("Error reading first line: %v", err)
		conn.Close()
		return
	}
	firstLine = strings.TrimSpace(firstLine)

	// Handle data connections
	if strings.HasPrefix(firstLine, "DATA:") {
		s.handleDataConnection(&bufferedConnection{Conn: conn, reader: reader}, firstLine)
		return
	}

	// This is a control connection - continue with tunnel setup
	token := firstLine

	// Read local port
	localPort, err := readControlLine(reader)
	if err != nil {
		log.Printf("Error reading local port: %v", err)
		conn.Close()
		return
	}
	localPort = strings.TrimSpace(localPort)

	ctx := context.Background()

	// Authenticate token and get port assignment
	teamToken, portAssignment, err := s.authenticateToken(ctx, token)
	if err != nil {
		fmt.Fprintf(conn, "ERROR:Invalid token or authentication failed\n")
		log.Printf("❌ Authentication failed for token from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	_ = conn.SetReadDeadline(time.Time{})
	log.Printf("Token authenticated for team: %s", teamToken.Team.Name)
	log.Printf("📍 Assigned port: %d", portAssignment.Port)

	// Check if there's already a tunnel for this port/token (restored or active)
	s.mu.Lock()
	existingTunnel := s.findTunnelByTokenAndPort(token, portAssignment.Port)
	if existingTunnel != nil {
		if existingTunnel.Client == nil {
			log.Printf("🔄 Found existing restored tunnel %s, reconnecting client", existingTunnel.ID)
		} else {
			log.Printf("🔄 Found existing active tunnel %s, replacing client connection", existingTunnel.ID)
		}
		s.mu.Unlock()

		// Reconnect the client to the existing tunnel (restored or active)
		s.reconnectClientToTunnel(existingTunnel, conn, teamToken, portAssignment, localPort)
		return
	}
	s.mu.Unlock()

	// Create new tunnel using the pre-assigned port
	tunnel, err := s.createTunnel(teamToken, portAssignment, localPort, conn)
	if err != nil {
		fmt.Fprintf(conn, "ERROR:%s\n", err.Error())
		log.Printf("Error creating tunnel: %v", err)
		conn.Close()
		return
	}

	// Send success response
	fmt.Fprintf(conn, "SUCCESS:%s:%s\n", tunnel.ID, tunnel.RemotePort)
	log.Printf("🎯 Tunnel created: %s (team:%s, local:%s -> remote:%s)",
		tunnel.ID, teamToken.Team.Name, localPort, tunnel.RemotePort)

	// Monitor control connection - but don't kill tunnel on errors
	// Tunnels should only die on explicit DISCONNECT, not on idle timeouts
	for {
		// Set a read deadline to prevent indefinite blocking
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		line, err := readControlLine(reader)

		if err != nil {
			// Check if it's just a timeout (expected for idle connections)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout is normal - client is idle but connected
				// Log periodically but don't stop tunnel
				log.Printf("💤 Control connection idle for tunnel %s (tunnel still active)", tunnel.ID)
				continue
			}

			// For other errors (connection closed, etc), close control conn but keep tunnel alive
			log.Printf("⚠️ Control connection lost for tunnel %s: %v (tunnel infrastructure remains active for reconnection)", tunnel.ID, err)
			conn.Close()

			// Mark tunnel client as nil so it can be reconnected
			s.mu.Lock()
			if tunnel.Client == conn {
				tunnel.Client = nil
				log.Printf("🔄 Tunnel %s ready for client reconnection", tunnel.ID)
			}
			s.mu.Unlock()
			return
		}

		// Clear deadline after successful read
		conn.SetReadDeadline(time.Time{})

		line = strings.TrimSpace(line)
		switch line {
		case "DISCONNECT":
			log.Printf("🚪 Client explicitly disconnected from tunnel %s", tunnel.ID)
			s.stopTunnel(tunnel)
			return
		case "PING":
			// Respond to PING with PONG
			fmt.Fprintf(conn, "PONG\n")
		case "KEEPALIVE":
			// Just acknowledge keepalive, no response needed
			// This keeps the connection alive and prevents idle timeout
		}
		// Ignore other messages
	}
}

// revokeToken is reachable only after the HTTP API authorizes and revokes the exact team token.
func (s *Server) revokeToken(teamID, tokenID string) {
	s.mu.RLock()
	var targets []*Tunnel
	for _, tunnel := range s.tunnels {
		if tunnel.TeamID == teamID && tunnel.TokenID == tokenID {
			targets = append(targets, tunnel)
		}
	}
	s.mu.RUnlock()
	for _, tunnel := range targets {
		s.stopTunnel(tunnel)
	}
}

// findTunnelByTokenAndPort finds any tunnel (restored or active) by token and port
func (s *Server) findTunnelByTokenAndPort(token string, port int) *Tunnel {
	for _, tunnel := range s.tunnels {
		if tunnel.Token == token && tunnel.RemotePort == strconv.Itoa(port) {
			return tunnel
		}
	}
	return nil
}

// reconnectClientToTunnel reconnects a client to an existing restored tunnel
func (s *Server) reconnectClientToTunnel(tunnel *Tunnel, conn net.Conn, teamToken *database.TeamToken, _ *database.PortAssignment, localPort string) {
	// If there's an existing client, close it gracefully
	s.mu.Lock()
	select {
	case <-tunnel.stopChan:
		s.mu.Unlock()
		conn.Close()
		return
	default:
	}
	oldClient := tunnel.Client
	wasRestored := (oldClient == nil) // Check if this was a restored tunnel without a client
	if oldClient != nil {
		log.Printf("🔄 Closing existing client connection for tunnel %s", tunnel.ID)
		oldClient.Close()
		// Do NOT close tunnel.stopChan here! This keeps the tunnel alive.
	}

	// Update tunnel with new client connection
	tunnel.Client = conn
	tunnel.LocalPort = localPort
	// Do NOT reset stopChan here; keep the tunnel running
	s.mu.Unlock()

	// Send success response to client
	fmt.Fprintf(conn, "SUCCESS:%s:%s\n", tunnel.ID, tunnel.RemotePort)
	if oldClient != nil {
		log.Printf("🎯 Client connection replaced for tunnel: %s (team:%s, local:%s -> remote:%s)",
			tunnel.ID, teamToken.Team.Name, localPort, tunnel.RemotePort)
	} else {
		log.Printf("🎯 Client reconnected to restored tunnel: %s (team:%s, local:%s -> remote:%s)",
			tunnel.ID, teamToken.Team.Name, localPort, tunnel.RemotePort)
	}

	// Reactivate the tunnel in database
	ctx := context.Background()
	if tunnel.SessionID != "" {
		sessionID, _ := uuid.Parse(tunnel.SessionID)
		clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
		if err := s.dbService.ReactivateRestoredTunnel(ctx, sessionID, clientIP); err != nil {
			log.Printf("⚠️ Failed to reactivate tunnel in database: %v", err)
		}
	}

	// For restored tunnels, acceptRestoredConnections is already handling incoming connections
	// and will now forward them through the newly connected client.
	// For tunnels with existing clients, start normal tunnel monitoring
	if !wasRestored {
		// Start normal tunnel operations (monitor control connection)
		go s.monitorControlConnection(tunnel, conn)
	} else {
		// For restored tunnels, just monitor the control connection
		// acceptRestoredConnections is already running and will handle forwarding
		go s.monitorControlConnection(tunnel, conn)
	}
}

// monitorControlConnection monitors the control connection for disconnect messages
func (s *Server) monitorControlConnection(tunnel *Tunnel, conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := readControlLine(reader)
		if err != nil {
			log.Printf("Control connection closed for tunnel %s: %v", tunnel.ID, err)
			// Mark client as disconnected but keep tunnel alive for restoration
			s.mu.Lock()
			if tunnel.Client == conn {
				tunnel.Client = nil
			}
			s.mu.Unlock()
			log.Printf("🔌 Client disconnected from tunnel %s, keeping port alive for reconnection", tunnel.ID)
			return
		}
		line = strings.TrimSpace(line)
		if line == "DISCONNECT" {
			log.Printf("🚪 Client requested disconnect for tunnel %s", tunnel.ID)
			s.stopTunnel(tunnel)
			return
		}
	}
}

// handleDataConnection handles a data connection from a client
func (s *Server) handleDataConnection(conn net.Conn, dataLine string) {
	// Parse the data line: DATA:connectionID
	parts := strings.Split(dataLine, ":")
	if len(parts) < 2 {
		log.Printf("Invalid data connection format: %s", dataLine)
		conn.Close()
		return
	}

	connID := parts[1]

	// Find the pending connection
	s.mu.Lock()
	connChan, exists := s.pendingConns[connID]
	if !exists {
		s.mu.Unlock()
		log.Printf("No pending data connection")
		conn.Close()
		return
	}
	delete(s.pendingConns, connID)
	defer s.mu.Unlock()

	_ = conn.SetReadDeadline(time.Time{})
	// Send the connection to the waiting handler
	select {
	case connChan <- conn:
		log.Printf("Data connection paired")
	default:
		log.Printf("Failed to pair data connection")
		conn.Close()
	}
}

// createTunnel creates a new tunnel using database-assigned port
func (s *Server) createTunnel(teamToken *database.TeamToken, portAssignment *database.PortAssignment, localPort string, client net.Conn) (*Tunnel, error) {
	ctx := context.Background()

	// Generate random tunnel ID
	tunnelID, err := generateTunnelID()
	if err != nil {
		return nil, fmt.Errorf("error generating tunnel ID: %v", err)
	}

	// Use the pre-assigned port from database
	remotePort := strconv.Itoa(portAssignment.Port)

	// Create listener for the tunnel on the assigned port
	listener, err := net.Listen("tcp", net.JoinHostPort(s.config.BindAddress, remotePort))
	if err != nil {
		return nil, fmt.Errorf("error creating tunnel listener on port %s: %v", remotePort, err)
	}

	tunnel := &Tunnel{
		ID:           tunnelID,
		Token:        teamToken.Token,
		TeamID:       teamToken.TeamID,
		TokenID:      teamToken.ID.String(),
		PortAssignID: portAssignment.ID.String(),
		LocalPort:    localPort,
		RemotePort:   remotePort,
		BindAddress:  s.config.BindAddress,
		Client:       client,
		Listener:     listener,
		CreatedAt:    time.Now(),
		stopChan:     make(chan struct{}),
	}

	// Create connection session in database
	clientIP := client.RemoteAddr().(*net.TCPAddr).IP.String()
	session, connLog, err := s.dbService.StartConnection(ctx,
		teamToken.TeamID, teamToken.ID, portAssignment.ID,
		clientIP, portAssignment.Port, "tcp")

	if err != nil {
		// Log error but don't fail tunnel creation
		log.Printf("⚠️ Failed to create database session: %v", err)
	} else {
		tunnel.SessionID = session.ID.String()
		if connLog != nil {
			tunnel.ConnectionLog = connLog.ID.String()
		}
		log.Printf("📊 Database session created: %s", session.ID)
	}

	// Register the listener goroutine before publishing the tunnel to revocation.
	tunnel.wg.Add(1)
	// Add to tunnels map
	s.mu.Lock()
	s.tunnels[tunnelID] = tunnel
	s.mu.Unlock()

	go tunnel.handleTunnel()
	// Publication precedes the final check, so concurrent API revocation either
	// observes this tunnel or this query observes the revoked token.
	if _, _, err := s.authenticateToken(ctx, teamToken.Token); err != nil {
		s.stopTunnel(tunnel)
		return nil, fmt.Errorf("token revoked during tunnel creation")
	}

	return tunnel, nil
}

// handleTunnel handles tunnel traffic
func (t *Tunnel) handleTunnel() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in tunnel %s: %v", t.ID, r)
		}
		// Ensure stopChan is closed when client disconnects
		t.stopOnce.Do(func() { close(t.stopChan) })
	}()

	defer t.Listener.Close()
	go t.acceptConnections()

	// Wait for stop signal or client disconnection
	<-t.stopChan

	// End database session
	if t.SessionID != "" && t.ConnectionLog != "" {
		ctx := context.Background()
		server := getServerFromTunnel(t)
		if server != nil && server.dbService != nil {
			sessionID, _ := uuid.Parse(t.SessionID)
			logID, _ := uuid.Parse(t.ConnectionLog)
			if err := server.dbService.EndConnection(ctx, sessionID, logID, "closed", nil); err != nil {
				log.Printf("⚠️ Failed to end database session: %v", err)
			}
		}
	}

	log.Printf("🔚 Tunnel %s finished", t.ID)
}

// acceptConnections accepts and handles incoming connections on the tunnel port
func (t *Tunnel) acceptConnections() {
	defer t.wg.Done()

	for {
		select {
		case <-t.stopChan:
			return
		default:
			conn, err := t.Listener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("Error accepting connection on tunnel %s: %v", t.ID, err)
				}
				return
			}

			// Apply security validation for external connections
			server := getServerFromTunnel(t)
			if server != nil && server.securityMiddleware != nil {
				if err := server.securityMiddleware.ValidateConnection(conn); err != nil {
					log.Printf("🚫 External connection rejected for tunnel %s from %s: %v", t.ID, conn.RemoteAddr(), err)
					conn.Close()
					continue
				}
				// Wrap with security features
				conn = server.securityMiddleware.WrapConnection(conn)
			}

			t.wg.Add(1)
			go t.handleConnection(conn)
		}
	}
}

// handleConnection handles a single tunnel connection
func (t *Tunnel) handleConnection(externalConn net.Conn) {
	defer t.wg.Done()
	defer externalConn.Close()

	// Extract client connection details
	clientAddr := externalConn.RemoteAddr().(*net.TCPAddr)
	clientIP := clientAddr.IP.String()
	clientPort := clientAddr.Port

	log.Printf("🔌 New connection to tunnel %s from %s:%d", t.ID, clientIP, clientPort)

	s := getServerFromTunnel(t)
	if s == nil {
		return
	}
	s.mu.RLock()
	client := t.Client
	s.mu.RUnlock()
	if client == nil {
		return
	}
	connChan := make(chan net.Conn, 1)
	connID, err := generateTunnelID()
	if err != nil {
		return
	}
	s.mu.Lock()
	s.pendingConns[connID] = connChan
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingConns, connID)
		select {
		case unused := <-connChan:
			unused.Close()
		default:
		}
		s.mu.Unlock()
	}()
	t.controlMu.Lock()
	_, err = fmt.Fprintf(client, "CONNECT\nCONN_ID:%s\n", connID)
	t.controlMu.Unlock()
	if err != nil {
		return
	}

	// Wait for data connection with timeout
	select {
	case dataConn := <-connChan:
		// Clean up the pending connection
		s.mu.Lock()
		delete(s.pendingConns, connID)
		s.mu.Unlock()

		log.Printf("Data connection established")

		// Create a connection log entry for this specific connection
		connectionLogID := t.createConnectionLog(clientIP, clientPort)

		// Bridge the connections and track statistics
		t.bridgeConnectionsWithLogging(externalConn, dataConn, connectionLogID)

	case <-t.stopChan:
		return
	case <-time.After(10 * time.Second):
		log.Printf("Timeout waiting for data connection")
		s.mu.Lock()
		delete(s.pendingConns, connID)
		s.mu.Unlock()
		t.logConnectionAttempt(clientIP, clientPort, "timeout", "Timeout waiting for data connection")
	}
}

// logConnectionAttempt logs a connection attempt (successful or failed)
// Valid status values (per database constraint):
//   - "active": Connection is currently active
//   - "closed": Connection completed normally
//   - "error": Connection failed due to an error
//   - "timeout": Connection timed out
func (t *Tunnel) logConnectionAttempt(clientIP string, clientPort int, status string, errorMsg string) {
	if t.TeamID == "" || t.TokenID == "" || t.PortAssignID == "" {
		return // Skip if we don't have proper IDs
	}

	ctx := context.Background()
	server := getServerFromTunnel(t)
	if server == nil || server.dbService == nil {
		return
	}

	tokenID, _ := uuid.Parse(t.TokenID)
	portAssignID, _ := uuid.Parse(t.PortAssignID)

	serverPort, _ := strconv.Atoi(t.RemotePort)

	// Create connection log through service
	session, connLog, err := server.dbService.StartConnection(ctx, t.TeamID, tokenID, portAssignID,
		clientIP, serverPort, "tcp")

	if err != nil {
		log.Printf("⚠️ Failed to log connection attempt: %v", err)
		return
	}

	// If this was a failed connection, end it immediately
	if status != "active" && connLog != nil {
		var errorMessage *string
		if errorMsg != "" {
			errorMessage = &errorMsg
		}
		if err := server.dbService.EndConnection(ctx, session.ID, connLog.ID, status, errorMessage); err != nil {
			log.Printf("⚠️ Failed to end failed connection log: %v", err)
		}
		log.Printf("📝 Logged connection attempt from %s:%d - %s", clientIP, clientPort, status)
	}
}

// createConnectionLog creates a connection log entry for a successful connection
func (t *Tunnel) createConnectionLog(clientIP string, clientPort int) uuid.UUID {
	if t.TeamID == "" || t.TokenID == "" || t.PortAssignID == "" || t.SessionID == "" {
		return uuid.Nil
	}

	ctx := context.Background()
	server := getServerFromTunnel(t)
	if server == nil || server.dbService == nil {
		return uuid.Nil
	}

	tokenID, _ := uuid.Parse(t.TokenID)
	portAssignID, _ := uuid.Parse(t.PortAssignID)

	serverPort, _ := strconv.Atoi(t.RemotePort)

	// Create connection log through service
	_, connLog, err := server.dbService.StartConnection(ctx, t.TeamID, tokenID, portAssignID,
		clientIP, serverPort, "tcp")

	if err != nil || connLog == nil {
		log.Printf("⚠️ Failed to create connection log: %v", err)
		return uuid.Nil
	}

	log.Printf("📊 Created connection log: %s (client: %s:%d)", connLog.ID, clientIP, clientPort)
	return connLog.ID
}

// bridgeConnectionsWithLogging bridges two connections bidirectionally with detailed logging
func (t *Tunnel) bridgeConnectionsWithLogging(conn1, conn2 net.Conn, connectionLogID uuid.UUID) {
	defer conn1.Close()
	defer conn2.Close()

	startTime := time.Now()
	type copyResult struct {
		received bool
		bytes    int64
		err      error
	}
	results := make(chan copyResult, 2)
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-t.stopChan:
			conn1.Close()
			conn2.Close()
		case <-finished:
		}
	}()
	copyDirection := func(dst, src net.Conn, received bool) {
		n, err := io.Copy(dst, src)
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			dst.Close()
			src.Close()
		}
		if conn, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = conn.CloseWrite()
		}
		results <- copyResult{received, n, err}
	}
	go copyDirection(conn1, conn2, true)
	go copyDirection(conn2, conn1, false)
	var bytesReceived, bytesSent int64
	var bridgeErr error
	for i := 0; i < 2; i++ {
		result := <-results
		if result.received {
			bytesReceived = result.bytes
		} else {
			bytesSent = result.bytes
		}
		if result.err != nil && result.err != io.EOF && !strings.Contains(result.err.Error(), "use of closed network connection") {
			bridgeErr = result.err
		}
	}
	duration := time.Since(startTime)

	// Determine final status
	status := "closed"
	var errorMessage *string
	if bridgeErr != nil {
		status = "error"
		errMsg := bridgeErr.Error()
		errorMessage = &errMsg
	}

	// Update session activity and end the connection log
	if t.SessionID != "" && connectionLogID != uuid.Nil {
		ctx := context.Background()
		server := getServerFromTunnel(t)
		if server != nil && server.dbService != nil {
			sessionID, _ := uuid.Parse(t.SessionID)

			// Update connection activity (this will update stats)
			if err := server.dbService.UpdateConnectionActivity(ctx, sessionID, connectionLogID, bytesReceived, bytesSent); err != nil {
				log.Printf("⚠️ Failed to update session activity: %v", err)
			}

			// End the connection
			if err := server.dbService.EndConnection(ctx, sessionID, connectionLogID, status, errorMessage); err != nil {
				log.Printf("⚠️ Failed to end connection: %v", err)
			}
		}
	}

	log.Printf("📊 Bridge finished for tunnel %s - Duration: %v, Sent: %d bytes, Received: %d bytes, Status: %s",
		t.ID, duration, bytesSent, bytesReceived, status)
}

// Helper function to get server reference from tunnel
var globalServer *Server

func getServerFromTunnel(_ *Tunnel) *Server {
	return globalServer
}

// stopTunnel stops a tunnel
func (s *Server) stopTunnel(tunnel *Tunnel) {
	tunnel.stopOnce.Do(func() { close(tunnel.stopChan) })
	if tunnel.Listener != nil {
		tunnel.Listener.Close()
	}
	s.mu.Lock()
	client := tunnel.Client
	tunnel.Client = nil
	if s.tunnels[tunnel.ID] == tunnel {
		delete(s.tunnels, tunnel.ID)
	}
	s.mu.Unlock()
	if client != nil {
		client.Close()
	}
	tunnel.wg.Wait()
}

// generateTunnelID generates a random tunnel ID
func generateTunnelID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// restoreActiveConnections restores tunnel listeners for active connections from the database
func (s *Server) restoreActiveConnections() error {
	ctx := context.Background()

	log.Printf("🔄 Checking for active connections to restore...")

	// First, cleanup stale sessions (older than 5 minutes)
	staleThreshold := 5 * time.Minute
	staleCount, err := s.dbService.CleanupStaleConnections(ctx, staleThreshold)
	if err != nil {
		log.Printf("⚠️ Failed to cleanup stale connections: %v", err)
	} else if staleCount > 0 {
		log.Printf("🧹 Cleaned up %d stale connection sessions", staleCount)
	}

	// Get active sessions grouped by port
	portSessions, err := s.dbService.RestoreActiveSessions(ctx)
	if err != nil {
		return fmt.Errorf("failed to restore active sessions: %w", err)
	}

	if len(portSessions) == 0 {
		log.Printf("ℹ️ No active connections found to restore")
		return nil
	}

	restoredCount := 0
	for port, sessions := range portSessions {
		if len(sessions) > 0 {
			// Take the first session to get token and port assignment details
			session := sessions[0]

			// Get full session details including token and port assignment
			sessionDetail, token, portAssignment, err := s.dbService.GetSessionWithDetails(ctx, session.ID)
			if err != nil {
				log.Printf("⚠️ Failed to get session details for port %d: %v", port, err)
				continue
			}

			// Create a restored tunnel listener for this port
			err = s.createRestoredTunnelListener(sessionDetail, token, portAssignment)
			if err != nil {
				log.Printf("⚠️ Failed to restore tunnel listener on port %d: %v", port, err)
				// Mark the session as inactive since we couldn't restore it
				errorMsg := fmt.Sprintf("Failed to restore listener: %v", err)
				s.dbService.EndConnection(ctx, session.ID, uuid.Nil, "error", &errorMsg)
				continue
			}

			restoredCount++
			log.Printf("✅ Restored tunnel listener on port %d (sessions: %d)", port, len(sessions))
		}
	}

	if restoredCount > 0 {
		log.Printf("🎉 Successfully restored %d tunnel listeners from %d active sessions", restoredCount, len(portSessions))
	}

	return nil
}

// createRestoredTunnelListener creates a tunnel listener for a restored connection
func (s *Server) createRestoredTunnelListener(session *database.ConnectionSession, token *database.TeamToken, portAssignment *database.PortAssignment) error {
	// Generate a new tunnel ID for the restored listener
	tunnelID, err := generateTunnelID()
	if err != nil {
		return fmt.Errorf("failed to generate tunnel ID: %w", err)
	}

	// Create listener on the assigned port
	listener, err := net.Listen("tcp", net.JoinHostPort(s.config.BindAddress, strconv.Itoa(portAssignment.Port)))
	if err != nil {
		return fmt.Errorf("failed to create listener on port %d: %w", portAssignment.Port, err)
	}

	// Create a restored tunnel object that can accept new client connections
	tunnel := &Tunnel{
		ID:           tunnelID,
		Token:        token.Token,
		TeamID:       token.TeamID,
		TokenID:      token.ID.String(),
		PortAssignID: portAssignment.ID.String(),
		LocalPort:    "restored",
		RemotePort:   strconv.Itoa(portAssignment.Port),
		BindAddress:  s.config.BindAddress,
		Client:       nil, // No client connection for restored tunnels initially
		Listener:     listener,
		CreatedAt:    time.Now(),
		stopChan:     make(chan struct{}),
		SessionID:    session.ID.String(),
	}

	// Register the listener goroutine before publishing the tunnel to revocation.
	tunnel.wg.Add(1)
	// Add to tunnels map
	s.mu.Lock()
	s.tunnels[tunnelID] = tunnel
	s.mu.Unlock()

	// Start accepting connections on the restored listener
	go tunnel.acceptRestoredConnections(s)

	return nil
}

// acceptRestoredConnections handles connections for restored tunnel listeners
func (t *Tunnel) acceptRestoredConnections(s *Server) {
	defer t.wg.Done()

	log.Printf("🎧 Restored port %s listening for external connections (waiting for client reconnection)", t.RemotePort)

	for {
		select {
		case <-t.stopChan:
			return
		default:
			conn, err := t.Listener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("Error accepting connection on restored tunnel %s: %v", t.ID, err)
				}
				return
			}

			// Apply security validation for external connections to restored ports
			if s != nil && s.securityMiddleware != nil {
				if err := s.securityMiddleware.ValidateConnection(conn); err != nil {
					log.Printf("🚫 External connection rejected for restored port %s from %s: %v", t.RemotePort, conn.RemoteAddr(), err)
					conn.Close()
					continue
				}
				// Wrap with security features
				conn = s.securityMiddleware.WrapConnection(conn)
			}

			// For restored tunnels without clients, check if client is now connected
			clientAddr := conn.RemoteAddr().(*net.TCPAddr)
			log.Printf("🌐 External connection attempt to restored port %s from %s:%d",
				t.RemotePort, clientAddr.IP.String(), clientAddr.Port)

			// Check if the tunnel now has an active client
			t.wg.Add(1)
			go func(c net.Conn) {
				// Check if client is available (with a short wait)
				maxWaitTime := 2 * time.Second
				checkInterval := 100 * time.Millisecond
				waited := time.Duration(0)

				for waited < maxWaitTime {
					s.mu.RLock()
					connected := t.Client != nil
					s.mu.RUnlock()
					if connected {
						// Client is now connected, handle this connection normally
						log.Printf("✅ Client reconnected for restored port %s, handling connection", t.RemotePort)
						t.handleConnection(c)
						// handleConnection will call t.wg.Done() and close the connection
						return
					}
					time.Sleep(checkInterval)
					waited += checkInterval
				}

				// Client still not available, close connection gracefully
				// We need to call Done() and Close() here since handleConnection was not called
				defer t.wg.Done()
				defer c.Close()

				log.Printf("⏰ Client not available for restored port %s, closing connection from %s:%d",
					t.RemotePort, clientAddr.IP.String(), clientAddr.Port)

				// Log the connection attempt
				t.logConnectionAttempt(clientAddr.IP.String(), clientAddr.Port, "error",
					"Tunnel client not connected")
			}(conn)
		}
	}
}

func readControlLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	return string(line), err
}
