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

	server := &Server{
		config:       config,
		tunnels:      make(map[string]*Tunnel),
		pendingConns: make(map[string]chan net.Conn),
		stopChan:     make(chan struct{}),
		dbService:    dbService,
	}

	// Create API server if port is specified
	if config.APIPort != "" {
		server.apiServer = NewAPIServer(dbService, config.BindAddress, config.APIPort)
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
	s.controlListener, err = net.Listen("tcp", net.JoinHostPort(s.config.BindAddress, s.config.ControlPort))
	if err != nil {
		return fmt.Errorf("error starting control listener: %v", err)
	}

	log.Printf("🚀 Tunnel server started on %s:%s", s.config.BindAddress, s.config.ControlPort)
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

	// Stop API server
	if s.apiServer != nil {
		if err := s.apiServer.Stop(); err != nil {
			log.Printf("⚠️ Error stopping API server: %v", err)
		}
	}

	// Stop all tunnels
	s.mu.Lock()
	for _, tunnel := range s.tunnels {
		s.stopTunnel(tunnel)
	}
	s.mu.Unlock()

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

			s.wg.Add(1)
			go s.handleControlConnection(conn)
		}
	}
}

// handleControlConnection handles a single control connection
func (s *Server) handleControlConnection(conn net.Conn) {
	defer s.wg.Done()

	log.Printf("🔗 New control connection from %s", conn.RemoteAddr())

	// Simple protocol: read token and local port on separate lines
	reader := bufio.NewReader(conn)

	// Read first line to determine connection type
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading first line: %v", err)
		conn.Close()
		return
	}
	firstLine = strings.TrimSpace(firstLine)

	// Handle data connections
	if strings.HasPrefix(firstLine, "DATA:") {
		s.handleDataConnection(conn, firstLine)
		return
	}

	// This is a control connection - continue with tunnel setup
	token := firstLine

	// Read local port
	localPort, err := reader.ReadString('\n')
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

	log.Printf("✅ Token authenticated for team: %s", teamToken.Team.Name)
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

	// Keep connection alive and handle tunnel traffic
	tunnel.handleTunnel()
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
func (s *Server) reconnectClientToTunnel(tunnel *Tunnel, conn net.Conn, teamToken *database.TeamToken, portAssignment *database.PortAssignment, localPort string) {
	// If there's an existing client, close it gracefully
	s.mu.Lock()
	oldClient := tunnel.Client
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

	// Start normal tunnel operations
	tunnel.handleTunnel()
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
	log.Printf("📥 Received data connection for %s", connID)

	// Find the pending connection
	s.mu.Lock()
	connChan, exists := s.pendingConns[connID]
	if !exists {
		s.mu.Unlock()
		log.Printf("❌ No pending connection found for %s", connID)
		conn.Close()
		return
	}
	s.mu.Unlock()

	// Send the connection to the waiting handler
	select {
	case connChan <- conn:
		log.Printf("✅ Data connection paired for %s", connID)
	default:
		log.Printf("❌ Failed to pair data connection for %s", connID)
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

	// Add to tunnels map
	s.mu.Lock()
	s.tunnels[tunnelID] = tunnel
	s.mu.Unlock()

	return tunnel, nil
}

// handleTunnel handles tunnel traffic
func (t *Tunnel) handleTunnel() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in tunnel %s: %v", t.ID, r)
		}
	}()

	defer t.Client.Close()
	defer t.Listener.Close()

	t.wg.Add(1)
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

	// Send connect notification to client via control connection
	_, err := fmt.Fprintf(t.Client, "CONNECT\n")
	if err != nil {
		log.Printf("Error sending connect notification: %v", err)
		// Log failed connection attempt
		t.logConnectionAttempt(clientIP, clientPort, "error", fmt.Sprintf("Control connection error: %v", err))
		return
	}

	// Wait for client to establish data connection
	s := getServerFromTunnel(t)
	if s == nil {
		log.Printf("Could not get server reference")
		t.logConnectionAttempt(clientIP, clientPort, "error", "No server reference available")
		return
	}

	// Create a channel for this specific connection
	connChan := make(chan net.Conn, 1)
	connID := fmt.Sprintf("%s-%d", t.ID, time.Now().UnixNano())

	s.mu.Lock()
	s.pendingConns[connID] = connChan
	s.mu.Unlock()

	// Send the connection ID to the client
	_, err = fmt.Fprintf(t.Client, "CONN_ID:%s\n", connID)
	if err != nil {
		log.Printf("Error sending connection ID: %v", err)
		s.mu.Lock()
		delete(s.pendingConns, connID)
		s.mu.Unlock()
		t.logConnectionAttempt(clientIP, clientPort, "error", fmt.Sprintf("Connection ID send error: %v", err))
		return
	}

	// Wait for data connection with timeout
	select {
	case dataConn := <-connChan:
		// Clean up the pending connection
		s.mu.Lock()
		delete(s.pendingConns, connID)
		s.mu.Unlock()

		log.Printf("🔄 Data connection established for %s", connID)

		// Create a connection log entry for this specific connection
		connectionLogID := t.createConnectionLog(clientIP, clientPort)

		// Bridge the connections and track statistics
		t.bridgeConnectionsWithLogging(externalConn, dataConn, connectionLogID)

	case <-time.After(10 * time.Second):
		log.Printf("⏰ Timeout waiting for data connection for %s", connID)
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
	done := make(chan struct{}, 2)
	var bytesReceived, bytesSent int64
	var bridgeErr error

	// Track connection start
	log.Printf("🌉 Starting bridge for tunnel %s (log: %s)", t.ID, connectionLogID)

	go func() {
		defer func() { done <- struct{}{} }()
		n, err := io.Copy(conn1, conn2)
		bytesReceived = n
		if err != nil && err != io.EOF {
			bridgeErr = err
			log.Printf("Error copying to conn1: %v", err)
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		n, err := io.Copy(conn2, conn1)
		bytesSent = n
		if err != nil && err != io.EOF {
			if bridgeErr == nil {
				bridgeErr = err
			}
			log.Printf("Error copying to conn2: %v", err)
		}
	}()

	// Wait for one direction to finish
	<-done
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
	close(tunnel.stopChan)
	if tunnel.Listener != nil {
		tunnel.Listener.Close()
	}
	if tunnel.Client != nil {
		tunnel.Client.Close()
	}

	// Wait for all tunnel goroutines to finish
	tunnel.wg.Wait()

	delete(s.tunnels, tunnel.ID)
}

// generateTunnelID generates a random tunnel ID
func generateTunnelID() (string, error) {
	bytes := make([]byte, 8)
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

	// Add to tunnels map
	s.mu.Lock()
	s.tunnels[tunnelID] = tunnel
	s.mu.Unlock()

	// Start accepting connections on the restored listener
	tunnel.wg.Add(1)
	go tunnel.acceptRestoredConnections(s)

	return nil
}

// acceptRestoredConnections handles connections for restored tunnel listeners
func (t *Tunnel) acceptRestoredConnections(_ *Server) {
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

			// For restored tunnels without clients, just send helpful message
			clientAddr := conn.RemoteAddr().(*net.TCPAddr)
			log.Printf("🌐 External connection attempt to restored port %s from %s:%d",
				t.RemotePort, clientAddr.IP.String(), clientAddr.Port)

			go func(c net.Conn) {
				defer c.Close()
				t.sendRestoredPortMessage(c)

				// Log the external connection attempt
				t.logConnectionAttempt(clientAddr.IP.String(), clientAddr.Port, "closed",
					"External connection to restored port - waiting for tunnel client reconnection")
			}(conn)
		}
	}
}

// sendRestoredPortMessage sends a helpful message to connections on restored ports
func (t *Tunnel) sendRestoredPortMessage(conn net.Conn) {
	message := fmt.Sprintf(`HTTP/1.1 503 Service Unavailable
Content-Type: text/plain
Content-Length: 200
Connection: close

Port %s was restored from database after server restart.
The tunnel client is not currently connected.
Please reconnect your tunnel client to restore full functionality.

To reconnect: Use the same token and connect to the tunnel server.`, t.RemotePort)

	conn.Write([]byte(message))
}
