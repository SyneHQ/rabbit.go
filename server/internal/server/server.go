package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"rabbit.go/internal/database"
	"rabbit.go/internal/middleware"
	notebookruntime "rabbit.go/internal/runtime"

	"github.com/google/uuid"
)

// Config holds server configuration
type Config struct {
	ConfigFile        string
	BindAddress       string
	TunnelBindAddress string // Database ingress; independent of the public control listener.
	APIBindAddress    string // Management ingress; independent of the public control listener.
	ControlPort       string
	LogLevel          string
	APIPort           string // Port for HTTP API server
}

// Server represents the tunnel server
type Server struct {
	config           Config
	operator         OperatorConfig
	streamAudit      *streamAuditQueue
	controlListener  net.Listener
	privateListener  net.Listener
	private          *privateConnect
	tunnels          map[string]*Tunnel
	pendingConns     map[string]*pendingConnection
	mu               sync.RWMutex
	stopChan         chan struct{}
	stopOnce         sync.Once
	shutdownMu       sync.Mutex
	shutdownCtx      context.Context
	shutdownDone     chan struct{}
	shutdownErr      error
	shutdownCause    error
	shutdownFinished bool
	cleanupCtx       context.Context
	cleanupCancel    context.CancelFunc
	closingTunnels   map[*Tunnel]struct{}
	lifecycleMu      sync.Mutex
	started, stopped bool
	connections      map[net.Conn]struct{}
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup

	// Database integration
	dbService     *database.Service
	closeDatabase func() error

	// API server
	apiServer *APIServer

	// Security middleware
	securityMiddleware *middleware.SecurityMiddleware
	runtimeRouter      *notebookruntime.Router
}

// Tunnel represents an active tunnel session
type Tunnel struct {
	ID             string
	Token          string
	TeamID         string
	TokenID        string
	PortAssignID   string
	LocalPort      string
	RemotePort     string
	BindAddress    string
	Client         net.Conn
	Listener       net.Listener
	CreatedAt      time.Time
	stopChan       chan struct{}
	stopOnce       sync.Once // Ensure stopChan is only closed once
	endOnce        sync.Once
	cleanupStarted bool  // Server.mu protects cleanup registration.
	cleanupErr     error // Published by endOnce.
	server         *Server
	ctx            context.Context
	cancel         context.CancelFunc
	metadataMu     sync.Mutex
	streams        map[*tunnelStream]struct{}
	controlMu      sync.Mutex
	busyOwner      net.Conn
	tokenEpoch     string
	controlEpoch   uint64
	wg             sync.WaitGroup

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
	var err error
	config, err = normalizeBindAddresses(config)
	if err != nil {
		return nil, err
	}
	if err := validateOperatorToken(); err != nil {
		return nil, err
	}
	operator, err := LoadOperatorConfig(config.ConfigFile)
	if err != nil {
		return nil, err
	}
	private, err := loadPrivateConnect(operator.PrivateConnect)
	if err != nil {
		return nil, err
	}
	var runtimeRouter *notebookruntime.Router
	if os.Getenv("RABBIT_NOTEBOOK_AUTHORITY_URL") != "" {
		if os.Getenv("NOTEBOOK_RUNTIME_SERVICE_TOKEN") == os.Getenv("RABBIT_NOTEBOOK_BROKER_TOKEN") {
			return nil, fmt.Errorf("notebook authority and broker credentials must be distinct")
		}
		authority, err := notebookruntime.NewHTTPAuthority(os.Getenv("RABBIT_NOTEBOOK_AUTHORITY_URL"), os.Getenv("NOTEBOOK_RUNTIME_SERVICE_TOKEN"),
			os.Getenv("RABBIT_ALLOW_INSECURE_LOCAL") == "true" && os.Getenv("ENVIRONMENT") != "production")
		if err != nil {
			return nil, fmt.Errorf("invalid notebook runtime authority configuration")
		}
		runtimeRouter, err = notebookruntime.NewRouter(authority, os.Getenv("RABBIT_NOTEBOOK_BROKER_TOKEN"))
		if err != nil {
			return nil, fmt.Errorf("invalid notebook broker configuration")
		}
	}
	configured := false
	defer func() {
		if !configured && private != nil {
			private.close()
		}
		if !configured && runtimeRouter != nil {
			runtimeRouter.Close()
		}
	}()
	log.Println("Loading .env file")
	// Initialize database connection
	dbConfig := database.GetConfigFromEnv()
	db, err := database.NewDatabase(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	defer func() {
		if !configured {
			db.Close()
		}
	}()
	dbService := database.NewService(db)
	if private != nil {
		private.tokenActive = func(ctx context.Context, tunnel *Tunnel) (time.Time, error) {
			tokenID, tokenErr := uuid.Parse(tunnel.TokenID)
			portID, portErr := uuid.Parse(tunnel.PortAssignID)
			if tokenErr != nil || portErr != nil {
				return time.Time{}, net.ErrClosed
			}
			return dbService.CheckTransportAuthority(ctx, tunnel.TeamID, tunnel.Token, tokenID, portID)
		}
	}

	// Test database connection
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	if err := dbService.HealthCheck(ctx); err != nil {
		return nil, fmt.Errorf("database health check failed: %w", err)
	}

	log.Printf("✅ Database connection established")

	// Initialize security middleware
	securityMiddleware := middleware.NewSecurityMiddleware(operator.Security)

	serverCtx, serverCancel := context.WithCancel(context.Background())
	server := &Server{
		private:            private,
		config:             config,
		operator:           operator,
		tunnels:            make(map[string]*Tunnel),
		pendingConns:       make(map[string]*pendingConnection),
		connections:        make(map[net.Conn]struct{}),
		ctx:                serverCtx,
		cancel:             serverCancel,
		stopChan:           make(chan struct{}),
		dbService:          dbService,
		closeDatabase:      db.Close,
		securityMiddleware: securityMiddleware,
		runtimeRouter:      runtimeRouter,
	}

	if operator.AuditQueueCapacity > 0 {
		server.streamAudit = newStreamAuditQueue(operator.AuditQueueCapacity, operator.AuditWriteTimeout, operator.AuditShutdownTimeout, dbService.RecordCompletedStream)
	}

	// Create API server if port is specified
	if config.APIPort != "" {
		server.apiServer = NewAPIServer(dbService, config.APIBindAddress, config.APIPort, config.ControlPort)
		server.apiServer.onRevoke = server.revokeToken
		server.apiServer.runtimeStats = server.runtimeStats
		server.apiServer.privateRoute = server.privateRouteInfo
		server.apiServer.ready = server.transportReady
	}

	configured = true
	return server, nil
}

// authenticateToken validates a token using the database and returns port assignment
func (s *Server) authenticateToken(ctx context.Context, token string) (*database.TeamToken, *database.PortAssignment, error) {
	return s.dbService.AuthenticateToken(ctx, token)
}

// Start starts the tunnel server
func (s *Server) Start() (err error) {
	s.lifecycleMu.Lock()
	if s.started || s.stopped {
		s.lifecycleMu.Unlock()
		return fmt.Errorf("server cannot be started more than once or after Stop")
	}
	select {
	case <-s.stopChan:
		s.lifecycleMu.Unlock()
		return fmt.Errorf("server cannot start during shutdown")
	default:
	}
	s.started = true
	defer func() {
		s.lifecycleMu.Unlock()
		if err != nil {
			err = errors.Join(err, s.Stop())
		}
	}()
	s.controlListener, err = controlListener(net.JoinHostPort(s.config.BindAddress, s.config.ControlPort))
	if err != nil {
		return fmt.Errorf("error starting control listener: %v", err)
	}
	if s.private != nil {
		s.privateListener, err = net.Listen("tcp", s.private.address)
		if err != nil {
			return fmt.Errorf("error starting private CONNECT listener: %w", err)
		}
	}

	log.Printf("🚀 Tunnel server started on %s:%s", s.config.BindAddress, s.config.ControlPort)
	log.Printf("🔐 Security middleware enabled")
	log.Printf("📡 Using database-based authentication")

	// Bind management synchronously so Start cannot report an unavailable API as ready.
	if s.apiServer != nil {
		apiListener, listenErr := net.Listen("tcp", s.apiServer.server.Addr)
		if listenErr != nil {
			return fmt.Errorf("error starting management listener: %w", listenErr)
		}
		s.apiServer.prepare(s.ctx)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.apiServer.server.Serve(apiListener); err != nil && err != http.ErrServerClosed {
				log.Printf("❌ API server error: %v", err)
			}
		}()
	}

	// Restore active connections after listeners have been acquired.
	if err := s.restoreActiveConnections(); err != nil {
		log.Printf("Failed to restore active connections: %v", err)
	}

	s.wg.Add(1)
	go s.handleControlConnections()
	if s.privateListener != nil {
		s.wg.Add(1)
		go s.handlePrivateConnections()
	}

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

			s.mu.Lock()
			select {
			case <-s.stopChan:
				s.mu.Unlock()
				secureConn.Close()
				return
			default:
			}
			s.connections[secureConn] = struct{}{}
			s.wg.Add(1)
			s.mu.Unlock()
			go s.handleControlConnection(secureConn)
		}
	}
}

// handleControlConnection handles a single control connection
func (s *Server) handleControlConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.connections, conn)
		s.mu.Unlock()
	}()

	log.Printf("New control connection from %s", conn.RemoteAddr())
	_ = conn.SetReadDeadline(time.Now().Add(s.handshakeTimeout()))

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
	if firstLine == notebookruntime.RegisterFrame || firstLine == notebookruntime.OpenFrame || firstLine == notebookruntime.DataFrame {
		if s.runtimeRouter == nil {
			conn.Close()
			return
		}
		s.runtimeRouter.Handle(firstLine, conn, reader)
		return
	}

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

	ctx, cancel := s.metadataContext()
	defer cancel()

	// Authenticate token and get port assignment
	teamToken, portAssignment, err := s.authenticateToken(ctx, token)
	if err != nil {
		writeControlFrame(conn, "ERROR:Invalid token or authentication failed\n")
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
		s.reconnectClientToTunnel(existingTunnel, conn, reader, teamToken, localPort)
		return
	}
	s.mu.Unlock()

	// Create new tunnel using the pre-assigned port
	tunnel, err := s.createTunnel(teamToken, portAssignment, localPort, conn)
	if err != nil {
		writeControlFrame(conn, "ERROR:%s\n", err.Error())
		log.Printf("Error creating tunnel: %v", err)
		conn.Close()
		return
	}

	tunnel.controlMu.Lock()
	s.mu.Lock()
	select {
	case <-tunnel.stopChan:
		s.mu.Unlock()
		tunnel.controlMu.Unlock()
		conn.Close()
		return
	default:
	}
	if tunnel.Client != nil && tunnel.Client != conn {
		// A reconnect completed while the first registration was being checked.
		s.mu.Unlock()
		tunnel.controlMu.Unlock()
		conn.Close()
		return
	}
	s.replaceControlOwnerLocked(tunnel, conn)
	s.mu.Unlock()
	err = writeControlFrame(conn, "SUCCESS:%s:%s\n", tunnel.ID, tunnel.RemotePort)
	tunnel.controlMu.Unlock()
	if err != nil {
		s.stopControlOwner(tunnel, conn)
		conn.Close()
		return
	}
	s.monitorControlConnection(tunnel, conn, reader)
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

// reconnectClientToTunnel reuses the listener and preserves parser read-ahead.
func (s *Server) reconnectClientToTunnel(tunnel *Tunnel, conn net.Conn, reader *bufio.Reader, teamToken *database.TeamToken, localPort string) {
	// Serialize publication with CONNECT/PONG writes so SUCCESS is the first frame.
	tunnel.controlMu.Lock()
	s.mu.Lock()
	select {
	case <-tunnel.stopChan:
		s.mu.Unlock()
		tunnel.controlMu.Unlock()
		conn.Close()
		return
	default:
	}
	oldConnections := s.replaceControlOwnerLocked(tunnel, conn)
	tunnel.LocalPort = localPort
	s.mu.Unlock()
	closeReplacedOwner(oldConnections)
	err := writeControlFrame(conn, "SUCCESS:%s:%s\n", tunnel.ID, tunnel.RemotePort)
	tunnel.controlMu.Unlock()
	if err != nil {
		s.disconnectClient(tunnel, conn)
		return
	}
	if tunnel.SessionID != "" && s.dbService != nil {
		err := s.withActiveTunnelMetadata(tunnel, conn, func(ctx context.Context) error {
			sessionID, _ := uuid.Parse(tunnel.SessionID)
			clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
			return s.dbService.ReactivateRestoredTunnel(ctx, sessionID, clientIP)
		})
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("Failed to reactivate tunnel metadata: %v", err)
		}
	}
	log.Printf("Client reconnected to tunnel %s for team %s", tunnel.ID, teamToken.TeamID)
	s.monitorControlConnection(tunnel, conn, reader)
}

func (s *Server) disconnectClient(tunnel *Tunnel, conn net.Conn) {
	s.mu.Lock()
	var connections []net.Conn
	if tunnel.Client == conn {
		connections = s.replaceControlOwnerLocked(tunnel, nil)
	}
	s.mu.Unlock()
	closeShutdownConnection(conn)
	closeReplacedOwner(connections)
}

// monitorControlConnection is owned by the tracked connection handler.
func (s *Server) monitorControlConnection(tunnel *Tunnel, conn net.Conn, reader *bufio.Reader) {
	defer s.disconnectClient(tunnel, conn)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			return
		}
		line, err := readControlLine(reader)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		s.mu.RLock()
		current := tunnel.Client == conn
		s.mu.RUnlock()
		if !current {
			return
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "CAPS:busy-v1":
			if err := tunnel.writeControl(conn, "CAPS:busy-v1\n"); err != nil {
				return
			}
			s.mu.Lock()
			if s.controlOwnerActiveLocked(tunnel, conn) {
				tunnel.busyOwner = conn
			}
			s.mu.Unlock()
		case strings.HasPrefix(line, "BUSY:"):
			s.rejectPending(tunnel, conn, strings.TrimPrefix(line, "BUSY:"))
		case line == "DISCONNECT":
			s.stopControlOwner(tunnel, conn)
			return
		case line == "PING":
			if err := tunnel.writeControl(conn, "PONG\n"); err != nil {
				return
			}
		case line == "KEEPALIVE":
		}
	}
}

// handleDataConnection consumes a capability only for its original live owner.
func (s *Server) handleDataConnection(conn net.Conn, dataLine string) {
	connID := strings.TrimPrefix(dataLine, "DATA:")
	if connID == dataLine || connID == "" || strings.Contains(connID, ":") {
		conn.Close()
		return
	}
	s.mu.Lock()
	pending := s.pendingConns[connID]
	delete(s.pendingConns, connID)
	if pending == nil || !s.controlOwnerActiveLocked(pending.tunnel, pending.owner) {
		s.mu.Unlock()
		conn.Close()
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		s.mu.Unlock()
		conn.Close()
		return
	}
	select {
	case pending.ready <- conn:
		s.mu.Unlock()
	default:
		s.mu.Unlock()
		conn.Close()
	}
}

// createTunnel creates a new tunnel using database-assigned port
func (s *Server) createTunnel(teamToken *database.TeamToken, portAssignment *database.PortAssignment, localPort string, client net.Conn) (*Tunnel, error) {
	ctx, cancel := s.metadataContext()
	defer cancel()

	// Generate random tunnel ID
	tunnelID, err := generateTunnelID()
	if err != nil {
		return nil, fmt.Errorf("error generating tunnel ID: %v", err)
	}
	tokenEpoch, err := generateTunnelID()
	if err != nil {
		return nil, fmt.Errorf("error generating tunnel epoch: %w", err)
	}

	// Use the pre-assigned port from database
	remotePort := strconv.Itoa(portAssignment.Port)

	// Create listener for the tunnel on the assigned port
	listener, err := net.Listen("tcp", net.JoinHostPort(s.tunnelBindAddress(), remotePort))
	if err != nil {
		return nil, fmt.Errorf("error creating tunnel listener on port %s: %v", remotePort, err)
	}

	tunnel := &Tunnel{
		tokenEpoch:   tokenEpoch,
		ID:           tunnelID,
		Token:        teamToken.Token,
		TeamID:       teamToken.TeamID,
		TokenID:      teamToken.ID.String(),
		PortAssignID: portAssignment.ID.String(),
		LocalPort:    localPort,
		RemotePort:   remotePort,
		BindAddress:  s.tunnelBindAddress(),
		server:       s,
		Client:       nil, // Published after the initial SUCCESS frame is serialized.
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

	tunnel.initLifecycle(s)

	// Register the listener goroutine before publishing the tunnel to revocation.
	tunnel.wg.Add(1)
	// Add to tunnels map
	s.mu.Lock()
	select {
	case <-s.stopChan:
		s.mu.Unlock()
		tunnel.wg.Done()
		s.stopTunnel(tunnel)
		return nil, net.ErrClosed
	default:
	}
	s.tunnels[tunnelID] = tunnel
	s.mu.Unlock()

	go tunnel.acceptConnections()
	// Publication precedes the final check, so concurrent API revocation either
	// observes this tunnel or this query observes the revoked token.
	if _, _, err := s.authenticateToken(ctx, teamToken.Token); err != nil {
		s.stopTunnel(tunnel)
		return nil, fmt.Errorf("token revoked during tunnel creation")
	}

	return tunnel, nil
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
	parent := t.ctx
	if parent == nil {
		parent = context.Background()
	}
	dataConn, err := s.pairConnection(parent, t, client)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			t.logConnectionAttempt(clientIP, clientPort, "timeout", "Timeout waiting for data connection")
		}
		return
	}
	defer dataConn.Close()
	connectionLogID := t.createConnectionLog(clientIP, clientPort)
	stream, ok := s.beginTunnelStream(t, client, externalConn, dataConn)
	if !ok {
		t.finishStreamLog(connectionLogID, 0, 0, "closed", nil)
		return
	}
	defer s.endTunnelStream(t, stream)
	t.bridgeConnectionsWithLogging(externalConn, dataConn, connectionLogID)
}

// logConnectionAttempt logs a connection attempt (successful or failed)
// Valid status values (per database constraint):
//   - "active": Connection is currently active
//   - "closed": Connection completed normally
//   - "error": Connection failed due to an error
//   - "timeout": Connection timed out
func (t *Tunnel) logConnectionAttempt(clientIP string, clientPort int, status string, errorMsg string) {
	record := t.createConnectionLog(clientIP, clientPort)
	if status != "active" {
		t.finishStreamLog(record, 0, 0, status, &errorMsg)
	}
}

// createConnectionLog captures immutable stream metadata without database I/O.
func (t *Tunnel) createConnectionLog(clientIP string, clientPort int) *database.ConnectionLog {
	if t.server == nil || t.server.streamAudit == nil || t.TeamID == "" {
		return nil
	}
	tokenID, tokenErr := uuid.Parse(t.TokenID)
	portID, portErr := uuid.Parse(t.PortAssignID)
	sessionID, sessionErr := uuid.Parse(t.SessionID)
	if tokenErr != nil || portErr != nil || sessionErr != nil {
		return nil
	}
	serverPort, _ := strconv.Atoi(t.RemotePort)
	return &database.ConnectionLog{ID: uuid.New(), TeamID: t.TeamID, TokenID: tokenID, PortAssignID: portID, SessionID: sessionID, ClientIP: clientIP, ClientPort: clientPort, ServerPort: serverPort, Protocol: "tcp", StartedAt: time.Now()}
}

// bridgeConnectionsWithLogging bridges two connections bidirectionally with detailed logging
func (t *Tunnel) bridgeConnectionsWithLogging(conn1, conn2 net.Conn, connectionLogID *database.ConnectionLog) {
	defer conn1.Close()
	defer conn2.Close()
	select {
	case <-t.stopChan:
		t.finishStreamLog(connectionLogID, 0, 0, "closed", nil)
		return
	default:
	}

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
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
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
		if result.err != nil && !errors.Is(result.err, io.EOF) && !errors.Is(result.err, net.ErrClosed) {
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

	t.finishStreamLog(connectionLogID, bytesReceived, bytesSent, status, errorMessage)

	log.Printf("📊 Bridge finished for tunnel %s - Duration: %v, Sent: %d bytes, Received: %d bytes, Status: %s",
		t.ID, duration, bytesSent, bytesReceived, status)
}

func getServerFromTunnel(t *Tunnel) *Server { return t.server }

// closeTunnelSockets closes admission and sockets before any metadata wait.
func (s *Server) closeTunnelSockets(tunnel *Tunnel) {
	s.mu.Lock()
	if !tunnel.cleanupStarted {
		tunnel.cleanupStarted = true
		if s.closingTunnels == nil {
			s.closingTunnels = make(map[*Tunnel]struct{})
		}
		s.closingTunnels[tunnel] = struct{}{}
	}
	s.signalTunnelStopLocked(tunnel)
	client := tunnel.Client
	tunnel.Client = nil
	if s.tunnels[tunnel.ID] == tunnel {
		delete(s.tunnels, tunnel.ID)
	}
	streams := make([]*tunnelStream, 0, len(tunnel.streams))
	for stream := range tunnel.streams {
		streams = append(streams, stream)
	}
	s.mu.Unlock()
	if tunnel.Listener != nil {
		tunnel.Listener.Close()
	}
	if client != nil {
		closeShutdownConnection(client)
	}
	for _, stream := range streams {
		closeShutdownConnection(stream.external)
		closeShutdownConnection(stream.data)
	}
}

// stopTunnel retains ownership until streams and reconnect metadata have joined.
func (s *Server) stopTunnel(tunnel *Tunnel) error {
	s.closeTunnelSockets(tunnel)
	tunnel.endOnce.Do(func() {
		defer func() {
			s.recordShutdownError(tunnel.cleanupErr)
			s.mu.Lock()
			delete(s.closingTunnels, tunnel)
			s.mu.Unlock()
		}()
		tunnel.wg.Wait()
		// A reconnect may already be inside the bounded metadata operation.
		// Wait for it before deleting the session's Redis key.
		tunnel.metadataMu.Lock()
		defer tunnel.metadataMu.Unlock()
		if s.dbService == nil || tunnel.SessionID == "" {
			return
		}
		ctx, cancel := s.cleanupContext()
		defer cancel()
		sessionID, _ := uuid.Parse(tunnel.SessionID)
		logID, _ := uuid.Parse(tunnel.ConnectionLog)
		if err := s.dbService.EndConnection(ctx, sessionID, logID, "closed", nil); err != nil {
			tunnel.cleanupErr = fmt.Errorf("tunnel metadata cleanup: %w", err)
			log.Printf("Failed to end tunnel session: %v", err)
		}
	})
	return tunnel.cleanupErr
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
	ctx, cancel := s.metadataContext()
	defer cancel()

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
	tokenEpoch, err := generateTunnelID()
	if err != nil {
		return fmt.Errorf("failed to generate tunnel epoch: %w", err)
	}

	// Create listener on the assigned port
	listener, err := net.Listen("tcp", net.JoinHostPort(s.tunnelBindAddress(), strconv.Itoa(portAssignment.Port)))
	if err != nil {
		return fmt.Errorf("failed to create listener on port %d: %w", portAssignment.Port, err)
	}

	// Create a restored tunnel object that can accept new client connections
	tunnel := &Tunnel{
		tokenEpoch:   tokenEpoch,
		ID:           tunnelID,
		Token:        token.Token,
		TeamID:       token.TeamID,
		TokenID:      token.ID.String(),
		PortAssignID: portAssignment.ID.String(),
		LocalPort:    "restored",
		RemotePort:   strconv.Itoa(portAssignment.Port),
		BindAddress:  s.tunnelBindAddress(),
		server:       s,
		Client:       nil, // No client connection for restored tunnels initially
		Listener:     listener,
		CreatedAt:    time.Now(),
		stopChan:     make(chan struct{}),
		SessionID:    session.ID.String(),
	}

	tunnel.initLifecycle(s)

	// Register the listener goroutine before publishing the tunnel to revocation.
	tunnel.wg.Add(1)
	// Add to tunnels map
	s.mu.Lock()
	select {
	case <-s.stopChan:
		s.mu.Unlock()
		tunnel.wg.Done()
		s.stopTunnel(tunnel)
		return net.ErrClosed
	default:
	}
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
					select {
					case <-t.stopChan:
						c.Close()
						t.wg.Done()
						return
					case <-time.After(checkInterval):
					}
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
