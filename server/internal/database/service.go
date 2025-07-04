package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// Service provides high-level business logic for database operations
type Service struct {
	repo *Repository
	db   *Database
}

// NewService creates a new service instance
func NewService(db *Database) *Service {
	return &Service{
		repo: NewRepository(db),
		db:   db,
	}
}

// Team operations

// GetTeamByID retrieves a team by ID
func (s *Service) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	return s.repo.GetTeamByID(ctx, id)
}

// GetTeamByName retrieves a team by name
func (s *Service) GetTeamByName(ctx context.Context, name string) (*Team, error) {
	return s.repo.GetTeamByName(ctx, name)
}

// GenerateTokenForTeam creates a new token for an existing team with automatic port assignment
func (s *Service) GenerateTokenForTeam(ctx context.Context, teamID string, tokenName, tokenDescription string, expiresAt *time.Time) (*TeamToken, *PortAssignment, error) {
	return s.repo.CreateTokenForTeam(ctx, teamID, tokenName, tokenDescription, expiresAt)
}

// Authentication and Token operations

// AuthenticateToken validates a token and returns team and port information
func (s *Service) AuthenticateToken(ctx context.Context, token string) (*TeamToken, *PortAssignment, error) {
	// Get team token
	teamToken, err := s.repo.GetTeamTokenByToken(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Update last used timestamp
	if err := s.repo.UpdateTokenLastUsed(ctx, teamToken.ID); err != nil {
		// Log error but don't fail authentication
		fmt.Printf("Warning: failed to update token last used: %v\n", err)
	}

	// Get port assignment
	portAssignment, err := s.repo.GetPortAssignmentByToken(ctx, teamToken.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get port assignment: %w", err)
	}

	return teamToken, portAssignment, nil
}

// Connection management

// StartConnection creates a new connection session and log entry
func (s *Service) StartConnection(ctx context.Context, teamID string, tokenID, portAssignID uuid.UUID, clientIP string, serverPort int, protocol string) (*ConnectionSession, *ConnectionLog, error) {
	// Create connection session
	session, err := s.repo.CreateConnectionSession(ctx, teamID, tokenID, portAssignID, clientIP, serverPort, protocol)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection session: %w", err)
	}

	// Create connection log
	log, err := s.repo.CreateConnectionLog(ctx, teamID, tokenID, portAssignID, session.ID, clientIP, 0, serverPort, protocol)
	if err != nil {
		// Session created but log failed - not critical
		fmt.Printf("Warning: failed to create connection log: %v\n", err)
		return session, nil, nil
	}

	return session, log, nil
}

// UpdateConnectionActivity updates session and connection statistics
func (s *Service) UpdateConnectionActivity(ctx context.Context, sessionID, logID uuid.UUID, bytesReceived, bytesSent int64) error {
	// Update session last seen
	if err := s.repo.UpdateSessionLastSeen(ctx, sessionID); err != nil {
		// Log error but continue
		fmt.Printf("Warning: failed to update session last seen: %v\n", err)
	}

	// Update connection log stats
	if logID != uuid.Nil {
		if err := s.repo.UpdateConnectionLogStats(ctx, logID, bytesReceived, bytesSent); err != nil {
			return fmt.Errorf("failed to update connection stats: %w", err)
		}
	}

	return nil
}

// EndConnection closes a connection session and log entry
func (s *Service) EndConnection(ctx context.Context, sessionID, logID uuid.UUID, status string, errorMessage *string) error {
	// End session
	if err := s.repo.EndConnectionSession(ctx, sessionID); err != nil {
		// Log error but continue
		fmt.Printf("Warning: failed to end session: %v\n", err)
	}

	// End connection log
	if logID != uuid.Nil {
		if err := s.repo.EndConnectionLog(ctx, logID, status, errorMessage); err != nil {
			return fmt.Errorf("failed to end connection log: %w", err)
		}
	}

	return nil
}

// Statistics and health

// GetConnectionStats retrieves connection statistics for a team
func (s *Service) GetConnectionStats(ctx context.Context, teamID string, from, to time.Time) ([]ConnectionStats, error) {
	return s.repo.GetConnectionStats(ctx, teamID, from, to)
}

// GetPortAssignmentByPort retrieves port assignment information
func (s *Service) GetPortAssignmentByPort(ctx context.Context, port int, protocol string) (*PortAssignment, error) {
	return s.repo.GetPortAssignmentByPort(ctx, port, protocol)
}

// HealthCheck verifies database connectivity and basic operations
func (s *Service) HealthCheck(ctx context.Context) error {
	// Test database connectivity
	if err := s.db.DB.PingContext(ctx); err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}

	// Test Redis connectivity
	if err := s.db.Redis.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}

	// Test basic query
	var count int
	if err := s.db.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM public.\"Team\"").Scan(&count); err != nil {
		return fmt.Errorf("database query failed: %w", err)
	}

	return nil
}

func (s *Service) ListTeamsWithTokens(ctx context.Context) ([]TokenRow, error) {
	return s.repo.ListTeamsWithTokens(ctx)
}

// GetDatabaseStats returns basic database statistics
func (s *Service) GetDatabaseStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count teams
	var teamCount int
	if err := s.db.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM public.\"Team\" WHERE is_active = true").Scan(&teamCount); err == nil {
		stats["active_teams"] = teamCount
	}

	// Count tokens
	var tokenCount int
	if err := s.db.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM team_tokens WHERE is_active = true").Scan(&tokenCount); err == nil {
		stats["active_tokens"] = tokenCount
	}

	// Count port assignments
	var portCount int
	if err := s.db.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM port_assignments").Scan(&portCount); err == nil {
		stats["port_assignments"] = portCount
	}

	// Count active sessions
	var sessionCount int
	if err := s.db.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM connection_sessions WHERE status = 'active'").Scan(&sessionCount); err == nil {
		stats["active_sessions"] = sessionCount
	}

	// Count total connections today
	var connectionsToday int
	if err := s.db.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM connection_logs WHERE started_at >= CURRENT_DATE").Scan(&connectionsToday); err == nil {
		stats["connections_today"] = connectionsToday
	}

	return stats, nil
}

// GetActiveSessions retrieves all active connection sessions for server restart recovery
func (s *Service) GetActiveSessions(ctx context.Context) ([]ConnectionSession, error) {
	return s.repo.GetActiveSessions(ctx)
}

// GetSessionWithDetails retrieves a session with its associated token and port assignment details
func (s *Service) GetSessionWithDetails(ctx context.Context, sessionID uuid.UUID) (*ConnectionSession, *TeamToken, *PortAssignment, error) {
	return s.repo.GetSessionWithDetails(ctx, sessionID)
}

// CleanupStaleConnections marks old sessions as inactive and returns count of cleaned sessions
func (s *Service) CleanupStaleConnections(ctx context.Context, staleThreshold time.Duration) (int, error) {
	return s.repo.MarkStaleSessionsInactive(ctx, staleThreshold)
}

// RestoreActiveSessions queries active sessions and returns them grouped by port for restoration
func (s *Service) RestoreActiveSessions(ctx context.Context) (map[int][]ConnectionSession, error) {
	sessions, err := s.repo.GetActiveSessions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}

	// Group sessions by port
	portSessions := make(map[int][]ConnectionSession)
	for _, session := range sessions {
		portSessions[session.ServerPort] = append(portSessions[session.ServerPort], session)
	}

	return portSessions, nil
}

// RestoreSession reactivates a session when a tunnel is restored
func (s *Service) RestoreSession(ctx context.Context, sessionID uuid.UUID) error {
	return s.repo.UpdateSessionLastSeen(ctx, sessionID)
}

// ReactivateRestoredTunnel marks a tunnel as fully active when client reconnects
func (s *Service) ReactivateRestoredTunnel(ctx context.Context, sessionID uuid.UUID, clientIP string) error {
	// Update session with new activity
	if err := s.repo.UpdateSessionLastSeen(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	// Store the reactivation event in Redis for monitoring
	reactivationData := map[string]interface{}{
		"session_id":     sessionID.String(),
		"client_ip":      clientIP,
		"reactivated_at": time.Now(),
	}

	if err := s.db.SetActiveSession(sessionID, reactivationData); err != nil {
		// Log error but don't fail the reactivation
		log.Printf("⚠️ Failed to store reactivation data in Redis: %v", err)
	}

	return nil
}

// GetRestoredTunnelInfo gets information about a restored tunnel
func (s *Service) GetRestoredTunnelInfo(ctx context.Context, sessionID uuid.UUID) (*ConnectionSession, *TeamToken, *PortAssignment, error) {
	return s.repo.GetSessionWithDetails(ctx, sessionID)
}
