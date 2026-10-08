package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Repository provides database operations
type Repository struct {
	db *Database
}

// NewRepository creates a new repository instance
func NewRepository(db *Database) *Repository {
	return &Repository{db: db}
}

// Team operations

// GetTeamByID retrieves a team by ID
func (r *Repository) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	return r.lookupTeam(ctx, "id", id)
}

// GetTeamByName retrieves an active team by name.
func (r *Repository) GetTeamByName(ctx context.Context, name string) (*Team, error) {
	return r.lookupTeam(ctx, "name", name)
}

func (r *Repository) lookupTeam(ctx context.Context, field, value string) (*Team, error) {
	team := &Team{}
	query := "SELECT id,name,description,created_at,updated_at,is_active FROM " + r.db.identityTeams() + " t WHERE " + field + "=$1 AND is_active"
	err := r.db.DB.QueryRowContext(ctx, query, value).Scan(&team.ID, &team.Name, &team.Description, &team.CreatedAt, &team.UpdatedAt, &team.IsActive)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("team not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get team: %w", err)
	}
	return team, nil
}

// Team Token operations

// GetTeamTokenByToken retrieves a team token by token string
func (r *Repository) GetTeamTokenByToken(ctx context.Context, token string) (*TeamToken, error) {
	teamToken := &TeamToken{}
	query := `
		SELECT t.id, t.team_id, t.token, t.name, t.description, t.created_at,
		       t.expires_at, t.last_used_at, t.is_active,
		       identity.id, identity.name, identity.description, identity.is_active
		FROM team_tokens t
		JOIN ` + r.db.identityTeams() + ` identity ON t.team_id = identity.id AND identity.is_active
		WHERE t.token = $1 AND t.is_active = true
		  AND (t.expires_at IS NULL OR t.expires_at > NOW())`

	team := &Team{}
	err := r.db.DB.QueryRowContext(ctx, query, token).Scan(
		&teamToken.ID, &teamToken.TeamID, &teamToken.Token, &teamToken.Name,
		&teamToken.Description, &teamToken.CreatedAt, &teamToken.ExpiresAt,
		&teamToken.LastUsedAt, &teamToken.IsActive,
		&team.ID, &team.Name, &team.Description, &team.IsActive,
	)

	if err != nil {
		fmt.Println("error", err)
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("token not found or expired")
		}
		return nil, fmt.Errorf("failed to get team token: %w", err)
	}

	teamToken.Team = team
	return teamToken, nil
}

type TokenRow struct {
	TeamID, TeamName, TeamDesc, TeamCreated                                         string
	TokenID, TokenName, Token, TokenDesc, TokenCreated, TokenExpires, TokenLastUsed *string
	Port                                                                            *int
	Protocol                                                                        *string
}

// ListTeamsWithTokens returns all teams with their tokens and port assignments
func (r *Repository) ListTeamsWithTokens(ctx context.Context) ([]TokenRow, error) {
	// Query teams with their tokens and port assignments
	query := `
		SELECT 
			t.id, t.name, COALESCE(t.description, '') as description, 
			t.created_at as created_at,
			tt.id, tt.name, NULL::text, tt.description, tt.created_at, tt.expires_at, tt.last_used_at,
			pa.port, pa.protocol
		FROM ` + r.db.identityTeams() + ` t
		LEFT JOIN team_tokens tt ON t.id = tt.team_id AND tt.is_active = true
		LEFT JOIN port_assignments pa ON tt.id = pa.token_id AND pa.is_reserved = true
		WHERE t.is_active
		ORDER BY t.name, tt.created_at
	`

	rows, err := r.db.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query teams: %w", err)
	}
	defer rows.Close()

	var tokenRows []TokenRow

	for rows.Next() {
		var (
			teamID, teamName, teamDesc, teamCreated                                         string
			tokenID, tokenName, token, tokenDesc, tokenCreated, tokenExpires, tokenLastUsed *string
			port                                                                            *int
			protocol                                                                        *string
		)
		err := rows.Scan(
			&teamID, &teamName, &teamDesc, &teamCreated,
			&tokenID, &tokenName, &token, &tokenDesc, &tokenCreated, &tokenExpires, &tokenLastUsed,
			&port, &protocol,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		tokenRows = append(tokenRows, TokenRow{
			TeamID:        teamID,
			TeamName:      teamName,
			TeamDesc:      teamDesc,
			TeamCreated:   teamCreated,
			TokenID:       tokenID,
			TokenName:     tokenName,
			Token:         token,
			TokenDesc:     tokenDesc,
			TokenCreated:  tokenCreated,
			TokenExpires:  tokenExpires,
			TokenLastUsed: tokenLastUsed,
			Port:          port,
			Protocol:      protocol,
		})
	}

	return tokenRows, nil
}

// ListTokensByTeamID retrieves all tokens for a team
func (r *Repository) ListTokensByTeamID(ctx context.Context, teamID string) ([]TeamToken, error) {
	query := `SELECT id, team_id, token, name, description, created_at, expires_at, last_used_at, is_active FROM team_tokens WHERE team_id = $1`

	rows, err := r.db.DB.QueryContext(ctx, query, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to query tokens: %w", err)
	}
	defer rows.Close()

	var tokens []TeamToken
	for rows.Next() {
		var token TeamToken
		err := rows.Scan(&token.ID, &token.TeamID, &token.Token, &token.Name, &token.Description, &token.CreatedAt, &token.ExpiresAt, &token.LastUsedAt, &token.IsActive)
		if err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}

		tokens = append(tokens, token)
	}

	return tokens, nil
}

// UpdateTokenLastUsed updates the last used timestamp for a token
func (r *Repository) UpdateTokenLastUsed(ctx context.Context, tokenID uuid.UUID) error {
	query := `UPDATE team_tokens SET last_used_at = NOW() WHERE id = $1`

	_, err := r.db.DB.ExecContext(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to update token last used: %w", err)
	}

	return nil
}

// Port Assignment operations

// GetPortAssignmentByToken retrieves port assignment for a token
func (r *Repository) GetPortAssignmentByToken(ctx context.Context, tokenID uuid.UUID) (*PortAssignment, error) {
	assignment := &PortAssignment{}
	query := `
		SELECT pa.id, pa.team_id, pa.token_id, pa.port, pa.protocol, pa.is_reserved, pa.created_at, pa.updated_at,
		       t.id, t.name, t.description, t.is_active,
		       tt.id, tt.team_id, tt.token, tt.name, tt.description, tt.created_at, tt.expires_at, tt.last_used_at, tt.is_active
		FROM port_assignments pa
		JOIN ` + r.db.identityTeams() + ` t ON pa.team_id = t.id AND t.is_active
		JOIN team_tokens tt ON pa.token_id = tt.id
		WHERE pa.token_id = $1 AND pa.is_reserved = true`

	team := &Team{}
	token := &TeamToken{}

	err := r.db.DB.QueryRowContext(ctx, query, tokenID).Scan(
		&assignment.ID, &assignment.TeamID, &assignment.TokenID, &assignment.Port,
		&assignment.Protocol, &assignment.IsReserved, &assignment.CreatedAt, &assignment.UpdatedAt,
		&team.ID, &team.Name, &team.Description, &team.IsActive,
		&token.ID, &token.TeamID, &token.Token, &token.Name, &token.Description,
		&token.CreatedAt, &token.ExpiresAt, &token.LastUsedAt, &token.IsActive,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("port assignment not found")
		}
		return nil, fmt.Errorf("failed to get port assignment: %w", err)
	}

	assignment.Team = team
	assignment.Token = token
	return assignment, nil
}

// GetPortAssignmentByPort retrieves port assignment by port and protocol
func (r *Repository) GetPortAssignmentByPort(ctx context.Context, port int, protocol string) (*PortAssignment, error) {
	assignment := &PortAssignment{}
	query := `
		SELECT id, team_id, token_id, port, protocol, is_reserved, created_at, updated_at
		FROM port_assignments WHERE port = $1 AND protocol = $2 AND is_reserved = true`

	err := r.db.DB.QueryRowContext(ctx, query, port, protocol).Scan(
		&assignment.ID, &assignment.TeamID, &assignment.TokenID, &assignment.Port,
		&assignment.Protocol, &assignment.IsReserved, &assignment.CreatedAt, &assignment.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("port assignment not found")
		}
		return nil, fmt.Errorf("failed to get port assignment: %w", err)
	}

	return assignment, nil
}

// ListPortAssignmentsByTeamID retrieves all port assignments for a team
func (r *Repository) ListPortAssignmentsByTeamID(ctx context.Context, teamID string) ([]PortAssignment, error) {
	query := `SELECT id, team_id, token_id, port, protocol, is_reserved, created_at, updated_at FROM port_assignments WHERE team_id = $1 AND is_reserved = true`

	rows, err := r.db.DB.QueryContext(ctx, query, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to query port assignments: %w", err)
	}
	defer rows.Close()

	var assignments []PortAssignment
	for rows.Next() {
		var assignment PortAssignment
		err := rows.Scan(&assignment.ID, &assignment.TeamID, &assignment.TokenID, &assignment.Port,
			&assignment.Protocol, &assignment.IsReserved, &assignment.CreatedAt, &assignment.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan port assignment: %w", err)
		}
		assignments = append(assignments, assignment)
	}

	return assignments, nil
}

// Connection Session operations

// CreateConnectionSession creates a new connection session
func (r *Repository) CreateConnectionSession(ctx context.Context, teamID string, tokenID, portAssignID uuid.UUID, clientIP string, serverPort int, protocol string) (*ConnectionSession, error) {
	session := &ConnectionSession{
		ID:           uuid.New(),
		TeamID:       teamID,
		TokenID:      tokenID,
		PortAssignID: portAssignID,
		ClientIP:     clientIP,
		ServerPort:   serverPort,
		Protocol:     protocol,
		StartedAt:    time.Now(),
		LastSeenAt:   time.Now(),
		Status:       "active",
	}

	query := `
		INSERT INTO connection_sessions (id, team_id, token_id, port_assign_id, client_ip, server_port, protocol, started_at, last_seen_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, team_id, token_id, port_assign_id, client_ip, server_port, protocol, started_at, last_seen_at, status`

	err := r.db.DB.QueryRowContext(ctx, query,
		session.ID, session.TeamID, session.TokenID, session.PortAssignID,
		session.ClientIP, session.ServerPort, session.Protocol,
		session.StartedAt, session.LastSeenAt, session.Status,
	).Scan(&session.ID, &session.TeamID, &session.TokenID, &session.PortAssignID,
		&session.ClientIP, &session.ServerPort, &session.Protocol,
		&session.StartedAt, &session.LastSeenAt, &session.Status)

	if err != nil {
		return nil, fmt.Errorf("failed to create connection session: %w", err)
	}

	// Also store in Redis for fast access
	if err := r.db.SetActiveSessionContext(ctx, session.ID, session); err != nil {
		// Log error but don't fail the operation
		fmt.Printf("Warning: failed to store session in Redis: %v\n", err)
	}

	return session, nil
}

// UpdateSessionLastSeen updates the last seen timestamp for a session
func (r *Repository) UpdateSessionLastSeen(ctx context.Context, sessionID uuid.UUID) error {
	query := `UPDATE connection_sessions SET last_seen_at = NOW() WHERE id = $1`

	_, err := r.db.DB.ExecContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to update session last seen: %w", err)
	}

	return nil
}

// EndConnectionSession marks a connection session as inactive
func (r *Repository) EndConnectionSession(ctx context.Context, sessionID uuid.UUID) error {
	query := `UPDATE connection_sessions SET status = 'inactive', last_seen_at = NOW() WHERE id = $1`

	_, err := r.db.DB.ExecContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to end connection session: %w", err)
	}

	// Remove from Redis
	if err := r.db.DeleteActiveSessionContext(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to remove session from Redis: %w", err)
	}

	return nil
}

// Connection Log operations

// CreateConnectionLog creates a new connection log entry
func (r *Repository) CreateConnectionLog(ctx context.Context, teamID string, tokenID, portAssignID, sessionID uuid.UUID, clientIP string, clientPort, serverPort int, protocol string) (*ConnectionLog, error) {
	log := &ConnectionLog{
		ID:            uuid.New(),
		TeamID:        teamID,
		TokenID:       tokenID,
		PortAssignID:  portAssignID,
		SessionID:     sessionID,
		ClientIP:      clientIP,
		ClientPort:    clientPort,
		ServerPort:    serverPort,
		Protocol:      protocol,
		StartedAt:     time.Now(),
		BytesReceived: 0,
		BytesSent:     0,
		Status:        "active",
	}

	query := `
		INSERT INTO connection_logs (id, team_id, token_id, port_assign_id, session_id, client_ip, client_port, server_port, protocol, started_at, bytes_received, bytes_sent, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id, team_id, token_id, port_assign_id, session_id, client_ip, client_port, server_port, protocol, started_at, ended_at, bytes_received, bytes_sent, connection_time_ms, status, error_message, user_agent, request_path`

	err := r.db.DB.QueryRowContext(ctx, query,
		log.ID, log.TeamID, log.TokenID, log.PortAssignID, log.SessionID,
		log.ClientIP, log.ClientPort, log.ServerPort, log.Protocol,
		log.StartedAt, log.BytesReceived, log.BytesSent, log.Status,
	).Scan(&log.ID, &log.TeamID, &log.TokenID, &log.PortAssignID, &log.SessionID,
		&log.ClientIP, &log.ClientPort, &log.ServerPort, &log.Protocol,
		&log.StartedAt, &log.EndedAt, &log.BytesReceived, &log.BytesSent,
		&log.ConnectionTime, &log.Status, &log.ErrorMessage, &log.UserAgent, &log.RequestPath)

	if err != nil {
		return nil, fmt.Errorf("failed to create connection log: %w", err)
	}

	return log, nil
}

// UpdateConnectionLogStats updates the bytes sent/received for a connection log
func (r *Repository) UpdateConnectionLogStats(ctx context.Context, logID uuid.UUID, bytesReceived, bytesSent int64) error {
	query := `
		UPDATE connection_logs 
		SET bytes_received = bytes_received + $2, bytes_sent = bytes_sent + $3
		WHERE id = $1`

	_, err := r.db.DB.ExecContext(ctx, query, logID, bytesReceived, bytesSent)
	if err != nil {
		return fmt.Errorf("failed to update connection log stats: %w", err)
	}

	return nil
}

// EndConnectionLog closes a connection log entry
func (r *Repository) EndConnectionLog(ctx context.Context, logID uuid.UUID, status string, errorMessage *string) error {
	query := `
		UPDATE connection_logs 
		SET ended_at = NOW(), status = $2, error_message = $3
		WHERE id = $1`

	_, err := r.db.DB.ExecContext(ctx, query, logID, status, errorMessage)
	if err != nil {
		return fmt.Errorf("failed to end connection log: %w", err)
	}

	return nil
}

// CompleteStream is idempotent: a repeated completion cannot double-count bytes.
func (r *Repository) CompleteStream(ctx context.Context, logID uuid.UUID, bytesReceived, bytesSent int64, status string, errorMessage *string) error {
	query := `
		WITH completed AS (
			UPDATE connection_logs
			SET bytes_received = $2, bytes_sent = $3,
				ended_at = COALESCE(ended_at, NOW()),
				status = CASE WHEN ended_at IS NULL THEN $4 ELSE status END,
				error_message = CASE WHEN ended_at IS NULL THEN $5 ELSE error_message END
			WHERE id = $1
			RETURNING session_id
		)
		UPDATE connection_sessions SET last_seen_at = NOW()
		WHERE id IN (SELECT session_id FROM completed)`
	if _, err := r.db.DB.ExecContext(ctx, query, logID, bytesReceived, bytesSent, status, errorMessage); err != nil {
		return fmt.Errorf("failed to complete stream log: %w", err)
	}
	return nil
}

// GetConnectionStats retrieves connection statistics for a team
func (r *Repository) GetConnectionStats(ctx context.Context, teamID string, from, to time.Time) ([]ConnectionStats, error) {
	query := `
		SELECT team_id, date, total_connections, active_connections, 
		       total_bytes_received, total_bytes_sent, avg_connection_time_ms
		FROM connection_stats
		WHERE team_id = $1 AND date BETWEEN $2 AND $3
		ORDER BY date`

	rows, err := r.db.DB.QueryContext(ctx, query, teamID, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection stats: %w", err)
	}
	defer rows.Close()

	var stats []ConnectionStats
	for rows.Next() {
		var stat ConnectionStats
		err := rows.Scan(&stat.TeamID, &stat.Date, &stat.TotalConnections,
			&stat.ActiveConnections, &stat.TotalBytesReceived,
			&stat.TotalBytesSent, &stat.AvgConnectionTime)
		if err != nil {
			return nil, fmt.Errorf("failed to scan connection stats: %w", err)
		}
		stats = append(stats, stat)
	}

	return stats, nil
}

// generateSecureToken generates a cryptographically secure token
func generateSecureToken() (string, error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Hash the bytes for additional security
	hash := sha256.Sum256(bytes)

	// Return as hex string
	return hex.EncodeToString(hash[:]), nil
}

// GetActiveSessions retrieves all active connection sessions for server restart recovery
func (r *Repository) GetActiveSessions(ctx context.Context) ([]ConnectionSession, error) {
	query := `
		SELECT cs.id, cs.team_id, cs.token_id, cs.port_assign_id, cs.client_ip, 
		       cs.server_port, cs.protocol, cs.started_at, cs.last_seen_at, cs.status
		FROM connection_sessions cs
		WHERE cs.status = 'active'
		ORDER BY cs.started_at`

	rows, err := r.db.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []ConnectionSession
	for rows.Next() {
		var session ConnectionSession
		err := rows.Scan(
			&session.ID, &session.TeamID, &session.TokenID, &session.PortAssignID,
			&session.ClientIP, &session.ServerPort, &session.Protocol,
			&session.StartedAt, &session.LastSeenAt, &session.Status,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// GetSessionWithDetails retrieves a session with its associated token and port assignment details
func (r *Repository) GetSessionWithDetails(ctx context.Context, sessionID uuid.UUID) (*ConnectionSession, *TeamToken, *PortAssignment, error) {
	query := `
		SELECT 
			cs.id, cs.team_id, cs.token_id, cs.port_assign_id, cs.client_ip, 
			cs.server_port, cs.protocol, cs.started_at, cs.last_seen_at, cs.status,
			tt.id, tt.team_id, tt.token, tt.name, tt.description, tt.created_at, 
			tt.expires_at, tt.last_used_at, tt.is_active,
			pa.id, pa.team_id, pa.token_id, pa.port, pa.protocol, pa.is_reserved,
			pa.created_at, pa.updated_at
		FROM connection_sessions cs
		JOIN team_tokens tt ON cs.token_id = tt.id
		JOIN port_assignments pa ON cs.port_assign_id = pa.id
		WHERE cs.id = $1`

	var session ConnectionSession
	var token TeamToken
	var portAssignment PortAssignment

	err := r.db.DB.QueryRowContext(ctx, query, sessionID).Scan(
		&session.ID, &session.TeamID, &session.TokenID, &session.PortAssignID,
		&session.ClientIP, &session.ServerPort, &session.Protocol,
		&session.StartedAt, &session.LastSeenAt, &session.Status,
		&token.ID, &token.TeamID, &token.Token, &token.Name, &token.Description,
		&token.CreatedAt, &token.ExpiresAt, &token.LastUsedAt, &token.IsActive,
		&portAssignment.ID, &portAssignment.TeamID, &portAssignment.TokenID,
		&portAssignment.Port, &portAssignment.Protocol, &portAssignment.IsReserved,
		&portAssignment.CreatedAt, &portAssignment.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil, fmt.Errorf("session not found")
		}
		return nil, nil, nil, fmt.Errorf("failed to get session details: %w", err)
	}

	return &session, &token, &portAssignment, nil
}

// MarkStaleSessionsInactive marks sessions as inactive if they haven't been seen recently
func (r *Repository) MarkStaleSessionsInactive(ctx context.Context, staleThreshold time.Duration) (int, error) {
	query := `
		UPDATE connection_sessions 
		SET status = 'inactive', last_seen_at = NOW()
		WHERE status = 'active' 
		AND last_seen_at < $1`

	staleTime := time.Now().Add(-staleThreshold)
	result, err := r.db.DB.ExecContext(ctx, query, staleTime)
	if err != nil {
		return 0, fmt.Errorf("failed to mark stale sessions inactive: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rowsAffected), nil
}

// DeleteTokenForTeam atomically revokes a token and releases its port, retaining audit rows.
func (r *Repository) DeleteTokenForTeam(ctx context.Context, teamID string, tokenID uuid.UUID) (*PortAssignment, error) {
	tx, err := r.db.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE team_tokens SET is_active = false WHERE team_id = $1 AND id = $2 AND is_active = true`, teamID, tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected != 1 {
		return nil, sql.ErrNoRows
	}
	assignment := &PortAssignment{}
	err = tx.QueryRowContext(ctx, `UPDATE port_assignments SET is_reserved = false WHERE team_id = $1 AND token_id = $2 AND is_reserved = true RETURNING id, team_id, token_id, port, protocol, is_reserved, created_at, updated_at`, teamID, tokenID).Scan(
		&assignment.ID, &assignment.TeamID, &assignment.TokenID, &assignment.Port,
		&assignment.Protocol, &assignment.IsReserved, &assignment.CreatedAt, &assignment.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to release port: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE connection_sessions SET status = 'inactive' WHERE team_id = $1 AND token_id = $2 AND status = 'active'`, teamID, tokenID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE connection_logs SET status = 'closed', ended_at = NOW() WHERE team_id = $1 AND token_id = $2 AND status = 'active'`, teamID, tokenID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return assignment, nil
}
