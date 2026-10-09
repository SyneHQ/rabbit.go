package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	firstTunnelPort        = 10000
	lastTunnelPort         = 65535
	portAllocationAttempts = 64
	portLockLifetime       = 10 * time.Minute
	portLockCleanupBudget  = time.Second
)

var errPortAllocationBusy = errors.New("port allocation contention limit reached")

// CreateTokenForTeam commits one token and one PostgreSQL reservation together.
// Redis coordinates candidates; the partial unique index remains authoritative.
func (r *Repository) CreateTokenForTeam(ctx context.Context, teamID string, tokenName, tokenDescription string, expiresAt *time.Time) (*TeamToken, *PortAssignment, error) {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	var lockedPort int
	var owner uuid.UUID
	defer func() {
		// Release only after commit or rollback. Cancellation must not strand an
		// advisory lease for its full lifetime when Redis is still available.
		_ = tx.Rollback()
		if lockedPort != 0 {
			cleanup, cancel := context.WithTimeout(context.Background(), portLockCleanupBudget)
			defer cancel()
			// Cleanup failure leaves a bounded TTL; PostgreSQL still owns reservations.
			// Do not turn a committed token into an error that invites replay.
			_, _ = r.db.ReleasePortLock(cleanup, lockedPort, owner)
		}
	}()

	var teamExists bool
	err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+r.db.identityTeams()+" t WHERE id = $1 AND is_active)", teamID).Scan(&teamExists)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check team existence: %w", err)
	}
	if !teamExists {
		return nil, nil, fmt.Errorf("team not found")
	}
	tokenValue, err := generateSecureToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate token: %w", err)
	}
	teamToken := &TeamToken{
		ID: uuid.New(), TeamID: teamID, Token: tokenValue, Name: tokenName,
		Description: tokenDescription, CreatedAt: time.Now(), ExpiresAt: expiresAt, IsActive: true,
	}
	owner = teamToken.ID
	err = tx.QueryRowContext(ctx, `
		INSERT INTO team_tokens (id, team_id, token, name, description, created_at, expires_at, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, team_id, token, name, COALESCE(description, ''), created_at, expires_at, last_used_at, is_active`,
		teamToken.ID, teamToken.TeamID, teamToken.Token, teamToken.Name,
		teamToken.Description, teamToken.CreatedAt, teamToken.ExpiresAt, teamToken.IsActive,
	).Scan(&teamToken.ID, &teamToken.TeamID, &teamToken.Token, &teamToken.Name,
		&teamToken.Description, &teamToken.CreatedAt, &teamToken.ExpiresAt, &teamToken.LastUsedAt, &teamToken.IsActive)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create team token: %w", err)
	}

	usedPorts, err := reservedTunnelPorts(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	attempts := 0
	for port := firstTunnelPort; port <= lastTunnelPort; port++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if usedPorts[port] {
			continue
		}
		if attempts == portAllocationAttempts {
			return nil, nil, errPortAllocationBusy
		}
		attempts++
		// An interrupted Redis reply can hide a successful SET NX. Cleanup may
		// release only this owner even when acquisition returns an error.
		lockedPort = port
		acquired, err := r.db.TryPortLock(ctx, port, owner, portLockLifetime)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to acquire port lock: %w", err)
		}
		if !acquired {
			lockedPort = 0
			continue
		}
		assignment := &PortAssignment{
			ID: uuid.New(), TeamID: teamID, TokenID: owner, Port: port,
			Protocol: "tcp", IsReserved: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		err = tx.QueryRowContext(ctx, `
			INSERT INTO port_assignments (id, team_id, token_id, port, protocol, is_reserved, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (port, protocol) WHERE is_reserved = true DO NOTHING
			RETURNING id, team_id, token_id, port, protocol, is_reserved, created_at, updated_at`,
			assignment.ID, assignment.TeamID, assignment.TokenID, assignment.Port,
			assignment.Protocol, assignment.IsReserved, assignment.CreatedAt, assignment.UpdatedAt,
		).Scan(&assignment.ID, &assignment.TeamID, &assignment.TokenID, &assignment.Port,
			&assignment.Protocol, &assignment.IsReserved, &assignment.CreatedAt, &assignment.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			// A concurrent reservation or an expired lease can invalidate the
			// snapshot. Retry another candidate without aborting this transaction.
			if _, err := r.db.ReleasePortLock(ctx, lockedPort, owner); err != nil {
				return nil, nil, fmt.Errorf("failed to release contended port lock: %w", err)
			}
			lockedPort = 0
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create port assignment: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
		}
		return teamToken, assignment, nil
	}
	return nil, nil, fmt.Errorf("no available ports in range %d-%d", firstTunnelPort, lastTunnelPort)
}

func reservedTunnelPorts(ctx context.Context, tx *sql.Tx) (map[int]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT port FROM port_assignments
		WHERE port BETWEEN $1 AND $2 AND protocol = 'tcp' AND is_reserved = true`, firstTunnelPort, lastTunnelPort)
	if err != nil {
		return nil, fmt.Errorf("failed to query used ports: %w", err)
	}
	defer rows.Close()
	used := make(map[int]bool)
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, fmt.Errorf("failed to scan port: %w", err)
		}
		used[port] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read used ports: %w", err)
	}
	return used, nil
}
