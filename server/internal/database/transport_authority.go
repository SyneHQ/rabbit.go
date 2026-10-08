package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// CheckTransportAuthority is a read-only renewal check. It does not update
// last-used timestamps or create a session for each physical source connection.
func (s *Service) CheckTransportAuthority(ctx context.Context, tenant, token string, tokenID, portID uuid.UUID) (time.Time, error) {
	if err := s.db.EnsureIdentityMode(ctx); err != nil {
		return time.Time{}, err
	}
	var expires sql.NullTime
	err := s.db.DB.QueryRowContext(ctx, `SELECT tt.expires_at FROM team_tokens tt
		JOIN `+s.db.identityTeams()+` team ON team.id = tt.team_id
		JOIN port_assignments pa ON pa.token_id = tt.id AND pa.team_id = tt.team_id
		WHERE tt.id = $1 AND tt.team_id = $2 AND tt.token = $3 AND tt.is_active
		AND (tt.expires_at IS NULL OR tt.expires_at > NOW()) AND team.is_active
		AND pa.id = $4 AND pa.is_reserved AND pa.protocol = 'tcp'
	`, tokenID, tenant, token, portID).Scan(&expires)
	if err != nil {
		return time.Time{}, errors.New("database transport authority unavailable")
	}
	return expires.Time, nil
}
