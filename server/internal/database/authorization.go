package database

import "context"

func (s *Service) AuthorizeTeam(ctx context.Context, user, team string, admin bool) (bool, error) {
	if err := s.db.EnsureIdentityMode(ctx); err != nil {
		return false, err
	}
	var allowed bool
	query := `SELECT EXISTS(SELECT 1 FROM rabbit_team_memberships m JOIN rabbit_teams t ON t.id=m.team_id WHERE m.user_id=$1 AND m.team_id=$2 AND m.is_active AND t.is_active AND (NOT $3 OR m.role IN ('OWNER','ADMIN')))`
	if s.db.IdentityMode != IdentityStandalone {
		query = `SELECT EXISTS(SELECT 1 FROM postgoose_user_teams m JOIN "Team" t ON t.id=m."teamId" WHERE m."userId"=$1 AND m."teamId"=$2 AND NOT m.deleted AND NOT t.deleted AND (NOT $3 OR m.role::text IN ('OWNER','ADMIN')))`
	}
	err := s.db.DB.QueryRowContext(ctx, query, user, team, admin).Scan(&allowed)
	return allowed, err
}
