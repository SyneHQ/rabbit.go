package database

import "context"

func (s *Service) AuthorizeTeam(ctx context.Context, user, team string, admin bool) (bool, error) {
	var allowed bool
	err := s.db.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM postgoose_user_teams m JOIN "Team" t ON t.id=m."teamId" WHERE m."userId"=$1 AND m."teamId"=$2 AND NOT m.deleted AND NOT t.deleted AND (NOT $3 OR m.role::text IN ('OWNER','ADMIN')))`, user, team, admin).Scan(&allowed)
	return allowed, err
}
