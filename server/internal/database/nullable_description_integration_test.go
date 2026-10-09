package database

import (
	"database/sql"
	"testing"
	"time"
)

// Use the real migration schema: description is nullable, including rows from
// other valid writers. Reading a missing description must not rewrite the row.
func TestNullableTokenDescriptionPreservesAuthentication(t *testing.T) {
	db, ctx := ownedIdentityDatabase(t)
	if err := db.RunMigrations("migrations.sql"); err != nil {
		t.Fatal(err)
	}
	if err := db.BootstrapTeam(ctx, "description-fixture", "Description fixture", "owner"); err != nil {
		t.Fatal(err)
	}
	service := NewService(db)
	repo := NewRepository(db)
	expires := time.Now().Add(time.Hour)
	token, port, err := service.GenerateTokenForTeam(ctx, "description-fixture", "fixture", "created description", &expires)
	if err != nil {
		t.Fatal(err)
	}
	defer db.ReleasePortLock(ctx, port.Port, token.ID)
	session, _, err := service.StartConnection(ctx, token.TeamID, token.ID, port.ID, "127.0.0.1", port.Port, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value any
		want  string
	}{{"NULL", nil, ""}, {"text", "persisted description", "persisted description"}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.DB.ExecContext(ctx, `UPDATE team_tokens SET description=$2 WHERE id=$1`, token.ID, tc.value); err != nil {
				t.Fatal(err)
			}
			authenticated, assignment, err := service.AuthenticateToken(ctx, token.Token)
			if err != nil || authenticated == nil || assignment == nil {
				t.Fatal("valid nullable-description token failed authentication", err)
			}
			if authenticated.Description != tc.want || assignment.Token.Description != tc.want {
				t.Fatal("authentication returned an incorrect description")
			}
			listed, err := repo.ListTokensByTeamID(ctx, token.TeamID)
			if err != nil || len(listed) != 1 || listed[0].Description != tc.want {
				t.Fatal("token listing failed nullable description", err)
			}
			loaded, details, _, err := repo.GetSessionWithDetails(ctx, session.ID)
			if err != nil || loaded == nil || details == nil || details.Description != tc.want {
				t.Fatal("session details failed nullable description", err)
			}
			var persisted sql.NullString
			if err := db.DB.QueryRowContext(ctx, `SELECT description FROM team_tokens WHERE id=$1`, token.ID).Scan(&persisted); err != nil {
				t.Fatal(err)
			}
			if persisted.Valid != (tc.value != nil) || persisted.String != tc.want {
				t.Fatal("reading a token changed its persisted description")
			}
		})
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE team_tokens SET description=NULL WHERE id=$1`, token.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AuthenticateToken(ctx, "not-the-token"); err == nil {
		t.Fatal("unknown token authenticated")
	}
	for _, tc := range []struct{ name, deny, restore string }{
		{"revoked", `UPDATE team_tokens SET is_active=false WHERE id=$1`, `UPDATE team_tokens SET is_active=true WHERE id=$1`},
		{"expired", `UPDATE team_tokens SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1`, `UPDATE team_tokens SET expires_at=NOW()+INTERVAL '1 hour' WHERE id=$1`},
		{"inactive team", `UPDATE rabbit_teams SET is_active=false WHERE id=(SELECT team_id FROM team_tokens WHERE id=$1)`, `UPDATE rabbit_teams SET is_active=true WHERE id=(SELECT team_id FROM team_tokens WHERE id=$1)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.DB.ExecContext(ctx, tc.deny, token.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, err := service.AuthenticateToken(ctx, token.Token); err == nil {
				t.Fatal("nullable description bypassed authentication policy")
			}
			if _, err := db.DB.ExecContext(ctx, tc.restore, token.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
