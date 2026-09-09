package database

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"os"
	"testing"
)

func TestAtomicScopedRevocationRetainsHistory(t *testing.T) {
	dsn := os.Getenv("SECURITY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	for _, q := range []string{
		`CREATE TEMP TABLE team_tokens(id uuid PRIMARY KEY,team_id text,is_active boolean)`,
		`CREATE TEMP TABLE port_assignments(id uuid PRIMARY KEY,team_id text,token_id uuid,port integer,protocol text,is_reserved boolean,created_at timestamptz DEFAULT NOW(),updated_at timestamptz DEFAULT NOW())`,
		`CREATE UNIQUE INDEX ON port_assignments(port,protocol) WHERE is_reserved=true`,
		`CREATE TEMP TABLE connection_sessions(team_id text,token_id uuid,status text)`,
		`CREATE TEMP TABLE connection_logs(team_id text,token_id uuid,status text,ended_at timestamptz)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	token, port, missing := uuid.New(), uuid.New(), uuid.New()
	for _, q := range []string{
		`INSERT INTO team_tokens VALUES ($1,'team',true)`,
		`INSERT INTO port_assignments(id,team_id,token_id,port,protocol,is_reserved) VALUES ('` + port.String() + `','team',$1,12345,'tcp',true)`,
		`INSERT INTO connection_sessions VALUES ('team',$1,'active')`,
		`INSERT INTO connection_logs VALUES ('team',$1,'active',NULL)`,
	} {
		if _, err := db.Exec(q, token); err != nil {
			t.Fatal(err)
		}
	}
	db.Exec(`INSERT INTO team_tokens VALUES ($1,'team',true)`, missing)
	repo := NewRepository(&Database{DB: db})
	ctx := context.Background()
	if _, err := repo.DeleteTokenForTeam(ctx, "foreign", token); err == nil {
		t.Fatal("foreign team revoked token")
	}
	var active bool
	db.QueryRow(`SELECT is_active FROM team_tokens WHERE id=$1`, token).Scan(&active)
	if !active {
		t.Fatal("foreign team changed token")
	}
	if _, err := repo.DeleteTokenForTeam(ctx, "team", missing); err == nil {
		t.Fatal("missing port unexpectedly revoked")
	}
	db.QueryRow(`SELECT is_active FROM team_tokens WHERE id=$1`, missing).Scan(&active)
	if !active {
		t.Fatal("failed revoke did not roll back token")
	}
	assignment, err := repo.DeleteTokenForTeam(ctx, "team", token)
	if err != nil || assignment.Port != 12345 || assignment.IsReserved {
		t.Fatalf("valid revoke failed: %+v %v", assignment, err)
	}
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM port_assignments WHERE id=$1 AND is_reserved=false`, port).Scan(&count)
	if count != 1 {
		t.Fatal("port audit record lost")
	}
	db.QueryRow(`SELECT COUNT(*) FROM connection_logs WHERE token_id=$1 AND status='closed' AND ended_at IS NOT NULL`, token).Scan(&count)
	if count != 1 {
		t.Fatal("connection history lost or still active")
	}
	if _, err := db.Exec(`INSERT INTO port_assignments(id,team_id,token_id,port,protocol,is_reserved) VALUES ($1,'team',$2,12345,'tcp',true)`, uuid.New(), missing); err != nil {
		t.Fatalf("released port cannot be reused: %v", err)
	}
}
