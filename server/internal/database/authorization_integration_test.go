package database

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

func TestRealMetadataMembership(t *testing.T) {
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
	for _, q := range []string{`CREATE TEMP TABLE "Team"(id text,deleted boolean)`, `CREATE TEMP TABLE postgoose_user_teams("userId" text,"teamId" text,role text,deleted boolean)`, `INSERT INTO "Team" VALUES ('a',false),('b',false),('deleted',true)`, `INSERT INTO postgoose_user_teams VALUES ('owner','a','OWNER',false),('member','a','MEMBER',false),('owner','deleted','OWNER',false),('revoked','a','OWNER',true)`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := NewService(&Database{DB: db})
	for _, tc := range []struct {
		user, team  string
		admin, want bool
	}{{"owner", "a", true, true}, {"owner", "b", false, false}, {"member", "a", false, true}, {"member", "a", true, false}, {"revoked", "a", false, false}, {"owner", "deleted", true, false}} {
		ok, err := s.AuthorizeTeam(context.Background(), tc.user, tc.team, tc.admin)
		if err != nil || ok != tc.want {
			t.Fatalf("%+v got %v %v", tc, ok, err)
		}
	}
}
