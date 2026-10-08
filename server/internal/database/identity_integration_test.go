package database

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestIdentityModePreservesExistingAuthority(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		valid       bool
	}{{"", IdentityPostgoose, true}, {IdentityStandalone, IdentityStandalone, true}, {IdentityPostgoose, IdentityPostgoose, true}, {"unknown", "", false}} {
		got, err := normalizeIdentityMode(tc.input)
		if (err == nil) != tc.valid || got != tc.want {
			t.Fatalf("mode %q: %q, %v", tc.input, got, err)
		}
	}
	if err := (&Database{}).BootstrapTeam(context.Background(), "team", "name", "owner"); err == nil {
		t.Fatal("bootstrap accepted implicit compatibility mode")
	}
}

// ownedIdentityDatabase creates and removes one database without changing existing application data.
func ownedIdentityDatabase(t *testing.T) (*Database, context.Context) {
	t.Helper()
	raw, redisURL := os.Getenv("RABBIT_TRANSPORT_DATABASE_URL"), os.Getenv("RABBIT_TRANSPORT_REDIS_URL")
	if raw == "" || redisURL == "" {
		t.Skip("requires disposable PostgreSQL and Redis fixtures")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("invalid fixture database URL")
	}
	admin, err := sql.Open("postgres", raw)
	if err != nil {
		t.Fatal("open fixture database")
	}
	t.Cleanup(func() { admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	name := "rabbit_identity_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		t.Fatalf("create owned fixture database: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, `DROP DATABASE "`+name+`" WITH (FORCE)`); err != nil {
			t.Errorf("remove owned fixture database: %v", err)
		}
	})
	parsed.Path, parsed.RawPath = "/"+name, ""
	fixture, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatal("open owned database")
	}
	t.Cleanup(func() { fixture.Close() })
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal("invalid fixture Redis URL")
	}
	opt.ContextTimeoutEnabled = true
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { rdb.Close() })
	db := &Database{DB: fixture, Redis: rdb, ctx: ctx, IdentityMode: IdentityStandalone}
	return db, ctx
}

func TestStandaloneMigrationTokenLifecycle(t *testing.T) {
	db, ctx := ownedIdentityDatabase(t)
	fixture := db.DB
	if err := db.ValidateIdentitySchema(ctx); err == nil {
		t.Fatal("empty database passed identity validation")
	}
	if err := db.RunMigrations("migrations.sql"); err != nil {
		t.Fatal(err)
	}
	if err := db.RunMigrations("migrations.sql"); err != nil {
		t.Fatalf("migration is not repeatable: %v", err)
	}
	var external *string
	if err := fixture.QueryRowContext(ctx, `SELECT to_regclass('public."Team"')::text`).Scan(&external); err != nil || external != nil {
		t.Fatal("migration created an application Team table")
	}
	if err := db.ValidateIdentitySchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.BootstrapTeam(ctx, "team", "Test team", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := db.BootstrapTeam(ctx, "team", "Replacement", "intruder"); err == nil {
		t.Fatal("bootstrap replaced an existing team")
	}
	if _, err := fixture.ExecContext(ctx, `INSERT INTO rabbit_team_memberships(team_id,user_id,role) VALUES('team','member','MEMBER')`); err != nil {
		t.Fatal(err)
	}
	service := NewService(db)
	for _, tc := range []struct {
		user, team  string
		admin, want bool
	}{{"owner", "team", true, true}, {"member", "team", false, true}, {"member", "team", true, false}, {"intruder", "team", false, false}, {"owner", "foreign", false, false}} {
		ok, err := service.AuthorizeTeam(ctx, tc.user, tc.team, tc.admin)
		if err != nil || ok != tc.want {
			t.Fatalf("membership %+v: %v %v", tc, ok, err)
		}
	}
	if _, err := service.GetTeamByID(ctx, "team"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetTeamByName(ctx, "Test team"); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour)
	token, port, err := service.GenerateTokenForTeam(ctx, "team", "fixture", "", &expiry)
	if err != nil {
		t.Fatal(err)
	}
	defer db.ReleasePortLock(port.Port)
	if _, _, err := service.AuthenticateToken(ctx, token.Token); err != nil {
		t.Fatalf("new token rejected: %v", err)
	}
	if rows, err := service.ListTeamsWithTokens(ctx); err != nil || len(rows) != 1 || rows[0].Token != nil {
		t.Fatal("team listing failed or exposed token")
	}
	if _, err := service.DeleteTunnelForTeam(ctx, "foreign", token.ID); err == nil {
		t.Fatal("foreign team revoked token")
	}
	if _, _, err := service.AuthenticateToken(ctx, token.Token); err != nil {
		t.Fatal("foreign revocation changed token")
	}
	if _, err := service.DeleteTunnelForTeam(ctx, "team", token.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AuthenticateToken(ctx, token.Token); err == nil {
		t.Fatal("revoked token still authenticates")
	}
}

func TestLegacyMigrationPreservesApplicationIdentity(t *testing.T) {
	db, ctx := ownedIdentityDatabase(t)
	for _, statement := range []string{
		`CREATE TABLE public."Team"(id text PRIMARY KEY,name text,description text,deleted boolean,"createdAt" timestamptz,"updatedAt" timestamptz,application_counter int DEFAULT 0)`,
		`CREATE TABLE public.postgoose_user_teams("teamId" text,"userId" text,role text,deleted boolean)`,
		`CREATE FUNCTION public.update_updated_at_column() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.application_counter=OLD.application_counter+1; RETURN NEW; END $$`,
		`CREATE TRIGGER update_teams_updated_at BEFORE UPDATE ON public."Team" FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column()`,
		`INSERT INTO public."Team" VALUES('legacy','Legacy team','application record',false,NOW(),NOW(),7)`,
		`INSERT INTO public.postgoose_user_teams VALUES('legacy','legacy-owner','OWNER',false)`,
	} {
		if _, err := db.DB.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	var before, after string
	if err := db.DB.QueryRowContext(ctx, `SELECT row_to_json(t)::text FROM public."Team" t WHERE id='legacy'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := db.RunMigrations("migrations.sql"); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT row_to_json(t)::text FROM public."Team" t WHERE id='legacy'`).Scan(&after); err != nil || before != after {
		t.Fatal("migration changed application rows")
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE public."Team" SET name=name WHERE id='legacy'`); err != nil {
		t.Fatal(err)
	}
	var counter int
	if err := db.DB.QueryRowContext(ctx, `SELECT application_counter FROM public."Team" WHERE id='legacy'`).Scan(&counter); err != nil || counter != 8 {
		t.Fatal("migration replaced the application trigger or function")
	}
	db.IdentityMode = IdentityPostgoose
	if err := db.ValidateIdentitySchema(ctx); err != nil {
		t.Fatal(err)
	}
	service := NewService(db)
	if ok, err := service.AuthorizeTeam(ctx, "legacy-owner", "legacy", true); err != nil || !ok {
		t.Fatal("legacy authorization failed")
	}
	if ok, err := service.AuthorizeTeam(ctx, "owner", "team", true); err != nil || ok {
		t.Fatal("legacy mode used standalone authority")
	}
	if _, err := service.GetTeamByID(ctx, "legacy"); err != nil {
		t.Fatal(err)
	}
	if err := db.BootstrapTeam(ctx, "forbidden", "Forbidden", "owner"); err == nil {
		t.Fatal("bootstrap modified compatibility identities")
	}
}

func TestIdentityBindingRejectsSameIDAcrossModes(t *testing.T) {
	for _, initial := range []string{IdentityStandalone, IdentityPostgoose} {
		t.Run(initial, func(t *testing.T) {
			db, ctx := ownedIdentityDatabase(t)
			if err := db.RunMigrations("migrations.sql"); err != nil {
				t.Fatal(err)
			}
			for _, statement := range []string{
				`CREATE TABLE public."Team"(id text PRIMARY KEY,name text,description text,deleted boolean,"createdAt" timestamptz,"updatedAt" timestamptz)`,
				`CREATE TABLE public.postgoose_user_teams("teamId" text,"userId" text,role text,deleted boolean)`,
				`INSERT INTO public."Team" VALUES('same-id','Legacy','legacy',false,NOW(),NOW())`,
				`INSERT INTO public.postgoose_user_teams VALUES('same-id','legacy-owner','OWNER',false)`,
				`INSERT INTO rabbit_teams(id,name) VALUES('same-id','Standalone')`,
				`INSERT INTO rabbit_team_memberships(team_id,user_id,role) VALUES('same-id','standalone-owner','OWNER')`,
			} {
				if _, err := db.DB.ExecContext(ctx, statement); err != nil {
					t.Fatal(err)
				}
			}
			db.IdentityMode = initial
			service := NewService(db)
			token, port, err := service.GenerateTokenForTeam(ctx, "same-id", "binding regression", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer db.ReleasePortLock(port.Port)
			if _, _, err := service.AuthenticateToken(ctx, token.Token); err != nil {
				t.Fatal(err)
			}
			other := *db
			other.IdentityMode = IdentityStandalone
			if initial == IdentityStandalone {
				other.IdentityMode = IdentityPostgoose
			}
			foreign := NewService(&other)
			if _, _, err := foreign.AuthenticateToken(ctx, token.Token); err == nil {
				t.Fatal("token crossed identity authority")
			}
			if _, _, err := foreign.GenerateTokenForTeam(ctx, "same-id", "foreign", "", nil); err == nil {
				t.Fatal("foreign authority generated token")
			}
			if _, err := foreign.DeleteTunnelForTeam(ctx, "same-id", token.ID); err == nil {
				t.Fatal("foreign authority revoked token")
			}
			if err := other.BootstrapTeam(ctx, "fresh-id", "New team", "owner"); err == nil {
				t.Fatal("bootstrap crossed identity authority")
			}
			if err := other.ValidateIdentitySchema(ctx); err == nil {
				t.Fatal("startup accepted a conflicting identity binding")
			}
			if _, _, err := service.AuthenticateToken(ctx, token.Token); err != nil {
				t.Fatal("rejected mode switch changed the original token")
			}
		})
	}
}

func TestIdentityBindingSerializesFirstUse(t *testing.T) {
	db, ctx := ownedIdentityDatabase(t)
	if err := db.RunMigrations("migrations.sql"); err != nil {
		t.Fatal(err)
	}
	first, second := *db, *db
	first.IdentityMode, second.IdentityMode = IdentityStandalone, IdentityPostgoose
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, candidate := range []*Database{&first, &second} {
		go func(d *Database) { <-start; results <- d.EnsureIdentityMode(ctx) }(candidate)
	}
	close(start)
	successes := 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("simultaneous binding had %d successes", successes)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM rabbit_identity_binding`).Scan(&count); err != nil || count != 1 {
		t.Fatal("binding is not unique")
	}
}

func TestIdentityBindingInfersLegacyRowsFailClosed(t *testing.T) {
	db, ctx := ownedIdentityDatabase(t)
	if err := db.RunMigrations("migrations.sql"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO team_tokens(team_id,token,name) VALUES('old-team','old-token','old')`); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureIdentityMode(ctx); err == nil {
		t.Fatal("existing token rows bound to standalone")
	}
	var bound string
	if err := db.DB.QueryRowContext(ctx, `SELECT mode FROM rabbit_identity_binding WHERE singleton`).Scan(&bound); err != nil || bound != IdentityPostgoose {
		t.Fatal("legacy rows were not durably bound")
	}
	db.IdentityMode = IdentityPostgoose
	if err := db.EnsureIdentityMode(ctx); err != nil {
		t.Fatal(err)
	}
}
