package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTransportAuthorityIsReadOnlyAndTracksRevocation(t *testing.T) {
	db, ctx := allocatorFixture(t)
	service := NewService(db)
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	token, port, err := service.GenerateTokenForTeam(ctx, "allocator", "transport", "", &expires)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		until, err := service.CheckTransportAuthority(ctx, token.TeamID, token.Token, token.ID, port.ID)
		if err != nil || !until.Equal(expires) {
			t.Fatal("active token lost its exact expiry", err)
		}
	}
	var used sql.NullTime
	if err := db.DB.QueryRowContext(ctx, `SELECT last_used_at FROM team_tokens WHERE id=$1`, token.ID).Scan(&used); err != nil || used.Valid {
		t.Fatal("renewal mutated token usage metadata", err)
	}
	for name, check := range map[string]func() error{
		"foreign tenant": func() error {
			_, err := service.CheckTransportAuthority(ctx, "other", token.Token, token.ID, port.ID)
			return err
		},
		"rotated secret": func() error {
			_, err := service.CheckTransportAuthority(ctx, token.TeamID, "other", token.ID, port.ID)
			return err
		},
		"foreign token": func() error {
			_, err := service.CheckTransportAuthority(ctx, token.TeamID, token.Token, uuid.New(), port.ID)
			return err
		},
		"foreign port": func() error {
			_, err := service.CheckTransportAuthority(ctx, token.TeamID, token.Token, token.ID, uuid.New())
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if check() == nil {
				t.Fatal("foreign authority accepted")
			}
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.CheckTransportAuthority(cancelled, token.TeamID, token.Token, token.ID, port.ID); err == nil {
		t.Fatal("renewal ignored cancellation")
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE team_tokens SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1`, token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckTransportAuthority(ctx, token.TeamID, token.Token, token.ID, port.ID); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE team_tokens SET expires_at=NULL WHERE id=$1`, token.ID); err != nil {
		t.Fatal(err)
	}
	if until, err := service.CheckTransportAuthority(ctx, token.TeamID, token.Token, token.ID, port.ID); err != nil || !until.IsZero() {
		t.Fatal("unexpired token rejected", err)
	}
	if _, err := service.DeleteTunnelForTeam(ctx, token.TeamID, token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckTransportAuthority(ctx, token.TeamID, token.Token, token.ID, port.ID); err == nil {
		t.Fatal("revoked token accepted")
	}
}
