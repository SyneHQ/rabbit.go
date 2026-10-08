package database

import (
	"context"
	"fmt"
	"strings"
	"unicode"
)

const (
	IdentityStandalone = "standalone"
	IdentityPostgoose  = "postgoose"
)

func normalizeIdentityMode(mode string) (string, error) {
	if mode == "" {
		return IdentityPostgoose, nil
	}
	if mode != IdentityStandalone && mode != IdentityPostgoose {
		return "", fmt.Errorf("RABBIT_IDENTITY_MODE must be standalone or postgoose")
	}
	return mode, nil
}

// identityTeams returns a fixed projection. Compatibility mode never changes application tables.
func (d *Database) identityTeams() string {
	if d.IdentityMode != IdentityStandalone {
		return `(SELECT id::text AS id, name, COALESCE(description, '') AS description,
		"createdAt" AS created_at, "updatedAt" AS updated_at, NOT deleted AS is_active FROM public."Team")`
	}
	return `rabbit_teams`
}

func validIdentity(value string) bool {
	return len(value) > 0 && len(value) <= 255 && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

// BootstrapTeam creates a standalone team and its owner in one transaction.
// Existing identities cause an error. This method does not modify their permissions.
func (d *Database) BootstrapTeam(ctx context.Context, teamID, name, ownerID string) error {
	if d.IdentityMode != IdentityStandalone {
		return fmt.Errorf("bootstrap requires standalone identity mode")
	}
	if !validIdentity(teamID) || !validIdentity(ownerID) || !validIdentity(name) {
		return fmt.Errorf("team ID, name and owner ID must contain 1 to 255 characters without surrounding spaces or control characters")
	}
	if err := d.EnsureIdentityMode(ctx); err != nil {
		return err
	}
	tx, err := d.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO rabbit_teams(id,name) VALUES($1,$2)`, teamID, name); err != nil {
		return fmt.Errorf("create standalone team: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO rabbit_team_memberships(team_id,user_id,role) VALUES($1,$2,'OWNER')`, teamID, ownerID); err != nil {
		return fmt.Errorf("create standalone owner: %w", err)
	}
	return tx.Commit()
}

// ValidateIdentitySchema checks the selected authority without changing it.
func (d *Database) ValidateIdentitySchema(ctx context.Context) error {
	mode, err := normalizeIdentityMode(d.IdentityMode)
	if err != nil {
		return err
	}
	teams := `SELECT id,name,description,created_at,updated_at,is_active FROM ` + d.identityTeams() + ` t LIMIT 0`
	membership := `SELECT team_id,user_id,role,is_active FROM rabbit_team_memberships LIMIT 0`
	if mode == IdentityPostgoose {
		membership = `SELECT "teamId","userId",role,deleted FROM postgoose_user_teams LIMIT 0`
	}
	for _, query := range []string{teams, membership} {
		rows, err := d.DB.QueryContext(ctx, query)
		if err != nil {
			return fmt.Errorf("identity schema for %s is unavailable. Configure RABBIT_IDENTITY_MODE and apply its schema: %w", mode, err)
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return d.EnsureIdentityMode(ctx)
}
