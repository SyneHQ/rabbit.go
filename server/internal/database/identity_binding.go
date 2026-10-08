package database

import (
	"context"
	"database/sql"
	"fmt"
)

// EnsureIdentityMode binds shared token tables to one authority. There is no automatic mode migration.
func (d *Database) EnsureIdentityMode(ctx context.Context) error {
	requested, err := normalizeIdentityMode(d.IdentityMode)
	if err != nil {
		return err
	}
	var bound string
	err = d.DB.QueryRowContext(ctx, `SELECT mode FROM rabbit_identity_binding WHERE singleton=true`).Scan(&bound)
	if err == nil {
		return checkIdentityBinding(bound, requested)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("identity binding is unavailable. Apply the Rabbit metadata migration: %w", err)
	}
	tx, err := d.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A table lock also serializes the first insert when no binding row exists.
	if _, err := tx.ExecContext(ctx, `LOCK TABLE rabbit_identity_binding IN EXCLUSIVE MODE`); err != nil {
		return err
	}
	err = tx.QueryRowContext(ctx, `SELECT mode FROM rabbit_identity_binding WHERE singleton=true`).Scan(&bound)
	if err == sql.ErrNoRows {
		var legacy bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_tokens) OR EXISTS(SELECT 1 FROM port_assignments) OR EXISTS(SELECT 1 FROM connection_sessions) OR EXISTS(SELECT 1 FROM connection_logs)`).Scan(&legacy); err != nil {
			return err
		}
		bound = requested
		if legacy {
			bound = IdentityPostgoose
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO rabbit_identity_binding(singleton,mode) VALUES(true,$1)`, bound); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return checkIdentityBinding(bound, requested)
}

func checkIdentityBinding(bound, requested string) error {
	if bound != requested {
		return fmt.Errorf("metadata is bound to %s identity mode. Use separate metadata for %s", bound, requested)
	}
	return nil
}
