//go:build linux

package server

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lib/pq"
)

func nativePrivatePostgres(t *testing.T, f *nativePrivateFixture, dialer *nativePrivateDialer, caFile, application string) *sql.DB {
	t.Helper()
	fixture, err := url.Parse(f.h.fixtureDSN)
	if err != nil {
		t.Fatal(err)
	}
	dsn := &url.URL{Scheme: "postgres", Host: dialer.claims.Authority, User: url.User("postgres"), Path: fixture.Path}
	dsn.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {caFile}, "connect_timeout": {"5"}, "application_name": {application}, "default_transaction_read_only": {"on"}, "statement_timeout": {"25000"}}.Encode()
	connector, err := pq.NewConnector(dsn.String())
	if err != nil {
		t.Fatal("cannot configure native PostgreSQL connector")
	}
	connector.Dialer(dialer)
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

// Real PostgreSQL runs in the controller's Unix-socket-only container. The
// existing SSLRequest fixture relay is the source TLS endpoint. Its localhost
// identity is verified by lib/pq on both query and separate CancelRequest sockets.
func TestNativePrivateConnectPostgres(t *testing.T) {
	adminURL := os.Getenv("RABBIT_TRANSPORT_DATABASE_URL")
	if adminURL == "" || os.Getenv("RABBIT_DATABASE_CLIENT_TEST_BINARY") == "" || os.Getenv("RABBIT_TRANSPORT_REDIS_URL") == "" {
		t.Skip("requires native Rabbit client and owned PostgreSQL/Redis fixtures")
	}
	var accepted atomic.Int32
	relay, ca := newKelvoPostgresRelayObserved(t, adminURL, func() { accepted.Add(1) })
	f := newNativePrivateFixture(t, relay)
	caFile := filepath.Join(t.TempDir(), "postgres-source-ca.pem")
	if err := os.WriteFile(caFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err := f.h.fixture.ExecContext(ctx, `CREATE UNLOGGED TABLE private_connect_rows AS
 SELECT i::BIGINT AS id,(i%17)::INTEGER AS category,
 CASE WHEN i%13=0 THEN NULL ELSE 'row-'||i::TEXT END AS note FROM generate_series(1,100000) AS fixture(i)`); err != nil {
		t.Fatal(err)
	}

	t.Run("native CTE and exact rows", func(t *testing.T) {
		dialer := f.dialer()
		db := nativePrivatePostgres(t, f, dialer, caFile, "rabbit-private-rows")
		var count, sum int64
		var readOnly string
		if err := db.QueryRowContext(ctx, `WITH grouped AS (SELECT category,count(*) AS n,sum(id) AS s FROM private_connect_rows GROUP BY category)
 SELECT sum(n)::BIGINT,sum(s)::BIGINT,current_setting('transaction_read_only') FROM grouped`).Scan(&count, &sum, &readOnly); err != nil {
			t.Fatal(err)
		}
		if count != 100000 || sum != 5000050000 || readOnly != "on" {
			t.Fatal("native CTE changed data or read-only scope", count, sum, readOnly)
		}
		rows, err := db.QueryContext(ctx, `SELECT id,category,note FROM private_connect_rows ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var seen int64
		for rows.Next() {
			var id, category int64
			var note sql.NullString
			if err := rows.Scan(&id, &category, &note); err != nil {
				t.Fatal(err)
			}
			seen++
			if id != seen || category != id%17 || note.Valid != (id%13 != 0) || note.Valid && note.String != "row-"+strconv.FormatInt(id, 10) {
				t.Fatal("native result content changed", id)
			}
		}
		if rows.Err() != nil || seen != 100000 || dialer.opens.Load() != 1 {
			t.Fatal("native result incomplete or connection unexpectedly reopened", seen, rows.Err(), dialer.opens.Load())
		}
	})

	t.Run("wrong source and tenant never dial customer", func(t *testing.T) {
		for _, scope := range []string{"source", "tenant"} {
			dialer := f.dialer()
			if scope == "source" {
				dialer.claims.Source = "foreign-source"
			} else {
				dialer.claims.Tenant = "foreign-tenant"
			}
			before := accepted.Load()
			db := nativePrivatePostgres(t, f, dialer, caFile, "rabbit-private-denied")
			if err := db.PingContext(ctx); err == nil || accepted.Load() != before || dialer.opens.Load() != 0 {
				t.Fatal("denied source reached customer", scope, err)
			}
			db.Close()
		}
	})

	t.Run("native driver verifies original source hostname", func(t *testing.T) {
		dialer := f.dialer()
		dialer.claims.Authority = strings.Replace(dialer.claims.Authority, "localhost:", "wrong-source.invalid:", 1)
		db := nativePrivatePostgres(t, f, dialer, caFile, "rabbit-private-hostname")
		err := db.PingContext(ctx)
		if err == nil || !strings.Contains(err.Error(), "certificate") || dialer.opens.Load() != 1 {
			t.Fatal("native source TLS did not reject the wrong hostname", err)
		}
	})

	t.Run("separate TLS cancellation connection", func(t *testing.T) {
		dialer := f.dialer()
		db := nativePrivatePostgres(t, f, dialer, caFile, "rabbit-private-cancel")
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		var pid int
		if err := conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cancelNativeOwnedQuery(t, f.h.fixture, pid, "rabbit-private-cancel") })
		query, stop := context.WithCancel(ctx)
		defer stop()
		done := make(chan error, 1)
		go func() { _, err := conn.ExecContext(query, `SELECT pg_sleep(20)`); done <- err }()
		waitNativePostgresState(t, f.h.fixture, pid, true)
		before := dialer.opens.Load()
		stop()
		select {
		case err := <-done:
			var pgError *pq.Error
			if !errors.Is(err, context.Canceled) && !(errors.As(err, &pgError) && pgError.Code == "57014") {
				t.Fatal("native cancellation did not return the expected result", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("native cancellation did not finish within its budget")
		}
		if dialer.opens.Load() != before+1 {
			t.Fatal("CancelRequest did not use a separate one-use CONNECT", before, dialer.opens.Load())
		}
		waitNativePostgresState(t, f.h.fixture, pid, false)
	})

	t.Run("revocation closes active query and rejects reconnect", func(t *testing.T) {
		dialer := f.dialer()
		db := nativePrivatePostgres(t, f, dialer, caFile, "rabbit-private-revoked")
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		var pid int
		if err := conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cancelNativeOwnedQuery(t, f.h.fixture, pid, "rabbit-private-revoked") })
		done := make(chan error, 1)
		go func() { _, err := conn.ExecContext(ctx, `SELECT pg_sleep(20)`); done <- err }()
		waitNativePostgresState(t, f.h.fixture, pid, true)
		f.revoked.Store(true)
		defer f.revoked.Store(false)
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("revoked source query succeeded")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("revocation did not close the active native query")
		}
		// Socket revocation stops result delivery. PostgreSQL may continue a
		// non-I/O query until its next disconnect check; do not claim otherwise.
		before := accepted.Load()
		retry := nativePrivatePostgres(t, f, f.dialer(), caFile, "rabbit-private-retry")
		if err := retry.PingContext(ctx); err == nil || accepted.Load() != before {
			t.Fatal("revoked source reconnected to the customer", err)
		}
	})
}

func cancelNativeOwnedQuery(t *testing.T, db *sql.DB, pid int, application string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `SELECT pg_cancel_backend(pid) FROM pg_stat_activity
 WHERE pid=$1 AND application_name=$2 AND datname=current_database()`, pid, application); err != nil {
		t.Error("could not cancel owned native fixture query during cleanup", err)
	}
}

func waitNativePostgresState(t *testing.T, db *sql.DB, pid int, active bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		var running bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND state='active' AND query='SELECT pg_sleep(20)')`, pid).Scan(&running); err != nil {
			t.Fatal("cannot inspect owned query", err)
		}
		if running == active {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("owned PostgreSQL query did not reach its expected state")
		case <-time.After(20 * time.Millisecond):
		}
	}
}
