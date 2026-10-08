package database

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStreamAccountingPreservesTunnelSession(t *testing.T) {
	dsn := os.Getenv("SECURITY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, query := range []string{
		`CREATE TEMP TABLE connection_sessions(id uuid PRIMARY KEY,status text,last_seen_at timestamptz)`,
		`CREATE TEMP TABLE connection_logs(
			id uuid PRIMARY KEY, team_id text, token_id uuid, port_assign_id uuid,
			session_id uuid REFERENCES connection_sessions(id), client_ip text,
			client_port integer, server_port integer, protocol text,
			started_at timestamptz, ended_at timestamptz, bytes_received bigint,
			bytes_sent bigint, connection_time_ms bigint, status text,
			error_message text, user_agent text, request_path text)`,
	} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	session, other := uuid.New(), uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO connection_sessions VALUES ($1,'active',NOW()),($2,'active',NOW())`, session, other); err != nil {
		t.Fatal(err)
	}
	// No Redis client is configured: stream bookkeeping must not create a session.
	service := NewService(&Database{DB: db})
	log, err := service.StartStream(ctx, "team", uuid.New(), uuid.New(), session, "127.0.0.1", 4242, 5432, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if log.SessionID != session || log.ClientPort != 4242 {
		t.Fatalf("stream lost its parent or client port: %+v", log)
	}
	for range 2 {
		if err := service.EndStream(ctx, log.ID, 123, 456, "closed", nil); err != nil {
			t.Fatal(err)
		}
	}
	var sessions, active int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*),COUNT(*) FILTER (WHERE status='active') FROM connection_sessions`).Scan(&sessions, &active); err != nil {
		t.Fatal(err)
	}
	if sessions != 2 || active != 2 {
		t.Fatalf("stream completion created or closed a tunnel session: total=%d active=%d", sessions, active)
	}
	var received, sent int64
	var status string
	var ended bool
	if err := db.QueryRowContext(ctx, `SELECT bytes_received,bytes_sent,status,ended_at IS NOT NULL FROM connection_logs WHERE id=$1`, log.ID).Scan(&received, &sent, &status, &ended); err != nil {
		t.Fatal(err)
	}
	if received != 123 || sent != 456 || status != "closed" || !ended {
		t.Fatalf("incorrect or duplicated final accounting: %d %d %q %v", received, sent, status, ended)
	}
	// API revocation closes logs before active relays finish reporting bytes.
	revoked, err := service.StartStream(ctx, "team", uuid.New(), uuid.New(), session, "127.0.0.1", 4343, 5432, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := db.ExecContext(ctx, `UPDATE connection_logs SET ended_at=$2,status='closed',error_message='revoked' WHERE id=$1`, revoked.ID, revokedAt); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		message := "relay interrupted"
		if err := service.EndStream(ctx, revoked.ID, 987, 654, "error", &message); err != nil {
			t.Fatal(err)
		}
	}
	var endedAt time.Time
	var message string
	if err := db.QueryRowContext(ctx, `SELECT bytes_received,bytes_sent,status,ended_at,error_message FROM connection_logs WHERE id=$1`, revoked.ID).Scan(&received, &sent, &status, &endedAt, &message); err != nil {
		t.Fatal(err)
	}
	if received != 987 || sent != 654 || status != "closed" || !endedAt.Equal(revokedAt) || message != "revoked" {
		t.Fatalf("late relay completion lost counters or replaced revocation outcome: %d %d %q %v %q", received, sent, status, endedAt, message)
	}
	canceled, cancelQuery := context.WithCancel(context.Background())
	cancelQuery()
	if _, err := service.StartStream(canceled, "team", uuid.New(), uuid.New(), session, "127.0.0.1", 4242, 5432, "tcp"); err == nil {
		t.Fatal("stream setup ignored cancellation")
	}
}

func TestCompletedAuditCannotReactivateRevokedSession(t *testing.T) {
	dsn := os.Getenv("SECURITY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, query := range []string{
		`CREATE TEMP TABLE connection_sessions(id uuid PRIMARY KEY,status text,last_seen_at timestamptz)`,
		`CREATE TEMP TABLE connection_logs(id uuid PRIMARY KEY,team_id text,token_id uuid,port_assign_id uuid,session_id uuid,client_ip text,client_port integer,server_port integer,protocol text,started_at timestamptz,ended_at timestamptz,bytes_received bigint,bytes_sent bigint,connection_time_ms bigint,status text,error_message text)`,
	} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	session := uuid.New()
	ended := time.Now().UTC().Truncate(time.Microsecond)
	started := ended.Add(-time.Second)
	if _, err := db.ExecContext(ctx, `INSERT INTO connection_sessions VALUES($1,'inactive',$2)`, session, started); err != nil {
		t.Fatal(err)
	}
	service := NewService(&Database{DB: db})
	record := ConnectionLog{ID: uuid.New(), TeamID: "team", TokenID: uuid.New(), PortAssignID: uuid.New(), SessionID: session, ClientIP: "127.0.0.1", ClientPort: 4242, ServerPort: 5432, Protocol: "tcp", StartedAt: started, EndedAt: &ended, BytesReceived: 12, BytesSent: 34, Status: "closed"}
	for range 2 {
		if err := service.RecordCompletedStream(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	var active int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM connection_sessions WHERE status='active'`).Scan(&active); err != nil || active != 0 {
		t.Fatal("late audit reactivated a session")
	}
	var count int
	var received, sent int64
	var actualStart, actualEnd time.Time
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*),SUM(bytes_received),SUM(bytes_sent),MIN(started_at),MAX(ended_at) FROM connection_logs WHERE status='closed'`).Scan(&count, &received, &sent, &actualStart, &actualEnd); err != nil || count != 1 || received != 12 || sent != 34 || !actualStart.Equal(started) || !actualEnd.Equal(ended) {
		t.Fatalf("completed audit changed values: count=%d bytes=%d/%d error=%v", count, received, sent, err)
	}
	record.ID = uuid.New()
	record.Status = "active"
	if err := service.RecordCompletedStream(ctx, record); err == nil {
		t.Fatal("active audit record accepted")
	}
}
