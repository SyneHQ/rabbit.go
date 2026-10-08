package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type cleanupConnector struct{ exec func(string) error }
type cleanupConn struct{ exec func(string) error }
type cleanupDriver struct{}

func (c cleanupConnector) Connect(context.Context) (driver.Conn, error) {
	return cleanupConn{c.exec}, nil
}
func (cleanupConnector) Driver() driver.Driver          { return cleanupDriver{} }
func (cleanupDriver) Open(string) (driver.Conn, error)  { return nil, errors.New("unused") }
func (cleanupConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (cleanupConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (cleanupConn) Close() error                        { return nil }
func (c cleanupConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if err := c.exec(query); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

type cleanupRedisFailure struct{ err error }

func (cleanupRedisFailure) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h cleanupRedisFailure) ProcessHook(redis.ProcessHook) redis.ProcessHook {
	return func(context.Context, redis.Cmder) error { return h.err }
}
func (h cleanupRedisFailure) ProcessPipelineHook(redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(context.Context, []redis.Cmder) error { return h.err }
}

func TestEndConnectionPreservesSessionAndLogErrors(t *testing.T) {
	sessionError, logError := errors.New("session update failed"), errors.New("log update failed")
	db := sql.OpenDB(cleanupConnector{exec: func(query string) error {
		if strings.Contains(query, "connection_sessions") {
			return sessionError
		}
		return logError
	}})
	defer db.Close()
	service := NewService(&Database{DB: db})
	for _, logID := range []uuid.UUID{uuid.Nil, uuid.New()} {
		err := service.EndConnection(context.Background(), uuid.New(), logID, "closed", nil)
		if !errors.Is(err, sessionError) {
			t.Fatalf("session failure was lost: %v", err)
		}
		if logID != uuid.Nil && !errors.Is(err, logError) {
			t.Fatalf("log failure was lost: %v", err)
		}
	}
}

func TestEndConnectionPreservesRedisCleanupFailure(t *testing.T) {
	redisError := errors.New("session key removal failed")
	var logCompleted bool
	db := sql.OpenDB(cleanupConnector{exec: func(query string) error {
		if strings.Contains(query, "connection_logs") {
			logCompleted = true
		}
		return nil
	}})
	defer db.Close()
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer rdb.Close()
	rdb.AddHook(cleanupRedisFailure{redisError})
	service := NewService(&Database{DB: db, Redis: rdb})
	err := service.EndConnection(context.Background(), uuid.New(), uuid.New(), "closed", nil)
	if !errors.Is(err, redisError) {
		t.Fatalf("Redis cleanup failure was lost: %v", err)
	}
	if !logCompleted {
		t.Fatal("Redis failure skipped independent log completion")
	}
}
