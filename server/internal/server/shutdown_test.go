package server

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"rabbit.go/internal/database"
)

type shutdownSQLDriver struct{ calls atomic.Int64 }
type shutdownSQLConn struct{ owner *shutdownSQLDriver }

var shutdownDriver shutdownSQLDriver

func init()                                                    { sql.Register("rabbit-shutdown-test", &shutdownDriver) }
func (d *shutdownSQLDriver) Open(string) (driver.Conn, error)  { return &shutdownSQLConn{d}, nil }
func (c *shutdownSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *shutdownSQLConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (c *shutdownSQLConn) Close() error                        { return nil }
func (c *shutdownSQLConn) ExecContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Result, error) {
	c.owner.calls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func shutdownServer() *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{ctx: ctx, cancel: cancel, stopChan: make(chan struct{}), tunnels: make(map[string]*Tunnel)}
}

func awaitShutdown(t *testing.T, s *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.WaitShutdown(ctx); errors.Is(err, ErrShutdownIncomplete) {
		t.Fatal("released teardown owner did not finish")
	}
}

func TestShutdownCleanCompletionIsStableForConcurrentCallers(t *testing.T) {
	for range 20 {
		s := shutdownServer()
		var closed atomic.Int64
		s.closeDatabase = func() error { closed.Add(1); return nil }
		start := make(chan struct{})
		results := make(chan error, 32)
		for range cap(results) {
			go func() { <-start; results <- s.Stop() }()
		}
		close(start)
		for range cap(results) {
			if err := <-results; err != nil {
				t.Fatalf("completed shutdown reported cancellation: %v", err)
			}
		}
		if err := s.Stop(); err != nil {
			t.Fatalf("repeat shutdown changed completion: %v", err)
		}
		if closed.Load() != 1 {
			t.Fatal("concurrent callers repeated pool closure")
		}
	}
}

func TestShutdownWaitCancellationDoesNotChangeSharedOutcome(t *testing.T) {
	s := shutdownServer()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	s.closeDatabase = func() error { close(entered); <-release; return nil }
	result := make(chan error, 1)
	go func() { result <- s.Stop() }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, wait := range []func(context.Context) error{s.Shutdown, s.WaitShutdown} {
		if err := wait(ctx); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrShutdownIncomplete) {
			t.Fatalf("canceled waiter lost pending outcome: %v", err)
		}
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-result; err != nil {
		t.Fatalf("caller cancellation poisoned shared cleanup: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("shared outcome changed after completion: %v", err)
	}
}

func TestShutdownUsesOneMetadataBudget(t *testing.T) {
	db, err := sql.Open("rabbit-shutdown-test", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := shutdownServer()
	s.dbService = database.NewService(&database.Database{DB: db})
	for range 12 {
		tunnel := &Tunnel{ID: uuid.NewString(), SessionID: uuid.NewString(), stopChan: make(chan struct{})}
		tunnel.initLifecycle(s)
		s.tunnels[tunnel.ID] = tunnel
	}
	before := shutdownDriver.calls.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = s.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing shared deadline: %v", err)
	}
	awaitShutdown(t, s)
	if time.Since(started) > time.Second {
		t.Fatal("each tunnel received a fresh metadata timeout")
	}
	if got := shutdownDriver.calls.Load() - before; got != 1 {
		t.Fatalf("expired cleanup started %d metadata calls", got)
	}
	if err := s.Stop(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("later Stop hid cleanup failure: %v", err)
	}
	if len(s.tunnels) != 0 || len(s.closingTunnels) != 0 {
		t.Fatal("joined shutdown retained tunnel custody")
	}
}

func TestShutdownRetainsReconnectCustodyAfterDeadline(t *testing.T) {
	s := shutdownServer()
	owner, peer := net.Pipe()
	defer peer.Close()
	tunnel := &Tunnel{ID: "held", Client: owner, stopChan: make(chan struct{})}
	tunnel.initLifecycle(s)
	s.tunnels[tunnel.ID] = tunnel
	var closed atomic.Int64
	s.closeDatabase = func() error { closed.Add(1); return nil }
	entered, canceled, release, metadataDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	go func() {
		defer close(metadataDone)
		_ = s.withActiveTunnelMetadata(tunnel, owner, func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
			return ctx.Err()
		})
	}()
	<-entered
	// A disconnect can remove the active map entry before server shutdown.
	tunnelStopDone := make(chan struct{})
	go func() { _ = s.stopTunnel(tunnel); close(tunnelStopDone) }()
	<-canceled
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("unjoined metadata reported complete: %v", err)
	}
	<-canceled
	if closed.Load() != 0 {
		t.Fatal("metadata pool closed while reconnect still owned it")
	}
	if _, err := peer.Write([]byte("late")); err == nil {
		t.Fatal("deadline left tunnel admission open")
	}
	s.mu.RLock()
	_, retained := s.closingTunnels[tunnel]
	s.mu.RUnlock()
	if !retained {
		t.Fatal("unjoined tunnel lost cleanup custody")
	}
	done := s.shutdownDone
	for range 4 {
		if err := s.Stop(); !errors.Is(err, ErrShutdownIncomplete) {
			t.Fatalf("repeat Stop hid pending cleanup: %v", err)
		}
		if s.shutdownDone != done {
			t.Fatal("repeat Stop replaced teardown owner")
		}
	}
	releaseOnce.Do(func() { close(release) })
	<-metadataDone
	<-tunnelStopDone
	awaitShutdown(t, s)
	if closed.Load() != 1 {
		t.Fatal("released metadata pool did not close exactly once")
	}
	if err := s.Stop(); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("late completion lost timeout outcome: %v", err)
	}
}

func TestShutdownCancelsAndJoinsManagementHandlers(t *testing.T) {
	s := shutdownServer()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	api := &APIServer{server: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-release
		_, _ = io.WriteString(w, "done")
	})}}
	api.prepare(s.ctx)
	s.apiServer = api
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); _ = api.server.Serve(listener) }()
	var closed atomic.Int64
	s.closeDatabase = func() error { closed.Add(1); return nil }
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		client := &http.Client{Timeout: time.Second}
		if response, err := client.Get("http://" + listener.Addr().String()); err == nil {
			response.Body.Close()
		}
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("running handler reported complete: %v", err)
	}
	<-canceled
	if closed.Load() != 0 {
		t.Fatal("pool closed before HTTP handler returned")
	}
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("management listener survived shutdown")
	}
	releaseOnce.Do(func() { close(release) })
	awaitShutdown(t, s)
	<-requestDone
	if closed.Load() != 1 {
		t.Fatal("handler completion did not release pool custody")
	}
}

func TestShutdownRetainsAuditWriterAndPoolErrors(t *testing.T) {
	s := shutdownServer()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	s.streamAudit = newStreamAuditQueue(1, time.Minute, time.Minute, func(context.Context, database.ConnectionLog) error { close(entered); <-release; return nil })
	s.streamAudit.submit(database.ConnectionLog{})
	<-entered
	poolError := errors.New("pool cleanup failed")
	var closed atomic.Int64
	s.closeDatabase = func() error { closed.Add(1); return poolError }
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("unjoined audit reported complete: %v", err)
	}
	if closed.Load() != 0 {
		t.Fatal("pool closed under a live audit writer")
	}
	releaseOnce.Do(func() { close(release) })
	awaitShutdown(t, s)
	if err := s.Stop(); !errors.Is(err, poolError) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cleanup errors were discarded: %v", err)
	}
	if closed.Load() != 1 {
		t.Fatal("pool cleanup ran more than once")
	}
}
