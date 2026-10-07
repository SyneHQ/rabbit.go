package server

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"rabbit.go/internal/database"
)

type canceledQueryDriver struct{}
type canceledQueryConn struct{}

func (canceledQueryDriver) Open(string) (driver.Conn, error)  { return canceledQueryConn{}, nil }
func (canceledQueryConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (canceledQueryConn) Close() error                        { return nil }
func (canceledQueryConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (canceledQueryConn) QueryContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(time.Second):
		return nil, errors.New("request cancellation did not reach metadata query")
	}
}

func init() { sql.Register("rabbit-canceled-query-test", canceledQueryDriver{}) }

func TestMetadataHandlerPreservesRequestCancellation(t *testing.T) {
	db, err := sql.Open("rabbit-canceled-query-test", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	api := &APIServer{dbService: database.NewService(&database.Database{DB: db})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest("GET", "/api/v1/teams/team/tokens", nil).WithContext(ctx)
	started := time.Now()
	api.getTeamTokens(httptest.NewRecorder(), request)
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("canceled request kept its metadata query running for %s", elapsed)
	}
}

func TestManagementRequestHasBoundedMetadataBudget(t *testing.T) {
	handler := metadataRequestDeadline(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > metadataTimeout {
			t.Fatal("management authorization has no bounded budget")
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/health", nil))
}

func TestManagementIPv6Address(t *testing.T) {
	api := NewAPIServer(nil, "::1", "8080", "9999")
	if api.server.Addr != "[::1]:8080" {
		t.Fatalf("invalid IPv6 API address: %q", api.server.Addr)
	}
}

func TestManagementBindFailureFailsServerStart(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("RABBIT_TLS_CERT_PEM", "")
	t.Setenv("RABBIT_TLS_KEY_PEM", "")
	t.Setenv("RABBIT_TLS_CERT_FILE", "")
	t.Setenv("RABBIT_TLS_KEY_FILE", "")
	t.Setenv("RABBIT_ALLOW_INSECURE_LOCAL", "true")
	t.Setenv("ENVIRONMENT", "test")
	s := &Server{config: Config{BindAddress: "127.0.0.1", ControlPort: "0"},
		stopChan: make(chan struct{}), apiServer: &APIServer{server: &http.Server{Addr: listener.Addr().String()}}}
	if err := s.Start(); err == nil {
		t.Fatal("Start succeeded with an occupied management port")
	}
	if !s.stopped {
		t.Fatal("failed startup did not close its resources")
	}
	if s.controlListener != nil {
		if conn, err := net.DialTimeout("tcp", s.controlListener.Addr().String(), time.Second); err == nil {
			conn.Close()
			t.Fatal("failed API startup left the control listener open")
		}
	}
}
