package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type deadlineProbe struct {
	net.Conn
	mu                        sync.Mutex
	readAt, writeAt           time.Time
	readUpdates, writeUpdates int
	reads, writes             int
	setError                  error
}

func (p *deadlineProbe) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readAt = t
	p.readUpdates++
	return p.setError
}

func (p *deadlineProbe) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writeAt = t
	p.writeUpdates++
	return p.setError
}

func (p *deadlineProbe) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readAt, p.writeAt = t, t
	p.readUpdates++
	p.writeUpdates++
	return p.setError
}

func (p *deadlineProbe) Read(b []byte) (int, error) {
	p.mu.Lock()
	p.reads++
	p.mu.Unlock()
	return len(b), nil
}

func (p *deadlineProbe) Write(b []byte) (int, error) {
	p.mu.Lock()
	p.writes++
	p.mu.Unlock()
	return len(b), nil
}

func TestContinuousTrafficCoalescesWithinExactIdleBounds(t *testing.T) {
	for _, idle := range []time.Duration{time.Millisecond, time.Second, 30 * time.Minute} {
		t.Run(idle.String(), func(t *testing.T) {
			probe := &deadlineProbe{}
			sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: idle}}
			conn := sm.WrapConnection(probe).(*secureConnection)
			slack := min(idle/16, time.Second)
			start := time.Now()
			for i := range 1001 {
				now := start.Add(time.Duration(i) * slack / 10)
				if err := conn.applyReadDeadline(now, false); err != nil {
					t.Fatal(err)
				}
				if err := conn.applyWriteDeadline(now, false); err != nil {
					t.Fatal(err)
				}
				for _, actual := range []time.Time{probe.readAt, probe.writeAt} {
					if actual.Before(now.Add(idle)) || actual.After(now.Add(idle+slack)) {
						t.Fatalf("idle deadline outside allowed window at step %d: %s", i, actual.Sub(now))
					}
				}
			}
			if probe.readUpdates > 101 || probe.writeUpdates > 101 {
				t.Fatalf("continuous traffic refreshed too often: reads=%d writes=%d", probe.readUpdates, probe.writeUpdates)
			}
		})
	}
}

func TestExplicitDeadlinesAreImmediateAndNeverExtended(t *testing.T) {
	probe := &deadlineProbe{}
	sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: time.Hour}}
	conn := sm.WrapConnection(probe)
	explicit := time.Now().Add(time.Minute)
	if err := conn.SetDeadline(explicit); err != nil {
		t.Fatal(err)
	}
	if !probe.readAt.Equal(explicit) || !probe.writeAt.Equal(explicit) {
		t.Fatal("explicit deadline was not immediately applied in both directions")
	}
	for range 1000 {
		_, _ = conn.Read(make([]byte, 1))
		_, _ = conn.Write([]byte{1})
	}
	if probe.readUpdates != 1 || probe.writeUpdates != 1 || !probe.readAt.Equal(explicit) || !probe.writeAt.Equal(explicit) {
		t.Fatal("activity changed or repeatedly reapplied an exact explicit deadline")
	}
	past := time.Now().Add(-time.Second)
	if err := conn.SetWriteDeadline(past); err != nil || !probe.writeAt.Equal(past) || !probe.readAt.Equal(explicit) {
		t.Fatal("direction-specific deadline did not preserve the independent reader deadline")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil || !probe.readAt.After(explicit) || !probe.writeAt.After(explicit) {
		t.Fatal("clearing explicit deadline failed to restore idle bounds")
	}
}

func TestIdleReadExpiresWithoutEarlyTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	idle := 40 * time.Millisecond
	sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: idle}}
	conn := sm.WrapConnection(a)
	start := time.Now()
	_, err := conn.Read(make([]byte, 1))
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("idle read did not time out: %v", err)
	}
	if elapsed := time.Since(start); elapsed < idle || elapsed > time.Second {
		t.Fatalf("idle read expired outside bounded wait: %s", elapsed)
	}
}

func TestConcurrentExplicitDeadlineInterruptsAndCanBeCleared(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: time.Hour}}
	conn := sm.WrapConnection(a)
	finished := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); finished <- err }()
	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("explicit deadline did not interrupt reader: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader ignored explicit deadline")
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() { _, err := b.Write([]byte("x")); finished <- err }()
	data := make([]byte, 1)
	if _, err := io.ReadFull(conn, data); err != nil || string(data) != "x" {
		t.Fatalf("cleared deadline did not preserve bytes: %q %v", data, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestDeadlineFailurePreventsUnderlyingIO(t *testing.T) {
	failure := errors.New("deadline unavailable")
	probe := &deadlineProbe{setError: failure}
	sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: time.Minute}}
	conn := sm.WrapConnection(probe)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, failure) {
		t.Fatal("read hid deadline failure")
	}
	if _, err := conn.Write([]byte{1}); !errors.Is(err, failure) {
		t.Fatal("write hid deadline failure")
	}
	if probe.reads != 0 || probe.writes != 0 {
		t.Fatal("failed deadline allowed unbounded I/O")
	}
}

func TestConcurrentIOAndDeadlineSetters(t *testing.T) {
	probe := &deadlineProbe{}
	sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: time.Minute}}
	conn := sm.WrapConnection(probe)
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 1000 {
				_, _ = conn.Read(make([]byte, 1))
				_, _ = conn.Write([]byte{1})
			}
		})
	}
	workers.Go(func() {
		for range 1000 {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_ = conn.SetDeadline(time.Time{})
		}
	})
	workers.Wait()
}

type countedWriteConn struct {
	net.Conn
	writes int
}

func (c *countedWriteConn) Write(b []byte) (int, error) {
	c.writes++
	return c.Conn.Write(b)
}

func TestTLSWriteTimeoutRemainsFatalWithoutRetry(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := certServer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	certServer.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	server := tls.Server(a, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true})
	client := tls.Client(b, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"})
	handshake := make(chan error, 1)
	go func() { handshake <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	_ = a.SetDeadline(time.Time{})
	_ = b.SetDeadline(time.Time{})
	counted := &countedWriteConn{Conn: client}
	sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: time.Second}}
	conn := sm.WrapConnection(counted)
	if err := conn.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, first := conn.Write(make([]byte, 65536))
	if timeout, ok := first.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected TLS write timeout: %v", first)
	}
	if counted.writes != 1 {
		t.Fatal("wrapper retried a timed-out TLS write")
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	_, second := conn.Write([]byte("must not be replayed"))
	if timeout, ok := second.(net.Error); !ok || !timeout.Timeout() || counted.writes != 2 {
		t.Fatalf("clearing deadline hid or retried fatal TLS state: %v", second)
	}
}
