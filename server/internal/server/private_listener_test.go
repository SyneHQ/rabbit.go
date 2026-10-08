package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type privateAcceptError struct{ temporary bool }

func (privateAcceptError) Error() string     { return "fixture accept error" }
func (privateAcceptError) Timeout() bool     { return false }
func (e privateAcceptError) Temporary() bool { return e.temporary }

type privateListenerFixture struct {
	net.Listener
	accept func() (net.Conn, error)
	done   chan struct{}
	once   sync.Once
}

func (l *privateListenerFixture) Accept() (net.Conn, error) { return l.accept() }
func (l *privateListenerFixture) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func TestPrivateListenerRecoversTemporaryAcceptErrors(t *testing.T) {
	l := &privateListenerFixture{done: make(chan struct{})}
	var attempts atomic.Int32
	recovered := make(chan struct{})
	l.accept = func() (net.Conn, error) {
		switch attempts.Add(1) {
		case 1, 2:
			return nil, privateAcceptError{temporary: true}
		case 3:
			server, peer := net.Pipe()
			peer.Close()
			return server, nil
		default:
			close(recovered)
			<-l.done
			return nil, net.ErrClosed
		}
	}
	s := &Server{stopChan: make(chan struct{}), private: &privateConnect{}, privateListener: l}
	s.wg.Add(1)
	go s.handlePrivateConnections()
	t.Cleanup(func() {
		if err := s.Stop(); err != nil {
			t.Error(err)
		}
	})
	select {
	case <-recovered:
	case <-time.After(time.Second):
		t.Fatal("temporary accept failure did not recover")
	}
	if attempts.Load() != 4 || !s.transportReady() || s.private.failed.Load() {
		t.Fatal("recovered listener marked unavailable")
	}
}

func TestPrivateListenerFailureWithdrawsReadinessAndJoins(t *testing.T) {
	for _, temporary := range []bool{false, true} {
		t.Run(map[bool]string{false: "fatal", true: "retry exhausted"}[temporary], func(t *testing.T) {
			l := &privateListenerFixture{done: make(chan struct{})}
			var attempts atomic.Int32
			l.accept = func() (net.Conn, error) {
				attempts.Add(1)
				return nil, privateAcceptError{temporary: temporary}
			}
			closed := make(chan struct{})
			s := &Server{stopChan: make(chan struct{}), privateListener: l,
				private: &privateConnect{close: func() { close(closed) }}}
			s.wg.Add(1)
			go s.handlePrivateConnections()
			select {
			case <-s.stopChan:
			case <-time.After(3 * time.Second):
				t.Fatal("failed private listener did not start shutdown")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := s.WaitShutdown(ctx)
			if err == nil || errors.Is(err, ErrShutdownIncomplete) || !strings.Contains(err.Error(), "private CONNECT listener failed") {
				t.Fatal("listener failure did not finish shutdown with its cause", err)
			}
			want := int32(1)
			if temporary {
				want = 9
			}
			if attempts.Load() != want || s.transportReady() || !s.private.failed.Load() {
				t.Fatal("failure did not withdraw readiness with bounded attempts", attempts.Load())
			}
			select {
			case <-closed:
			default:
				t.Fatal("shutdown reported complete before authority cleanup")
			}
			api := &APIServer{ready: s.transportReady}
			response := httptest.NewRecorder()
			api.healthCheck(response, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
			if response.Code != http.StatusServiceUnavailable {
				t.Fatal("health remained successful after private ingress failed", response.Code)
			}
		})
	}
}
