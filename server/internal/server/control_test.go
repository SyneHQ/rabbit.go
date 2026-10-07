package server

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"rabbit.go/internal/database"
	"rabbit.go/internal/middleware"
)

func TestControlWriteTimeoutAndDeadlineReset(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	started := time.Now()
	err := writeControlFrameTimeout(server, 25*time.Millisecond, "PING\n")
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("blocked control write did not time out: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("control write exceeded its bound")
	}
	read := make(chan error, 1)
	go func() {
		b := make([]byte, 5)
		_, err := io.ReadFull(peer, b)
		if err == nil && string(b) != "PONG\n" {
			err = io.ErrUnexpectedEOF
		}
		read <- err
	}()
	if _, err := server.Write([]byte("PONG\n")); err != nil {
		t.Fatalf("timed-out control write left stale deadline: %v", err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
}

func TestReconnectPreservesBufferedPingAndDisconnect(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	tunnel := &Tunnel{ID: "reconnect", RemotePort: "5432", stopChan: make(chan struct{})}
	s := &Server{tunnels: map[string]*Tunnel{tunnel.ID: tunnel}}
	// The frame was already read by the authentication parser.
	reader := bufio.NewReader(io.MultiReader(strings.NewReader("PING\n"), conn))
	finished := make(chan struct{})
	go func() {
		s.reconnectClientToTunnel(tunnel, conn, reader, &database.TeamToken{TeamID: "team"}, "5432")
		close(finished)
	}()
	peer.SetDeadline(time.Now().Add(time.Second))
	responses := bufio.NewReader(peer)
	for _, want := range []string{"SUCCESS:reconnect:5432\n", "PONG\n"} {
		got, err := responses.ReadString('\n')
		if err != nil || got != want {
			t.Fatalf("reconnect response: got %q %v, want %q", got, err, want)
		}
	}
	if _, err := io.WriteString(peer, "DISCONNECT\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("reconnected control handler did not stop")
	}
	if len(s.tunnels) != 0 || tunnel.Client != nil {
		t.Fatal("disconnect left the tunnel registered")
	}
}

func TestReplacedControlCannotDisconnectSuccessor(t *testing.T) {
	old, oldPeer := net.Pipe()
	defer oldPeer.Close()
	current, currentPeer := net.Pipe()
	defer current.Close()
	defer currentPeer.Close()
	tunnel := &Tunnel{Client: current, stopChan: make(chan struct{})}
	s := &Server{}
	s.monitorControlConnection(tunnel, old, bufio.NewReader(strings.NewReader("DISCONNECT\n")))
	select {
	case <-tunnel.stopChan:
		t.Fatal("old control socket stopped replacement")
	default:
	}
	if tunnel.Client != current {
		t.Fatal("old control socket cleared replacement")
	}
}

func TestStopClosesUnclassifiedConnectionsAndIsIdempotent(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sm := middleware.NewSecurityMiddleware(middleware.DefaultSecurityConfig())
	s := &Server{
		controlListener:    listener,
		securityMiddleware: sm,
		stopChan:           make(chan struct{}),
		connections:        make(map[net.Conn]struct{}),
		tunnels:            make(map[string]*Tunnel),
	}
	defer s.Stop()
	s.wg.Add(1)
	go s.handleControlConnections()
	peer, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.RLock()
		accepted := len(s.connections) == 1
		s.mu.RUnlock()
		if accepted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("connection was not registered")
		}
		time.Sleep(time.Millisecond)
	}
	finished := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() { defer wg.Done(); s.Stop() }()
		}
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for the pre-authentication handshake timeout")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("unclassified socket survived shutdown: %v", err)
	}
	if len(s.connections) != 0 || sm.GetStats()["global_connections"] != 0 {
		t.Fatal("shutdown leaked accepted connection accounting")
	}
}

func TestDatabaseIngressBindIsIndependent(t *testing.T) {
	s := &Server{config: Config{BindAddress: "0.0.0.0"}}
	if got := s.tunnelBindAddress(); got != "127.0.0.1" {
		t.Fatalf("database ingress inherited public control bind: %q", got)
	}
	s.config.TunnelBindAddress = "10.20.0.3"
	if got := s.tunnelBindAddress(); got != "10.20.0.3" {
		t.Fatalf("explicit private bind ignored: %q", got)
	}
}

func TestMetadataContextIsBoundedAndCanceledOnShutdown(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	s := &Server{ctx: parent}
	ctx, cancel := s.metadataContext()
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > metadataTimeout {
		t.Fatal("metadata work has no bounded deadline")
	}
	stop()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("metadata did not inherit shutdown cancellation")
	}
}

func TestStopClosesOwnedMetadataOnce(t *testing.T) {
	closed := 0
	s := &Server{
		stopChan:      make(chan struct{}),
		closeDatabase: func() error { closed++; return nil },
	}
	s.Stop()
	s.Stop()
	if closed != 1 {
		t.Fatalf("owned database closed %d times", closed)
	}
}

func TestStartFailureClosesOwnedResources(t *testing.T) {
	t.Setenv("RABBIT_TLS_CERT_PEM", "invalid certificate")
	t.Setenv("RABBIT_TLS_KEY_PEM", "invalid key")
	closed := false
	s := &Server{
		config:        Config{BindAddress: "127.0.0.1", ControlPort: "0"},
		stopChan:      make(chan struct{}),
		closeDatabase: func() error { closed = true; return nil },
	}
	if err := s.Start(); err == nil {
		t.Fatal("invalid TLS configuration started a listener")
	}
	if !closed {
		t.Fatal("listener startup failure leaked the owned database")
	}
}

func TestPrivateIngressDefaultsAndValidation(t *testing.T) {
	config, err := normalizeBindAddresses(Config{BindAddress: "0.0.0.0"})
	if err != nil || config.APIBindAddress != "127.0.0.1" || config.TunnelBindAddress != "127.0.0.1" {
		t.Fatalf("private ingress inherited public control bind: %+v %v", config, err)
	}
	for _, invalid := range []Config{{APIBindAddress: "localhost"}, {TunnelBindAddress: "example.com"}} {
		if _, err := normalizeBindAddresses(invalid); err == nil {
			t.Fatal("nonliteral private bind accepted")
		}
	}
}
