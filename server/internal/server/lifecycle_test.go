package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestFailedRegistrationCannotStopReplacement(t *testing.T) {
	old, oldPeer := net.Pipe()
	defer old.Close()
	defer oldPeer.Close()
	current, currentPeer := net.Pipe()
	defer current.Close()
	defer currentPeer.Close()
	tunnel := &Tunnel{ID: "tunnel", Client: current, stopChan: make(chan struct{})}
	s := &Server{tunnels: map[string]*Tunnel{tunnel.ID: tunnel}}
	// Initial SUCCESS failed, then reconnect published a successor before cleanup.
	s.stopControlOwner(tunnel, old)
	if tunnel.Client != current || s.tunnels[tunnel.ID] != tunnel {
		t.Fatal("stale registration failure removed its successor")
	}
	select {
	case <-tunnel.stopChan:
		t.Fatal("stale registration failure stopped successor")
	default:
	}
	s.stopControlOwner(tunnel, current)
	select {
	case <-tunnel.stopChan:
	default:
		t.Fatal("current control owner could not stop its tunnel")
	}
}

func TestLateDataCapabilityRejectsRevokedAndReplacedOwners(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "replaced", true: "revoked"}[revoke], func(t *testing.T) {
			owner, ownerPeer := net.Pipe()
			defer owner.Close()
			defer ownerPeer.Close()
			tunnel := &Tunnel{ID: "t", Client: owner, stopChan: make(chan struct{})}
			ready := make(chan net.Conn, 1)
			s := &Server{tunnels: map[string]*Tunnel{"t": tunnel}, pendingConns: map[string]*pendingConnection{
				"capability": {tunnel: tunnel, owner: owner, ready: ready},
			}}
			if revoke {
				s.stopTunnel(tunnel)
			} else {
				current, peer := net.Pipe()
				defer current.Close()
				defer peer.Close()
				tunnel.Client = current
			}
			data, peer := net.Pipe()
			defer data.Close()
			defer peer.Close()
			s.handleDataConnection(data, "DATA:capability")
			if len(ready) != 0 {
				t.Fatal("late data socket was paired to a stopped or replaced owner")
			}
			peer.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := peer.Write([]byte("late payload")); err == nil {
				t.Fatal("rejected data socket remained writable")
			}
		})
	}
}

func TestRelayAdmissionRechecksRevocationAfterPairing(t *testing.T) {
	owner, ownerPeer := net.Pipe()
	defer owner.Close()
	defer ownerPeer.Close()
	tunnel := &Tunnel{ID: "t", Client: owner, stopChan: make(chan struct{})}
	ready := make(chan net.Conn, 1)
	s := &Server{tunnels: map[string]*Tunnel{"t": tunnel}, pendingConns: map[string]*pendingConnection{
		"capability": {tunnel: tunnel, owner: owner, ready: ready},
	}}
	data, dataPeer := net.Pipe()
	defer data.Close()
	defer dataPeer.Close()
	external, externalPeer := net.Pipe()
	defer external.Close()
	defer externalPeer.Close()
	s.handleDataConnection(data, "DATA:capability")
	paired := <-ready
	// Stop wins after DATA pairing but before the selected handler starts copying.
	s.stopTunnel(tunnel)
	if _, ok := s.beginTunnelStream(tunnel, owner, external, paired); ok {
		t.Fatal("revoked pair was admitted to the relay")
	}
}

func TestRevocationClosesAdmittedSocketsSynchronously(t *testing.T) {
	owner, peer := net.Pipe()
	defer owner.Close()
	defer peer.Close()
	tunnel := &Tunnel{ID: "t", Client: owner, stopChan: make(chan struct{})}
	s := &Server{tunnels: map[string]*Tunnel{"t": tunnel}}
	external, externalPeer := net.Pipe()
	defer external.Close()
	defer externalPeer.Close()
	data, dataPeer := net.Pipe()
	defer data.Close()
	defer dataPeer.Close()
	stream, ok := s.beginTunnelStream(tunnel, owner, external, data)
	if !ok {
		t.Fatal("live pair rejected")
	}
	defer s.endTunnelStream(tunnel, stream)
	// No bridge watcher has started: Stop itself must close admitted sockets.
	s.stopTunnel(tunnel)
	for _, conn := range []net.Conn{externalPeer, dataPeer} {
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte("late")); err == nil {
			t.Fatal("revocation left an admitted socket writable")
		}
	}
}

func TestShutdownFencesReconnectMetadata(t *testing.T) {
	owner, peer := net.Pipe()
	defer owner.Close()
	defer peer.Close()
	tunnel := &Tunnel{ID: "t", Client: owner, stopChan: make(chan struct{})}
	s := &Server{tunnels: map[string]*Tunnel{"t": tunnel}}
	tunnel.initLifecycle(s)
	entered, canceled, release, completed := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		s.withActiveTunnelMetadata(tunnel, owner, func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			close(canceled)
			// Simulate a Redis response arriving after request cancellation.
			<-release
			return ctx.Err()
		})
		close(completed)
	}()
	<-entered
	stopped := make(chan struct{})
	go func() { s.stopTunnel(tunnel); close(stopped) }()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("tunnel shutdown did not cancel reconnect metadata")
	}
	select {
	case <-stopped:
		t.Fatal("shutdown cleanup overtook an in-flight reconnect metadata write")
	default:
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("metadata completion did not release shutdown")
	}
	<-completed
	err := s.withActiveTunnelMetadata(tunnel, owner, func(context.Context) error {
		t.Error("stopped tunnel attempted to recreate session metadata")
		return nil
	})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected stopped metadata rejection: %v", err)
	}
}

func TestStartRejectsRepeatAndStoppedServer(t *testing.T) {
	for _, s := range []*Server{{started: true}, {stopped: true}} {
		if err := s.Start(); err == nil {
			t.Fatal("Start accepted an already-started or stopped server")
		}
		if s.controlListener != nil {
			t.Fatal("rejected Start published a listener")
		}
	}
}

func TestConcurrentStartFailureAndStopCloseResourcesOnce(t *testing.T) {
	t.Setenv("RABBIT_TLS_CERT_PEM", "invalid")
	t.Setenv("RABBIT_TLS_KEY_PEM", "invalid")
	for range 10 {
		closed := 0
		s := &Server{config: Config{BindAddress: "127.0.0.1", ControlPort: "0"},
			stopChan: make(chan struct{}), closeDatabase: func() error { closed++; return nil }}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); s.Start() }()
		go func() { defer wg.Done(); s.Stop() }()
		wg.Wait()
		if closed != 1 || !s.stopped || s.controlListener != nil {
			t.Fatal("concurrent failed startup and shutdown leaked resources")
		}
		if err := s.Start(); err == nil {
			t.Fatal("Start succeeded after concurrent Stop")
		}
	}
}
