package server

import (
	"bufio"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"rabbit.go/internal/database"
)

func ownerPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	return conn, peer
}

func requireOwnerPipeClosed(t *testing.T, peer net.Conn) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err := peer.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("old owner socket did not close: %v", err)
	}
}

func TestReconnectClosesOldOwnerStreamsBeforeAcknowledgingSuccessor(t *testing.T) {
	old, oldPeer := ownerPipe(t)
	current, currentPeer := ownerPipe(t)
	external, externalPeer := ownerPipe(t)
	data, dataPeer := ownerPipe(t)
	queued, queuedPeer := ownerPipe(t)
	tunnel := &Tunnel{ID: "route", Client: old, RemotePort: "10001", stopChan: make(chan struct{}), busyOwner: old}
	s := &Server{stopChan: make(chan struct{}), tunnels: map[string]*Tunnel{"route": tunnel}, pendingConns: make(map[string]*pendingConnection)}
	tunnel.server = s
	stream, ok := s.beginTunnelStream(tunnel, old, external, data)
	if !ok {
		t.Fatal("old owner admission failed")
	}
	defer s.endTunnelStream(tunnel, stream)
	pending := &pendingConnection{tunnel: tunnel, owner: old, ready: make(chan net.Conn, 1), rejected: make(chan struct{})}
	pending.ready <- queued
	s.pendingConns["old-open"] = pending
	finished := make(chan struct{})
	go func() {
		s.reconnectClientToTunnel(tunnel, current, bufio.NewReader(current), &database.TeamToken{TeamID: "tenant"}, "5432")
		close(finished)
	}()
	t.Cleanup(func() {
		currentPeer.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("successor control handler did not return")
		}
	})
	currentPeer.SetDeadline(time.Now().Add(time.Second))
	reader := bufio.NewReader(currentPeer)
	if line, err := reader.ReadString('\n'); err != nil || line != "SUCCESS:route:10001\n" {
		t.Fatalf("successor registration failed: %q %v", line, err)
	}
	for _, peer := range []net.Conn{oldPeer, externalPeer, dataPeer, queuedPeer} {
		requireOwnerPipeClosed(t, peer)
	}
	select {
	case <-pending.rejected:
	default:
		t.Fatal("old pending open was not rejected")
	}
	s.mu.RLock()
	remaining, active, busy := len(s.pendingConns), tunnel.Client == current, tunnel.busyOwner
	s.mu.RUnlock()
	if remaining != 0 || !active || busy != nil {
		t.Fatal("replacement retained old admission state")
	}
	if _, err := io.WriteString(currentPeer, "PING\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "PONG\n" {
		t.Fatalf("replacement lost control: %q %v", line, err)
	}
	select {
	case <-tunnel.stopChan:
		t.Fatal("replacement stopped the shared tunnel")
	default:
	}
}

func TestDisconnectOnlyClosesStreamsOfCurrentOwner(t *testing.T) {
	old, oldPeer := ownerPipe(t)
	current, currentPeer := ownerPipe(t)
	external, externalPeer := ownerPipe(t)
	data, dataPeer := ownerPipe(t)
	tunnel := &Tunnel{ID: "route", Client: current, stopChan: make(chan struct{})}
	s := &Server{tunnels: map[string]*Tunnel{"route": tunnel}, pendingConns: make(map[string]*pendingConnection)}
	stream, ok := s.beginTunnelStream(tunnel, current, external, data)
	if !ok {
		t.Fatal("current owner admission failed")
	}
	defer s.endTunnelStream(tunnel, stream)
	s.disconnectClient(tunnel, old)
	requireOwnerPipeClosed(t, oldPeer)
	if tunnel.Client != current {
		t.Fatal("stale disconnect removed the current owner")
	}
	// A stale handler must leave the current data socket usable.
	written := make(chan error, 1)
	go func() { _, err := data.Write([]byte("x")); written <- err }()
	dataPeer.SetReadDeadline(time.Now().Add(time.Second))
	var value [1]byte
	if _, err := io.ReadFull(dataPeer, value[:]); err != nil || value[0] != 'x' {
		t.Fatalf("stale disconnect closed the current stream: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	s.disconnectClient(tunnel, current)
	for _, peer := range []net.Conn{currentPeer, externalPeer, dataPeer} {
		requireOwnerPipeClosed(t, peer)
	}
	if tunnel.Client != nil {
		t.Fatal("disconnected owner remained available")
	}
}

func TestOwnerReplacementDoesNotConsumeAnotherTunnelOpen(t *testing.T) {
	old, _ := ownerPipe(t)
	current, _ := ownerPipe(t)
	target := &Tunnel{Client: old}
	other := &Tunnel{Client: old}
	pending := &pendingConnection{tunnel: other, owner: old, ready: make(chan net.Conn, 1), rejected: make(chan struct{})}
	s := &Server{pendingConns: map[string]*pendingConnection{"other": pending}}
	s.mu.Lock()
	connections := s.replaceControlOwnerLocked(target, current)
	s.mu.Unlock()
	closeReplacedOwner(connections)
	if s.pendingConns["other"] != pending {
		t.Fatal("replacement consumed another tunnel's pending open")
	}
	select {
	case <-pending.rejected:
		t.Fatal("replacement rejected another tunnel's pending open")
	default:
	}
}
