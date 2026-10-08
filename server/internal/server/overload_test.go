package server

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBusyNegotiationAndScopedRejection(t *testing.T) {
	owner, peer := net.Pipe()
	defer owner.Close()
	defer peer.Close()
	otherOwner, otherPeer := net.Pipe()
	defer otherOwner.Close()
	defer otherPeer.Close()
	tunnel := &Tunnel{ID: "owner", Client: owner, stopChan: make(chan struct{})}
	other := &Tunnel{ID: "other", Client: otherOwner, stopChan: make(chan struct{})}
	rejected, foreign := make(chan struct{}), make(chan struct{})
	s := &Server{stopChan: make(chan struct{}), tunnels: map[string]*Tunnel{tunnel.ID: tunnel, other.ID: other}, pendingConns: map[string]*pendingConnection{
		"own": {tunnel: tunnel, owner: owner, rejected: rejected}, "foreign": {tunnel: other, owner: otherOwner, rejected: foreign},
	}}
	s.rejectPending(tunnel, owner, "own")
	select {
	case <-rejected:
		t.Fatal("BUSY accepted without negotiation")
	default:
	}
	finished := make(chan struct{})
	go func() { s.monitorControlConnection(tunnel, owner, bufio.NewReader(owner)); close(finished) }()
	peer.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(peer, "CAPS:busy-v1\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(peer)
	if line, err := reader.ReadString('\n'); err != nil || line != "CAPS:busy-v1\n" {
		t.Fatal("negotiation failed")
	}
	if _, err := io.WriteString(peer, "BUSY:foreign\nBUSY:own\nPING\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "PONG\n" {
		t.Fatal("control stopped after rejection")
	}
	select {
	case <-rejected:
	default:
		t.Fatal("owned pending request stayed open")
	}
	select {
	case <-foreign:
		t.Fatal("foreign request rejected")
	default:
	}
	if _, err := io.WriteString(peer, "DISCONNECT\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("control handler did not stop")
	}
}

func TestOldControlClientDoesNotReceiveCapabilities(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	tunnel := &Tunnel{Client: conn, stopChan: make(chan struct{})}
	s := &Server{}
	done := make(chan struct{})
	go func() {
		s.monitorControlConnection(tunnel, conn, bufio.NewReader(strings.NewReader("PING\nDISCONNECT\n")))
		close(done)
	}()
	peer.SetDeadline(time.Now().Add(time.Second))
	got := make([]byte, 5)
	if _, err := io.ReadFull(peer, got); err != nil || string(got) != "PONG\n" {
		t.Fatal("old client received a new protocol frame")
	}
	<-done
}
