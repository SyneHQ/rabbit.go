package middleware

import (
	"net"
	"testing"
	"time"
)

func TestExplicitHandshakeDeadlineSurvivesWrapperRead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: time.Hour}}
	conn := sm.WrapConnection(a)
	conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	started := time.Now()
	_, err := conn.Read(make([]byte, 1))
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected timeout: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("idle timeout replaced handshake deadline")
	}
	conn.SetReadDeadline(time.Time{})
	go b.Write([]byte("x"))
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestCloseCountsConnectionOnceAndPreservesHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	raw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: time.Second}, globalConnections: 2, ipStats: map[string]*IPStats{"127.0.0.1": {CurrentConnections: 2}}}
	conn := sm.WrapConnection(raw)
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("half-close not forwarded: %d %v", n, err)
	}
	conn.Close()
	conn.Close()
	if sm.globalConnections != 1 || sm.ipStats["127.0.0.1"].CurrentConnections != 1 {
		t.Fatal("duplicate close corrupts rate-limit counters")
	}
}
