package server

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/google/uuid"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"rabbit.go/internal/middleware"
	"testing"
	"time"
)

func TestRevocationStopsActiveStream(t *testing.T) {
	a, ap := net.Pipe()
	b, bp := net.Pipe()
	defer ap.Close()
	defer bp.Close()
	tunnel := &Tunnel{ID: "owned", TeamID: "team", TokenID: "token", stopChan: make(chan struct{})}
	other := &Tunnel{ID: "foreign", TeamID: "other", TokenID: "token", stopChan: make(chan struct{})}
	s := &Server{tunnels: map[string]*Tunnel{"owned": tunnel, "foreign": other}}
	tunnel.wg.Add(1)
	go func() { defer tunnel.wg.Done(); tunnel.bridgeConnectionsWithLogging(a, b, uuid.Nil) }()
	go ap.Write([]byte("before"))
	data := make([]byte, 6)
	bp.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(bp, data); err != nil || string(data) != "before" {
		t.Fatalf("legitimate stream failed: %q %v", data, err)
	}
	revoked := make(chan struct{})
	go func() { s.revokeToken("team", "token"); close(revoked) }()
	select {
	case <-revoked:
	case <-time.After(time.Second):
		t.Fatal("revocation left an active stream alive")
	}
	select {
	case <-other.stopChan:
		t.Fatal("revoked another team's tunnel")
	default:
	}
	if _, err := ap.Write([]byte("after")); err == nil {
		t.Fatal("revoked stream still writable")
	}
}

func TestTLSBridgePreservesBidirectionalHalfClose(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := certServer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			c.(*tls.Conn).Handshake()
			accepted <- c
		}
	}()
	remote, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	serverTLS := <-accepted
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localListener.Close()
	local, err := net.Dial("tcp", localListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	serverTCP, err := localListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	config := middleware.DefaultSecurityConfig()
	config.IdleTimeout = time.Second
	sm := middleware.NewSecurityMiddleware(config)
	defer sm.Stop()
	tunnel := &Tunnel{ID: "tls", stopChan: make(chan struct{})}
	finished := make(chan struct{})
	go func() {
		tunnel.bridgeConnectionsWithLogging(sm.WrapConnection(serverTCP), sm.WrapConnection(serverTLS), uuid.Nil)
		close(finished)
	}()
	remote.SetDeadline(time.Now().Add(2 * time.Second))
	local.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := remote.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := remote.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(local)
	if err != nil || string(request) != "request" {
		t.Fatalf("request half-close failed: %q %v", request, err)
	}
	if _, err := local.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := local.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(remote)
	if err != nil || string(response) != "response" {
		t.Fatalf("response half-close failed: %q %v", response, err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("bridge failed to finish after both half-closes")
	}
}

func TestDataHandshakePreservesBufferedPayload(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	paired := make(chan net.Conn, 1)
	s := &Server{pendingConns: map[string]chan net.Conn{"capability": paired}}
	s.wg.Add(1)
	go s.handleControlConnection(a)
	go b.Write([]byte("DATA:capability\npayload"))
	var c net.Conn
	select {
	case c = <-paired:
	case <-time.After(time.Second):
		t.Fatal("data connection did not pair")
	}
	defer c.Close()
	payload := make([]byte, 7)
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, payload); err != nil || string(payload) != "payload" {
		t.Fatalf("buffered payload lost: %q %v", payload, err)
	}
	s.wg.Wait()
}
