package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rabbit.go/internal/middleware"
	"rabbit.go/transport"

	"github.com/google/uuid"
)

type privateAuthorityFunc func(context.Context, string, transport.VerifiedOpen) (time.Time, error)

func (f privateAuthorityFunc) Authorize(ctx context.Context, token string, open transport.VerifiedOpen) (time.Time, error) {
	return f(ctx, token, open)
}

type privateFixture struct {
	server     *Server
	tunnel     *Tunnel
	clientTLS  *tls.Config
	claims     transport.OpenClaims
	key        ed25519.PrivateKey
	dispatched atomic.Int32
	revoked    atomic.Bool
	checks     atomic.Int32
}

func privateTestTLS(t *testing.T) (*tls.Config, *tls.Config, string, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caRaw, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caRaw)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	identity := "spiffe://example.test/worker/worker-a"
	uri, _ := url.Parse(identity)
	cert := func(serial int64, client bool) tls.Certificate {
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		if client {
			template.URIs = []*url.URL{uri}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		raw, err := x509.CreateCertificate(rand.Reader, template, ca, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{raw, caRaw}, PrivateKey: key}
	}
	server, worker := cert(2, false), cert(3, true)
	digest := sha256.Sum256(worker.Certificate[0])
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"}},
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{worker}, NextProtos: []string{"http/1.1"}}, identity, hex.EncodeToString(digest[:])
}

func privateSourcePair() (net.Conn, net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		return nil, nil, err
	}
	server, err := listener.Accept()
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return server, client, nil
}

func newPrivateFixture(t *testing.T, source func(net.Conn)) *privateFixture {
	return newPrivateFixtureMode(t, source, false)
}

func newPrivateFixtureMode(t *testing.T, source func(net.Conn), reserved bool) *privateFixture {
	t.Helper()
	serverTLS, clientTLS, identity, certDigest := privateTestTLS(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := transport.NewReplayRegistry(64)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{ctx: ctx, cancel: cancel, stopChan: make(chan struct{}), connections: make(map[net.Conn]struct{}),
		tunnels: make(map[string]*Tunnel), pendingConns: make(map[string]*pendingConnection)}
	config := middleware.DefaultSecurityConfig()
	config.TrustedNetworks = []string{"127.0.0.1/32"}
	config.MaxGlobalConnections = 16
	s.securityMiddleware = middleware.NewSecurityMiddleware(config)
	s.operator.PairingTimeout = 500 * time.Millisecond
	s.private = &privateConnect{tls: serverTLS, replays: registry,
		trust: []transport.Trust{{Issuer: "issuer", Audience: "private-connect", ClusterTenant: "shared", ServicePrincipal: "gateway", WorkerIdentity: identity, PublicKey: public}}}
	if reserved {
		if err := s.enableReservedIngress(transport.ReservationLimits{Sockets: 16, Handshakes: 2, Parents: 2,
			SetupTimeout: 2 * time.Second, TerminationWindow: time.Second}); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.privateListener = listener
	owner, ownerPeer := net.Pipe()
	tunnel := &Tunnel{ID: strings.Repeat("1", 64), tokenEpoch: strings.Repeat("2", 64), TeamID: "team-a", TokenID: uuid.NewString(), RemotePort: "10001", server: s, stopChan: make(chan struct{})}
	tunnel.initLifecycle(s)
	s.mu.Lock()
	s.tunnels[tunnel.ID] = tunnel
	s.replaceControlOwnerLocked(tunnel, owner)
	route := tunnel.privateRouteLocked()
	s.mu.Unlock()
	now := time.Now().Unix()
	f := &privateFixture{server: s, tunnel: tunnel, clientTLS: clientTLS, key: private,
		claims: transport.OpenClaims{Version: transport.Version, Issuer: "issuer", Audience: "private-connect", ID: strings.Repeat("3", 64), IssuedAt: now, ExpiresAt: now + 60, SessionExpiresAt: now + 120,
			ClusterTenant: "shared", ServicePrincipal: "gateway", Tenant: route.Tenant, TokenID: route.TokenID, TokenGeneration: route.TokenGeneration, TunnelID: route.TunnelID, ControlOwner: route.ControlOwner,
			Source: "connection-a", SourceRevision: strings.Repeat("4", 64), Authority: "database.customer.internal:5432", WorkerIdentity: identity, WorkerCertSHA256: certDigest,
			Execution: transport.Execution{Kind: "query", ID: "query-a", GrantSHA256: strings.Repeat("5", 64), Worker: "worker-a", Owner: strings.Repeat("6", 32), Claim: strings.Repeat("7", 32)}}}
	s.private.tokenActive = func(context.Context, *Tunnel) (time.Time, error) { return time.Time{}, nil }
	s.private.authority = privateAuthorityFunc(func(ctx context.Context, _ string, open transport.VerifiedOpen) (time.Time, error) {
		f.checks.Add(1)
		if f.revoked.Load() || ctx.Err() != nil || open.Claims().Source != f.claims.Source || open.Claims().SourceRevision != f.claims.SourceRevision {
			return time.Time{}, transport.ErrAuthority
		}
		return time.Unix(time.Now().Unix()+3, 0), nil
	})
	done := make(chan struct{})
	var streams sync.WaitGroup
	go func() {
		defer close(done)
		reader := bufio.NewReader(ownerPeer)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			id, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line != "CONNECT\n" || !strings.HasPrefix(id, "CONN_ID:") {
				return
			}
			f.dispatched.Add(1)
			if source == nil {
				continue
			}
			data, peer, err := privateSourcePair()
			if err != nil {
				return
			}
			streams.Add(1)
			go func() { defer streams.Done(); defer peer.Close(); source(peer) }()
			if reserved {
				admitted, err := s.acceptIngress(data, false)
				if err != nil {
					data.Close()
					return
				}
				data = admitted
			}
			s.handleDataConnection(data, "DATA:"+strings.TrimSpace(strings.TrimPrefix(id, "CONN_ID:")))
			s.finishIngress(data)
		}
	}()
	s.wg.Add(1)
	go s.handlePrivateConnections()
	if reserved {
		s.wg.Add(1)
		go s.maintainReservedIngress()
	}
	t.Cleanup(func() {
		if err := s.Stop(); err != nil {
			t.Error(err)
		}
		ownerPeer.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("control fixture did not join")
		}
		joined := make(chan struct{})
		go func() { streams.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("source fixture did not join")
		}
		s.mu.RLock()
		remaining := len(s.connections) + len(s.pendingConns) + len(tunnel.streams)
		s.mu.RUnlock()
		if remaining != 0 {
			t.Error("private ingress retained owned state", remaining)
		}
	})
	return f
}

func (f *privateFixture) open(t *testing.T, claims transport.OpenClaims, payload string) (*tls.Conn, *bufio.Reader, string) {
	t.Helper()
	token, err := transport.SignOpen(claims, f.key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", f.server.privateListener.Addr().String(), f.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeShutdownConnection(conn) })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n\r\n%s", claims.Authority, claims.Authority, token, payload)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return conn, reader, status
}

func TestPrivateConnectRelaysReadAheadAndHalfClose(t *testing.T) {
	sourceErr := make(chan error, 1)
	f := newPrivateFixture(t, func(conn net.Conn) {
		request, err := io.ReadAll(conn)
		if err != nil || string(request) != "request" {
			sourceErr <- fmt.Errorf("request changed: %q %v", request, err)
			return
		}
		_, err = io.WriteString(conn, "response")
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		sourceErr <- err
	})
	conn, reader, status := f.open(t, f.claims, "request")
	if status != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatal(status)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(reader)
	if err != nil || string(response) != "response" {
		t.Fatalf("response changed: %q %v", response, err)
	}
	if err := <-sourceErr; err != nil {
		t.Fatal(err)
	}
	_, _, status = f.open(t, f.claims, "")
	if !strings.Contains(status, "403") || f.dispatched.Load() != 1 {
		t.Fatal("replayed open reached source", status, f.dispatched.Load())
	}
}

func TestPrivateConnectRejectsForeignRouteSourceAndOwnerBeforeDispatch(t *testing.T) {
	f := newPrivateFixture(t, func(conn net.Conn) { io.Copy(io.Discard, conn) })
	for name, change := range map[string]func(*transport.OpenClaims){
		"tenant":          func(c *transport.OpenClaims) { c.Tenant = "other" },
		"token":           func(c *transport.OpenClaims) { c.TokenID = uuid.NewString() },
		"generation":      func(c *transport.OpenClaims) { c.TokenGeneration = strings.Repeat("a", 64) },
		"owner":           func(c *transport.OpenClaims) { c.ControlOwner = strings.Repeat("a", 64) },
		"restart":         func(c *transport.OpenClaims) { c.TunnelID = strings.Repeat("a", 64) },
		"source":          func(c *transport.OpenClaims) { c.Source = "connection-b" },
		"source revision": func(c *transport.OpenClaims) { c.SourceRevision = strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			claims := f.claims
			change(&claims)
			_, _, status := f.open(t, claims, "")
			if strings.Contains(status, "200") {
				t.Fatal("foreign grant accepted")
			}
		})
	}
	if f.dispatched.Load() != 0 {
		t.Fatal("denied grant reached the customer")
	}
}

func TestPrivateConnectRevocationStopsActiveLeasedStream(t *testing.T) {
	f := newPrivateFixture(t, func(conn net.Conn) { io.Copy(io.Discard, conn) })
	conn, reader, status := f.open(t, f.claims, "")
	if !strings.Contains(status, "200") {
		t.Fatal(status)
	}
	f.revoked.Store(true)
	conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("revoked stream stayed readable")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("authority revocation did not close the stream")
	}
	if f.checks.Load() < 3 {
		t.Fatal("no live renewal check ran")
	}
}

func TestPrivateConnectWaitsForPairingAndShutdownJoinsPendingOpen(t *testing.T) {
	f := newPrivateFixture(t, nil)
	_, _, status := f.open(t, f.claims, "")
	if !strings.Contains(status, "503") || f.dispatched.Load() != 1 {
		t.Fatal("unpaired stream acknowledged", status)
	}
	if err := f.server.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateRouteGenerationChangesOnReplacement(t *testing.T) {
	f := newPrivateFixture(t, nil)
	old, ok := f.server.privateRouteInfo(f.tunnel.TeamID, f.tunnel.TokenID)
	if !ok {
		t.Fatal("route missing")
	}
	next, peer := net.Pipe()
	defer peer.Close()
	f.server.mu.Lock()
	closed := f.server.replaceControlOwnerLocked(f.tunnel, next)
	f.server.mu.Unlock()
	closeReplacedOwner(closed)
	current, ok := f.server.privateRouteInfo(f.tunnel.TeamID, f.tunnel.TokenID)
	if !ok || current.ControlOwner == old.ControlOwner || current.TokenGeneration != old.TokenGeneration {
		t.Fatal("replacement did not fence old owner")
	}
	_, _, status := f.open(t, f.claims, "")
	if !strings.Contains(status, "503") || f.dispatched.Load() != 0 {
		t.Fatal("stale owner ticket accepted")
	}
	if _, ok := f.server.privateRouteInfo("other", f.tunnel.TokenID); ok {
		t.Fatal("foreign tenant discovered route")
	}
}

func TestPrivateConnectRequiresVerifiedClientCertificate(t *testing.T) {
	f := newPrivateFixture(t, nil)
	config := f.clientTLS.Clone()
	config.Certificates = nil
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.server.privateListener.Addr().String(), config)
	if err == nil {
		defer closeShutdownConnection(conn)
		conn.SetDeadline(time.Now().Add(time.Second))
		_, err = io.WriteString(conn, "CONNECT database.customer.internal:5432 HTTP/1.1\r\n\r\n")
		if err == nil {
			var b [1]byte
			_, err = conn.Read(b[:])
		}
	}
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("missing client certificate was not rejected", err)
	}
	if f.dispatched.Load() != 0 {
		t.Fatal("unauthenticated source dispatch")
	}
}
