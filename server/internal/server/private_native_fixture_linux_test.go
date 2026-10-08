//go:build linux

package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"rabbit.go/transport"
)

// This fixture holds issuer and worker authority inside the test process. It
// qualifies Rabbit independently from any application's production broker.
type nativePrivateFixture struct {
	h       *transportHarness
	tls     *tls.Config
	key     ed25519.PrivateKey
	claims  transport.OpenClaims
	revoked atomic.Bool
}

func newNativePrivateFixture(t *testing.T, sourceAddress string) *nativePrivateFixture {
	t.Helper()
	serverTLS, workerTLS, identity, digest := privateTestTLS(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replays, err := transport.NewReplayRegistry(128)
	if err != nil {
		t.Fatal(err)
	}
	f := &nativePrivateFixture{tls: workerTLS, key: private}
	f.h = newTransportHarnessConfigured(t, sourceAddress, func(s *Server) {
		s.private = &privateConnect{address: "127.0.0.1:0", tls: serverTLS, replays: replays,
			trust: []transport.Trust{{Issuer: "fixture", Audience: "database-ingress", ClusterTenant: "shared", ServicePrincipal: "native-qualification", WorkerIdentity: identity, PublicKey: public}}}
		s.private.tokenActive = func(ctx context.Context, tunnel *Tunnel) (time.Time, error) {
			tokenID, tokenErr := uuid.Parse(tunnel.TokenID)
			portID, portErr := uuid.Parse(tunnel.PortAssignID)
			if tokenErr != nil || portErr != nil {
				return time.Time{}, transport.ErrAuthority
			}
			return s.dbService.CheckTransportAuthority(ctx, tunnel.TeamID, tunnel.Token, tokenID, portID)
		}
		s.private.authority = privateAuthorityFunc(func(ctx context.Context, _ string, open transport.VerifiedOpen) (time.Time, error) {
			claims := open.Claims()
			if f.revoked.Load() || ctx.Err() != nil || claims.Source != f.claims.Source || claims.SourceRevision != f.claims.SourceRevision || claims.Execution != f.claims.Execution {
				return time.Time{}, transport.ErrAuthority
			}
			return time.Unix(time.Now().Unix()+3, 0), nil
		})
	})
	if sourceAddress == "" {
		sourceAddress = f.h.plain
	}
	_, port, err := net.SplitHostPort(sourceAddress)
	if err != nil {
		t.Fatal(err)
	}
	f.h.server.mu.RLock()
	var route transport.RouteInfo
	for _, tunnel := range f.h.server.tunnels {
		route = tunnel.privateRouteLocked()
	}
	f.h.server.mu.RUnlock()
	if route.Validate() != nil {
		t.Fatal("native client did not establish a usable private route")
	}
	f.claims = transport.OpenClaims{Version: 1, Issuer: "fixture", Audience: "database-ingress", ClusterTenant: "shared", ServicePrincipal: "native-qualification",
		Tenant: route.Tenant, TokenID: route.TokenID, TokenGeneration: route.TokenGeneration, TunnelID: route.TunnelID, ControlOwner: route.ControlOwner,
		Source: "native-source", SourceRevision: strings.Repeat("1", 64), Authority: net.JoinHostPort("localhost", port), WorkerIdentity: identity, WorkerCertSHA256: digest,
		Execution: transport.Execution{Kind: "query", ID: "native-query", GrantSHA256: strings.Repeat("2", 64), Worker: "fixture-worker", Owner: strings.Repeat("3", 32), Claim: strings.Repeat("4", 32)}}
	return f
}

type nativePrivateDialer struct {
	fixture *nativePrivateFixture
	claims  transport.OpenClaims
	opens   atomic.Int32
}

func (f *nativePrivateFixture) dialer() *nativePrivateDialer {
	return &nativePrivateDialer{fixture: f, claims: f.claims}
}

func (d *nativePrivateDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialTimeout(network, address, 5*time.Second)
}

func (d *nativePrivateDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, network, address)
}

func (d *nativePrivateDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != d.claims.Authority {
		return nil, fmt.Errorf("native driver changed original source authority")
	}
	claims := d.claims
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	claims.ID = hex.EncodeToString(id[:])
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = claims.IssuedAt + 30
	claims.SessionExpiresAt = claims.IssuedAt + 120
	token, err := transport.SignOpen(claims, d.fixture.key)
	if err != nil {
		return nil, err
	}
	dial := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: d.fixture.tls}
	conn, err := dial.DialContext(ctx, "tcp", d.fixture.h.server.privateListener.Addr().String())
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			closeShutdownConnection(conn)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if end, hasEnd := ctx.Deadline(); hasEnd && end.Before(deadline) {
		deadline = end
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n\r\n", address, address, token); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(conn, 4096)
	line, err := reader.ReadSlice('\n')
	if err != nil || string(line) != "HTTP/1.1 200 Connection Established\r\n" {
		return nil, fmt.Errorf("private CONNECT refused")
	}
	line, err = reader.ReadSlice('\n')
	if err != nil || string(line) != "\r\n" {
		return nil, fmt.Errorf("invalid private CONNECT response")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	d.opens.Add(1)
	ok = true
	return &nativeAuthorityConn{bufferedConnection: bufferedConnection{Conn: conn, reader: reader}, authority: address}, nil
}

type nativeAuthorityConn struct {
	bufferedConnection
	authority string
}

type nativeAuthorityAddr string

func (a nativeAuthorityAddr) Network() string       { return "tcp" }
func (a nativeAuthorityAddr) String() string        { return string(a) }
func (c *nativeAuthorityConn) RemoteAddr() net.Addr { return nativeAuthorityAddr(c.authority) }
