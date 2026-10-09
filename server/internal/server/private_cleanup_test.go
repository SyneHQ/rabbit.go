package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"rabbit.go/transport"
)

type cleanupTestAuthority struct {
	until   atomic.Int64
	started atomic.Int64
	denied  atomic.Bool
}

func (a *cleanupTestAuthority) ReadCleanupLease(ctx context.Context, r transport.CleanupLeaseRequest) (transport.CleanupLeaseResponse, error) {
	v := transport.CleanupLeaseResponse{ValidUntil: a.until.Load(), CancellationStartedAt: a.started.Load()}
	if ctx.Err() != nil || a.denied.Load() || r.Validate() != nil || v.ValidateAt(time.Now()) != nil {
		return transport.CleanupLeaseResponse{}, transport.ErrCleanup
	}
	return v, nil
}
func (a *cleanupTestAuthority) AuthorizeCleanup(ctx context.Context, r transport.CleanupLeaseRequest, c transport.PostgresAbortClaims) (time.Time, error) {
	v, err := a.ReadCleanupLease(ctx, r)
	if err != nil || v.CancellationStartedAt != c.CancellationStartedAt || v.ValidUntil > c.ExpiresAt {
		return time.Time{}, transport.ErrCleanup
	}
	return time.Unix(v.ValidUntil, 0), nil
}
func enableCleanupFixture(t *testing.T, f *privateFixture) (ed25519.PublicKey, *cleanupTestAuthority) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &cleanupTestAuthority{}
	a.started.Store(time.Now().Unix())
	a.until.Store(a.started.Load() + 5)
	f.server.private.acceptedKeyID = "fixture-route"
	f.server.private.acceptedKey = key
	f.server.private.accepted = make(map[string]*acceptedPrivateParent)
	f.server.private.acceptedLimit = 16
	f.server.private.cleanup = a
	return pub, a
}
func cleanupConnect(t *testing.T, f *privateFixture, token, header string) (*tls.Conn, *bufio.Reader, string, string) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.server.privateListener.Addr().String(), f.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeShutdownConnection(conn) })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n%s\r\n", f.claims.Authority, f.claims.Authority, token, header); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	receipt := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
		if strings.HasPrefix(line, "Rabbit-Accepted-Open: ") {
			receipt = strings.TrimSpace(strings.TrimPrefix(line, "Rabbit-Accepted-Open: "))
		}
	}
	return conn, reader, status, receipt
}
func acceptedFixtureOpen(t *testing.T, f *privateFixture, pub ed25519.PublicKey) (*tls.Conn, *bufio.Reader, transport.AcceptedOpenClaims) {
	t.Helper()
	token, err := transport.SignOpen(f.claims, f.key)
	if err != nil {
		t.Fatal(err)
	}
	conn, reader, status, receipt := cleanupConnect(t, f, token, "Rabbit-Accepted-Open: required-v1\r\n")
	if status != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatal("accepted DATA rejected", status)
	}
	sum := sha256.Sum256([]byte(token))
	claims, err := transport.VerifyAcceptedOpen(receipt, transport.AcceptedOpenTrust{KeyID: "fixture-route", PublicKey: pub}, hex.EncodeToString(sum[:]), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return conn, reader, claims
}
func abortFixtureToken(t *testing.T, f *privateFixture, a *cleanupTestAuthority, accepted transport.AcceptedOpenClaims, id string) string {
	t.Helper()
	c := transport.PostgresAbortClaims{Version: 1, Issuer: f.claims.Issuer, Audience: f.claims.Audience, ID: strings.Repeat(id, 64), IssuedAt: time.Now().Unix(), ExpiresAt: a.until.Load(), DataTicketSHA256: accepted.DataTicketSHA256, AcceptanceID: accepted.AcceptanceID, WorkerIdentity: f.claims.WorkerIdentity, WorkerCertSHA256: f.claims.WorkerCertSHA256, CancellationStartedAt: a.started.Load(), Protocol: transport.PostgresCancel}
	token, err := transport.SignPostgresAbort(c, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func TestPrivateCleanupPreservesSourceBytesAndConsumesParentOnce(t *testing.T) {
	f := newPrivateFixture(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	pub, a := enableCleanupFixture(t, f)
	parent, _, accepted := acceptedFixtureOpen(t, f, pub)
	defer parent.Close()
	token := abortFixtureToken(t, f, a, accepted, "a")
	conn, reader, status, receipt := cleanupConnect(t, f, token, "Rabbit-Postgres-Abort: required-v1\r\n")
	if status != "HTTP/1.1 200 Connection Established\r\n" || receipt != "" {
		t.Fatal("typed abort rejected or minted data receipt", status)
	}
	payload := "opaque-original-source-TLS-records"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != payload {
		t.Fatal("source TLS bytes changed", err)
	}
	conn.Close()
	for _, retry := range []string{token, abortFixtureToken(t, f, a, accepted, "b")} {
		_, _, status, _ := cleanupConnect(t, f, retry, "Rabbit-Postgres-Abort: required-v1\r\n")
		if status != "HTTP/1.1 403 Forbidden\r\n" {
			t.Fatal("parent allowed repeated cleanup", status)
		}
	}
	if f.dispatched.Load() != 2 {
		t.Fatal("unexpected source dispatches", f.dispatched.Load())
	}
}
func TestPrivateCleanupRejectsClosedParentAndMissingOptIn(t *testing.T) {
	f := newPrivateFixture(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	token, _ := transport.SignOpen(f.claims, f.key)
	_, _, status, _ := cleanupConnect(t, f, token, "Rabbit-Accepted-Open: required-v1\r\n")
	if status != "HTTP/1.1 403 Forbidden\r\n" || f.dispatched.Load() != 0 {
		t.Fatal("missing operator opt-in dispatched source")
	}
	pub, a := enableCleanupFixture(t, f)
	parent, _, accepted := acceptedFixtureOpen(t, f, pub)
	parent.Close()
	deadline := time.Now().Add(time.Second)
	for {
		f.server.mu.RLock()
		n := len(f.server.private.accepted)
		f.server.mu.RUnlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed parent retained authority")
		}
		time.Sleep(time.Millisecond)
	}
	_, _, status, _ = cleanupConnect(t, f, abortFixtureToken(t, f, a, accepted, "a"), "Rabbit-Postgres-Abort: required-v1\r\n")
	if status != "HTTP/1.1 403 Forbidden\r\n" || f.dispatched.Load() != 1 {
		t.Fatal("closed parent authorized cleanup", status)
	}
}
func TestPrivateCleanupDenialBeforeReceiptDoesNotRetain(t *testing.T) {
	f := newPrivateFixture(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	enableCleanupFixture(t, f)
	var n atomic.Int32
	f.server.private.authority = privateAuthorityFunc(func(context.Context, string, transport.VerifiedOpen) (time.Time, error) {
		if n.Add(1) > 1 {
			return time.Time{}, transport.ErrLeaseDenied
		}
		return time.Now().Add(3 * time.Second), nil
	})
	token, _ := transport.SignOpen(f.claims, f.key)
	_, _, status, receipt := cleanupConnect(t, f, token, "Rabbit-Accepted-Open: required-v1\r\n")
	if status != "HTTP/1.1 403 Forbidden\r\n" || receipt != "" {
		t.Fatal("canceled pairing minted receipt")
	}
	f.server.mu.RLock()
	nparents := len(f.server.private.accepted)
	f.server.mu.RUnlock()
	if nparents != 0 {
		t.Fatal("unaccepted parent retained")
	}
}
func TestPrivateCleanupSuspendsDataWithoutRestoringExecution(t *testing.T) {
	var received atomic.Int64
	var sourceCount atomic.Int32
	f := newPrivateFixture(t, func(c net.Conn) {
		first := sourceCount.Add(1) == 1
		buf := make([]byte, 128)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				if first {
					received.Add(int64(n))
				}
				if _, e := c.Write(buf[:n]); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	pub, a := enableCleanupFixture(t, f)
	var denied atomic.Bool
	f.server.private.authority = privateAuthorityFunc(func(context.Context, string, transport.VerifiedOpen) (time.Time, error) {
		if denied.Load() {
			return time.Time{}, transport.ErrLeaseDenied
		}
		return time.Unix(time.Now().Unix()+2, 0), nil
	})
	parent, reader, accepted := acceptedFixtureOpen(t, f, pub)
	defer parent.Close()
	parent.Write([]byte("first"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}
	denied.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.server.mu.RLock()
		entry := f.server.private.accepted[accepted.DataTicketSHA256]
		f.server.mu.RUnlock()
		if entry == nil {
			t.Fatal("cleanup-authorized parent closed")
		}
		entry.gate.mu.RLock()
		paused := entry.gate.paused
		entry.gate.mu.RUnlock()
		if paused {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DATA was not suspended")
		}
		time.Sleep(time.Millisecond)
	}
	parent.Write([]byte("must-not-reach-source"))
	time.Sleep(30 * time.Millisecond)
	if received.Load() != 5 {
		t.Fatal("DATA forwarded after lease denial", received.Load())
	}
	abort, abortReader, status, _ := cleanupConnect(t, f, abortFixtureToken(t, f, a, accepted, "a"), "Rabbit-Postgres-Abort: required-v1\r\n")
	if status != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatal("suspended parent cleanup rejected", status)
	}
	abort.Write([]byte("cancel"))
	if _, err := io.ReadFull(abortReader, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	abort.Close()
	a.denied.Store(true)
	parent.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("hard cleanup revoke kept DATA alive")
	}
}
func TestPrivateConnectRejectsMixedCleanupHeaders(t *testing.T) {
	for _, header := range []string{"Rabbit-Accepted-Open: required-v1\r\nRabbit-Postgres-Abort: required-v1\r\n", "Rabbit-Accepted-Open: optional\r\n", "Rabbit-Postgres-Abort: required-v1\r\nrabbit-postgres-abort: required-v1\r\n"} {
		r := bufio.NewReader(strings.NewReader("CONNECT x:1 HTTP/1.1\r\nHost: x:1\r\nProxy-Authorization: Bearer token\r\n" + header + "\r\n"))
		if _, _, _, err := readPrivateConnectMode(r); err == nil {
			t.Fatal("ambiguous cleanup request accepted")
		}
	}
}
