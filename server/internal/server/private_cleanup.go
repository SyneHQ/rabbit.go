package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"time"

	"rabbit.go/transport"
)

// The server lock protects this registry and the exact parent stream. Deleting
// a parent removes cleanup authority; the receipt alone cannot restore it.
type acceptedPrivateParent struct {
	verified     transport.VerifiedOpen
	token        string
	receipt      string
	acceptanceID string
	tunnel       *Tunnel
	owner        net.Conn
	stream       *tunnelStream
	used         bool
	gate         *privateDataGate
	cutoff       transport.CleanupLeaseResponse
}

func (s *Server) acceptPrivateParent(token string, verified transport.VerifiedOpen, tunnel *Tunnel, owner net.Conn, stream *tunnelStream, gate *privateDataGate) (string, func(), error) {
	if s.private == nil || len(s.private.acceptedKey) != ed25519.PrivateKeySize || s.private.cleanup == nil {
		return "", nil, transport.ErrCleanup
	}
	now := time.Now()
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", nil, err
	}
	receipt, err := transport.SignAcceptedOpen(transport.AcceptedOpenClaims{Version: 1, DataTicketSHA256: verified.Digest(), AcceptanceID: hex.EncodeToString(id), AcceptedAt: now.Unix(), ExpiresAt: verified.SessionDeadline().Unix()}, s.private.acceptedKeyID, s.private.acceptedKey)
	if err != nil {
		return "", nil, err
	}
	entry := &acceptedPrivateParent{verified: verified, token: token, receipt: receipt, acceptanceID: hex.EncodeToString(id), tunnel: tunnel, owner: owner, stream: stream, gate: gate}
	s.mu.Lock()
	_, held := tunnel.streams[stream]
	if gate == nil {
		held = false
	} else {
		select {
		case <-gate.done:
			held = false
		default:
		}
	}
	if !held || !s.controlOwnerActiveLocked(tunnel, owner) || len(s.private.accepted) >= s.private.acceptedLimit || s.private.accepted[verified.Digest()] != nil {
		s.mu.Unlock()
		return "", nil, transport.ErrCleanup
	}
	s.private.accepted[verified.Digest()] = entry
	s.mu.Unlock()
	return receipt, func() {
		s.mu.Lock()
		if s.private.accepted[verified.Digest()] == entry {
			delete(s.private.accepted, verified.Digest())
		}
		s.mu.Unlock()
	}, nil
}

func (s *Server) acceptedParentActiveLocked(entry *acceptedPrivateParent, claims transport.PostgresAbortClaims) bool {
	if entry == nil || s.private.accepted[claims.DataTicketSHA256] != entry || entry.acceptanceID != claims.AcceptanceID || !time.Now().Before(entry.verified.SessionDeadline()) {
		return false
	}
	c := entry.verified.Claims()
	if c.Issuer != claims.Issuer || c.Audience != claims.Audience || c.WorkerIdentity != claims.WorkerIdentity || c.WorkerCertSHA256 != claims.WorkerCertSHA256 {
		return false
	}
	tunnel, owner, active := s.privateOwnerLocked(c)
	_, held := entry.tunnel.streams[entry.stream]
	return active && tunnel == entry.tunnel && owner == entry.owner && held && entry.stream.owner == owner
}

func (s *Server) authorizePrivateCleanup(ctx context.Context, entry *acceptedPrivateParent, claims transport.PostgresAbortClaims) (time.Time, error) {
	s.mu.RLock()
	active := s.acceptedParentActiveLocked(entry, claims)
	s.mu.RUnlock()
	if !active || s.private.tokenActive == nil || s.private.cleanup == nil {
		return time.Time{}, transport.ErrCleanup
	}
	until, err := s.private.tokenActive(ctx, entry.tunnel)
	if err != nil || ctx.Err() != nil {
		return time.Time{}, transport.ErrCleanup
	}
	cleanupUntil, err := s.private.cleanup.AuthorizeCleanup(ctx, transport.CleanupLeaseRequest{Version: 1, DataTicketSHA256: claims.DataTicketSHA256, AcceptedOpen: entry.receipt}, claims)
	now := time.Now()
	if err != nil || ctx.Err() != nil || !cleanupUntil.After(now) || cleanupUntil.After(time.Unix(claims.ExpiresAt, 0)) || cleanupUntil.After(entry.verified.SessionDeadline()) {
		return time.Time{}, transport.ErrCleanup
	}
	if !until.IsZero() && until.Before(cleanupUntil) {
		cleanupUntil = until
	}
	if !s.pinPrivateCleanup(entry, transport.CleanupLeaseResponse{ValidUntil: cleanupUntil.Unix(), CancellationStartedAt: claims.CancellationStartedAt}) {
		return time.Time{}, transport.ErrCleanup
	}
	if !cleanupUntil.After(now) {
		return time.Time{}, transport.ErrCleanup
	}
	s.mu.RLock()
	active = s.acceptedParentActiveLocked(entry, claims)
	s.mu.RUnlock()
	if !active {
		return time.Time{}, transport.ErrCleanup
	}
	return cleanupUntil, nil
}

// The trusted parent owns the PostgreSQL encoder and original source TLS.
// Rabbit cannot inspect encrypted protocol bytes. It enforces physical parent
// custody, live revocation checks, one use, five seconds and 256 KiB per direction.
// The trusted parent must never transfer this connection to an untrusted child.
func (s *Server) handlePrivatePostgresAbort(parent context.Context, conn *tls.Conn, reader *bufio.Reader, authority, token string, state tls.ConnectionState) {
	if s.private.cleanup == nil || len(s.private.acceptedKey) != ed25519.PrivateKeySize {
		privateFailure(conn, "403 Forbidden")
		return
	}
	var claims transport.PostgresAbortClaims
	for _, trust := range s.private.trust {
		candidate, err := transport.VerifyAbortWorker(token, trust, state, time.Now())
		if err == nil {
			claims = candidate
			break
		}
	}
	if claims.ID == "" {
		privateFailure(conn, "403 Forbidden")
		return
	}
	s.mu.RLock()
	entry := s.private.accepted[claims.DataTicketSHA256]
	active := s.acceptedParentActiveLocked(entry, claims)
	s.mu.RUnlock()
	if !active || entry.verified.Claims().Authority != authority {
		privateFailure(conn, "403 Forbidden")
		return
	}
	until, err := transport.VerifiedAbortPeerDeadline(state, claims, time.Now())
	if err != nil {
		privateFailure(conn, "403 Forbidden")
		return
	}
	ctx, cancel := context.WithDeadline(parent, until)
	defer cancel()
	until, err = s.authorizePrivateCleanup(ctx, entry, claims)
	if err != nil {
		privateFailure(conn, "403 Forbidden")
		return
	}
	if entry.gate == nil || !entry.gate.pause() {
		privateFailure(conn, "403 Forbidden")
		return
	}
	s.mu.Lock()
	if !s.acceptedParentActiveLocked(entry, claims) || entry.used {
		s.mu.Unlock()
		privateFailure(conn, "403 Forbidden")
		return
	}
	err = s.ordinaryIngress(conn)
	if err == nil {
		err = s.private.replays.ConsumeAbort(claims, time.Now())
	}
	if err == nil {
		entry.used = true
		entry.tunnel.wg.Add(1)
	}
	s.mu.Unlock()
	if err != nil {
		privateFailure(conn, "403 Forbidden")
		return
	}
	defer entry.tunnel.wg.Done()
	pairing, stop := context.WithDeadline(ctx, until)
	data, err := s.pairConnection(pairing, entry.tunnel, entry.owner)
	stop()
	if err != nil {
		privateFailure(conn, "503 Service Unavailable")
		return
	}
	defer finishPairedIngress(data)
	defer closeShutdownConnection(data)
	external := &bufferedConnection{Conn: conn, reader: reader}
	stream, ok := s.beginTunnelStream(entry.tunnel, entry.owner, external, data)
	if !ok {
		privateFailure(conn, "403 Forbidden")
		return
	}
	defer s.endTunnelStream(entry.tunnel, stream)
	until, err = s.authorizePrivateCleanup(ctx, entry, claims)
	if err != nil {
		privateFailure(conn, "403 Forbidden")
		return
	}
	if data.SetDeadline(until) != nil || conn.SetDeadline(until) != nil {
		return
	}
	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	guard, stopGuard := context.WithCancel(ctx)
	guardDone := make(chan struct{})
	go func() {
		defer close(guardDone)
		defer closeShutdownConnection(external)
		defer closeShutdownConnection(data)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-guard.Done():
				return
			case <-ticker.C:
				check, stop := context.WithDeadline(guard, until)
				next, err := s.authorizePrivateCleanup(check, entry, claims)
				stop()
				if err != nil || !time.Now().Before(until) {
					return
				}
				// A subsequent authority response can shorten this lease, never extend it.
				if next.Before(until) {
					until = next
					if external.SetDeadline(until) != nil || data.SetDeadline(until) != nil {
						return
					}
				}
			}
		}
	}()
	defer func() { stopGuard(); <-guardDone }()
	boundedAbortRelay(external, data)
}

const privateAbortByteLimit int64 = 256 << 10

func boundedAbortRelay(external, data net.Conn) {
	done := make(chan struct{}, 2)
	copyBounded := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, io.LimitReader(src, privateAbortByteLimit))
		done <- struct{}{}
	}
	go copyBounded(data, external)
	go copyBounded(external, data)
	<-done
	closeShutdownConnection(external)
	closeShutdownConnection(data)
	<-done
}

func (s *Server) pinPrivateCleanup(entry *acceptedPrivateParent, lease transport.CleanupLeaseResponse) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.acceptedRetentionActiveLocked(entry) || lease.ValidateAt(time.Now()) != nil {
		return false
	}
	if entry.cutoff.ValidUntil != 0 && (entry.cutoff.CancellationStartedAt != lease.CancellationStartedAt || lease.ValidUntil > entry.cutoff.ValidUntil) {
		return false
	}
	entry.cutoff = lease
	entry.gate.allowReceive()
	return true
}
