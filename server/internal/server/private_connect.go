package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"rabbit.go/transport"
)

// The private listener shares the process admission counter and shutdown owner
// with public control and DATA sockets. Its mTLS keys never reach source drivers.
func (s *Server) handlePrivateConnections() {
	defer s.wg.Done()
	consecutive := 0
	for {
		raw, err := s.privateListener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
			}
			consecutive++
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() && consecutive <= 8 {
				timer := time.NewTimer(min(time.Second, 5*time.Millisecond*time.Duration(1<<uint(consecutive-1))))
				select {
				case <-s.stopChan:
					timer.Stop()
					return
				case <-timer.C:
					continue
				}
			}
			s.private.failed.Store(true)
			s.shutdownMu.Lock()
			s.shutdownErr = errors.Join(s.shutdownErr, errors.New("private CONNECT listener failed"))
			s.shutdownMu.Unlock()
			// The accept goroutine must return before shutdown joins s.wg.
			go func() { _ = s.Stop() }()
			return
		}
		consecutive = 0
		admitted, err := s.acceptIngress(raw, false)
		if err != nil {
			raw.Close()
			continue
		}
		conn := tls.Server(admitted, s.private.tls)
		s.mu.Lock()
		select {
		case <-s.stopChan:
			s.mu.Unlock()
			closeShutdownConnection(conn)
			s.finishIngress(admitted)
			return
		default:
		}
		s.connections[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer s.finishIngress(admitted)
			defer func() {
				closeShutdownConnection(conn)
				s.mu.Lock()
				delete(s.connections, conn)
				s.mu.Unlock()
			}()
			s.handlePrivateConnect(conn)
		}()
	}
}

func (s *Server) transportReady() bool {
	select {
	case <-s.stopChan:
		return false
	default:
		return s.private == nil || !s.private.failed.Load()
	}
}

func (s *Server) handlePrivateConnect(conn *tls.Conn) {
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	handshake, stop := context.WithTimeout(parent, s.handshakeTimeout())
	defer stop()
	deadline, _ := handshake.Deadline()
	if conn.SetDeadline(deadline) != nil || conn.HandshakeContext(handshake) != nil {
		return
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
		return
	}
	reader := bufio.NewReaderSize(conn, privateHeaderLimit)
	if prefix, err := reader.Peek(5); err == nil && string(prefix) == "POST " {
		s.handlePrivateRoute(handshake, conn, reader, state)
		return
	}
	authority, token, err := readPrivateConnect(reader)
	if err != nil {
		privateFailure(conn, "400 Bad Request")
		return
	}
	var verified transport.VerifiedOpen
	for _, trust := range s.private.trust {
		candidate, err := transport.VerifyOpen(token, authority, trust, state, time.Now())
		if err == nil {
			verified = candidate
			break
		}
	}
	if verified.Digest() == "" {
		privateFailure(conn, "403 Forbidden")
		return
	}
	claims := verified.Claims()
	s.mu.RLock()
	tunnel, owner, active := s.privateOwnerLocked(claims)
	s.mu.RUnlock()
	if !active {
		privateFailure(conn, "503 Service Unavailable")
		return
	}
	until, err := s.authorizePrivate(handshake, token, verified, tunnel, owner)
	if err != nil {
		privateFailure(conn, "403 Forbidden")
		return
	}
	// Admission and the tunnel wait-group slot are fenced by the same lock as
	// revocation. No teardown owner can join before this stream is registered.
	s.mu.Lock()
	current, currentOwner, active := s.privateOwnerLocked(claims)
	if !active || current != tunnel || currentOwner != owner {
		s.mu.Unlock()
		privateFailure(conn, "503 Service Unavailable")
		return
	}
	err = s.ordinaryIngress(conn)
	if err == nil {
		err = s.private.replays.Consume(verified, time.Now())
	}
	if err == nil {
		tunnel.wg.Add(1)
	}
	s.mu.Unlock()
	if err != nil {
		privateFailure(conn, "403 Forbidden")
		return
	}
	defer tunnel.wg.Done()
	pairing, cancel := context.WithDeadline(parent, until)
	data, err := s.pairConnection(pairing, tunnel, owner)
	cancel()
	if err != nil {
		privateFailure(conn, "503 Service Unavailable")
		return
	}
	defer finishPairedIngress(data)
	// Pairing can spend most of the first lease. Refresh custody before sending
	// success and before either direction can expose database bytes.
	refresh, cancel := context.WithDeadline(parent, until)
	until, err = s.authorizePrivate(refresh, token, verified, tunnel, owner)
	cancel()
	if err != nil || !until.After(time.Now()) {
		privateFailure(conn, "403 Forbidden")
		return
	}
	external := &bufferedConnection{Conn: conn, reader: reader}
	stream, ok := s.beginTunnelStream(tunnel, owner, external, data)
	if !ok {
		privateFailure(conn, "503 Service Unavailable")
		return
	}
	defer s.endTunnelStream(tunnel, stream)
	if conn.SetDeadline(until) != nil || data.SetDeadline(until) != nil {
		return
	}
	guard, cancelGuard := context.WithCancel(parent)
	guardDone := make(chan struct{})
	go func() {
		defer close(guardDone)
		s.renewPrivate(guard, token, verified, tunnel, owner, external, data, until)
	}()
	defer func() { cancelGuard(); <-guardDone }()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	tunnel.bridgeConnectionsWithLogging(external, data, tunnel.createConnectionLog(remote.IP.String(), remote.Port))
}

func (s *Server) authorizePrivate(parent context.Context, token string, verified transport.VerifiedOpen, expected *Tunnel, owner net.Conn) (time.Time, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	s.mu.RLock()
	t, currentOwner, active := s.privateOwnerLocked(verified.Claims())
	s.mu.RUnlock()
	if !active || t != expected || currentOwner != owner || s.private.tokenActive == nil {
		return time.Time{}, transport.ErrAuthority
	}
	tokenUntil, err := s.private.tokenActive(ctx, t)
	if err != nil {
		return time.Time{}, transport.ErrAuthority
	}
	until, err := s.private.authority.Authorize(ctx, token, verified)
	if err != nil || ctx.Err() != nil {
		return time.Time{}, transport.ErrAuthority
	}
	if !tokenUntil.IsZero() && tokenUntil.Before(until) {
		until = tokenUntil
	}
	// An injected authority has the same short-deadline contract as HTTP.
	return verified.LeaseDeadline(verified.Digest(), until.Unix(), time.Now())
}

func (s *Server) renewPrivate(ctx context.Context, token string, verified transport.VerifiedOpen, tunnel *Tunnel, owner, external, data net.Conn, until time.Time) {
	defer closeShutdownConnection(external)
	defer closeShutdownConnection(data)
	for {
		remaining := time.Until(until)
		if remaining <= 0 {
			return
		}
		timer := time.NewTimer(min(5*time.Second, max(250*time.Millisecond, remaining/3)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-tunnel.stopChan:
			timer.Stop()
			return
		case <-timer.C:
		}
		request, cancel := context.WithDeadline(ctx, until)
		next, err := s.authorizePrivate(request, token, verified, tunnel, owner)
		cancel()
		if err != nil || !time.Now().Before(until) {
			return
		}
		if external.SetDeadline(next) != nil || data.SetDeadline(next) != nil {
			return
		}
		until = next
	}
}
