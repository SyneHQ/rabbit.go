package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"rabbit.go/internal/middleware"
	"rabbit.go/transport"
)

// Construction-only integration. No operator configuration selects this mode.
// The notebook router must acquire explicit socket/work custody before it can
// share a server with reserved database traffic.
type reservedIngress struct {
	ledger   *transport.ReservationAccounting
	handlers map[*middleware.ProvisionalConnection]chan struct{}
}

func (s *Server) enableReservedIngress(limits transport.ReservationLimits) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.started || s.stopped || s.reserved != nil || s.private == nil || s.runtimeRouter != nil || s.securityMiddleware == nil {
		return middleware.ErrProvisionalState
	}
	ledger, err := transport.NewReservationAccounting(limits, s.private.replays)
	if err != nil {
		return err
	}
	if err := s.securityMiddleware.EnableReservations(ledger); err != nil {
		return err
	}
	s.reserved = &reservedIngress{ledger: ledger, handlers: make(map[*middleware.ProvisionalConnection]chan struct{})}
	return nil
}

// acceptIngress is shared by every database listener, including restored
// assigned ports. Unknown control/DATA and private sockets are provisional.
func (s *Server) acceptIngress(raw net.Conn, ordinary bool) (net.Conn, error) {
	if s.securityMiddleware == nil {
		return nil, middleware.ErrProvisionalState
	}
	if s.reserved == nil {
		if err := s.securityMiddleware.ValidateConnection(raw); err != nil {
			return nil, err
		}
		return s.securityMiddleware.WrapConnection(raw), nil
	}
	p, err := s.securityMiddleware.AcceptProvisional(raw)
	if err != nil {
		return nil, err
	}
	if ordinary {
		if err := p.AdmitOrdinary(); err != nil {
			closeShutdownConnection(p)
			_ = p.Joined()
			return nil, err
		}
	}
	s.mu.Lock()
	select {
	case <-s.stopChan:
		s.mu.Unlock()
		closeShutdownConnection(p)
		_ = p.Joined()
		return nil, net.ErrClosed
	default:
	}
	s.reserved.handlers[p] = make(chan struct{})
	s.mu.Unlock()
	return p, nil
}

func provisionalIngress(conn net.Conn) *middleware.ProvisionalConnection {
	switch c := conn.(type) {
	case *middleware.ProvisionalConnection:
		return c
	case *bufferedConnection:
		return provisionalIngress(c.Conn)
	case *tls.Conn:
		return provisionalIngress(c.NetConn())
	default:
		return nil
	}
}

func (s *Server) ordinaryIngress(conn net.Conn) error {
	if s.reserved == nil {
		return nil
	}
	p := provisionalIngress(conn)
	if p == nil {
		return middleware.ErrProvisionalState
	}
	return p.AdmitOrdinary()
}

// finishIngress is the initial handler's acknowledgement, not a socket close.
// A transferred DATA owner retains the same allocation independently.
func (s *Server) finishIngress(conn net.Conn) {
	if s.reserved == nil {
		return
	}
	p := provisionalIngress(conn)
	if p == nil {
		return
	}
	if err := p.Joined(); err != nil {
		s.recordShutdownError(err)
	}
	s.mu.Lock()
	if done := s.reserved.handlers[p]; done != nil {
		delete(s.reserved.handlers, p)
		close(done)
	}
	s.mu.Unlock()
}

type pairedIngress struct {
	net.Conn
	work       *middleware.ConnectionWork
	setupDone  <-chan struct{}
	finishOnce sync.Once
}

func (p *pairedIngress) CloseWrite() error {
	if half, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return middleware.ErrProvisionalState
}

// Only the pairing/relay owner calls finishPairedIngress after all its work has
// returned. Revocation and shutdown close sockets without forging this join.
func finishPairedIngress(conn net.Conn) {
	if conn == nil {
		return
	}
	closeShutdownConnection(conn)
	if p, ok := conn.(*pairedIngress); ok {
		p.finishOnce.Do(func() { _ = p.work.Joined() })
	}
}

func waitPairedIngress(ctx context.Context, conn net.Conn) error {
	p, ok := conn.(*pairedIngress)
	if !ok {
		return nil
	}
	select {
	case <-p.setupDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Called under Server.mu after the exact pending capability and current owner
// are verified. Its original handler is still charged until finishIngress.
func (s *Server) retainDATAIngress(conn net.Conn, pair *transport.ReservationPair) (net.Conn, error) {
	if s.reserved == nil {
		return conn, nil
	}
	p := provisionalIngress(conn)
	if p == nil || s.reserved.handlers[p] == nil {
		return nil, middleware.ErrProvisionalState
	}
	var err error
	if pair == nil {
		err = p.AdmitOrdinary()
	} else {
		err = p.AdmitDATASocket(pair)
	}
	if err != nil {
		return nil, err
	}
	work, err := p.RetainWork()
	if err != nil {
		return nil, err
	}
	return &pairedIngress{Conn: conn, work: work, setupDone: s.reserved.handlers[p]}, nil
}

func (s *Server) maintainReservedIngress() {
	defer s.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopChan:
			s.cleanupReservedIngress(true)
			return
		case <-ticker.C:
			s.cleanupReservedIngress(false)
		}
	}
}

func (s *Server) cleanupReservedIngress(drain bool) {
	connections, setups := s.securityMiddleware.ReservationCleanup(time.Now(), drain)
	wanted := make(map[*transport.ReservationPair]bool, len(setups))
	for _, pair := range setups {
		wanted[pair] = true
	}
	s.mu.Lock()
	for id, pending := range s.pendingConns {
		if pending.reservation != nil && wanted[pending.reservation] {
			delete(s.pendingConns, id)
			close(pending.rejected)
		}
	}
	s.mu.Unlock()
	for _, conn := range connections {
		closeShutdownConnection(conn)
	}
}

func (s *Server) reservedIngressError() error {
	if s.reserved == nil {
		return nil
	}
	state := s.reserved.ledger.Snapshot(time.Now())
	if state.LiveSockets != 0 || state.Parents != 0 || state.Pairing != 0 {
		return errors.New("reserved ingress retains unconfirmed socket or setup ownership")
	}
	return nil
}

// A caller's shutdown deadline does not manufacture socket completion. The
// existing teardown owner retains uncertain allocations until they actually
// join; Shutdown reports its bounded incomplete result while this owner waits.
func (s *Server) joinReservedIngress() {
	if s.reserved == nil {
		return
	}
	s.cleanupReservedIngress(true)
	if s.reservedIngressError() == nil {
		return
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		s.cleanupReservedIngress(true)
		if s.reservedIngressError() == nil {
			return
		}
	}
}
