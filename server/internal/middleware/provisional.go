package middleware

import (
	"errors"
	"net"
	"sync"
	"time"

	"rabbit.go/transport"
)

var ErrProvisionalState = errors.New("connection admission or ownership is no longer valid")

// ProvisionalConnection is a bounded handshake that must be classified before
// database traffic. Only ordinary admission uses per-IP rate/concurrency limits.
// Its process slot remains charged until Close succeeds and every owner joins.
// This path is not selectable from operator configuration yet.
type ProvisionalConnection struct {
	conn     net.Conn
	sm       *SecurityMiddleware
	identity *ProvisionalConnection
	socket   *transport.AdmittedSocket
	ip       net.IP
	ipText   string
	// Mutable ownership and classification fields are protected by sm.mu.
	classified, ordinary, closing, closed, joined, released bool
	work                                                    int
	closeOnce                                               sync.Once
	closeErr                                                error
}

// ConnectionWork holds a distinct trusted owner across a DATA handoff. A copy
// of a handle cannot acknowledge another owner's work.
type ConnectionWork struct {
	connection *ProvisionalConnection
	identity   *ConnectionWork
	joined     bool
}

// EnableReservations is construction-only. Refuse a mode switch with live
// legacy sockets, a different ceiling, or an already-used ledger. After this
// succeeds every listener must call AcceptProvisional; legacy admission fails.
func (sm *SecurityMiddleware) EnableReservations(ledger *transport.ReservationAccounting) error {
	if sm == nil || ledger == nil {
		return ErrProvisionalState
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s := ledger.Snapshot(time.Now())
	if sm.reservations != nil || sm.globalConnections != 0 || s.Limit != sm.config.MaxGlobalConnections ||
		s.LiveSockets != 0 || s.Parents != 0 || s.Ordinary != 0 || s.Handshakes != 0 || s.Draining {
		return ErrProvisionalState
	}
	sm.reservations = ledger
	sm.provisional = make(map[*transport.AdmittedSocket]*ProvisionalConnection)
	return nil
}

// AcceptProvisional owns no socket on error; its caller must close raw. The
// fixed handshake partition bounds work before authentication and per-IP state.
func (sm *SecurityMiddleware) AcceptProvisional(raw net.Conn) (*ProvisionalConnection, error) {
	if sm == nil || raw == nil {
		return nil, ErrProvisionalState
	}
	address, ok := raw.RemoteAddr().(*net.TCPAddr)
	if !ok || address.IP == nil {
		return nil, ErrProvisionalState
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.reservations == nil || sm.globalConnections >= sm.config.MaxGlobalConnections {
		return nil, ErrProvisionalState
	}
	socket, err := sm.reservations.Accept(time.Now())
	if err != nil {
		return nil, err
	}
	p := &ProvisionalConnection{conn: &secureConnection{Conn: raw, sm: sm, untracked: true},
		sm: sm, socket: socket, ip: append(net.IP(nil), address.IP...), ipText: address.IP.String(), work: 1}
	p.identity = p
	sm.provisional[socket] = p
	sm.globalConnections++
	return p, nil
}

func (p *ProvisionalConnection) validLocked() bool {
	return p.identity == p && !p.released && p.sm.provisional[p.socket] == p
}

func (p *ProvisionalConnection) classifiableLocked() bool {
	return p.validLocked() && !p.classified && !p.closing && !p.joined
}

func (p *ProvisionalConnection) AdmitOrdinary() error {
	if p == nil || p.sm == nil {
		return ErrProvisionalState
	}
	p.sm.mu.Lock()
	defer p.sm.mu.Unlock()
	if !p.classifiableLocked() {
		return ErrProvisionalState
	}
	now := time.Now()
	stats, trusted, err := p.sm.checkIPLocked(p.ipText, p.ip, now)
	if err != nil {
		return err
	}
	if err := p.sm.reservations.AdmitOrdinary(p.socket, now); err != nil {
		return err
	}
	p.sm.recordIPAdmissionLocked(stats, trusted, now)
	p.classified, p.ordinary = true, true
	return nil
}

// Reserved promotion requires the same typed ticket/parent checks as the
// ledger. Callers must hold current route ownership and live-authority custody.
func (p *ProvisionalConnection) AdmitData(v transport.VerifiedReservation, until time.Time) (*transport.ReservationPair, error) {
	return p.admitPrivate(v, until, false)
}

func (p *ProvisionalConnection) AdmitAuxiliary(v transport.VerifiedReservation, until time.Time) (*transport.ReservationPair, error) {
	return p.admitPrivate(v, until, true)
}

func (p *ProvisionalConnection) admitPrivate(v transport.VerifiedReservation, until time.Time, auxiliary bool) (*transport.ReservationPair, error) {
	if p == nil || p.sm == nil {
		return nil, ErrProvisionalState
	}
	p.sm.mu.Lock()
	defer p.sm.mu.Unlock()
	if !p.classifiableLocked() {
		return nil, ErrProvisionalState
	}
	var pair *transport.ReservationPair
	var err error
	if auxiliary {
		pair, err = p.sm.reservations.AdmitAuxiliary(v, until, p.socket, time.Now())
	} else {
		pair, err = p.sm.reservations.AdmitData(v, until, p.socket, time.Now())
	}
	if err == nil {
		p.classified = true
	}
	return pair, err
}

func (p *ProvisionalConnection) AdmitDATASocket(pair *transport.ReservationPair) error {
	if p == nil || p.sm == nil || pair == nil {
		return ErrProvisionalState
	}
	p.sm.mu.Lock()
	defer p.sm.mu.Unlock()
	if !p.classifiableLocked() {
		return ErrProvisionalState
	}
	if err := pair.AdmitDATASocket(p.socket, time.Now()); err != nil {
		return err
	}
	p.classified = true
	return nil
}

func (p *ProvisionalConnection) RetainWork() (*ConnectionWork, error) {
	if p == nil || p.sm == nil {
		return nil, ErrProvisionalState
	}
	p.sm.mu.Lock()
	defer p.sm.mu.Unlock()
	if !p.validLocked() || p.closing || p.joined {
		return nil, ErrProvisionalState
	}
	w := &ConnectionWork{connection: p}
	w.identity = w
	p.work++
	return w, nil
}

// Joined acknowledges only the initial handler. A retained pairing/relay owner
// must separately join; neither a handler return nor a deadline releases it.
func (p *ProvisionalConnection) Joined() error {
	if p == nil || p.sm == nil || p.identity != p {
		return ErrProvisionalState
	}
	p.sm.mu.Lock()
	defer p.sm.mu.Unlock()
	if !p.joined {
		if !p.validLocked() {
			return ErrProvisionalState
		}
		p.joined = true
		p.work--
	}
	return p.releaseLocked()
}

func (w *ConnectionWork) Joined() error {
	if w == nil || w.identity != w || w.connection == nil {
		return ErrProvisionalState
	}
	p := w.connection
	p.sm.mu.Lock()
	defer p.sm.mu.Unlock()
	if !w.joined {
		if !p.validLocked() {
			return ErrProvisionalState
		}
		w.joined = true
		p.work--
	}
	return p.releaseLocked()
}

func (p *ProvisionalConnection) releaseLocked() error {
	if p.released || !p.closed || p.work != 0 {
		return nil
	}
	if err := p.socket.Joined(time.Now()); err != nil {
		return err
	}
	p.sm.globalConnections--
	if p.ordinary {
		stats := p.sm.ipStats[p.ipText]
		stats.CurrentConnections--
		stats.LastActivity = time.Now()
	}
	delete(p.sm.provisional, p.socket)
	p.released = true
	return nil
}

func (p *ProvisionalConnection) Close() error {
	if p == nil || p.sm == nil || p.identity != p {
		return ErrProvisionalState
	}
	p.closeOnce.Do(func() {
		p.sm.mu.Lock()
		p.closing = true
		p.sm.mu.Unlock()
		err := p.conn.Close()
		p.sm.mu.Lock()
		defer p.sm.mu.Unlock()
		p.closed = err == nil || errors.Is(err, net.ErrClosed)
		p.closeErr = errors.Join(err, p.releaseLocked())
	})
	return p.closeErr
}

func (p *ProvisionalConnection) CloseWrite() error {
	if half, ok := p.conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return ErrProvisionalState
}

// Keep the accepted connection private: callers must not replace the physical
// socket whose closure releases this allocation.
func (p *ProvisionalConnection) Read(data []byte) (int, error)     { return p.conn.Read(data) }
func (p *ProvisionalConnection) Write(data []byte) (int, error)    { return p.conn.Write(data) }
func (p *ProvisionalConnection) LocalAddr() net.Addr               { return p.conn.LocalAddr() }
func (p *ProvisionalConnection) RemoteAddr() net.Addr              { return p.conn.RemoteAddr() }
func (p *ProvisionalConnection) SetDeadline(until time.Time) error { return p.conn.SetDeadline(until) }
func (p *ProvisionalConnection) SetReadDeadline(until time.Time) error {
	return p.conn.SetReadDeadline(until)
}
func (p *ProvisionalConnection) SetWriteDeadline(until time.Time) error {
	return p.conn.SetWriteDeadline(until)
}

// ReservationCleanup returns exact sockets and pending pair owners that need
// cancellation. It performs no I/O and never acknowledges their completion.
func (sm *SecurityMiddleware) ReservationCleanup(now time.Time, drain bool) ([]*ProvisionalConnection, []*transport.ReservationPair) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.reservations == nil {
		return nil, nil
	}
	if drain {
		sm.reservations.Drain(now)
	}
	c := sm.reservations.Cleanup(now)
	connections := make([]*ProvisionalConnection, 0, len(c.Sockets))
	for _, socket := range c.Sockets {
		if p := sm.provisional[socket]; p != nil {
			connections = append(connections, p)
		}
	}
	return connections, c.Setups
}
