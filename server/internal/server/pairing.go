package server

import (
	"context"
	"errors"
	"net"
	"time"
)

var errPairingUnavailable = errors.New("database tunnel is unavailable")

// pairConnection is the single DATA-pairing path for assigned-port and private
// ingress. The caller owns its external socket and the tunnel wait-group slot.
func (s *Server) pairConnection(ctx context.Context, t *Tunnel, owner net.Conn) (net.Conn, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errPairingUnavailable
	}
	id, err := generateTunnelID()
	if err != nil {
		return nil, errPairingUnavailable
	}
	pending := &pendingConnection{tunnel: t, owner: owner, ready: make(chan net.Conn, 1), rejected: make(chan struct{})}
	s.mu.Lock()
	if !s.controlOwnerActiveLocked(t, owner) {
		s.mu.Unlock()
		return nil, errPairingUnavailable
	}
	s.pendingConns[id] = pending
	s.mu.Unlock()
	defer func() {
		var unused net.Conn
		s.mu.Lock()
		delete(s.pendingConns, id)
		select {
		case unused = <-pending.ready:
		default:
		}
		s.mu.Unlock()
		if unused != nil {
			closeShutdownConnection(unused)
		}
	}()
	if err := t.writeControl(owner, "CONNECT\nCONN_ID:%s\n", id); err != nil {
		return nil, errPairingUnavailable
	}
	timer := time.NewTimer(s.pairingTimeout())
	defer timer.Stop()
	select {
	case data := <-pending.ready:
		s.mu.RLock()
		active := s.controlOwnerActiveLocked(t, owner)
		s.mu.RUnlock()
		if !active || ctx.Err() != nil {
			closeShutdownConnection(data)
			return nil, errPairingUnavailable
		}
		return data, nil
	case <-pending.rejected:
	case <-t.stopChan:
	case <-s.stopChan:
	case <-ctx.Done():
	case <-timer.C:
		return nil, context.DeadlineExceeded
	}
	return nil, errPairingUnavailable
}
