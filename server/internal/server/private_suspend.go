package server

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"rabbit.go/transport"
)

// Pausing permanently stops worker-to-source DATA. Only bounded source completion
// can pass after a positive cleanup lease. Query writes never resume, even if a
// later ordinary lease would succeed. A busy write prevents retention.
type privateDataGate struct {
	mu          sync.RWMutex
	paused      bool
	receiveOnce sync.Once
	remaining   int64
	discarded   int64
	done        chan struct{}
	suspended   chan struct{}
	authorized  chan struct{}
	once        sync.Once
}

func newPrivateDataGate() *privateDataGate {
	return &privateDataGate{done: make(chan struct{}), suspended: make(chan struct{}), authorized: make(chan struct{}), remaining: privateAbortByteLimit}
}
func (g *privateDataGate) close() { g.once.Do(func() { close(g.done) }) }
func (g *privateDataGate) pause() bool {
	if !g.mu.TryLock() {
		return false
	}
	defer g.mu.Unlock()
	select {
	case <-g.done:
		return false
	default:
	}
	if !g.paused {
		g.paused = true
		close(g.suspended)
	}
	return true
}
func (g *privateDataGate) allowReceive()  { g.receiveOnce.Do(func() { close(g.authorized) }) }
func (g *privateDataGate) isPaused() bool { g.mu.RLock(); defer g.mu.RUnlock(); return g.paused }
func (g *privateDataGate) waitReceive() error {
	if !g.isPaused() {
		return nil
	}
	select {
	case <-g.done:
		return net.ErrClosed
	case <-g.authorized:
	}
	select {
	case <-g.done:
		return net.ErrClosed
	default:
		return nil
	}
}
func (g *privateDataGate) discard(n int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.discarded += int64(n)
	return g.discarded <= privateAbortByteLimit
}

// source distinguishes the source-side socket from the worker-side socket.
// During cleanup only source.Read and worker.Write can carry bounded completion
// bytes. Worker input is discarded to detect closure; no byte reaches source.
type privateGatedConnection struct {
	net.Conn
	gate   *privateDataGate
	source bool
}

func (c *privateGatedConnection) Read(b []byte) (int, error) {
	for {
		n, err := c.Conn.Read(b)
		if !c.gate.isPaused() {
			return n, err
		}
		if c.source && n > 0 {
			if e := c.gate.waitReceive(); e != nil {
				return 0, e
			}
			return n, err
		}
		if err != nil {
			c.gate.close()
			return 0, err
		}
		if !c.gate.discard(n) {
			c.gate.close()
			return 0, net.ErrClosed
		}
	}
}
func (c *privateGatedConnection) Write(b []byte) (int, error) {
	c.gate.mu.RLock()
	if !c.gate.paused {
		select {
		case <-c.gate.done:
			c.gate.mu.RUnlock()
			return 0, net.ErrClosed
		default:
		}
		n, err := c.Conn.Write(b)
		c.gate.mu.RUnlock()
		return n, err
	}
	c.gate.mu.RUnlock()
	if c.source {
		if !c.gate.discard(len(b)) {
			c.gate.close()
			return 0, net.ErrClosed
		}
		return len(b), nil
	}
	if err := c.gate.waitReceive(); err != nil {
		return 0, err
	}
	c.gate.mu.Lock()
	limit := min(int64(len(b)), c.gate.remaining)
	c.gate.remaining -= limit
	c.gate.mu.Unlock()
	if limit == 0 {
		c.gate.close()
		return 0, net.ErrClosed
	}
	n, err := c.Conn.Write(b[:limit])
	if int64(len(b)) > limit {
		c.gate.close()
		if err == nil {
			err = io.ErrShortWrite
		}
	}
	return n, err
}
func (c *privateGatedConnection) Close() error { c.gate.close(); return c.Conn.Close() }
func (c *privateGatedConnection) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return c.Close()
}

// retainPrivateCleanup runs only after an ordinary lease denial. It pauses DATA
// before asking for separate cleanup authority. Any missing or uncertain grant
// closes the pair. Positive responses cannot move the first fixed deadline.
func (s *Server) retainPrivateCleanup(ctx context.Context, verified transport.VerifiedOpen, external, data net.Conn) {
	s.mu.RLock()
	entry := s.private.accepted[verified.Digest()]
	s.mu.RUnlock()
	if entry == nil || entry.gate == nil || !entry.gate.pause() {
		return
	}
	var fixed transport.CleanupLeaseResponse
	for {
		s.mu.RLock()
		active := s.acceptedRetentionActiveLocked(entry)
		s.mu.RUnlock()
		if !active || s.private.cleanup == nil || s.private.tokenActive == nil {
			return
		}
		check, stop := context.WithTimeout(ctx, time.Second)
		tokenUntil, err := s.private.tokenActive(check, entry.tunnel)
		var lease transport.CleanupLeaseResponse
		if err == nil {
			lease, err = s.private.cleanup.ReadCleanupLease(check, transport.CleanupLeaseRequest{Version: 1, DataTicketSHA256: verified.Digest(), AcceptedOpen: entry.receipt})
		}
		checkErr := check.Err()
		stop()
		now := time.Now()
		if err != nil || checkErr != nil || lease.ValidateAt(now) != nil || time.Unix(lease.ValidUntil, 0).After(verified.SessionDeadline()) || (!tokenUntil.IsZero() && !tokenUntil.After(now)) {
			return
		}
		if !s.pinPrivateCleanup(entry, lease) {
			return
		}
		if fixed.ValidUntil == 0 {
			fixed = lease
		} else if fixed.CancellationStartedAt != lease.CancellationStartedAt || lease.ValidUntil > fixed.ValidUntil {
			return
		}
		until := time.Unix(lease.ValidUntil, 0)
		if !tokenUntil.IsZero() && tokenUntil.Before(until) {
			until = tokenUntil
		}
		s.mu.RLock()
		active = s.acceptedRetentionActiveLocked(entry)
		s.mu.RUnlock()
		if !active {
			return
		}
		if external.SetDeadline(until) != nil || data.SetDeadline(until) != nil {
			return
		}
		timer := time.NewTimer(min(250*time.Millisecond, time.Until(until)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-entry.gate.done:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (s *Server) acceptedRetentionActiveLocked(entry *acceptedPrivateParent) bool {
	if entry == nil || entry.gate == nil || s.private.accepted[entry.verified.Digest()] != entry || !time.Now().Before(entry.verified.SessionDeadline()) {
		return false
	}
	select {
	case <-entry.gate.done:
		return false
	default:
	}
	tunnel, owner, active := s.privateOwnerLocked(entry.verified.Claims())
	_, held := entry.tunnel.streams[entry.stream]
	return active && held && tunnel == entry.tunnel && owner == entry.owner
}
