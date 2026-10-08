package server

import (
	"context"
	"net"

	"rabbit.go/internal/database"
	"rabbit.go/transport"
	"time"
)

type pendingConnection struct {
	tunnel      *Tunnel
	owner       net.Conn
	ready       chan net.Conn
	rejected    chan struct{}
	reservation *transport.ReservationPair
	handlerDone <-chan struct{}
}

type tunnelStream struct {
	owner    net.Conn
	external net.Conn
	data     net.Conn
}

// replaceControlOwnerLocked fences the old owner before any new stream can be
// admitted. The caller closes returned sockets after releasing the server lock.
func (s *Server) replaceControlOwnerLocked(t *Tunnel, next net.Conn) []net.Conn {
	previous := t.Client
	if previous == next {
		return nil
	}
	t.Client = next
	if next != nil {
		t.controlEpoch++
	}
	t.busyOwner = nil
	if previous == nil {
		return nil
	}
	connections := []net.Conn{previous}
	for id, pending := range s.pendingConns {
		if pending.tunnel != t || pending.owner != previous {
			continue
		}
		delete(s.pendingConns, id)
		if pending.rejected != nil {
			close(pending.rejected)
		}
		select {
		case data := <-pending.ready:
			if data != nil {
				// The pairing goroutine retains its work acknowledgement. Close
				// this socket now, but let that owner consume or drain the slot.
				if _, retained := data.(*pairedIngress); retained {
					pending.ready <- data
				}
				connections = append(connections, data)
			}
		default:
		}
	}
	for stream := range t.streams {
		if stream.owner == previous {
			connections = append(connections, stream.external, stream.data)
		}
	}
	return connections
}

func closeReplacedOwner(connections []net.Conn) {
	for _, conn := range connections {
		if conn != nil {
			closeShutdownConnection(conn)
		}
	}
}

func (t *Tunnel) initLifecycle(s *Server) {
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	t.ctx, t.cancel = context.WithCancel(parent)
	t.streams = make(map[*tunnelStream]struct{})
}

// The server lock orders ownership checks, relay admission and revocation.
func (s *Server) controlOwnerActiveLocked(t *Tunnel, owner net.Conn) bool {
	if t == nil || owner == nil || t.Client != owner {
		return false
	}
	select {
	case <-s.stopChan:
		return false
	default:
	}
	select {
	case <-t.stopChan:
		return false
	default:
		return true
	}
}

func (s *Server) signalTunnelStopLocked(t *Tunnel) {
	t.stopOnce.Do(func() {
		close(t.stopChan)
		if t.cancel != nil {
			t.cancel()
		}
	})
}

func (s *Server) stopControlOwner(t *Tunnel, owner net.Conn) {
	s.mu.Lock()
	current := s.controlOwnerActiveLocked(t, owner)
	if current {
		s.signalTunnelStopLocked(t)
	}
	s.mu.Unlock()
	if current {
		s.stopTunnel(t)
	}
}

func (s *Server) beginTunnelStream(t *Tunnel, owner, external, data net.Conn) (*tunnelStream, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.controlOwnerActiveLocked(t, owner) {
		return nil, false
	}
	stream := &tunnelStream{owner: owner, external: external, data: data}
	if t.streams == nil {
		t.streams = make(map[*tunnelStream]struct{})
	}
	t.streams[stream] = struct{}{}
	return stream, true
}

func (s *Server) endTunnelStream(t *Tunnel, stream *tunnelStream) {
	s.mu.Lock()
	delete(t.streams, stream)
	s.mu.Unlock()
}

func (s *Server) withActiveTunnelMetadata(t *Tunnel, owner net.Conn, operation func(context.Context) error) error {
	t.metadataMu.Lock()
	defer t.metadataMu.Unlock()
	s.mu.RLock()
	active := s.controlOwnerActiveLocked(t, owner)
	s.mu.RUnlock()
	if !active {
		return net.ErrClosed
	}
	parent := t.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, metadataTimeout)
	defer cancel()
	return operation(ctx)
}

func (t *Tunnel) finishStreamLog(record *database.ConnectionLog, received, sent int64, status string, message *string) {
	if record == nil || t.server == nil || t.server.streamAudit == nil {
		return
	}
	completed := *record
	ended := time.Now()
	completed.EndedAt = &ended
	completed.BytesReceived, completed.BytesSent = received, sent
	completed.Status = status
	if message != nil {
		bounded := *message
		if len(bounded) > 512 {
			bounded = bounded[:512]
		}
		completed.ErrorMessage = &bounded
	}
	t.server.streamAudit.submit(completed)
}

// rejectPending consumes only an unpaired stream owned by the negotiated control socket.
func (s *Server) rejectPending(t *Tunnel, owner net.Conn, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := s.pendingConns[id]
	if t.busyOwner != owner || !s.controlOwnerActiveLocked(t, owner) || pending == nil || pending.tunnel != t || pending.owner != owner {
		return
	}
	delete(s.pendingConns, id)
	if pending.rejected != nil {
		close(pending.rejected)
	}
}
