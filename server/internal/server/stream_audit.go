package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"rabbit.go/internal/database"
)

type streamAuditQueue struct {
	items                              chan database.ConnectionLog
	write                              func(context.Context, database.ConnectionLog) error
	writeTimeout, shutdownTimeout      time.Duration
	ctx                                context.Context
	cancel                             context.CancelFunc
	done                               chan struct{}
	mu                                 sync.RWMutex
	closed                             bool
	closeOnce                          sync.Once
	accepted, written, dropped, failed atomic.Uint64
	inflight                           atomic.Int64
}

func newStreamAuditQueue(capacity int, writeTimeout, shutdownTimeout time.Duration, write func(context.Context, database.ConnectionLog) error) *streamAuditQueue {
	ctx, cancel := context.WithCancel(context.Background())
	queue := &streamAuditQueue{items: make(chan database.ConnectionLog, capacity), write: write, writeTimeout: writeTimeout, shutdownTimeout: shutdownTimeout, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go queue.run()
	return queue
}

func (q *streamAuditQueue) submit(record database.ConnectionLog) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		q.dropped.Add(1)
		return
	}
	select {
	case q.items <- record:
		q.accepted.Add(1)
	default:
		q.dropped.Add(1)
	}
}

func (q *streamAuditQueue) run() {
	defer close(q.done)
	defer func() {
		for range q.items {
			q.dropped.Add(1)
		}
	}()
	for {
		if q.ctx.Err() != nil {
			return
		}
		select {
		case <-q.ctx.Done():
			return
		case record, ok := <-q.items:
			if !ok {
				return
			}
			if q.ctx.Err() != nil {
				q.dropped.Add(1)
				return
			}
			ctx, cancel := context.WithTimeout(q.ctx, q.writeTimeout)
			q.inflight.Add(1)
			err := q.write(ctx, record)
			q.inflight.Add(-1)
			cancel()
			if err != nil {
				q.failed.Add(1)
			} else {
				q.written.Add(1)
			}
		}
	}
}

// close drains within one total budget. Cancelled database writes cannot delay relay teardown.
func (q *streamAuditQueue) close() {
	_ = q.closeContext(context.Background())
}

func (q *streamAuditQueue) closeContext(parent context.Context) error {
	q.closeInput()
	ctx, cancel := context.WithTimeout(parent, q.shutdownTimeout)
	defer cancel()
	defer q.cancel()
	select {
	case <-q.done:
		if q.failed.Load() != 0 || q.dropped.Load() != 0 {
			return errors.New("stream audit contains failed or dropped records")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *streamAuditQueue) closeInput() {
	q.closeOnce.Do(func() { q.mu.Lock(); q.closed = true; close(q.items); q.mu.Unlock() })
}

func (q *streamAuditQueue) abort() {
	q.closeInput()
	q.cancel()
}

func (q *streamAuditQueue) stats() map[string]interface{} {
	drained := false
	select {
	case <-q.done:
		drained = true
	default:
	}
	return map[string]interface{}{"enabled": true, "drain_complete": drained, "inflight": q.inflight.Load(), "queue_capacity": cap(q.items), "queue_depth": len(q.items), "accepted": q.accepted.Load(), "written": q.written.Load(), "dropped": q.dropped.Load(), "write_failures": q.failed.Load()}
}

func (s *Server) runtimeStats() map[string]interface{} {
	audit := map[string]interface{}{"enabled": false}
	if s.streamAudit != nil {
		audit = s.streamAudit.stats()
	}
	s.mu.RLock()
	pending, active := len(s.pendingConns), 0
	for _, tunnel := range s.tunnels {
		active += len(tunnel.streams)
	}
	s.mu.RUnlock()
	return map[string]interface{}{"stream_audit": audit, "pending_streams": pending, "active_streams": active}
}
