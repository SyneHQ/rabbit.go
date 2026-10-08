package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

const shutdownTimeout = 30 * time.Second

// ErrShutdownIncomplete means the one teardown owner still holds resources.
// A caller may use WaitShutdown; it must not close pools behind that owner.
var ErrShutdownIncomplete = errors.New("server shutdown incomplete")

// Stop applies one total 30-second budget to the complete shutdown.
func (s *Server) Stop() error { return s.Shutdown(context.Background()) }

// Shutdown starts teardown once. The first caller's context can shorten, but
// never extend, its total budget. Later callers cannot restart the deadline.
// If a dependency ignores cancellation, the same teardown owner keeps custody
// until it joins. Returning an error does not claim those resources are closed.
func (s *Server) Shutdown(parent context.Context) error {
	if parent == nil {
		return errors.New("shutdown requires a context")
	}
	s.stopOnce.Do(func() {
		ctx, cancel := context.WithTimeout(parent, shutdownTimeout)
		s.shutdownMu.Lock()
		s.ensureCleanupContextLocked()
		s.shutdownCtx, s.shutdownDone = ctx, make(chan struct{})
		cleanupCancel := s.cleanupCancel
		s.shutdownMu.Unlock()
		// Fence admission before any caller can receive an incomplete result.
		close(s.stopChan)
		if s.cancel != nil {
			s.cancel()
		}
		if s.apiServer != nil {
			s.apiServer.beginStop()
		}
		stopCancellation := context.AfterFunc(ctx, func() {
			cleanupCancel()
			if s.streamAudit != nil {
				s.streamAudit.abort()
			}
		})
		go func() {
			defer cancel()
			// Publish completion before canceling the internal deadline context.
			defer s.finishShutdown(ctx)
			defer cleanupCancel()
			defer stopCancellation()
			s.shutdown(ctx)
		}()
	})
	select {
	case <-s.shutdownDone:
		return s.shutdownError()
	case <-s.shutdownCtx.Done():
		return s.incompleteShutdown(s.shutdownCtx.Err())
	case <-parent.Done():
		return s.incompleteShutdown(parent.Err())
	}
}

// WaitShutdown joins the existing teardown owner without changing its deadline.
// A completed shutdown still returns any deadline or cleanup failure it observed.
func (s *Server) WaitShutdown(ctx context.Context) error {
	if ctx == nil {
		return errors.New("shutdown wait requires a context")
	}
	s.shutdownMu.Lock()
	done := s.shutdownDone
	s.shutdownMu.Unlock()
	if done == nil {
		return errors.New("shutdown has not started")
	}
	select {
	case <-done:
		return s.shutdownError()
	case <-ctx.Done():
		return s.incompleteShutdown(ctx.Err())
	}
}

func (s *Server) incompleteShutdown(cause error) error {
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	if s.shutdownFinished {
		return errors.Join(s.shutdownErr, s.shutdownCause)
	}
	// Only the shared deadline/cancellation is sticky. A later caller may stop
	// waiting without changing a shutdown that still has time to finish.
	if s.shutdownCause == nil {
		s.shutdownCause = s.shutdownCtx.Err()
	}
	return errors.Join(ErrShutdownIncomplete, cause, s.shutdownErr, s.shutdownCause)
}

func (s *Server) finishShutdown(ctx context.Context) {
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	if s.shutdownCause == nil {
		s.shutdownCause = ctx.Err()
	}
	s.shutdownFinished = true
	close(s.shutdownDone)
}

func (s *Server) shutdownError() error {
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	return errors.Join(s.shutdownErr, s.shutdownCause)
}

func (s *Server) recordShutdownError(err error) {
	if err == nil {
		return
	}
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	if s.shutdownCtx != nil {
		s.shutdownErr = errors.Join(s.shutdownErr, err)
	}
}

func (s *Server) ensureCleanupContextLocked() {
	if s.cleanupCtx == nil {
		s.cleanupCtx, s.cleanupCancel = context.WithCancel(context.Background())
	}
}

func (s *Server) cleanupContext() (context.Context, context.CancelFunc) {
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	s.ensureCleanupContextLocked()
	deadline := time.Now().Add(metadataTimeout)
	if s.shutdownCtx != nil {
		if end, ok := s.shutdownCtx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
	}
	return context.WithDeadline(s.cleanupCtx, deadline)
}

func closeShutdownConnection(conn net.Conn) {
	// Expired I/O interrupts TLS close-notify and any concurrent control write.
	_ = conn.SetDeadline(time.Now())
	_ = conn.Close()
}

func (s *Server) shutdown(ctx context.Context) {
	s.lifecycleMu.Lock()
	s.stopped = true
	if s.controlListener != nil {
		_ = s.controlListener.Close()
	}
	if s.privateListener != nil {
		_ = s.privateListener.Close()
	}
	s.lifecycleMu.Unlock()

	// Stop API admission now; its grace period shares the same deadline as
	// tunnel cleanup. The owned task always joins before metadata pools close.
	var apiDone chan error
	if s.apiServer != nil {
		apiDone = make(chan error, 1)
		go func() { apiDone <- s.apiServer.stop(ctx) }()
	}
	s.mu.RLock()
	connections := make([]net.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	tunnels := make(map[*Tunnel]struct{}, len(s.tunnels)+len(s.closingTunnels))
	for _, tunnel := range s.tunnels {
		tunnels[tunnel] = struct{}{}
	}
	for tunnel := range s.closingTunnels {
		tunnels[tunnel] = struct{}{}
	}
	s.mu.RUnlock()
	for _, conn := range connections {
		closeShutdownConnection(conn)
	}
	for tunnel := range tunnels {
		s.closeTunnelSockets(tunnel)
	}
	if s.runtimeRouter != nil {
		s.runtimeRouter.Close()
	}
	for tunnel := range tunnels {
		_ = s.stopTunnel(tunnel)
	}
	if apiDone != nil {
		if err := <-apiDone; err != nil {
			s.recordShutdownError(fmt.Errorf("management shutdown: %w", err))
		}
		// net/http.Shutdown and Close do not prove that handlers have returned.
		s.apiServer.handlers.Wait()
	}
	s.wg.Wait()
	if s.private != nil && s.private.close != nil {
		s.private.close()
	}
	if s.securityMiddleware != nil {
		s.securityMiddleware.Stop()
	}
	if s.streamAudit != nil {
		if err := s.streamAudit.closeContext(ctx); err != nil {
			s.recordShutdownError(fmt.Errorf("stream audit shutdown: %w", err))
		}
		// Never close a pool while an audit writer still owns a query on it.
		<-s.streamAudit.done
	}
	if s.closeDatabase != nil {
		if err := s.closeDatabase(); err != nil {
			s.recordShutdownError(fmt.Errorf("metadata pool cleanup: %w", err))
		}
	}
}
