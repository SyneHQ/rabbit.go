package server

import (
	"context"
	"fmt"
	"net"
	"time"
)

const (
	metadataTimeout     = 5 * time.Second
	controlWriteTimeout = 10 * time.Second
)

func (s *Server) metadataContext() (context.Context, context.CancelFunc) {
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, metadataTimeout)
}

func (s *Server) tunnelBindAddress() string {
	if s.config.TunnelBindAddress == "" {
		return "127.0.0.1"
	}
	return s.config.TunnelBindAddress
}

func writeControlFrame(conn net.Conn, format string, args ...any) error {
	return writeControlFrameTimeout(conn, controlWriteTimeout, format, args...)
}

func writeControlFrameTimeout(conn net.Conn, timeout time.Duration, format string, args ...any) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(conn, format, args...)
	clearErr := conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

func (t *Tunnel) writeControl(conn net.Conn, format string, args ...any) error {
	t.controlMu.Lock()
	defer t.controlMu.Unlock()
	timeout := controlWriteTimeout
	if t.server != nil {
		timeout = t.server.controlTimeout()
	}
	return writeControlFrameTimeout(conn, timeout, format, args...)
}

func normalizeBindAddresses(config Config) (Config, error) {
	if config.TunnelBindAddress == "" {
		config.TunnelBindAddress = "127.0.0.1"
	}
	if config.APIBindAddress == "" {
		config.APIBindAddress = "127.0.0.1"
	}
	if net.ParseIP(config.TunnelBindAddress) == nil || net.ParseIP(config.APIBindAddress) == nil {
		return config, fmt.Errorf("tunnel and API bind addresses must be literal IP addresses")
	}
	return config, nil
}
