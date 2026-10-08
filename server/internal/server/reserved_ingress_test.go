package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"rabbit.go/internal/middleware"
	notebookruntime "rabbit.go/internal/runtime"
	"rabbit.go/transport"
)

func reservedTestServer(t *testing.T) *Server {
	return reservedTestServerWithTimeout(t, 2*time.Second)
}

func reservedTestServerWithTimeout(t *testing.T, setupTimeout time.Duration) *Server {
	t.Helper()
	s := shutdownServer()
	s.pendingConns = make(map[string]*pendingConnection)
	s.connections = make(map[net.Conn]struct{})
	config := middleware.DefaultSecurityConfig()
	config.MaxGlobalConnections = 16
	config.TrustedNetworks = nil
	s.securityMiddleware = middleware.NewSecurityMiddleware(config)
	replays, err := transport.NewReplayRegistry(128)
	if err != nil {
		t.Fatal(err)
	}
	s.private = &privateConnect{replays: replays}
	if err := s.enableReservedIngress(transport.ReservationLimits{Sockets: 16, Handshakes: 2, Parents: 2,
		SetupTimeout: setupTimeout, TerminationWindow: time.Second}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := s.Shutdown(ctx)
		if errors.Is(err, ErrShutdownIncomplete) {
			t.Error("reserved fixture shutdown did not join", err)
		}
		if err := s.reservedIngressError(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func reservedTestIngress(t *testing.T, s *Server, ordinary bool) (net.Conn, net.Conn) {
	t.Helper()
	raw, peer, err := privateSourcePair()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := s.acceptIngress(raw, ordinary)
	if err != nil {
		raw.Close()
		peer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { closeShutdownConnection(conn); s.finishIngress(conn); peer.Close() })
	return conn, peer
}

func TestReservedDATAHandlerTransfersReadAheadWithoutReleasingRelay(t *testing.T) {
	s := reservedTestServer(t)
	owner, _ := ownerPipe(t)
	tunnel := &Tunnel{ID: "route", Client: owner, stopChan: make(chan struct{})}
	pending := &pendingConnection{tunnel: tunnel, owner: owner, ready: make(chan net.Conn, 1), rejected: make(chan struct{})}
	s.pendingConns["capability"] = pending
	conn, peer := reservedTestIngress(t, s, false)
	s.connections[conn] = struct{}{}
	s.wg.Add(1)
	go s.handleControlConnection(conn)
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(peer, "DATA:capability\nread-ahead"); err != nil {
		t.Fatal(err)
	}
	var data net.Conn
	select {
	case data = <-pending.ready:
	case <-time.After(time.Second):
		t.Fatal("DATA handler did not hand off its socket")
	}
	t.Cleanup(func() { finishPairedIngress(data) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitPairedIngress(ctx, data); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if state := s.reserved.ledger.Snapshot(time.Now()); state.LiveSockets != 1 || state.Ordinary != 1 {
		t.Fatal("handler return released its relay", state)
	}
	payload := make([]byte, len("read-ahead"))
	if _, err := io.ReadFull(data, payload); err != nil || string(payload) != "read-ahead" {
		t.Fatal("DATA framing lost buffered payload", err)
	}
	closeShutdownConnection(data)
	if s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 1 {
		t.Fatal("revocation forged relay completion")
	}
	finishPairedIngress(data)
	if s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 0 {
		t.Fatal("relay join retained socket admission")
	}
}

func TestReservedPairingWaitsForDATAHandlerAfterCancellation(t *testing.T) {
	s := reservedTestServer(t)
	owner, ownerPeer := ownerPipe(t)
	tunnel := &Tunnel{ID: "route", Client: owner, stopChan: make(chan struct{}), server: s}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { conn, err := s.pairConnection(ctx, tunnel, owner); finishPairedIngress(conn); result <- err }()
	ownerPeer.SetReadDeadline(time.Now().Add(time.Second))
	reader := bufio.NewReader(ownerPeer)
	line, err := reader.ReadString('\n')
	if err != nil || line != "CONNECT\n" {
		t.Fatal("pairing request failed", err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(strings.TrimPrefix(line, "CONN_ID:"))
	conn, _ := reservedTestIngress(t, s, false)
	s.handleDataConnection(conn, "DATA:"+id)
	cancel()
	select {
	case <-result:
		t.Fatal("pairing acknowledged an unfinished DATA handler")
	case <-time.After(20 * time.Millisecond):
	}
	s.finishIngress(conn)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled pairing succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("pairing did not join handler completion")
	}
	if s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 0 {
		t.Fatal("cancelled handoff lost its cleanup owner")
	}
}

func TestReservedReplacementClosesQueuedSocketWithoutStealingPairOwner(t *testing.T) {
	s := reservedTestServer(t)
	old, _ := ownerPipe(t)
	current, _ := ownerPipe(t)
	tunnel := &Tunnel{ID: "route", Client: old, stopChan: make(chan struct{})}
	conn, peer := reservedTestIngress(t, s, false)
	pending := &pendingConnection{tunnel: tunnel, owner: old, ready: make(chan net.Conn, 1), rejected: make(chan struct{})}
	s.mu.Lock()
	paired, err := s.retainDATAIngress(conn, nil)
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	pending.ready <- paired
	s.pendingConns["capability"] = pending
	closing := s.replaceControlOwnerLocked(tunnel, current)
	s.mu.Unlock()
	t.Cleanup(func() { finishPairedIngress(paired) })
	closeReplacedOwner(closing)
	requireOwnerPipeClosed(t, peer)
	s.finishIngress(conn)
	if len(pending.ready) != 1 || s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 1 {
		t.Fatal("replacement stole the pairing owner's acknowledgement")
	}
	finishPairedIngress(<-pending.ready)
	if s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 0 {
		t.Fatal("queued pairing owner could not join")
	}
}

type reservedCloseReceipt struct {
	net.Conn
	allow <-chan struct{}
}

func (c *reservedCloseReceipt) Close() error {
	err := c.Conn.Close()
	<-c.allow
	return err
}

func TestReservedAnonymousExpiryClosesWithoutAcknowledgingHandler(t *testing.T) {
	s := reservedTestServerWithTimeout(t, 100*time.Millisecond)
	raw, peer, err := privateSourcePair()
	if err != nil {
		t.Fatal(err)
	}
	allow := make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(allow) }) }
	conn, err := s.acceptIngress(&reservedCloseReceipt{Conn: raw, allow: allow}, false)
	if err != nil {
		raw.Close()
		peer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { unblock(); closeShutdownConnection(conn); s.finishIngress(conn); peer.Close() })
	s.wg.Add(1)
	go s.maintainReservedIngress()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	var payload [1]byte
	if _, err := peer.Read(payload[:]); !errors.Is(err, io.EOF) {
		t.Fatal("anonymous deadline did not close accepted socket", err)
	}
	if s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 1 {
		t.Fatal("expiry acknowledged unfinished handler work")
	}
	s.finishIngress(conn)
	if s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 1 {
		t.Fatal("peer EOF and handler join bypassed pending Close completion")
	}
	// A peer observes EOF before the local Close call necessarily returns. Join
	// that exact Close owner before expecting its physical completion receipt.
	unblock()
	closeShutdownConnection(conn)
	if s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 0 {
		t.Fatal("confirmed Close and handler join retained capacity")
	}
}

func TestReservedShutdownWaitsForRetainedWorkBeforeClosingDependencies(t *testing.T) {
	s := reservedTestServer(t)
	conn, _ := reservedTestIngress(t, s, true)
	work, err := provisionalIngress(conn).RetainWork()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = work.Joined() })
	closeShutdownConnection(conn)
	s.finishIngress(conn)
	closed := make(chan struct{})
	s.closeDatabase = func() error { close(closed); return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatal("shutdown discarded retained work", err)
	}
	select {
	case <-closed:
		t.Fatal("dependency closed before DATA ownership joined")
	default:
	}
	if err := work.Joined(); err != nil {
		t.Fatal(err)
	}
	awaitShutdown(t, s)
	select {
	case <-closed:
	default:
		t.Fatal("dependency retained after exact DATA join")
	}
}

func TestReservedModeRejectsUnqualifiedRuntimeAndLateConstruction(t *testing.T) {
	s := reservedTestServer(t)
	if err := s.enableReservedIngress(transport.ReservationLimits{}); err == nil {
		t.Fatal("active ledger replaced")
	}
	s.runtimeRouter = &notebookruntime.Router{}
	err := s.Start()
	s.runtimeRouter = nil
	if err == nil {
		t.Fatal("unqualified notebook router shared reserved ingress")
	}
}

type reservedSlowClose struct {
	net.Conn
	entered chan struct{}
	allow   <-chan struct{}
}

func (c *reservedSlowClose) Close() error {
	close(c.entered)
	<-c.allow
	return c.Conn.Close()
}

func TestReservedShutdownDeadlineDoesNotReleasePendingPhysicalClose(t *testing.T) {
	s := reservedTestServer(t)
	raw, peer, err := privateSourcePair()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	allow := make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(allow) }) }
	t.Cleanup(unblock)
	blocked := &reservedSlowClose{Conn: raw, entered: make(chan struct{}), allow: allow}
	conn, err := s.acceptIngress(blocked, true)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	s.finishIngress(conn)
	closed := make(chan struct{})
	s.closeDatabase = func() error { close(closed); return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatal("pending physical close reported completion", err)
	}
	select {
	case <-blocked.entered:
	default:
		t.Fatal("shutdown did not attempt physical close")
	}
	if s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 1 {
		t.Fatal("shutdown deadline released a live socket")
	}
	select {
	case <-closed:
		t.Fatal("dependency closed before physical socket")
	default:
	}
	unblock()
	awaitShutdown(t, s)
	if s.reserved.ledger.Snapshot(time.Now()).LiveSockets != 0 {
		t.Fatal("completed physical close retained capacity")
	}
}

func TestReservedMiddlewarePreservesVersionOnePrivateTLSAndHalfClose(t *testing.T) {
	sourceErr := make(chan error, 1)
	f := newPrivateFixtureMode(t, func(conn net.Conn) {
		payload, err := io.ReadAll(conn)
		if err != nil || string(payload) != "request" {
			sourceErr <- errors.New("source payload changed")
			return
		}
		_, err = io.WriteString(conn, "response")
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		sourceErr <- err
	}, true)
	conn, reader, status := f.open(t, f.claims, "request")
	if status != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatal(status)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != "response" {
		t.Fatal("private TLS half-close changed", err)
	}
	if err := <-sourceErr; err != nil {
		t.Fatal(err)
	}
	_, _, status = f.open(t, f.claims, "")
	if !strings.Contains(status, "403") || f.dispatched.Load() != 1 {
		t.Fatal("replayed private request reached source", status)
	}
}
