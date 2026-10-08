package tunnel

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
)

func testTCPListener(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func acceptTestConn(t *testing.T, listener *net.TCPListener) *net.TCPConn {
	t.Helper()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}

func testClient(t *testing.T, server, local *net.TCPListener, limit int) *TunnelClient {
	t.Helper()
	_, port, _ := net.SplitHostPort(local.Addr().String())
	client, err := NewTunnelClient(TunnelClientConfig{
		ServerAddress: server.Addr().String(), LocalPort: port, Token: "test-token", InsecureLocal: true,
		ConnectionTimeout: time.Second, HealthCheckInterval: time.Hour, MaxConcurrentConnections: limit,
		InitialRetryDelay: time.Hour, MaxRetryDelay: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Stop() })
	return client
}

func readTestLine(t *testing.T, reader *bufio.Reader, expected string) {
	t.Helper()
	line, err := controlLine(reader)
	if err != nil || line != expected {
		t.Fatalf("line = %q, %v; want %q", line, err, expected)
	}
}

func awaitClientStop(t *testing.T, client *TunnelClient) {
	t.Helper()
	done := make(chan struct{})
	go func() { client.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("client shutdown did not cancel its workers")
	}
}

func TestClientPreservesControlReadAheadAndHalfClose(t *testing.T) {
	server, local := testTCPListener(t), testTCPListener(t)
	client := testClient(t, server, local, 1)
	control := acceptTestConn(t, server)
	reader := bufio.NewReader(control)
	readTestLine(t, reader, "test-token")
	readTestLine(t, reader, client.Config.LocalPort)
	id := strings.Repeat("a", 64)
	if _, err := io.WriteString(control, "SUCCESS:tunnel:12345\nCONNECT\nCONN_ID:"+id+"\n"); err != nil {
		t.Fatal(err)
	}
	data := acceptTestConn(t, server)
	dataReader := bufio.NewReader(data)
	readTestLine(t, dataReader, "DATA:"+id)
	database := acceptTestConn(t, local)

	// The database returns its response only after observing request EOF.
	request := strings.Repeat("request with binary \x00 data", 4000)
	response := strings.Repeat("response with binary \x00 data", 5000)
	databaseDone := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(database)
		if err == nil && string(got) != request {
			err = errors.New("request changed in transit")
		}
		if err == nil {
			_, err = io.WriteString(database, response)
		}
		if err == nil {
			err = database.CloseWrite()
		}
		databaseDone <- err
	}()
	if _, err := io.WriteString(data, request); err != nil {
		t.Fatal(err)
	}
	if err := data.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(dataReader)
	if err != nil || string(got) != response {
		t.Fatalf("response changed or truncated: %d bytes, %v", len(got), err)
	}
	if err := <-databaseDone; err != nil {
		t.Fatal(err)
	}
	awaitClientStop(t, client)
	readTestLine(t, reader, "CAPS:busy-v1")
	readTestLine(t, reader, "DISCONNECT")
}

func TestControlLossCancelsActiveData(t *testing.T) {
	server, local := testTCPListener(t), testTCPListener(t)
	client := testClient(t, server, local, 1)
	control := acceptTestConn(t, server)
	reader := bufio.NewReader(control)
	readTestLine(t, reader, "test-token")
	readTestLine(t, reader, client.Config.LocalPort)
	id := strings.Repeat("a", 64)
	_, _ = io.WriteString(control, "SUCCESS:tunnel:12345\nCONNECT\nCONN_ID:"+id+"\n")
	data := acceptTestConn(t, server)
	readTestLine(t, bufio.NewReader(data), "DATA:"+id)
	database := acceptTestConn(t, local)
	control.Close()
	for _, conn := range []net.Conn{data, database} {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := conn.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("control loss left an active data stream")
		}
		if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatalf("control loss did not close a data stream: %v", err)
		}
	}
	awaitClientStop(t, client)
}

func TestClientBoundsDataConnectionsWithoutDroppingControl(t *testing.T) {
	server, local := testTCPListener(t), testTCPListener(t)
	client := testClient(t, server, local, 1)
	control := acceptTestConn(t, server)
	reader := bufio.NewReader(control)
	readTestLine(t, reader, "test-token")
	readTestLine(t, reader, client.Config.LocalPort)
	id := strings.Repeat("a", 64)
	_, _ = io.WriteString(control, "SUCCESS:tunnel:12345\nCONNECT\nCONN_ID:"+id+"\n")
	data := acceptTestConn(t, server)
	readTestLine(t, bufio.NewReader(data), "DATA:"+id)
	database := acceptTestConn(t, local)
	_, _ = io.WriteString(control, "CONNECT\nCONN_ID:"+strings.Repeat("b", 64)+"\nPONG\n")
	_ = server.SetDeadline(time.Now().Add(100 * time.Millisecond))
	unexpected, err := server.AcceptTCP()
	if err == nil {
		unexpected.Close()
		t.Fatal("exceeded configured data concurrency")
	}
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal(err)
	}
	// The admitted stream still works after overload.
	go io.WriteString(data, "alive")
	got := make([]byte, 5)
	if _, err := io.ReadFull(database, got); err != nil || string(got) != "alive" {
		t.Fatalf("overload interrupted admitted stream: %q, %v", got, err)
	}
	awaitClientStop(t, client)
	readTestLine(t, reader, "CAPS:busy-v1")
	readTestLine(t, reader, "DISCONNECT")
}

func TestStopCancelsStalledHandshakeAndIsIdempotent(t *testing.T) {
	server, local := testTCPListener(t), testTCPListener(t)
	client := testClient(t, server, local, 1)
	_ = acceptTestConn(t, server) // Never send SUCCESS.
	if err := client.Start(); err == nil {
		t.Fatal("allowed a second manager")
	}
	var stops sync.WaitGroup
	for range 4 {
		stops.Add(1)
		go func() { defer stops.Done(); client.Stop() }()
	}
	done := make(chan struct{})
	go func() { stops.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop waited for handshake timeout")
	}
	if err := client.Start(); err == nil {
		t.Fatal("restarted stopped client")
	}
}

func TestStopBeforeStart(t *testing.T) {
	client, err := NewTunnelClient(TunnelClientConfig{ServerAddress: "127.0.0.1:1", Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	if client.Config.MaxConcurrentConnections != 64 || client.Config.MaxReconnectAttempts != 0 {
		t.Fatal("unexpected concurrency or unlimited-retry default")
	}
	client.Stop()
	client.Stop()
	if err := client.Start(); err == nil {
		t.Fatal("started after Stop")
	}
}

func TestControlLineBoundsAndConfigValidation(t *testing.T) {
	for _, line := range []string{strings.Repeat("x", 4096) + "\n", strings.Repeat("x", 4095)} {
		if _, err := controlLine(bufio.NewReaderSize(strings.NewReader(line), maxControlLine)); err == nil {
			t.Fatal("accepted oversized or unterminated frame")
		}
	}
	if got, err := controlLine(bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 4095)+"\n"), maxControlLine)); err != nil || len(got) != 4095 {
		t.Fatalf("rejected maximum valid frame: %v", err)
	}
	for _, mutate := range []func(*TunnelClientConfig){
		func(c *TunnelClientConfig) { c.LocalPort = "5432\nDATA:other" },
		func(c *TunnelClientConfig) { c.LocalPort = "65536" },
		func(c *TunnelClientConfig) { c.MaxConcurrentConnections = -1 },
		func(c *TunnelClientConfig) { c.MaxConcurrentConnections = 4097 },
		func(c *TunnelClientConfig) { c.MaxReconnectAttempts = -1 },
		func(c *TunnelClientConfig) { c.HealthCheckInterval = -time.Second },
		func(c *TunnelClientConfig) { c.Token = strings.Repeat("x", 4096) },
	} {
		config := TunnelClientConfig{ServerAddress: "127.0.0.1:1", Token: "test-token"}
		mutate(&config)
		if _, err := NewTunnelClient(config); err == nil {
			t.Fatal("accepted invalid config")
		}
	}
	client, _ := NewTunnelClient(TunnelClientConfig{ServerAddress: "127.0.0.1:1", Token: "test-token"})
	defer client.Stop()
	if got := client.calculateBackoffDelay(100000); got != time.Minute {
		t.Fatalf("backoff overflowed: %s", got)
	}
}

func TestHealthMonitorOwnsConnectionAndStops(t *testing.T) {
	client, _ := NewTunnelClient(TunnelClientConfig{ServerAddress: "127.0.0.1:1", Token: "test-token", HealthCheckInterval: 10 * time.Millisecond})
	defer client.Stop()
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		client.healthMonitor(ctx, cancel, &sessionControl{conn: conn})
		close(done)
	}()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	readTestLine(t, bufio.NewReader(peer), "PING")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("health monitor survived its session")
	}
}

type errorReadConn struct{ net.Conn }

func (errorReadConn) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestBridgeHardErrorClosesBlockedPeer(t *testing.T) {
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()
	done := make(chan struct{})
	go func() { bridgeData(errorReadConn{first}, second); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge retained a blocked direction after hard error")
	}
}

func TestBoundedControlWriteAndDisconnect(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	if err := writeControl(conn, "PING\n", 10*time.Millisecond); err == nil {
		t.Fatal("stalled control write succeeded")
	}
	control := &sessionControl{conn: conn, ready: true}
	control.mu.Lock()
	writerDone := make(chan struct{})
	go func() {
		defer control.mu.Unlock()
		_, _ = conn.Write([]byte("PING\n"))
		close(writerDone)
	}()
	done := make(chan struct{})
	go func() { control.close(true); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disconnect waited indefinitely for writer lock")
	}
	<-writerDone
}

func TestAbsentControlTrafficEndsOnlyItsSession(t *testing.T) {
	server, local := testTCPListener(t), testTCPListener(t)
	_, port, _ := net.SplitHostPort(local.Addr().String())
	client, err := NewTunnelClient(TunnelClientConfig{ServerAddress: server.Addr().String(), LocalPort: port, Token: "test-token",
		InsecureLocal: true, HealthCheckInterval: 20 * time.Millisecond, ConnectionTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := client.runSession(ctx); finished <- err }()
	control := acceptTestConn(t, server)
	reader := bufio.NewReader(control)
	readTestLine(t, reader, "test-token")
	readTestLine(t, reader, port)
	_, _ = io.WriteString(control, "SUCCESS:tunnel:12345\n")
	// Drain outgoing PINGs, but never return a PONG. Successful local writes
	// must not count as proof the remote control loop is responsive. Any valid
	// incoming control traffic, including CONNECT, renews the liveness deadline.
	readDone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, reader); close(readDone) }()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("session succeeded without incoming control traffic")
		}
	case <-time.After(time.Second):
		t.Fatal("unresponsive control peer retained its session")
	}
	if ctx.Err() != nil {
		t.Fatal("failed session cancelled its parent's context")
	}
	<-readDone
}

func TestNegotiatedBusyRejectsExcessWithoutInterruptingStream(t *testing.T) {
	server, local := testTCPListener(t), testTCPListener(t)
	client := testClient(t, server, local, 1)
	control := acceptTestConn(t, server)
	reader := bufio.NewReader(control)
	readTestLine(t, reader, "test-token")
	readTestLine(t, reader, client.Config.LocalPort)
	_, _ = io.WriteString(control, "SUCCESS:tunnel:12345\n")
	readTestLine(t, reader, "CAPS:busy-v1")
	id := strings.Repeat("a", 64)
	_, _ = io.WriteString(control, "CAPS:busy-v1\nCONNECT\nCONN_ID:"+id+"\n")
	data := acceptTestConn(t, server)
	readTestLine(t, bufio.NewReader(data), "DATA:"+id)
	database := acceptTestConn(t, local)
	second := strings.Repeat("b", 64)
	started := time.Now()
	_, _ = io.WriteString(control, "CONNECT\nCONN_ID:"+second+"\n")
	readTestLine(t, reader, "BUSY:"+second)
	if time.Since(started) > time.Second {
		t.Fatal("overload rejection exceeded one second")
	}
	go io.WriteString(data, "alive")
	got := make([]byte, 5)
	if _, err := io.ReadFull(database, got); err != nil || string(got) != "alive" {
		t.Fatal("overload interrupted the admitted stream")
	}
	awaitClientStop(t, client)
	readTestLine(t, reader, "DISCONNECT")
}
