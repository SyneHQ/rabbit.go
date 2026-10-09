package server

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPrivateDataGateDropsReadAcrossPause(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	gate := newPrivateDataGate()
	conn := &privateGatedConnection{Conn: raw, gate: gate}
	defer conn.Close()
	done := make(chan int, 1)
	go func() { buf := make([]byte, 16); n, _ := conn.Read(buf); done <- n }()
	if !gate.pause() {
		t.Fatal("idle DATA gate failed to pause")
	}
	writeDone := make(chan struct{})
	go func() { peer.Write([]byte("late-data")); close(writeDone) }()
	select {
	case <-done:
		t.Fatal("paused read returned data")
	case <-time.After(20 * time.Millisecond):
	}
	conn.Close()
	select {
	case n := <-done:
		if n != 0 {
			t.Fatal("late DATA leaked", n)
		}
	case <-time.After(time.Second):
		t.Fatal("paused read did not join")
	}
	<-writeDone
}
func TestPrivateDataGateRejectsBusyWriteRetention(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	gate := newPrivateDataGate()
	conn := &privateGatedConnection{Conn: raw, gate: gate}
	defer conn.Close()
	done := make(chan struct{})
	go func() { conn.Write([]byte("in-flight")); close(done) }()
	deadline := time.Now().Add(time.Second)
	for {
		if !gate.mu.TryLock() {
			break
		}
		gate.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("write did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if gate.pause() {
		t.Fatal("busy DATA write authorized retention")
	}
	conn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("busy write did not join")
	}
}
func TestPrivateAbortRelayStopsAtByteLimit(t *testing.T) {
	external, caller := net.Pipe()
	data, source := net.Pipe()
	defer caller.Close()
	defer source.Close()
	done := make(chan struct{})
	go func() { boundedAbortRelay(external, data); close(done) }()
	sent := make(chan struct{})
	go func() {
		_, _ = io.Copy(caller, strings.NewReader(strings.Repeat("x", int(privateAbortByteLimit)+1)))
		close(sent)
	}()
	n, err := io.Copy(io.Discard, source)
	if err != nil || n != privateAbortByteLimit {
		t.Fatal("abort byte limit changed", n, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bounded relay did not join")
	}
	<-sent
}
func TestPrivateCleanupDoesNotRetainAmbiguousLeaseFailure(t *testing.T) {
	f := newPrivateFixture(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	pub, _ := enableCleanupFixture(t, f)
	parent, reader, _ := acceptedFixtureOpen(t, f, pub)
	defer parent.Close()
	// A generic authority failure must not enter the explicit-denial path.
	f.revoked.Store(true)
	parent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("ambiguous lease failure kept stream")
	}
	deadline := time.Now().Add(time.Second)
	for {
		f.server.mu.RLock()
		n := len(f.server.private.accepted)
		f.server.mu.RUnlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ambiguous failure retained parent")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestPrivateCleanupRejectsCurrentSourceRevocation(t *testing.T) {
	f := newPrivateFixture(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	pub, a := enableCleanupFixture(t, f)
	parent, _, accepted := acceptedFixtureOpen(t, f, pub)
	defer parent.Close()
	a.denied.Store(true)
	_, _, status, _ := cleanupConnect(t, f, abortFixtureToken(t, f, a, accepted, "a"), "Rabbit-Postgres-Abort: required-v1\r\n")
	if status != "HTTP/1.1 403 Forbidden\r\n" || f.dispatched.Load() != 1 {
		t.Fatal("revoked source dispatched abort")
	}
}

func TestPrivateDataGateBoundsReceiveOnlyCompletion(t *testing.T) {
	sourceRaw, backend := net.Pipe()
	workerRaw, worker := net.Pipe()
	defer backend.Close()
	defer worker.Close()
	gate := newPrivateDataGate()
	source := &privateGatedConnection{Conn: sourceRaw, gate: gate, source: true}
	external := &privateGatedConnection{Conn: workerRaw, gate: gate}
	if !gate.pause() {
		t.Fatal("pause failed")
	}
	gate.allowReceive()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer source.Close()
		defer external.Close()
		_, _ = io.Copy(external, source)
	}()
	sent := make(chan struct{})
	go func() {
		_, _ = io.Copy(backend, strings.NewReader(strings.Repeat("x", int(privateAbortByteLimit)+1)))
		close(sent)
	}()
	n, err := io.Copy(io.Discard, worker)
	if err != nil || n != privateAbortByteLimit {
		t.Fatal("receive-only limit changed", n, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receive-only relay did not join")
	}
	<-sent
}

func TestPrivateDataGateNeedsPositiveReceiveAuthority(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	gate := newPrivateDataGate()
	source := &privateGatedConnection{Conn: raw, gate: gate, source: true}
	defer source.Close()
	if !gate.pause() {
		t.Fatal("pause failed")
	}
	done := make(chan string, 1)
	go func() { buf := make([]byte, 8); n, _ := source.Read(buf); done <- string(buf[:n]) }()
	sent := make(chan struct{})
	go func() { peer.Write([]byte("complete")); close(sent) }()
	select {
	case <-done:
		t.Fatal("completion passed without authority")
	case <-time.After(20 * time.Millisecond):
	}
	gate.allowReceive()
	select {
	case got := <-done:
		if got != "complete" {
			t.Fatal("completion changed")
		}
	case <-time.After(time.Second):
		t.Fatal("authorized completion blocked")
	}
	<-sent
}

type finalCompletionConn struct{ net.Conn }

func (c finalCompletionConn) Read(b []byte) (int, error) { return copy(b, "ReadyForQuery"), io.EOF }
func TestPrivateDataGatePreservesFinalCompletionWithEOF(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	gate := newPrivateDataGate()
	if !gate.pause() {
		t.Fatal("pause failed")
	}
	gate.allowReceive()
	source := &privateGatedConnection{Conn: finalCompletionConn{raw}, gate: gate, source: true}
	buf := make([]byte, 32)
	n, err := source.Read(buf)
	if string(buf[:n]) != "ReadyForQuery" || err != io.EOF {
		t.Fatal("final protocol completion discarded", n, err)
	}
	select {
	case <-gate.done:
		t.Fatal("gate closed before final completion write")
	default:
	}
}
func TestPrivateCleanupBusyWriteDoesNotBlockServerOwnership(t *testing.T) {
	f := newPrivateFixture(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	pub, a := enableCleanupFixture(t, f)
	parent, _, accepted := acceptedFixtureOpen(t, f, pub)
	defer parent.Close()
	f.server.mu.RLock()
	entry := f.server.private.accepted[accepted.DataTicketSHA256]
	f.server.mu.RUnlock()
	raw, peer := net.Pipe()
	defer peer.Close()
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	blocked := &privateGatedConnection{Conn: raw, gate: entry.gate, source: true}
	joined := make(chan struct{})
	go func() { blocked.Write([]byte("blocked normal DATA")); close(joined) }()
	deadline := time.Now().Add(time.Second)
	for {
		if !entry.gate.mu.TryLock() {
			break
		}
		entry.gate.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("normal write did not start")
		}
		time.Sleep(time.Millisecond)
	}
	started := time.Now()
	_, _, status, _ := cleanupConnect(t, f, abortFixtureToken(t, f, a, accepted, "a"), "Rabbit-Postgres-Abort: required-v1\r\n")
	if status != "HTTP/1.1 403 Forbidden\r\n" || time.Since(started) > 500*time.Millisecond {
		t.Fatal("busy write blocked abort rejection", status, time.Since(started))
	}
	ownership := make(chan struct{})
	go func() { f.server.mu.Lock(); f.server.mu.Unlock(); close(ownership) }()
	select {
	case <-ownership:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("cleanup blocked server ownership lock")
	}
	raw.Close()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("blocked DATA writer did not join")
	}
}
