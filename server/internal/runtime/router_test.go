package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testAuthority struct {
	denied atomic.Bool
	lease  time.Duration
	calls  atomic.Int64
}

func (a *testAuthority) Authorize(_ context.Context, _ Registration) (time.Time, error) {
	a.calls.Add(1)
	if a.denied.Load() {
		return time.Time{}, ErrUnavailable
	}
	return time.Now().Add(a.lease), nil
}
func fixture() Registration {
	return Registration{Scope: Scope{
		RuntimeID: "runtime_1", TeamID: "team_1", InstallationID: "install_1", Service: "notebook-v2", CredentialGeneration: 1,
		PolicyRevision: 2, LedgerGeneration: "ledger_1", EnvironmentSHA256: strings.Repeat("a", 64)}, Credential: strings.Repeat("c", 64)}
}

const brokerSecret = "broker-token-with-at-least-32-bytes-12345"

func testRouter(t *testing.T) (*Router, *testAuthority) {
	t.Helper()
	a := &testAuthority{lease: 10 * time.Second}
	r, err := NewRouter(a, brokerSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r, a
}
func connect(t *testing.T, r *Router, frame string, value any) (net.Conn, *bufio.Reader) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { client.Close() })
	go r.Handle(frame, server, bufio.NewReader(server))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	body, _ := json.Marshal(value)
	if _, err := client.Write(append(body, '\n')); err != nil {
		t.Fatal(err)
	}
	return client, bufio.NewReader(client)
}
func line(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	v, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(v, "\n")
}
func register(t *testing.T, r *Router) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, b := connect(t, r, RegisterFrame, fixture())
	if line(t, b) != "READY" {
		t.Fatal("not ready")
	}
	return c, b
}

func pair(t *testing.T, r *Router, control *bufio.Reader) (net.Conn, *bufio.Reader, net.Conn, *bufio.Reader, string) {
	t.Helper()
	broker, br := connect(t, r, OpenFrame, OpenRequest{Scope: fixture().Scope, BrokerToken: brokerSecret})
	request := line(t, control)
	if !strings.HasPrefix(request, "OPEN ") {
		t.Fatal(request)
	}
	id := strings.TrimPrefix(request, "OPEN ")
	data, dr := connect(t, r, DataFrame, DataRequest{Registration: fixture(), ConnectionID: id})
	if line(t, dr) != "PAIRED" {
		t.Fatal("not paired")
	}
	if line(t, br) != "READY" {
		t.Fatal("broker not ready")
	}
	return broker, br, data, dr, id
}

func TestPrivatePairingAndSingleUse(t *testing.T) {
	r, a := testRouter(t)
	_, control := register(t, r)
	broker, br, data, dr, id := pair(t, r, control)
	go func() { _, _ = broker.Write([]byte("request")) }()
	p := make([]byte, 7)
	if _, err := io.ReadFull(dr, p); err != nil || string(p) != "request" {
		t.Fatalf("request: %q %v", p, err)
	}
	go func() { _, _ = data.Write([]byte("response")) }()
	p = make([]byte, 8)
	if _, err := io.ReadFull(br, p); err != nil || string(p) != "response" {
		t.Fatalf("response: %q %v", p, err)
	}
	_, duplicate := connect(t, r, DataFrame, DataRequest{Registration: fixture(), ConnectionID: id})
	if _, err := duplicate.ReadByte(); err == nil {
		t.Fatal("data id reused")
	}
	if a.calls.Load() < 5 {
		t.Fatal("missing publication/open/pair reauthorization")
	}
}

func TestDeniedBrokerAndScopeNeverOfferAStream(t *testing.T) {
	for _, change := range []func(*OpenRequest){
		func(v *OpenRequest) { v.BrokerToken = "wrong" }, func(v *OpenRequest) { v.TeamID = "other" },
		func(v *OpenRequest) { v.PolicyRevision++ }, func(v *OpenRequest) { v.Service = "jupyter" },
		func(v *OpenRequest) { v.LedgerGeneration = "replaced" },
	} {
		t.Run("denied", func(t *testing.T) {
			r, _ := testRouter(t)
			control, cr := register(t, r)
			v := OpenRequest{Scope: fixture().Scope, BrokerToken: brokerSecret}
			change(&v)
			_, br := connect(t, r, OpenFrame, v)
			if _, err := br.ReadByte(); err == nil {
				t.Fatal("unauthorized bridge")
			}
			_ = control.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			if _, err := cr.ReadByte(); err == nil {
				t.Fatal("offered unauthorized stream")
			}
		})
	}
}

func TestRevocationClosesExactActiveBridgeAndBlocksReconnect(t *testing.T) {
	r, a := testRouter(t)
	control, cr := register(t, r)
	broker, br, _, dr, _ := pair(t, r, cr)
	a.denied.Store(true)
	_, _ = control.Write([]byte("PING\n"))
	for _, reader := range []*bufio.Reader{br, dr, cr} {
		if _, err := reader.ReadByte(); err == nil {
			t.Fatal("revoked connection survived")
		}
	}
	broker.Close()
	_, next := connect(t, r, RegisterFrame, fixture())
	if _, err := next.ReadByte(); err == nil {
		t.Fatal("revoked reconnect accepted")
	}
}

func TestExpiredLeaseCannotBeUsedWithoutHeartbeat(t *testing.T) {
	r, a := testRouter(t)
	a.lease = 180 * time.Millisecond
	_, cr := register(t, r)
	if _, err := cr.ReadByte(); err == nil {
		t.Fatal("lease failed to close")
	}
}

func TestMalformedOrUnknownFrameFieldsDenied(t *testing.T) {
	r, _ := testRouter(t)
	for _, v := range []any{map[string]any{"runtimeId": "x", "localPort": "8888"}, map[string]any{"credential": strings.Repeat("s", 5000)}} {
		server, client := net.Pipe()
		defer client.Close()
		go r.Handle(RegisterFrame, server, bufio.NewReader(server))
		_ = client.SetDeadline(time.Now().Add(time.Second))
		body, _ := json.Marshal(v)
		_, _ = client.Write(append(body, '\n'))
		reader := bufio.NewReader(client)
		if _, err := reader.ReadByte(); err == nil {
			t.Fatal("invalid frame allowed")
		}
	}
}

func TestAuthorityExactScopeAndBoundedLease(t *testing.T) {
	reg := fixture()
	badScope := false
	badLease := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+brokerSecret {
			t.Error("service authentication missing")
		}
		var input struct {
			Registration
			Op string `json:"op"`
		}
		if json.NewDecoder(req.Body).Decode(&input) != nil || input.Registration != reg || input.Op != "authorize" {
			t.Error("wrong authority request")
		}
		team := reg.TeamID
		if badScope {
			team = "other"
		}
		expiry := time.Now().Add(9 * time.Second)
		if badLease {
			expiry = time.Now().Add(time.Hour)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"authorized": true, "service": "notebook-v2", "expiresAt": expiry,
			"runtime": map[string]any{"id": reg.RuntimeID, "teamId": team, "installationId": reg.InstallationID, "credentialGeneration": reg.CredentialGeneration,
				"policyRevision": reg.PolicyRevision, "ledgerGeneration": reg.LedgerGeneration, "environmentSha256": reg.EnvironmentSHA256,
				"provider": "customer", "enrollmentState": "active", "revokedAt": nil, "policy": map[string]any{"executionEnabled": false}}})
	}))
	defer server.Close()
	a, err := NewHTTPAuthority(server.URL, brokerSecret, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authorize(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	badScope = true
	if _, err = a.Authorize(context.Background(), reg); err == nil {
		t.Fatal("scope mismatch accepted")
	}
	badScope = false
	badLease = true
	if _, err = a.Authorize(context.Background(), reg); err == nil {
		t.Fatal("long lease accepted")
	}
	if _, err = NewHTTPAuthority("http://example.com/api", brokerSecret, true); err == nil {
		t.Fatal("remote plaintext accepted")
	}
	if _, err = NewHTTPAuthority(server.URL, brokerSecret, false); err == nil {
		t.Fatal("implicit local plaintext accepted")
	}
}

type blockedCloseConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockedCloseConn) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Close()
}
func TestSlowSocketCloseDoesNotBlockUnrelatedLease(t *testing.T) {
	r, _ := testRouter(t)
	a, b := net.Pipe()
	defer b.Close()
	slow := &blockedCloseConn{Conn: a, entered: make(chan struct{}), release: make(chan struct{})}
	defer close(slow.release)
	first := &session{registration: fixture(), control: slow, until: time.Now().Add(20 * time.Millisecond), streams: map[net.Conn]struct{}{}}
	c, d := net.Pipe()
	defer d.Close()
	reg := fixture()
	reg.RuntimeID = "other_runtime"
	second := &session{registration: reg, control: c, until: time.Now().Add(150 * time.Millisecond), streams: map[net.Conn]struct{}{}}
	r.mu.Lock()
	r.sessions[key(first.registration.Scope)] = first
	r.sessions[key(reg.Scope)] = second
	r.mu.Unlock()
	select {
	case <-slow.entered:
	case <-time.After(time.Second):
		t.Fatal("expiry did not close first session")
	}
	_ = d.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := d.Read(make([]byte, 1)); err == nil {
		t.Fatal("other session survived expiry")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("slow Close blocked unrelated expiry")
	}
	_, cr := register(t, r)
	if cr == nil {
		t.Fatal("new runtime admission blocked")
	}
}

type blockedAuthority struct {
	calls            atomic.Int64
	entered, release chan struct{}
}

func (a *blockedAuthority) Authorize(context.Context, Registration) (time.Time, error) {
	if a.calls.Add(1) == 1 {
		close(a.entered)
	}
	<-a.release
	return time.Time{}, ErrUnavailable
}
func TestQueuedRefreshSkipsAuthorityAfterRevocation(t *testing.T) {
	authority := &blockedAuthority{entered: make(chan struct{}), release: make(chan struct{})}
	r, err := NewRouter(authority, brokerSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	a, b := net.Pipe()
	defer b.Close()
	s := &session{registration: fixture(), control: a, until: time.Now().Add(10 * time.Second), streams: map[net.Conn]struct{}{}}
	r.mu.Lock()
	r.sessions[key(s.registration.Scope)] = s
	r.mu.Unlock()
	var waiting sync.WaitGroup
	for i := 0; i < 12; i++ {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			if r.refresh(s) {
				t.Error("revoked refresh succeeded")
			}
		}()
	}
	<-authority.entered
	close(authority.release)
	waiting.Wait()
	if authority.calls.Load() != 1 {
		t.Fatalf("queued dead-session calls=%d", authority.calls.Load())
	}
}
