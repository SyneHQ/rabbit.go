package middleware

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"rabbit.go/transport"
)

func provisionalMiddleware(t *testing.T, ceiling int) (*SecurityMiddleware, *transport.ReservationAccounting) {
	t.Helper()
	config := DefaultSecurityConfig()
	config.MaxGlobalConnections, config.TrustedNetworks = ceiling, nil
	sm := NewSecurityMiddleware(config)
	t.Cleanup(sm.Stop)
	replays, err := transport.NewReplayRegistry(128)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := transport.NewReservationAccounting(transport.ReservationLimits{Sockets: ceiling, Handshakes: 2,
		Parents: 1, SetupTimeout: 2 * time.Second, TerminationWindow: 3 * time.Second}, replays)
	if err != nil {
		t.Fatal(err)
	}
	if err := sm.EnableReservations(ledger); err != nil {
		t.Fatal(err)
	}
	return sm, ledger
}

func provisionalAccept(t *testing.T, sm *SecurityMiddleware) *ProvisionalConnection {
	t.Helper()
	raw, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	p, err := sm.AcceptProvisional(admissionConn{Conn: raw, address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5432}})
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close(); _ = p.Joined() })
	return p
}

// This fixture supplies the already-verified peer input to the ticket codec.
// Native listener gates must separately prove real TLS and source cancellation.
func provisionalTickets(t *testing.T) (transport.VerifiedReservation, transport.VerifiedReservation) {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := "spiffe://fixture.test/worker/one"
	uri, _ := url.Parse(identity)
	cert := &x509.Certificate{Raw: []byte("generated-peer-fixture"), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri}}
	hash := sha256.Sum256(cert.Raw)
	c := transport.ReservationClaims{OpenClaims: transport.OpenClaims{Version: transport.ReservationVersion,
		Issuer: "fixture", Audience: "rabbit", ID: strings.Repeat("1", 64), IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), SessionExpiresAt: now.Add(time.Minute).Unix(),
		ClusterTenant: "shared", ServicePrincipal: "gateway", Tenant: "tenant", Source: "source", SourceRevision: strings.Repeat("2", 64),
		TokenID: "token", TokenGeneration: strings.Repeat("3", 64), TunnelID: strings.Repeat("4", 64), ControlOwner: strings.Repeat("5", 64),
		Authority: "postgres.fixture.test:5432", WorkerIdentity: identity, WorkerCertSHA256: hex.EncodeToString(hash[:]),
		Execution: transport.Execution{Kind: "query", ID: "query", GrantSHA256: strings.Repeat("6", 64), Worker: "one", Owner: strings.Repeat("7", 32), Claim: strings.Repeat("8", 32)}}}
	trust := transport.Trust{Issuer: c.Issuer, Audience: c.Audience, ClusterTenant: c.ClusterTenant, ServicePrincipal: c.ServicePrincipal, WorkerIdentity: identity, PublicKey: public}
	state := tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	token, err := transport.SignReservation(c, key)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := transport.VerifyReservationData(token, c.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	c.ParentOpenSHA256, c.ID = parent.Digest(), strings.Repeat("a", 64)
	c.ExpiresAt, c.SessionExpiresAt = now.Add(10*time.Second).Unix(), now.Add(15*time.Second).Unix()
	token, err = transport.SignReservation(c, key)
	if err != nil {
		t.Fatal(err)
	}
	auxiliary, err := transport.VerifyReservationAuxiliary(token, c.Authority, trust, state, parent, now)
	if err != nil {
		t.Fatal(err)
	}
	return parent, auxiliary
}

func TestProvisionalClassificationPreservesReservedPairAtEveryOrdinaryLimit(t *testing.T) {
	for _, limit := range []string{"concurrent", "hourly", "burst", "blacklist"} {
		t.Run(limit, func(t *testing.T) {
			sm, ledger := provisionalMiddleware(t, 8)
			switch limit {
			case "concurrent":
				sm.config.MaxConnectionsPerIP = 1
			case "hourly":
				sm.config.MaxConnectionsPerHour = 1
			case "burst":
				sm.config.BurstThreshold = 1
			}
			ordinary := provisionalAccept(t, sm)
			if err := ordinary.AdmitOrdinary(); err != nil {
				t.Fatal(err)
			}
			if limit == "blacklist" {
				sm.mu.Lock()
				sm.ipStats[ordinary.ipText].IsBlacklisted = true
				sm.ipStats[ordinary.ipText].BlacklistUntil = time.Now().Add(time.Hour)
				sm.mu.Unlock()
			}
			rejected := provisionalAccept(t, sm)
			if err := rejected.AdmitOrdinary(); err == nil {
				t.Fatal("ordinary limit bypassed")
			}
			if err := rejected.Close(); err != nil {
				t.Fatal(err)
			}
			if err := rejected.Joined(); err != nil {
				t.Fatal(err)
			}
			if sm.ipStats[ordinary.ipText].CurrentConnections != 1 || sm.globalConnections != 1 {
				t.Fatal("rejection released another socket")
			}
			parent, auxiliary := provisionalTickets(t)
			private := provisionalAccept(t, sm)
			pair, err := private.AdmitData(parent, time.Now().Add(10*time.Second))
			if err != nil {
				t.Fatal("ordinary limit rejected reserved data", err)
			}
			data := provisionalAccept(t, sm)
			if err := data.AdmitDATASocket(pair); err != nil {
				t.Fatal(err)
			}
			if err := pair.SetupJoined(time.Now()); err != nil {
				t.Fatal(err)
			}
			aux := provisionalAccept(t, sm)
			auxPair, err := aux.AdmitAuxiliary(auxiliary, time.Now().Add(10*time.Second))
			if err != nil {
				t.Fatal("ordinary limit rejected reserved auxiliary", err)
			}
			auxData := provisionalAccept(t, sm)
			if err := auxData.AdmitDATASocket(auxPair); err != nil {
				t.Fatal(err)
			}
			if err := auxPair.SetupJoined(time.Now()); err != nil {
				t.Fatal(err)
			}
			if sm.ipStats[ordinary.ipText].CurrentConnections != 1 || ledger.Snapshot(time.Now()).LiveSockets != 5 {
				t.Fatal("reserved sockets changed ordinary accounting")
			}
			_ = pair.Revoke(time.Now())
		})
	}
}

func TestProvisionalHardCeilingAndLegacyAdmissionCannotConsumeReserve(t *testing.T) {
	sm, ledger := provisionalMiddleware(t, 8)
	parent, auxiliary := provisionalTickets(t)
	private := provisionalAccept(t, sm)
	pair, err := private.AdmitData(parent, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	data := provisionalAccept(t, sm)
	if err := data.AdmitDATASocket(pair); err != nil {
		t.Fatal(err)
	}
	if err := pair.SetupJoined(time.Now()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := provisionalAccept(t, sm).AdmitOrdinary(); err != nil {
			t.Fatal(err)
		}
	}
	ordinary := provisionalAccept(t, sm)
	if err := ordinary.AdmitOrdinary(); !errors.Is(err, transport.ErrSocketCapacity) {
		t.Fatal("ordinary consumed reserve", err)
	}
	_ = ordinary.Close()
	_ = ordinary.Joined()
	aux := provisionalAccept(t, sm)
	auxPair, err := aux.AdmitAuxiliary(auxiliary, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	auxData := provisionalAccept(t, sm)
	if err := auxData.AdmitDATASocket(auxPair); err != nil {
		t.Fatal(err)
	}
	if err := auxPair.SetupJoined(time.Now()); err != nil {
		t.Fatal(err)
	}
	provisionalAccept(t, sm)
	provisionalAccept(t, sm)
	if _, err := sm.AcceptProvisional(testAdmissionConn()); err == nil {
		t.Fatal("physical ceiling exceeded")
	}
	if err := sm.ValidateConnection(testAdmissionConn()); err == nil {
		t.Fatal("legacy admission bypassed reservation mode")
	}
	sm.RecordConnectionClosed(testAdmissionConn())
	state := ledger.Snapshot(time.Now())
	if sm.globalConnections != 8 || state.LiveSockets != 8 || state.Charged != 8 {
		t.Fatal("hard ceiling or legacy completion changed accounting", state)
	}
	connections, setups := sm.ReservationCleanup(time.Now(), true)
	if len(connections) != 8 || len(setups) != 0 {
		t.Fatal("drain lost sockets", len(connections), len(setups))
	}
	if _, err := sm.AcceptProvisional(testAdmissionConn()); err == nil {
		t.Fatal("drain admitted a socket")
	}
	for _, p := range connections {
		_ = p.Close()
		_ = p.Joined()
	}
	state = ledger.Snapshot(time.Now())
	if sm.globalConnections != 0 || state.LiveSockets != 0 || state.Parents != 0 {
		t.Fatal("drain did not join exact allocations", state)
	}
}

type provisionalBlockedClose struct {
	admissionConn
	started chan struct{}
	allow   <-chan struct{}
	failure error
}

func (c *provisionalBlockedClose) Close() error {
	close(c.started)
	if c.allow != nil {
		<-c.allow
	}
	return c.failure
}

func TestProvisionalCloseAndEveryWorkOwnerMustJoin(t *testing.T) {
	sm, ledger := provisionalMiddleware(t, 6)
	allow := make(chan struct{})
	raw := &provisionalBlockedClose{admissionConn: admissionConn{address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}, started: make(chan struct{}), allow: allow}
	p, err := sm.AcceptProvisional(raw)
	if err != nil {
		t.Fatal(err)
	}
	work, err := p.RetainWork()
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	<-raw.started
	if err := p.Joined(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RetainWork(); err == nil {
		t.Fatal("closing socket acquired work")
	}
	if err := p.AdmitOrdinary(); err == nil {
		t.Fatal("closing socket was promoted")
	}
	if ledger.Snapshot(time.Now()).LiveSockets != 1 {
		t.Fatal("pending physical close released admission")
	}
	close(allow)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if sm.globalConnections != 1 || ledger.Snapshot(time.Now()).LiveSockets != 1 {
		t.Fatal("handler completion lost relay owner")
	}
	copiedWork := *work
	if err := copiedWork.Joined(); err == nil {
		t.Fatal("copied work released real owner")
	}
	if err := work.Joined(); err != nil {
		t.Fatal(err)
	}
	if err := work.Joined(); err != nil {
		t.Fatal(err)
	}
	if sm.globalConnections != 0 || ledger.Snapshot(time.Now()).LiveSockets != 0 {
		t.Fatal("joined socket retained admission")
	}
}

func TestProvisionalFailedCloseAndForeignHandlesRemainCharged(t *testing.T) {
	sm, ledger := provisionalMiddleware(t, 6)
	raw := &provisionalBlockedClose{admissionConn: admissionConn{address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}, started: make(chan struct{}), failure: errors.New("unconfirmed close")}
	p, err := sm.AcceptProvisional(raw)
	if err != nil {
		t.Fatal(err)
	}
	foreign := &ProvisionalConnection{conn: p.conn, sm: sm, socket: p.socket, identity: p}
	if err := foreign.Close(); err == nil {
		t.Fatal("foreign handle closed another allocation")
	}
	if err := foreign.Joined(); err == nil {
		t.Fatal("foreign handle joined another allocation")
	}
	if err := p.Close(); err == nil {
		t.Fatal("unconfirmed close reported success")
	}
	_ = p.Joined()
	connections, _ := sm.ReservationCleanup(time.Now(), true)
	if len(connections) != 1 || connections[0] != p || sm.globalConnections != 1 || ledger.Snapshot(time.Now()).LiveSockets != 1 {
		t.Fatal("uncertain closure disappeared")
	}
}

func TestProvisionalConcurrentCompletionCountsEachOwnerOnce(t *testing.T) {
	sm, ledger := provisionalMiddleware(t, 6)
	p := provisionalAccept(t, sm)
	if err := p.AdmitOrdinary(); err != nil {
		t.Fatal(err)
	}
	work, err := p.RetainWork()
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() { _ = p.Close(); _ = p.Joined(); _ = work.Joined(); _ = sm.GetStats() })
	}
	workers.Wait()
	if sm.globalConnections != 0 || ledger.Snapshot(time.Now()).LiveSockets != 0 || sm.ipStats[p.ipText].CurrentConnections != 0 {
		t.Fatal("duplicate joins changed counters")
	}
}

func TestProvisionalReplayFailureCannotReleaseOriginalPair(t *testing.T) {
	sm, ledger := provisionalMiddleware(t, 6)
	parent, _ := provisionalTickets(t)
	private := provisionalAccept(t, sm)
	pair, err := private.AdmitData(parent, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	data := provisionalAccept(t, sm)
	if err := data.AdmitDATASocket(pair); err != nil {
		t.Fatal(err)
	}
	if err := pair.SetupJoined(time.Now()); err != nil {
		t.Fatal(err)
	}
	replay := provisionalAccept(t, sm)
	if _, err := replay.AdmitData(parent, time.Now().Add(10*time.Second)); !errors.Is(err, transport.ErrReplay) {
		t.Fatal("replay accepted", err)
	}
	_ = replay.Close()
	_ = replay.Joined()
	state := ledger.Snapshot(time.Now())
	if state.LiveSockets != 2 || state.Parents != 1 || sm.globalConnections != 2 {
		t.Fatal("failed replay changed original pair", state)
	}
	_ = pair.Revoke(time.Now())
}

func TestProvisionalEnableRejectsLiveLegacyAndMismatchedCeiling(t *testing.T) {
	config := DefaultSecurityConfig()
	config.MaxGlobalConnections = 6
	sm := NewSecurityMiddleware(config)
	defer sm.Stop()
	_, ledger := provisionalMiddleware(t, 6)
	if err := sm.ValidateConnection(testAdmissionConn()); err != nil {
		t.Fatal(err)
	}
	if err := sm.EnableReservations(ledger); err == nil {
		t.Fatal("live legacy socket escaped reservation accounting")
	}
	sm.RecordConnectionClosed(testAdmissionConn())
	_, other := provisionalMiddleware(t, 8)
	if err := sm.EnableReservations(other); err == nil {
		t.Fatal("different hard ceilings accepted")
	}
	if err := sm.EnableReservations(ledger); err != nil {
		t.Fatal(err)
	}
	if err := sm.EnableReservations(ledger); err == nil {
		t.Fatal("reservation owner replaced")
	}
}

func TestProvisionalPublicConnectionReplacementCannotReleaseLiveSocket(t *testing.T) {
	sm, ledger := provisionalMiddleware(t, 6)
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	p, err := sm.AcceptProvisional(admissionConn{Conn: raw, address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	replacement, replacementPeer := net.Pipe()
	defer replacement.Close()
	defer replacementPeer.Close()
	// Reproduce the original public-field substitution if that API returns.
	// Private fields are not settable through reflection or by package callers.
	field := reflect.ValueOf(p).Elem().FieldByName("Conn")
	if field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(replacement))
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Joined(); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := peer.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("released allocation left its accepted socket open", err)
	}
	if ledger.Snapshot(time.Now()).LiveSockets != 0 {
		t.Fatal("accepted socket closure did not release its allocation")
	}
}
