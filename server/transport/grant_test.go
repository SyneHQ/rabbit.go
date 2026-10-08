package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The codec receives an already-verified TLS state. Listener qualification must
// separately exercise real mTLS handshakes and runtime route/lease validation.
func grantFixture(t *testing.T) (OpenClaims, Trust, ed25519.PrivateKey, tls.ConnectionState, time.Time) {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := "spiffe://example.test/tenant/shared/worker/worker-a"
	uri, _ := url.Parse(identity)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	claims := OpenClaims{Version: Version, Issuer: "application", Audience: "database-ingress", ID: strings.Repeat("1", 64), IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), SessionExpiresAt: now.Add(time.Hour).Unix(),
		ClusterTenant: "shared", ServicePrincipal: "gateway", Tenant: "tenant-a", Source: "connection-a", SourceRevision: strings.Repeat("2", 64), TokenID: "token-a", TokenGeneration: strings.Repeat("3", 64), TunnelID: strings.Repeat("4", 64), ControlOwner: strings.Repeat("5", 64), Authority: "postgres.customer.internal:5432", WorkerIdentity: identity, WorkerCertSHA256: hex.EncodeToString(digest[:]),
		Execution: Execution{Kind: "query", ID: "query-a", GrantSHA256: strings.Repeat("6", 64), Worker: "worker-a", Owner: strings.Repeat("7", 32), Claim: strings.Repeat("8", 32)}}
	trust := Trust{Issuer: claims.Issuer, Audience: claims.Audience, ClusterTenant: claims.ClusterTenant, ServicePrincipal: claims.ServicePrincipal, WorkerIdentity: identity, PublicKey: public}
	state := tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	return claims, trust, private, state, now
}

func mustSign(t *testing.T, claims OpenClaims, key ed25519.PrivateKey) string {
	t.Helper()
	token, err := SignOpen(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestOpenGrantPinsTrustAuthorityAndTLSIdentity(t *testing.T) {
	claims, trust, private, state, now := grantFixture(t)
	token := mustSign(t, claims, private)
	verified, err := VerifyOpen(token, claims.Authority, trust, state, now)
	if err != nil || verified.Claims() != claims || !hexValue(verified.Digest(), 64) {
		t.Fatalf("valid scope rejected: %v", err)
	}
	for name, alter := range map[string]func(*Trust){
		"issuer": func(v *Trust) { v.Issuer = "other" }, "audience": func(v *Trust) { v.Audience = "other" },
		"cluster": func(v *Trust) { v.ClusterTenant = "other" }, "service": func(v *Trust) { v.ServicePrincipal = "other" },
		"worker": func(v *Trust) { v.WorkerIdentity += "/other" }, "key": func(v *Trust) { v.PublicKey = make(ed25519.PublicKey, 32) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := trust
			alter(&changed)
			if _, err := VerifyOpen(token, claims.Authority, changed, state, now); !errors.Is(err, ErrAuthority) {
				t.Fatal("foreign trust accepted")
			}
		})
	}
	for _, authority := range []string{"other.customer.internal:5432", "postgres.customer.internal:5433", "https://postgres.customer.internal:5432"} {
		if _, err := VerifyOpen(token, authority, trust, state, now); !errors.Is(err, ErrAuthority) {
			t.Fatal("foreign authority accepted")
		}
	}
	if _, err := VerifyOpen(token, claims.Authority, trust, state, now.Add(30*time.Second)); !errors.Is(err, ErrAuthority) {
		t.Fatal("expired admission accepted")
	}
}

func TestGrantRejectsUnverifiedAmbiguousAndExpiredPeers(t *testing.T) {
	claims, trust, private, original, now := grantFixture(t)
	token := mustSign(t, claims, private)
	for name, change := range map[string]func(*tls.ConnectionState){
		"unverified": func(s *tls.ConnectionState) { s.VerifiedChains = nil },
		"incomplete": func(s *tls.ConnectionState) { s.HandshakeComplete = false },
		"old-tls":    func(s *tls.ConnectionState) { s.Version = tls.VersionTLS12 },
		"empty-leaf": func(s *tls.ConnectionState) { s.PeerCertificates = nil },
		"nil-leaf":   func(s *tls.ConnectionState) { s.PeerCertificates = []*x509.Certificate{nil} },
		"nil-chain":  func(s *tls.ConnectionState) { s.VerifiedChains = [][]*x509.Certificate{{nil}} },
		"wrong-leaf": func(s *tls.ConnectionState) {
			c := *s.PeerCertificates[0]
			c.Raw = []byte("different")
			s.PeerCertificates = []*x509.Certificate{&c}
		},
		"ambiguous-uri": func(s *tls.ConnectionState) {
			c := *s.PeerCertificates[0]
			c.URIs = []*url.URL{c.URIs[0], c.URIs[0]}
			s.PeerCertificates = []*x509.Certificate{&c}
		},
		"expired-intermediate": func(s *tls.ConnectionState) {
			c := *s.PeerCertificates[0]
			c.NotAfter = now
			s.VerifiedChains = [][]*x509.Certificate{{s.PeerCertificates[0], &c}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := original
			change(&state)
			if _, err := VerifyOpen(token, claims.Authority, trust, state, now); !errors.Is(err, ErrAuthority) {
				t.Fatal("invalid peer accepted")
			}
		})
	}
}

func TestSignedScopeCannotBeChanged(t *testing.T) {
	claims, trust, private, state, now := grantFixture(t)
	token := mustSign(t, claims, private)
	parts := strings.Split(token, ".")
	for name, mutate := range map[string]func(*OpenClaims){
		"tenant": func(v *OpenClaims) { v.Tenant = "tenant-b" }, "source": func(v *OpenClaims) { v.Source = "source-b" },
		"revision": func(v *OpenClaims) { v.SourceRevision = strings.Repeat("a", 64) },
		"token":    func(v *OpenClaims) { v.TokenID = "token-b" }, "generation": func(v *OpenClaims) { v.TokenGeneration = strings.Repeat("a", 64) },
		"tunnel": func(v *OpenClaims) { v.TunnelID = strings.Repeat("a", 64) }, "control-owner": func(v *OpenClaims) { v.ControlOwner = strings.Repeat("a", 64) },
		"worker": func(v *OpenClaims) { v.Execution.Worker = "worker-b" }, "incarnation": func(v *OpenClaims) { v.Execution.Owner = strings.Repeat("a", 32) },
		"attempt": func(v *OpenClaims) { v.Execution.Claim = strings.Repeat("a", 32) }, "execution": func(v *OpenClaims) { v.Execution.ID = "query-b" },
		"grant": func(v *OpenClaims) { v.Execution.GrantSHA256 = strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			altered := claims
			mutate(&altered)
			payload, _ := json.Marshal(altered)
			changed := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]
			if _, err := VerifyOpen(changed, claims.Authority, trust, state, now); !errors.Is(err, ErrAuthority) {
				t.Fatal("changed signed scope accepted")
			}
		})
	}
}

func TestSignedMalformedJSONAndLifetimeFailClosed(t *testing.T) {
	claims, trust, private, state, now := grantFixture(t)
	payload, _ := json.Marshal(claims)
	header, _ := json.Marshal(joseHeader{"EdDSA", "rabbit-connect+jwt", claims.Issuer})
	signedRaw := func(body, h string) string {
		unsigned := base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + base64.RawURLEncoding.EncodeToString([]byte(body))
		return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(unsigned)))
	}
	for name, body := range map[string]string{
		"duplicate":        strings.Replace(string(payload), `"tenant":"tenant-a"`, `"tenant":"tenant-a","tenant":"tenant-b"`, 1),
		"case-alias":       strings.Replace(string(payload), `"tenant":"tenant-a"`, `"tenant":"tenant-a","TENANT":"tenant-b"`, 1),
		"unknown":          strings.TrimSuffix(string(payload), "}") + `,"unexpected":true}`,
		"second-document":  string(payload) + `{}`,
		"nested-duplicate": strings.Replace(string(payload), `"worker_id":"worker-a"`, `"worker_id":"worker-a","worker_id":"worker-b"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyOpen(signedRaw(body, string(header)), claims.Authority, trust, state, now); !errors.Is(err, ErrAuthority) {
				t.Fatal("malformed signed payload accepted")
			}
		})
	}
	if _, err := VerifyOpen(signedRaw(string(payload), strings.Replace(string(header), "rabbit-connect+jwt", "JWT", 1)), claims.Authority, trust, state, now); !errors.Is(err, ErrAuthority) {
		t.Fatal("another JWT protocol accepted")
	}
	for _, mutate := range []func(*OpenClaims){
		func(c *OpenClaims) { c.ExpiresAt = c.IssuedAt }, func(c *OpenClaims) { c.ExpiresAt = c.IssuedAt + 61 },
		func(c *OpenClaims) { c.SessionExpiresAt = c.ExpiresAt - 1 }, func(c *OpenClaims) { c.SessionExpiresAt = c.IssuedAt + 86401 },
		func(c *OpenClaims) { c.Execution.Kind = "other" }, func(c *OpenClaims) { c.ControlOwner = "" },
	} {
		changed := claims
		mutate(&changed)
		if _, err := SignOpen(changed, private); !errors.Is(err, ErrAuthority) {
			t.Fatal("invalid grant lifetime or binding accepted")
		}
	}
}

func TestLeaseCannotExtendSignedSessionOrCertificate(t *testing.T) {
	claims, trust, private, state, now := grantFixture(t)
	token := mustSign(t, claims, private)
	verified, err := VerifyOpen(token, claims.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	// A long-running connection can renew its live lease after its one-use
	// admission ticket expires. The maximum session deadline remains signed.
	later := now.Add(time.Minute)
	if _, err := verified.LeaseDeadline(verified.Digest(), later.Add(10*time.Second).Unix(), later); err != nil {
		t.Fatal("admission expiry incorrectly ended a leased session")
	}
	for _, seconds := range []int64{-1, 0, 16} {
		if _, err := verified.LeaseDeadline(verified.Digest(), now.Add(time.Duration(seconds)*time.Second).Unix(), now); !errors.Is(err, ErrAuthority) {
			t.Fatal("invalid live lease accepted")
		}
	}
	if _, err := verified.LeaseDeadline(strings.Repeat("a", 64), now.Add(time.Second).Unix(), now); !errors.Is(err, ErrAuthority) {
		t.Fatal("foreign grant lease accepted")
	}
	nearExpiry := now.Add(time.Hour - 5*time.Second)
	if _, err := verified.LeaseDeadline(verified.Digest(), nearExpiry.Add(10*time.Second).Unix(), nearExpiry); !errors.Is(err, ErrAuthority) {
		t.Fatal("session or certificate expiry extended")
	}
}

func TestAuthorityRequiresCanonicalHostAndPort(t *testing.T) {
	for _, value := range []string{"db.customer.internal:5432", "127.0.0.1:6379", "[2001:db8::1]:5432"} {
		if !ValidAuthority(value) {
			t.Errorf("valid authority rejected: %s", value)
		}
	}
	for _, value := range []string{"", "host", "host:0", "host:65536", "host:05432", "user@host:5432", "host:5432/path", "HOST:5432", "host.:5432", "-host:5432", "host:5432\r\n", "[fe80::1%eth0]:5432", "[::]:5432", "0.0.0.0:5432", "https://host:5432"} {
		if ValidAuthority(value) {
			t.Errorf("invalid authority accepted: %q", value)
		}
	}
}
