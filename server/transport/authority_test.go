package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type authorityRoundTrip func(*http.Request) (*http.Response, error)

func (f authorityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPooledAuthorityCertificateMustRemainCurrent(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Second)}
	state := &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{cert}}}
	if until, valid := authorityPeerDeadline(state, now); !valid || !until.Equal(cert.NotAfter) {
		t.Fatal("current verified peer rejected")
	}
	if _, valid := authorityPeerDeadline(state, now.Add(time.Second)); valid {
		t.Fatal("pooled authority certificate expiry ignored")
	}
	state.VerifiedChains = [][]*x509.Certificate{{nil}}
	if _, valid := authorityPeerDeadline(state, now); valid {
		t.Fatal("invalid verified chain accepted")
	}
}

func TestPooledAuthorityClientChainExpiresWithIntermediate(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	intermediate := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Second)}
	chain := []*x509.Certificate{leaf, intermediate}
	if until, valid := certificateDeadline(chain, now); !valid || !until.Equal(intermediate.NotAfter) {
		t.Fatal("authority client identity ignored intermediate lifetime")
	}
	if _, valid := certificateDeadline(chain, now.Add(time.Second)); valid {
		t.Fatal("authority client identity remained valid after expiry")
	}
	if _, valid := certificateDeadline(chain, now.Add(-2*time.Minute)); valid {
		t.Fatal("authority client identity accepted before its validity period")
	}
	if _, valid := certificateDeadline(nil, now); valid {
		t.Fatal("empty authority client identity accepted")
	}
}

func TestAuthorityLeaseCannotOutliveEitherPooledTLSIdentity(t *testing.T) {
	claims, trust, private, state, now := grantFixture(t)
	token := mustSign(t, claims, private)
	open, err := VerifyOpen(token, claims.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			nearExpiry := time.Now().Add(4 * time.Second).Truncate(time.Second)
			client := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
			server := *client
			if side == "client" {
				client.NotAfter = nearExpiry
			} else {
				server.NotAfter = nearExpiry
			}
			a := &HTTPLeaseAuthority{endpoint: "https://authority.test/lease", clientChain: []*x509.Certificate{client},
				client: &http.Client{Transport: authorityRoundTrip(func(*http.Request) (*http.Response, error) {
					body := fmt.Sprintf(`{"version":1,"open_sha256":%q,"valid_until":%d}`, open.Digest(), time.Now().Unix()+10)
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)),
						TLS: &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{&server}}}}, nil
				})}}
			until, err := a.Authorize(context.Background(), token, open)
			if err != nil || !until.Equal(nearExpiry) {
				t.Fatal("lease outlived authority TLS identity", until, err)
			}
		})
	}
}

func TestExpiredAuthorityClientCannotSendLeaseRequest(t *testing.T) {
	claims, trust, private, state, now := grantFixture(t)
	token := mustSign(t, claims, private)
	open, err := VerifyOpen(token, claims.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	a := &HTTPLeaseAuthority{endpoint: "https://authority.test/lease", clientChain: []*x509.Certificate{{NotBefore: now.Add(-time.Minute), NotAfter: now}},
		client: &http.Client{Transport: authorityRoundTrip(func(*http.Request) (*http.Response, error) {
			t.Fatal("expired client identity sent request over pooled connection")
			return nil, ErrAuthority
		})}}
	if _, err := a.Authorize(context.Background(), token, open); err == nil {
		t.Fatal("expired authority client accepted")
	}
}
