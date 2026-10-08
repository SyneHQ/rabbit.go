package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rabbit.go/transport"
)

func TestPrivateAuthorityMTLSAndStrictLeaseResponses(t *testing.T) {
	testPrivateAuthorityMTLS(t, transport.Version)
}

func TestPrivateReservationAuthorityMTLSAndStrictLeaseResponses(t *testing.T) {
	testPrivateAuthorityMTLS(t, transport.ReservationVersion)
}

func testPrivateAuthorityMTLS(t *testing.T, version int) {
	t.Helper()
	f := newPrivateFixture(t, nil)
	leaf, err := x509.ParseCertificate(f.clientTLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	// The codec's verified-peer input is separate from the actual authority
	// mTLS handshake exercised by each request below.
	state := tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	var token, digest string
	var authorize func(*transport.HTTPLeaseAuthority) (time.Time, error)
	if version == transport.Version {
		token, err = transport.SignOpen(f.claims, f.key)
		if err != nil {
			t.Fatal(err)
		}
		open, err := transport.VerifyOpen(token, f.claims.Authority, f.server.private.trust[0], state, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		digest = open.Digest()
		authorize = func(a *transport.HTTPLeaseAuthority) (time.Time, error) {
			return a.Authorize(context.Background(), token, open)
		}
	} else {
		claims := transport.ReservationClaims{OpenClaims: f.claims}
		claims.Version = transport.ReservationVersion
		token, err = transport.SignReservation(claims, f.key)
		if err != nil {
			t.Fatal(err)
		}
		open, err := transport.VerifyReservationData(token, claims.Authority, f.server.private.trust[0], state, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		digest = open.Digest()
		authorize = func(a *transport.HTTPLeaseAuthority) (time.Time, error) {
			return a.AuthorizeReservation(context.Background(), token, open)
		}
	}
	for _, mode := range []string{"valid", "wrong version", "wrong digest", "expired", "excess lease", "duplicate JSON", "unknown JSON", "redirect", "wrong media", "oversize", "unavailable", "encoded"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.PeerCertificates[0].URIs[0].String() != f.claims.WorkerIdentity {
					t.Error("authority did not verify Rabbit fixture identity")
					w.WriteHeader(403)
					return
				}
				data, err := io.ReadAll(io.LimitReader(r.Body, transport.MaxTokenBytes+1024))
				var request transport.LeaseRequest
				want := fmt.Sprintf(`{"version":%d,"token":%q,"open_sha256":%q}`, version, token, digest)
				if err != nil || string(data) != want || json.Unmarshal(data, &request) != nil || request.Version != version || request.Token != token || request.Digest != digest {
					t.Error("lease request lost signed scope")
					w.WriteHeader(400)
					return
				}
				response := transport.LeaseResponse{Version: version, Digest: digest, ValidUntil: time.Now().Unix() + 3}
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "wrong version":
					response.Version = 3 - version
				case "wrong digest":
					response.Digest = strings.Repeat("a", 64)
				case "expired":
					response.ValidUntil = time.Now().Unix()
				case "excess lease":
					response.ValidUntil = time.Now().Unix() + 20
				case "duplicate JSON":
					fmt.Fprintf(w, `{"version":%d,"version":%d}`, version, version)
					return
				case "unknown JSON":
					fmt.Fprintf(w, `{"version":%d,"open_sha256":%q,"valid_until":%d,"extra":true}`, version, digest, response.ValidUntil)
					return
				case "redirect":
					w.Header().Set("Location", "https://unrelated.invalid/lease")
					w.WriteHeader(307)
					return
				case "wrong media":
					w.Header().Set("Content-Type", "text/plain")
				case "oversize":
					io.WriteString(w, strings.Repeat(" ", 4097))
					return
				case "unavailable":
					w.WriteHeader(503)
					return
				case "encoded":
					w.Header().Set("Content-Encoding", "gzip")
				}
				json.NewEncoder(w).Encode(response)
			}))
			server.TLS = f.server.private.tls.Clone()
			server.StartTLS()
			t.Cleanup(server.Close)
			authority, err := transport.NewHTTPLeaseAuthority(server.URL, f.clientTLS)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(authority.Close)
			_, err = authorize(authority)
			if (err == nil) != (mode == "valid") {
				t.Fatal("unexpected live lease outcome", mode, err)
			}
		})
	}
}

func TestPrivateAuthorityRejectsUnverifiedTransportConfiguration(t *testing.T) {
	f := newPrivateFixture(t, nil)
	for _, endpoint := range []string{"http://127.0.0.1/lease", "https://user:password@example.test/lease", "https://example.test/lease?secret=x", "https://example.test/lease#part"} {
		if authority, err := transport.NewHTTPLeaseAuthority(endpoint, f.clientTLS); err == nil {
			authority.Close()
			t.Fatal("unsafe authority endpoint accepted")
		}
	}
	config := f.clientTLS.Clone()
	config.InsecureSkipVerify = true
	if authority, err := transport.NewHTTPLeaseAuthority("https://example.test/lease", config); err == nil {
		authority.Close()
		t.Fatal("unverified authority TLS accepted")
	}
}
