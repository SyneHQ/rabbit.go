package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rabbit.go/transport"
)

func TestPrivateAuthorityMTLSAndStrictLeaseResponses(t *testing.T) {
	f := newPrivateFixture(t, nil)
	token, err := transport.SignOpen(f.claims, f.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(f.clientTLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	// The codec's verified-peer input is separate from the actual authority
	// mTLS handshake exercised by each request below.
	state := tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	open, err := transport.VerifyOpen(token, f.claims.Authority, f.server.private.trust[0], state, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "wrong digest", "expired", "excess lease", "duplicate JSON", "redirect", "wrong media", "oversize", "unavailable", "encoded"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.PeerCertificates[0].URIs[0].String() != f.claims.WorkerIdentity {
					t.Error("authority did not verify Rabbit fixture identity")
					w.WriteHeader(403)
					return
				}
				data, err := io.ReadAll(io.LimitReader(r.Body, transport.MaxTokenBytes+1024))
				var request transport.LeaseRequest
				if err != nil || json.Unmarshal(data, &request) != nil || request.Version != 1 || request.Token != token || request.Digest != open.Digest() {
					t.Error("lease request lost signed scope")
					w.WriteHeader(400)
					return
				}
				response := transport.LeaseResponse{Version: 1, Digest: open.Digest(), ValidUntil: time.Now().Unix() + 3}
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "wrong digest":
					response.Digest = strings.Repeat("a", 64)
				case "expired":
					response.ValidUntil = time.Now().Unix()
				case "excess lease":
					response.ValidUntil = time.Now().Unix() + 20
				case "duplicate JSON":
					io.WriteString(w, `{"version":1,"version":1}`)
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
			_, err = authority.Authorize(context.Background(), token, open)
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
