package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"rabbit.go/transport"
)

func routeRequest(body string) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: rabbit.internal:8443\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", privateRoutePath, len(body), body)
}

func TestPrivateRouteRequestStrict(t *testing.T) {
	body := `{"version":1,"tenant":"team-a","token_id":"12345678-1234-1234-1234-123456789abc"}`
	valid := routeRequest(body)
	if tenant, token, err := readPrivateRoute(bufio.NewReaderSize(strings.NewReader(valid), privateHeaderLimit)); err != nil || tenant != "team-a" || token != "12345678-1234-1234-1234-123456789abc" {
		t.Fatal("valid route request rejected", err)
	}
	for name, request := range map[string]string{
		"wrong path":       strings.Replace(valid, privateRoutePath, privateRoutePath+"?x=1", 1),
		"wrong method":     strings.Replace(valid, "POST", "GET", 1),
		"duplicate length": strings.Replace(valid, "Connection: close", "Content-Length: 1", 1),
		"service header":   strings.Replace(valid, "Connection: close", "X-Service-Token: secret", 1),
		"user header":      strings.Replace(valid, "Connection: close", "X-User-ID: owner", 1),
		"chunked":          strings.Replace(valid, "Connection: close", "Transfer-Encoding: chunked", 1),
		"duplicate field":  routeRequest(strings.Replace(body, `"version":1`, `"version":1,"version":1`, 1)),
		"unknown field":    routeRequest(strings.Replace(body, `"version":1`, `"version":1,"extra":1`, 1)),
		"wrong version":    routeRequest(strings.Replace(body, `"version":1`, `"version":2`, 1)),
		"null version":     routeRequest(strings.Replace(body, `"version":1`, `"version":null`, 1)),
		"trailing body":    routeRequest(body + `{}`),
		"uppercase UUID":   routeRequest(strings.Replace(body, "9abc", "9ABC", 1)),
		"large body":       routeRequest(strings.Repeat("x", 1025)),
		"large header":     strings.Replace(valid, "Connection: close", "User-Agent: "+strings.Repeat("x", privateHeaderLimit), 1),
		"missing type":     strings.Replace(valid, "Content-Type: application/json\r\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := readPrivateRoute(bufio.NewReaderSize(strings.NewReader(request), privateHeaderLimit)); err == nil {
				t.Fatal("malformed route request accepted")
			}
		})
	}
}

func TestPrivateRouteIssuerPolicy(t *testing.T) {
	_, client, identity, _ := privateTestTLS(t)
	leaf, _ := x509.ParseCertificate(client.Certificates[0].Certificate[0])
	root, _ := x509.ParseCertificate(client.Certificates[0].Certificate[1])
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, root}}}
	p := &privateConnect{issuerIdentity: identity}
	if !p.routeIssuer(state, time.Now()) {
		t.Fatal("valid issuer denied")
	}
	if p.routeIssuer(state, leaf.NotAfter) {
		t.Fatal("expired issuer accepted")
	}
	p.trust = []transport.Trust{{WorkerIdentity: identity}}
	if p.routeIssuer(state, time.Now()) {
		t.Fatal("worker identity accepted as issuer")
	}
	for _, bad := range []string{"", "https://issuer.test", "spiffe:///issuer", "spiffe://user@issuer.test/id", "spiffe://issuer.test/id?query", "spiffe://issuer.test/id#fragment"} {
		if validPrivateIssuer(bad, nil) {
			t.Fatal("invalid issuer accepted")
		}
	}
	if validPrivateIssuer(identity, []PrivateTrust{{WorkerIdentity: identity}}) {
		t.Fatal("overlapping issuer accepted")
	}
	if !validPrivateIssuer(identity, nil) {
		t.Fatal("valid issuer configuration rejected")
	}
}

func TestPrivateRouteMTLS(t *testing.T) {
	for _, test := range []string{"issuer", "disabled", "worker", "wrong identity", "wrong tenant", "revoked", "replaced"} {
		t.Run(test, func(t *testing.T) {
			f := newPrivateFixture(t, nil)
			identity := f.server.private.trust[0].WorkerIdentity
			if test != "disabled" {
				f.server.private.issuerIdentity = identity
			}
			if test != "worker" {
				f.server.private.trust[0].WorkerIdentity = "spiffe://example.test/other-worker"
			}
			if test == "wrong identity" {
				f.server.private.issuerIdentity = "spiffe://example.test/other-issuer"
			}
			if test == "revoked" {
				f.server.private.tokenActive = func(context.Context, *Tunnel) (time.Time, error) { return time.Time{}, transport.ErrAuthority }
			}
			if test == "replaced" {
				f.server.private.tokenActive = func(context.Context, *Tunnel) (time.Time, error) {
					f.server.mu.Lock()
					f.tunnel.tokenEpoch = strings.Repeat("8", 64)
					f.server.mu.Unlock()
					return time.Time{}, nil
				}
			}
			tenant := "team-a"
			if test == "wrong tenant" {
				tenant = "team-b"
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", f.server.privateListener.Addr().String(), f.clientTLS)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"version":1,"tenant":%q,"token_id":%q}`, tenant, f.tunnel.TokenID)
			if _, err := io.WriteString(conn, routeRequest(body)); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			want := 403
			if test == "issuer" {
				want = 200
			}
			if test == "wrong tenant" || test == "revoked" || test == "replaced" {
				want = 404
			}
			if resp.StatusCode != want {
				t.Fatalf("status %d; want %d", resp.StatusCode, want)
			}
			if want == 200 {
				var result struct {
					Version int                 `json:"version"`
					Route   transport.RouteInfo `json:"route"`
				}
				if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Version != 1 || result.Route.Validate() != nil || result.Route.Tenant != tenant || result.Route.TokenID != f.tunnel.TokenID || resp.Header.Get("Cache-Control") != "private, no-store" {
					t.Fatal("invalid discovery response")
				}
			}
			if f.dispatched.Load() != 0 || f.checks.Load() != 0 {
				t.Fatal("route discovery opened source or issued authority")
			}
		})
	}
}
