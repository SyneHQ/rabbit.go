package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func apiTLSFixture(t *testing.T) *x509.CertPool {
	t.Helper()
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	cert := seed.TLS.Certificates[0]
	seed.Close()
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RABBIT_API_TLS_CERT_FILE", certFile)
	t.Setenv("RABBIT_API_TLS_KEY_FILE", keyFile)
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return pool
}

func TestManagementTLSVerifiedHTTPAndDenials(t *testing.T) {
	pool := apiTLSFixture(t)
	l, err := managementListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Service-Token") != "fixture-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		w.WriteHeader(204)
	}), ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := <-done; err != http.ErrServerClosed {
			t.Error(err)
		}
	})
	for _, tc := range []struct {
		name, scheme, token string
		trust               bool
		max                 uint16
		status              int
	}{
		{"trusted", "https", "fixture-token", true, tls.VersionTLS13, 204},
		{"missing-auth", "https", "", true, tls.VersionTLS13, 401},
		{"untrusted", "https", "fixture-token", false, tls.VersionTLS13, 0},
		{"tls12", "https", "fixture-token", true, tls.VersionTLS12, 0},
		{"plaintext", "http", "fixture-token", true, tls.VersionTLS13, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trust := x509.NewCertPool()
			if tc.trust {
				trust = pool
			}
			tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trust, MaxVersion: tc.max}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
			req, _ := http.NewRequest("GET", tc.scheme+"://"+l.Addr().String()+"/", nil)
			req.Header.Set("X-Service-Token", tc.token)
			resp, err := client.Do(req)
			if tc.status == 0 {
				if err == nil {
					resp.Body.Close()
					t.Fatal("TLS rejection was required")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d want=%d", resp.StatusCode, tc.status)
			}
			if resp.TLS != nil && resp.TLS.Version != tls.VersionTLS13 {
				t.Fatal("TLS 1.3 was required")
			}
		})
	}
}

func TestManagementTLSInvalidConfigurationDoesNotFallBack(t *testing.T) {
	for _, tc := range []struct{ cert, key string }{{"/private/missing-cert", ""}, {"", "/private/missing-key"}, {"/private/missing-cert", "/private/missing-key"}} {
		t.Setenv("RABBIT_API_TLS_CERT_FILE", tc.cert)
		t.Setenv("RABBIT_API_TLS_KEY_FILE", tc.key)
		l, err := managementListener("127.0.0.1:0")
		if err == nil {
			l.Close()
			t.Fatal("invalid TLS configuration accepted")
		}
		if strings.Contains(err.Error(), "/private/") {
			t.Fatal("error exposed a certificate path")
		}
	}
}

func TestManagementPlaintextCompatibility(t *testing.T) {
	t.Setenv("RABBIT_API_TLS_CERT_FILE", "")
	t.Setenv("RABBIT_API_TLS_KEY_FILE", "")
	l, err := managementListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
}
