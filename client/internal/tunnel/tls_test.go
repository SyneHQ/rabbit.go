package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifiedTLSForControlAndDataDial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	client, err := NewTunnelClient(TunnelClientConfig{ServerAddress: strings.TrimPrefix(server.URL, "https://"), Token: "test-token", CAFile: ca, ConnectionTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		conn, err := client.dialServer()
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	client.Config.ServerName = "wrong.example"
	if conn, err := client.dialServer(); err == nil {
		conn.Close()
		t.Fatal("accepted mismatched TLS hostname")
	}
	client.Config.ServerName = ""
	client.Config.CAFile = ""
	if conn, err := client.dialServer(); err == nil {
		conn.Close()
		t.Fatal("accepted untrusted certificate")
	}
}
func TestNoPlaintextFallback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			defer conn.Close()
			conn.Write([]byte("not TLS\n"))
		}
	}()
	client, _ := NewTunnelClient(TunnelClientConfig{ServerAddress: listener.Addr().String(), Token: "test-token", ConnectionTimeout: time.Second})
	if conn, err := client.dialServer(); err == nil {
		conn.Close()
		t.Fatal("downgraded to plaintext")
	}
	client.Config.InsecureLocal = true
	client.Config.ServerAddress = "8.8.8.8:9999"
	if _, err := client.dialServer(); err == nil {
		t.Fatal("allowed public plaintext")
	}
}

func TestTLSResumesOnlyWithinUnchangedClientTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(ca, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	config := TunnelClientConfig{ServerAddress: strings.TrimPrefix(server.URL, "https://"), Token: "test-token", CAFile: ca, ConnectionTimeout: time.Second}
	client, err := NewTunnelClient(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Stop()
	request := func(client *TunnelClient) bool {
		t.Helper()
		conn, err := client.dialServer()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		resumed := conn.(*tls.Conn).ConnectionState().DidResume
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		// Processing application reads also processes TLS 1.3 session tickets.
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Fatal(err)
		}
		return resumed
	}
	if request(client) || !request(client) {
		t.Fatal("expected a full handshake followed by TLS resumption")
	}
	previous := client.tlsConfig
	other, _ := NewTunnelClient(config)
	defer other.Stop()
	if request(other) || other.tlsConfig.ClientSessionCache == previous.ClientSessionCache {
		t.Fatal("session cache crossed client boundary")
	}
	client.Config.ServerName = "wrong.example"
	if conn, err := client.dialServer(); err == nil {
		conn.Close()
		t.Fatal("resumed through hostname mismatch")
	}
	client.Config.ServerName = ""
	if request(client) {
		t.Fatal("identity change retained previous session tickets")
	}

	// Replace the trust file at the same path. A stale root/cache would accept
	// the previously trusted server, so require its next handshake to fail.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	replacement := ca + ".new"
	if err := os.WriteFile(replacement, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, ca); err != nil {
		t.Fatal(err)
	}
	if conn, err := client.dialServer(); err == nil {
		conn.Close()
		t.Fatal("CA replacement retained old root or session ticket")
	}
	if client.tlsConfig == previous {
		t.Fatal("CA replacement retained old TLS config")
	}
	if err := os.WriteFile(ca, []byte("invalid CA"), 0600); err != nil {
		t.Fatal(err)
	}
	if conn, err := client.dialServer(); err == nil {
		conn.Close()
		t.Fatal("invalid replacement CA fell back to cached trust")
	}
}

func TestTLSDialCancellationDuringHandshake(t *testing.T) {
	listener := testTCPListener(t)
	client, _ := NewTunnelClient(TunnelClientConfig{ServerAddress: listener.Addr().String(), Token: "test-token", ConnectionTimeout: time.Minute})
	defer client.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		conn, err := client.dialServerContext(ctx)
		if conn != nil {
			conn.Close()
		}
		finished <- err
	}()
	_ = acceptTestConn(t, listener) // Leave the TLS handshake unanswered.
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("cancelled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("TLS handshake ignored cancellation")
	}
}

func TestTLSClientBridgePreservesHalfClose(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := fixture.TLS.Certificates
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: certificates})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *tls.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			tlsConn := conn.(*tls.Conn)
			_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
			if tlsConn.Handshake() == nil {
				accepted <- tlsConn
				return
			}
			conn.Close()
		}
		accepted <- nil
	}()
	data, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	remote := <-accepted
	if remote == nil {
		t.Fatal("TLS fixture handshake failed")
	}
	defer remote.Close()
	localListener := testTCPListener(t)
	local, err := net.DialTimeout("tcp", localListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	database := acceptTestConn(t, localListener)
	finished := make(chan struct{})
	go func() { bridgeData(data, local); close(finished) }()
	if _, err := io.WriteString(remote, "request"); err != nil {
		t.Fatal(err)
	}
	if err := remote.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(database)
	if err != nil || string(request) != "request" {
		t.Fatalf("request half-close failed: %q %v", request, err)
	}
	if _, err := io.WriteString(database, "response"); err != nil {
		t.Fatal(err)
	}
	if err := database.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(remote)
	if err != nil || string(response) != "response" {
		t.Fatalf("response half-close failed: %q %v", response, err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("TLS bridge did not finish after both half-closes")
	}
}
