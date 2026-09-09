package tunnel

import (
	"encoding/pem"
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
