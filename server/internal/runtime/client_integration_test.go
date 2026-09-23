package runtime

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Run with an explicitly built sibling client. No database or Docker is required.
func TestRuntimeClientTLSIntegration(t *testing.T) {
	binary := os.Getenv("RABBIT_RUNTIME_CLIENT_TEST_BINARY")
	if binary == "" {
		t.Skip("set RABBIT_RUNTIME_CLIENT_TEST_BINARY to the built sibling client")
	}
	router, authority := testRouter(t)
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certs, cert := certServer.TLS.Certificates, certServer.Certificate()
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certs, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var handlers sync.WaitGroup
	defer handlers.Wait()
	defer router.Close()
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				reader := bufio.NewReader(conn)
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				frame, err := reader.ReadString('\n')
				if err != nil {
					conn.Close()
					return
				}
				router.Handle(strings.TrimSuffix(frame, "\n"), conn, reader)
			}()
		}
	}()
	defer func() { listener.Close(); <-acceptDone }()
	helper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/probe" {
			http.NotFound(w, request)
			return
		}
		_, _ = io.WriteString(w, "private helper response")
	}))
	defer helper.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600)
	config := map[string]any{"version": 2, "serverAddress": listener.Addr().String(), "caFile": ca, "serverName": "", "helperAddress": strings.TrimPrefix(helper.URL, "http://"), "registration": fixture()}
	encoded, _ := json.Marshal(config)
	file := filepath.Join(dir, "runtime.json")
	os.WriteFile(file, encoded, 0600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.CommandContext(ctx, binary, "runtime-connect", "--connection-file", file)
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = command.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		router.mu.Lock()
		ready := len(router.sessions) == 1
		router.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client did not register")
		}
		time.Sleep(10 * time.Millisecond)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	broker, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	_ = broker.SetDeadline(time.Now().Add(10 * time.Second))
	input, _ := json.Marshal(OpenRequest{Scope: fixture().Scope, BrokerToken: brokerSecret})
	_, _ = broker.Write(append([]byte(OpenFrame+"\n"), append(input, '\n')...))
	reader := bufio.NewReader(broker)
	if line(t, reader) != "READY" {
		t.Fatal("not ready")
	}
	_, _ = io.WriteString(broker, "GET /v2/probe HTTP/1.1\r\nHost: notebook\r\nConnection: keep-alive\r\n\r\n")
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "private helper response" {
		t.Fatal("helper response lost")
	}
	// The next live authority denial closes this existing bridge, not just future opens.
	authority.denied.Store(true)
	_ = broker.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err = reader.ReadByte(); err == nil {
		t.Fatal("revoked private stream survived")
	} else if n, ok := err.(net.Error); ok && n.Timeout() {
		t.Fatal("revocation did not close active stream")
	}
}
