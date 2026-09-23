package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runtimeFixture() RuntimeRegistration {
	return RuntimeRegistration{RuntimeScope: RuntimeScope{RuntimeID: "runtime_1", TeamID: "team_1", InstallationID: "installation_1", Service: "notebook-v2",
		CredentialGeneration: 1, PolicyRevision: 1, LedgerGeneration: "ledger_1", EnvironmentSHA256: strings.Repeat("a", 64)}, Credential: strings.Repeat("s", 64)}
}

func TestRuntimeRejectsArbitraryServiceAndPlaintext(t *testing.T) {
	base := RuntimeClient{Registration: runtimeFixture(), HelperAddress: "127.0.0.1:8888"}
	if base.validate() != nil {
		t.Fatal("valid config rejected")
	}
	for _, mutate := range []func(*RuntimeClient){
		func(c *RuntimeClient) { c.HelperAddress = "example.com:8888" }, func(c *RuntimeClient) { c.Dial.InsecureLocal = true },
		func(c *RuntimeClient) { c.Registration.Service = "postgres" }, func(c *RuntimeClient) { c.Registration.PolicyRevision = 0 },
		func(c *RuntimeClient) { c.Registration.EnvironmentSHA256 = "unknown" },
	} {
		c := base
		mutate(&c)
		if c.validate() == nil {
			t.Fatal("unsafe runtime config accepted")
		}
	}
}

func TestRuntimePairsTLSDataWithFixedHelperAndStopsOnDisconnect(t *testing.T) {
	fixtureServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certs := fixtureServer.TLS.Certificates
	certificate := fixtureServer.Certificate()
	fixtureServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certs, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	helper, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	helperDone := make(chan error, 1)
	go func() {
		conn, err := helper.Accept()
		if err != nil {
			helperDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		p := make([]byte, 7)
		_, err = io.ReadFull(conn, p)
		if err == nil && string(p) != "request" {
			err = errRuntimeTransport
		}
		if err == nil {
			_, err = conn.Write([]byte("response"))
		}
		helperDone <- err
	}()
	client := &RuntimeClient{Dial: TunnelClientConfig{ServerAddress: listener.Addr().String(), CAFile: ca}, Registration: runtimeFixture(), HelperAddress: helper.Addr().String()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.runOnce(ctx) }()
	control, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	cr := bufio.NewReader(control)
	line, err := runtimeLine(cr)
	if err != nil || line != "RUNTIME-V2" {
		t.Fatalf("control frame %q %v", line, err)
	}
	line, err = runtimeLine(cr)
	if err != nil {
		t.Fatal(err)
	}
	var registration RuntimeRegistration
	if json.Unmarshal([]byte(line), &registration) != nil || registration != client.Registration {
		t.Fatal("changed registration")
	}
	_, _ = io.WriteString(control, "READY\nOPEN "+strings.Repeat("b", 64)+"\n")
	data, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	_ = data.SetDeadline(time.Now().Add(5 * time.Second))
	dr := bufio.NewReader(data)
	line, err = runtimeLine(dr)
	if err != nil || line != "RUNTIME-DATA-V2" {
		t.Fatalf("data frame %q %v", line, err)
	}
	line, err = runtimeLine(dr)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		RuntimeRegistration
		ConnectionID string `json:"connectionId"`
	}
	if json.Unmarshal([]byte(line), &request) != nil || request.RuntimeRegistration != client.Registration || request.ConnectionID != strings.Repeat("b", 64) {
		t.Fatal("changed data identity")
	}
	// Payload coalesced with pairing acknowledgement must not be discarded by buffering.
	_, _ = io.WriteString(data, "PAIRED\nrequest")
	p := make([]byte, 8)
	if _, err = io.ReadFull(dr, p); err != nil || string(p) != "response" {
		t.Fatalf("response %q %v", p, err)
	}
	if err = <-helperDone; err != nil {
		t.Fatal(err)
	}
	control.Close()
	select {
	case <-clientDone:
	case <-time.After(3 * time.Second):
		t.Fatal("control loss did not stop owned data goroutines")
	}
}
