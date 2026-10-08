//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Rabbit remains the fixture coordinator so this test exercises its actual
// server and customer client. Kelvo supplies a test binary, not an import of
// either project's internal packages. The helper is trusted fixture code only.
func TestKelvoPrivateNativePostgres(t *testing.T) {
	helper := os.Getenv("RABBIT_KELVO_NATIVE_HELPER")
	if helper == "" || os.Getenv("RABBIT_TRANSPORT_DATABASE_URL") == "" ||
		os.Getenv("RABBIT_DATABASE_CLIENT_TEST_BINARY") == "" || os.Getenv("RABBIT_TRANSPORT_REDIS_URL") == "" {
		t.Skip("requires the native Kelvo helper and owned Rabbit database fixtures")
	}
	if info, err := os.Stat(helper); err != nil || info.IsDir() || info.Mode()&0111 == 0 {
		t.Fatal("RABBIT_KELVO_NATIVE_HELPER must name an executable test binary")
	}
	var accepted atomic.Int32
	relay, sourceCA := newKelvoPostgresRelayObserved(t, os.Getenv("RABBIT_TRANSPORT_DATABASE_URL"), func() { accepted.Add(1) })
	f := newNativePrivateFixture(t, relay)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := f.h.fixture.ExecContext(ctx, `CREATE UNLOGGED TABLE private_connect_rows AS
SELECT i::BIGINT AS id,(i%17)::INTEGER AS category,
CASE WHEN i%13=0 THEN NULL ELSE 'row-'||i::TEXT END AS note FROM generate_series(1,100000) AS fixture(i)`); err != nil {
		t.Fatal("cannot create owned native row fixture")
	}
	for _, mode := range []string{"rows", "cancel", "denied-source", "denied-tenant", "hostname"} {
		t.Run(mode, func(t *testing.T) {
			before := accepted.Load()
			input := kelvoNativeInput(t, f, sourceCA, mode)
			result := runKelvoNativeHelper(t, helper, input)
			wantOpens := int32(1)
			wantMode := mode
			if mode == "cancel" {
				wantOpens = 2
			} else if strings.HasPrefix(mode, "denied-") {
				wantOpens = 0
				wantMode = "denied"
			}
			if result.Mode != wantMode || result.Opens != wantOpens || accepted.Load()-before != wantOpens {
				t.Fatal("native opener or customer-dial count did not match its scope", result.Opens, accepted.Load()-before)
			}
			if mode == "rows" && result.Rows != 100000 {
				t.Fatal("native row evidence is incomplete")
			}
		})
	}
}

func kelvoNativeInput(t *testing.T, f *nativePrivateFixture, sourceCA []byte, mode string) []byte {
	t.Helper()
	certificate := f.tls.Certificates[0]
	var certificatePEM []byte
	for _, raw := range certificate.Certificate {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})...)
	}
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal("cannot encode generated worker fixture key")
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[len(certificate.Certificate)-1]})
	claims := f.claims
	if mode == "denied-source" {
		claims.Source = "foreign-source"
		mode = "denied"
	} else if mode == "denied-tenant" {
		claims.Tenant = "foreign-tenant"
		mode = "denied"
	} else if mode == "hostname" {
		claims.Authority = strings.Replace(claims.Authority, "localhost:", "wrong-source.invalid:", 1)
	}
	database, err := url.Parse(f.h.fixtureDSN)
	if err != nil {
		t.Fatal("cannot identify owned fixture database")
	}
	input := map[string]any{
		"version": 1, "mode": mode, "claims": claims, "key": []byte(f.key), "source_ca": sourceCA,
		"database": strings.TrimPrefix(database.Path, "/"), "admin_url": f.h.fixtureDSN,
		"proxy": map[string]any{
			"ProxyAddress": f.h.server.privateListener.Addr().String(), "ProxyServerName": "localhost", "RootCAPEM": ca,
			"ClientCertificatePEM": certificatePEM, "ClientKeyPEM": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
			"WorkerIdentity": claims.WorkerIdentity, "Issuer": claims.Issuer, "Audience": claims.Audience,
			"ClusterTenant": claims.ClusterTenant, "ServicePrincipal": claims.ServicePrincipal,
			"IssuerPublicKey": f.key.Public().(ed25519.PublicKey),
		},
	}
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > 256<<10 {
		t.Fatal("cannot encode bounded native fixture input")
	}
	return encoded
}

type kelvoNativeResult struct {
	Version int    `json:"version"`
	Mode    string `json:"mode"`
	Rows    int64  `json:"rows"`
	Opens   int32  `json:"opens"`
}

func runKelvoNativeHelper(t *testing.T, helper string, input []byte) kelvoNativeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, helper, "-test.run=^TestRabbitNativePostgresHelper$", "-test.count=1", "-test.timeout=45s")
	command.Env = []string{"KELVO_RABBIT_NATIVE_HELPER=1", "GOMAXPROCS=1", "TZ=UTC"}
	command.Stdin = bytes.NewReader(input)
	output := &nativeHelperOutput{}
	command.Stdout, command.Stderr = output, output
	command.WaitDelay = 2 * time.Second
	if err := command.Run(); err != nil {
		// Helper diagnostics contain only fixed fixture messages, never config.
		t.Fatalf("native Kelvo helper failed: %s", output.String())
	}
	var result kelvoNativeResult
	found := false
	for _, line := range strings.Split(output.String(), "\n") {
		if !strings.HasPrefix(line, "KELVO_NATIVE_RESULT:") {
			continue
		}
		if found || json.Unmarshal([]byte(strings.TrimPrefix(line, "KELVO_NATIVE_RESULT:")), &result) != nil || result.Version != 1 {
			t.Fatal("invalid or duplicate native helper receipt")
		}
		found = true
	}
	if !found {
		t.Fatal("native helper emitted no result receipt")
	}
	return result
}

type nativeHelperOutput struct{ bytes.Buffer }

func (b *nativeHelperOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 32<<10 {
		return 0, errors.New("native helper output limit exceeded")
	}
	return b.Buffer.Write(data)
}
