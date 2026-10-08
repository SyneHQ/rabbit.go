//go:build !windows

package server

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateConnectConfigurationIsOptInAndUsesPrivateMTLS(t *testing.T) {
	if value, err := loadPrivateConnect(nil); err != nil || value != nil {
		t.Fatal("omitted private ingress changed existing behavior")
	}
	server, worker, identity, _ := privateTestTLS(t)
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certificate := func(name string, chain [][]byte) string {
		var data []byte
		for _, der := range chain {
			data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		return write(name, data, 0644)
	}
	key, err := x509.MarshalPKCS8PrivateKey(server.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := write("identity.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
	certFile := certificate("server.crt", server.Certificates[0].Certificate)
	workerFile := certificate("worker.crt", worker.Certificates[0].Certificate)
	caFile := certificate("ca.crt", server.Certificates[0].Certificate[1:])
	config := PrivateConnectConfig{Listen: "127.0.0.1:14443", CertificateFile: certFile, PrivateKeyFile: keyFile, ClientCAFile: caFile,
		AuthorityURL: "https://authority.internal/transport-lease", AuthorityCAFile: caFile, AuthorityCertificate: workerFile, AuthorityPrivateKey: keyFile,
		Trust: []PrivateTrust{{Issuer: "issuer", Audience: "private-connect", ClusterTenant: "shared", ServicePrincipal: "gateway", WorkerIdentity: identity, PublicKeyHex: hex.EncodeToString(make([]byte, 32))}}}
	active, err := loadPrivateConnect(&config)
	if err != nil {
		t.Fatal("valid private configuration rejected", err)
	}
	active.close()
	for _, field := range []string{"issuer", "audience", "cluster", "service"} {
		t.Run("oversized "+field, func(t *testing.T) {
			changed := config
			changed.Trust = append([]PrivateTrust{}, config.Trust...)
			entry := &changed.Trust[0]
			value := strings.Repeat("x", 129)
			switch field {
			case "issuer":
				entry.Issuer = value
			case "audience":
				entry.Audience = value
			case "cluster":
				entry.ClusterTenant = value
			case "service":
				entry.ServicePrincipal = value
			}
			if value, err := loadPrivateConnect(&changed); err == nil {
				value.close()
				t.Fatal("trust accepted a field that no valid ticket can match")
			}
		})
	}
	boundary := config
	boundary.Trust = append([]PrivateTrust{}, config.Trust...)
	boundary.Trust[0].Issuer = strings.Repeat("i", 128)
	boundary.Trust[0].Audience = strings.Repeat("a", 128)
	boundary.Trust[0].ClusterTenant = strings.Repeat("c", 128)
	boundary.Trust[0].ServicePrincipal = strings.Repeat("s", 128)
	boundary.Trust[0].WorkerIdentity = "spiffe://example.test/" + strings.Repeat("w", 512-len("spiffe://example.test/"))
	if value, err := loadPrivateConnect(&boundary); err != nil {
		t.Fatal("valid trust limits rejected", err)
	} else {
		value.close()
	}
	for _, bind := range []string{"0.0.0.0:14443", "[::]:14443", "8.8.8.8:14443", "localhost:14443", "127.0.0.1:014443"} {
		changed := config
		changed.Listen = bind
		if value, err := loadPrivateConnect(&changed); err == nil {
			value.close()
			t.Fatal("public or ambiguous bind accepted", bind)
		}
	}
	changed := config
	changed.Trust = append(append([]PrivateTrust{}, config.Trust...), config.Trust[0])
	if value, err := loadPrivateConnect(&changed); err == nil {
		value.close()
		t.Fatal("duplicate trust accepted")
	}
	if err := os.Chmod(keyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if value, err := loadPrivateConnect(&config); err == nil {
		value.close()
		t.Fatal("publicly readable private key accepted")
	}
	if err := os.Chmod(keyFile, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.key")
	if err := os.Symlink(keyFile, link); err != nil {
		t.Fatal(err)
	}
	changed = config
	changed.PrivateKeyFile = link
	if value, err := loadPrivateConnect(&changed); err == nil {
		value.close()
		t.Fatal("symbolic-link private key accepted")
	}
	if _, err := privateFile(write("oversized.pem", []byte(strings.Repeat("x", (64<<10)+1)), 0600), true); err == nil {
		t.Fatal("unbounded private input accepted")
	}
}
