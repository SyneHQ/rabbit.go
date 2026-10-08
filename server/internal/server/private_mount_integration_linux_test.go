//go:build linux

package server

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"gopkg.in/yaml.v3"
)

// The private development-cluster controller runs this test once to generate
// throwaway Secret contents and then inside a nonroot Pod using real SubPath
// mounts. Ordinary unit-test runs cannot count as mounted-file qualification.
func TestPrivateMountedSecretConfiguration(t *testing.T) {
	if output := os.Getenv("RABBIT_PRIVATE_MOUNT_GENERATE"); output != "" {
		generatePrivateMountFixture(t, output)
		return
	}
	root := os.Getenv("RABBIT_PRIVATE_MOUNT_ROOT")
	if root == "" {
		t.Skip("requires the named disposable Kubernetes Secret-mount fixture")
	}
	if root != "/etc/rabbit/fixture" || os.Geteuid() != 65532 || os.Getegid() != 65532 {
		t.Fatal("mounted-file qualification must run under its fixed nonroot identity")
	}
	for _, name := range []string{"server.key", "authority.key"} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0440 || stat.Uid != 0 || stat.Gid != 65532 {
			t.Fatal("key is not a root-owned 0440 Secret mount with the exact FSGroup", name)
		}
	}
	for _, name := range []string{"operator.yml", "default-group.yml", "wrong-group.yml", "world-key.yml"} {
		config, err := LoadOperatorConfig(filepath.Join(root, name))
		if err != nil {
			t.Fatal("mounted operator configuration could not be read", name, err)
		}
		private, err := loadPrivateConnect(config.PrivateConnect)
		if private != nil {
			private.close()
		}
		if (err == nil) != (name == "operator.yml") {
			t.Fatal("mounted key boundary did not enforce explicit trusted group", name, err)
		}
	}
	t.Log("RABBIT_PRIVATE_MOUNT_ACCEPTED root-owned-0440 subpath fsgroup65532 nonroot65532 strict-negative-cases")
}

func generatePrivateMountFixture(t *testing.T, output string) {
	t.Helper()
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !operatorFileOwnerAllowed(info) {
		t.Fatal("mount fixture output must be a trusted private directory")
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 0 {
		t.Fatal("mount fixture output must be empty")
	}
	server, worker, identity, _ := privateTestTLS(t)
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	certPEM := func(chain [][]byte) []byte {
		var data []byte
		for _, raw := range chain {
			data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})...)
		}
		return data
	}
	key, err := x509.MarshalPKCS8PrivateKey(server.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	write("server.key", keyPEM)
	write("authority.key", keyPEM)
	write("world.key", keyPEM)
	write("server.crt", certPEM(server.Certificates[0].Certificate))
	write("authority.crt", certPEM(worker.Certificates[0].Certificate))
	write("ca.crt", certPEM(server.Certificates[0].Certificate[1:]))
	const mount = "/etc/rabbit/fixture/"
	gid := uint32(65532)
	public := server.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	config := PrivateConnectConfig{Listen: "127.0.0.1:14443", CertificateFile: mount + "server.crt", PrivateKeyFile: mount + "server.key", PrivateKeyGroup: &gid,
		ClientCAFile: mount + "ca.crt", AuthorityURL: "https://localhost/transport-lease", AuthorityCAFile: mount + "ca.crt", AuthorityCertificate: mount + "authority.crt", AuthorityPrivateKey: mount + "authority.key",
		Trust: []PrivateTrust{{Issuer: "fixture", Audience: "database-ingress", ClusterTenant: "shared", ServicePrincipal: "analytics", WorkerIdentity: identity, PublicKeyHex: hex.EncodeToString(public)}}}
	for _, name := range []string{"operator.yml", "default-group.yml", "wrong-group.yml", "world-key.yml"} {
		changed := config
		switch name {
		case "default-group.yml":
			changed.PrivateKeyGroup = nil
		case "wrong-group.yml":
			wrong := uint32(65531)
			changed.PrivateKeyGroup = &wrong
		case "world-key.yml":
			changed.PrivateKeyFile = mount + "world.key"
		}
		data, err := yaml.Marshal(struct {
			Private *PrivateConnectConfig `yaml:"private_connect"`
		}{&changed})
		if err != nil || strings.Contains(string(data), "PRIVATE KEY") {
			t.Fatal("cannot encode mount fixture configuration")
		}
		write(name, data)
	}
}
