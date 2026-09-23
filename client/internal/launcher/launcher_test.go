//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rabbit.go/client/internal/tunnel"
)

func fixture(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return Config{Version: 2, PythonExecutable: "/bin/sh", StateDirectory: root, ServerAddress: "127.0.0.1:1",
		Registration: tunnel.RuntimeRegistration{RuntimeScope: tunnel.RuntimeScope{RuntimeID: "runtime", TeamID: "team", InstallationID: "install", Service: "notebook-v2",
			CredentialGeneration: 1, PolicyRevision: 2, LedgerGeneration: "ledger", EnvironmentSHA256: strings.Repeat("a", 64)}, Credential: strings.Repeat("c", 64)},
		Policy: Policy{Version: 1, ExecutionEnabled: true, MaxExecutionSeconds: 30}, CapabilityKeyBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}
}

func TestPrivateConfigAndIdentityValidation(t *testing.T) {
	config := fixture(t)
	path := filepath.Join(t.TempDir(), "node.json")
	data, _ := json.Marshal(config)
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("write")
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("chmod")
	}
	if _, err := Load(path); err == nil {
		t.Fatal("world-readable credential file accepted")
	}
	if os.Chmod(path, 0600) != nil {
		t.Fatal("chmod")
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if os.Symlink(path, link) != nil {
		t.Fatal("link")
	}
	if _, err := Load(link); err == nil {
		t.Fatal("symlink config accepted")
	}
	config.Registration.Service = "arbitrary"
	if config.validate() == nil {
		t.Fatal("arbitrary service accepted")
	}
}

func TestReadyIsBoundedAndMatchesEnrolledIdentity(t *testing.T) {
	config := fixture(t)
	ready := Ready{Version: 1, Status: "ready", Port: 12345, RuntimeID: "runtime", TeamID: "team", LedgerGeneration: "ledger", EnvironmentSHA256: strings.Repeat("a", 64)}
	var encoded bytes.Buffer
	_ = json.NewEncoder(&encoded).Encode(ready)
	parsed, err := readReady(&encoded)
	if err != nil || !parsed.matches(config) {
		t.Fatal("valid identity rejected")
	}
	parsed.LedgerGeneration = "replacement"
	if parsed.matches(config) {
		t.Fatal("lost ledger accepted")
	}
	if _, err = readReady(strings.NewReader(strings.Repeat("x", 16385) + "\n")); err == nil {
		t.Fatal("unbounded readiness accepted")
	}
	if _, err = readReady(strings.NewReader(`{"version":1,"status":"ready","port":80}` + "\n")); err == nil {
		t.Fatal("unexpected local port accepted")
	}
}

func TestHelperEnvironmentDoesNotInheritSecrets(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-inherit")
	t.Setenv("NOTEBOOK_RUNTIME_SERVICE_TOKEN", "must-not-inherit")
	for _, item := range privateEnvironment(fixture(t)) {
		if strings.Contains(item, "must-not-inherit") || strings.HasPrefix(item, "PYTHONPATH=") {
			t.Fatal("deployment environment inherited")
		}
	}
}

func fakeHelper(t *testing.T, c *Config, line string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "python-fixture")
	// The fixture ignores Python arguments and emits only the process readiness contract.
	script := "#!/bin/sh\nprintf '%s\\n' '" + line + "'\nexec /bin/sleep 30\n"
	if os.WriteFile(path, []byte(script), 0700) != nil {
		t.Fatal("write helper")
	}
	c.PythonExecutable = path
}

func TestMismatchedHelperStopsBeforeTransportStarts(t *testing.T) {
	c := fixture(t)
	fakeHelper(t, &c, `{"version":1,"status":"ready","port":12345,"runtimeId":"other","teamId":"team","ledgerGeneration":"ledger","environmentSha256":"`+strings.Repeat("a", 64)+`"}`)
	var output bytes.Buffer
	if err := Run(context.Background(), c, &output); !errors.Is(err, ErrHelper) {
		t.Fatalf("unexpected error %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("unverified helper published as ready")
	}
	files, _ := filepath.Glob(filepath.Join(c.StateDirectory, "launcher-*"))
	if len(files) != 0 {
		t.Fatal("temporary capability config retained")
	}
}

func TestCancellationStopsHelperAndRemovesTemporaryKey(t *testing.T) {
	c := fixture(t)
	fakeHelper(t, &c, `{"version":1,"status":"ready","port":12345,"runtimeId":"runtime","teamId":"team","ledgerGeneration":"ledger","environmentSha256":"`+strings.Repeat("a", 64)+`"}`)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := Run(ctx, c, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected error %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(c.StateDirectory, "launcher-*"))
	if len(files) != 0 {
		t.Fatal("temporary capability config retained")
	}
}
