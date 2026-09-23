//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type provisionFixture struct {
	sync.Mutex
	config         Config
	generation     int64
	credential     string
	policyRevision int64
	policy         Policy
	keyVersion     int64
	key            string
	counts         map[string]int
	drop           string
	badScope       bool
}

func transportCredential(n int64) string {
	return "nbc1." + strings.Repeat(string(rune('a'+n)), 32) + "." + strings.Repeat("k", 43)
}
func (f *provisionFixture) handler(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	operation := strings.TrimPrefix(r.URL.Path, "/api/notebook-runtimes-v2/")
	f.counts[operation]++
	var body map[string]any
	if json.NewDecoder(io.LimitReader(r.Body, 4097)).Decode(&body) != nil {
		w.WriteHeader(400)
		return
	}
	s := f.config.Registration.RuntimeScope
	if body["runtimeId"] != s.RuntimeID || body["teamId"] != s.TeamID {
		w.WriteHeader(403)
		return
	}
	if operation == "enroll" {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer nbe1.") {
			w.WriteHeader(401)
			return
		}
		if s.InstallationID == "" {
			f.config.Registration.InstallationID = body["installationId"].(string)
			s = f.config.Registration.RuntimeScope
		}
		if body["installationId"] != s.InstallationID || body["ledgerGeneration"] != s.LedgerGeneration || body["environmentSha256"] != s.EnvironmentSHA256 {
			w.WriteHeader(409)
			return
		}
	} else if r.Header.Get("Authorization") != "Bearer "+f.credential || body["installationId"] != s.InstallationID || body["credentialGeneration"] != float64(f.generation) {
		w.WriteHeader(401)
		return
	}
	if operation == "rotate" || operation == "enroll" {
		f.generation++
		f.credential = transportCredential(f.generation)
	}
	row := RuntimeWire{ID: s.RuntimeID, TeamID: s.TeamID, Provider: "customer", Name: "Fixture", EnrollmentState: "active", InstallationID: s.InstallationID,
		CredentialGeneration: f.generation, PolicyRevision: f.policyRevision, Policy: f.policy, PolicySHA256: policyDigest(f.policy), LedgerGeneration: s.LedgerGeneration, EnvironmentSHA256: s.EnvironmentSHA256, CreatedAt: time.Now().UTC()}
	if f.badScope {
		row.EnvironmentSHA256 = strings.Repeat("b", 64)
	}
	response := map[string]any{"runtime": row, "expiresAt": time.Now().Add(24 * time.Hour).UTC()}
	if operation == "bootstrap" {
		response["capability"] = map[string]any{"version": f.keyVersion, "algorithm": "HMAC-SHA256", "keyBase64": f.key}
	} else {
		response["credential"] = f.credential
	}
	if f.drop == operation {
		f.drop = ""
		connection, _, _ := w.(http.Hijacker).Hijack()
		connection.Close()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
func provisioning(t *testing.T) (*provisionFixture, string, string) {
	t.Helper()
	c := fixture(t)
	c.Registration.InstallationID = ""
	c.Registration.Credential = ""
	c.Registration.CredentialGeneration = 0
	f := &provisionFixture{config: c, policyRevision: 2, policy: c.Policy, keyVersion: 1, key: c.CapabilityKeyBase64, counts: map[string]int{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	ca := filepath.Join(dir, "app-ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	python := filepath.Join(dir, "python")
	descriptor, _ := json.Marshal(Descriptor{Version: 1, LedgerGeneration: c.Registration.LedgerGeneration, EnvironmentSHA256: c.Registration.EnvironmentSHA256, Compatibility: json.RawMessage(`{}`)})
	_ = os.WriteFile(python, []byte("#!/bin/sh\nprintf '%s\\n' '"+string(descriptor)+"'\n"), 0700)
	request := EnrollmentRequest{Version: 2, AppOrigin: server.URL, AppCAFile: ca, PythonExecutable: python, StateDirectory: c.StateDirectory,
		ServerAddress: c.ServerAddress, RuntimeID: c.Registration.RuntimeID, TeamID: c.Registration.TeamID, EnrollmentToken: "nbe1." + strings.Repeat("a", 32) + "." + strings.Repeat("b", 43)}
	requestPath := filepath.Join(dir, "enrollment.json")
	encoded, _ := json.Marshal(request)
	_ = os.WriteFile(requestPath, encoded, 0600)
	return f, requestPath, filepath.Join(dir, "state.json")
}

func TestEnrollBootstrapRotateAndPolicyRefresh(t *testing.T) {
	f, request, path := provisioning(t)
	c, err := Enroll(context.Background(), request, path, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Registration.CredentialGeneration != 1 || c.CapabilityKeyVersion != 1 || c.PendingOperation != "" {
		t.Fatal("incomplete enrollment")
	}
	saved, err := Load(path)
	if err != nil || saved.Registration != c.Registration {
		t.Fatal("credential not durable", err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Fatal("unsafe credential permissions")
	}
	f.Lock()
	f.policyRevision++
	f.policy.ExecutionEnabled = false
	f.Unlock()
	c, err = Bootstrap(context.Background(), path)
	if err != nil || c.Policy.ExecutionEnabled || c.Registration.PolicyRevision != 3 {
		t.Fatal("current policy did not refresh", err)
	}
	c, err = Rotate(context.Background(), path)
	if err != nil || c.Registration.CredentialGeneration != 2 || c.CapabilityKeyVersion != 1 {
		t.Fatal("rotation changed runtime key or failed", err)
	}
	f.Lock()
	defer f.Unlock()
	if f.counts["enroll"] != 1 || f.counts["rotate"] != 1 || f.counts["bootstrap"] != 3 {
		t.Fatal("unexpected provisioning retries", f.counts)
	}
}

func TestActiveLauncherExcludesProvisioningAndSecondStartup(t *testing.T) {
	f, request, path := provisioning(t)
	c, err := Enroll(context.Background(), request, path, false)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockState(c.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	operations := map[string]func() error{
		"bootstrap": func() error { _, err := Bootstrap(context.Background(), path); return err },
		"rotate":    func() error { _, err := Rotate(context.Background(), path); return err },
		"recover":   func() error { _, err := Enroll(context.Background(), request, path, true); return err },
		"start":     func() error { return Start(context.Background(), path, io.Discard) },
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, ErrBusy) {
				t.Fatalf("active installation was not excluded: %v", err)
			}
		})
	}
	f.Lock()
	defer f.Unlock()
	if f.counts["enroll"] != 1 || f.counts["bootstrap"] != 1 || f.counts["rotate"] != 0 {
		t.Fatal("busy operation contacted provisioning authority", f.counts)
	}
	saved, err := readState(path)
	if err != nil || saved.Registration != c.Registration || saved.PendingOperation != "" {
		t.Fatal("busy operation mutated durable registration", err)
	}
}

func TestLostRotationAckIsNeverRetriedAndCanExplicitlyRecover(t *testing.T) {
	f, request, path := provisioning(t)
	_, err := Enroll(context.Background(), request, path, false)
	if err != nil {
		t.Fatal(err)
	}
	f.Lock()
	f.drop = "rotate"
	f.Unlock()
	if _, err = Rotate(context.Background(), path); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = Rotate(context.Background(), path); !errors.Is(err, ErrUncertain) {
			t.Fatal("uncertain rotation retried")
		}
	}
	if _, err = Bootstrap(context.Background(), path); !errors.Is(err, ErrUncertain) {
		t.Fatal("uncertain credential used")
	}
	c, err := Enroll(context.Background(), request, path, true)
	if err != nil || c.PendingOperation != "" || c.Registration.CredentialGeneration != 3 {
		t.Fatal("explicit same-installation recovery failed", err)
	}
	f.Lock()
	defer f.Unlock()
	if f.counts["rotate"] != 1 {
		t.Fatal("rotation replayed")
	}
}
func TestLostEnrollmentAckPreservesInstallationAndRequiresExplicitRecovery(t *testing.T) {
	f, request, path := provisioning(t)
	f.drop = "enroll"
	if _, err := Enroll(context.Background(), request, path, false); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	before, _ := readState(path)
	if _, err := Enroll(context.Background(), request, path, false); err == nil {
		t.Fatal("automatic enrollment replay")
	}
	after, err := Enroll(context.Background(), request, path, true)
	if err != nil || after.Registration.InstallationID != before.Registration.InstallationID {
		t.Fatal("installation replaced", err)
	}
}
func TestBootstrapRejectsChangedStableIdentityAndUnversionedKey(t *testing.T) {
	f, request, path := provisioning(t)
	_, err := Enroll(context.Background(), request, path, false)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	f.badScope = true
	if _, err = Bootstrap(context.Background(), path); err == nil {
		t.Fatal("replacement environment accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected bootstrap overwrote private state")
	}
	f.badScope = false
	f.key = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	if _, err = Bootstrap(context.Background(), path); err == nil {
		t.Fatal("key replaced without version increment")
	}
	f.keyVersion = 2
	if c, err := Bootstrap(context.Background(), path); err != nil || c.CapabilityKeyVersion != 2 {
		t.Fatal("explicit key rotation rejected", err)
	}
}
func TestProvisioningRequiresVerifiedHTTPSAndNeverFollowsRedirect(t *testing.T) {
	if _, err := registry("http://127.0.0.1:1234", ""); err == nil {
		t.Fatal("plaintext accepted")
	}
	if _, err := registry("https://user:secret@example.test", ""); err == nil {
		t.Fatal("URL credentials accepted")
	}
	destinationCalls := 0
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls++ }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer server.Close()
	client, _ := registry(server.URL, "")
	if _, err := client.post(context.Background(), "bootstrap", strings.Repeat("s", 64), map[string]any{}); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	client, _ = registry(server.URL, ca)
	if _, err := client.post(context.Background(), "bootstrap", strings.Repeat("s", 64), map[string]any{}); err == nil || destinationCalls != 0 {
		t.Fatal("redirect followed")
	}
}
func TestPrivateJSONRejectsDuplicateFieldsAndHardLinks(t *testing.T) {
	if strictJSON([]byte(`{"version":2,"version":2}`), new(Config)) == nil {
		t.Fatal("duplicate field accepted")
	}
	f, request, path := provisioning(t)
	_ = f
	if _, err := Enroll(context.Background(), request, path, false); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "linked.json")
	if os.Link(path, link) != nil {
		t.Fatal("link")
	}
	if _, err := Load(path); err == nil {
		t.Fatal("multiply linked credential file accepted")
	}
}

func TestLostBootstrapResponseKeepsDurableCredentialAndDoesNotReenroll(t *testing.T) {
	f, request, path := provisioning(t)
	f.drop = "bootstrap"
	if _, err := Enroll(context.Background(), request, path, false); !errors.Is(err, ErrProvision) {
		t.Fatal(err)
	}
	state, err := readState(path)
	if err != nil || state.PendingOperation != "" || !runtimeSecret.MatchString(state.Registration.Credential) {
		t.Fatal("winning credential lost")
	}
	if _, err = Bootstrap(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	f.Lock()
	defer f.Unlock()
	if f.counts["enroll"] != 1 || f.counts["bootstrap"] != 2 {
		t.Fatal("enrollment replayed")
	}
}
func TestExplicitReenrollmentPreservesIdentityAndWorkerPathsAreDenied(t *testing.T) {
	_, request, path := provisioning(t)
	before, err := Enroll(context.Background(), request, path, false)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Enroll(context.Background(), request, path, true)
	if err != nil || after.Registration.InstallationID != before.Registration.InstallationID || after.Registration.CredentialGeneration != before.Registration.CredentialGeneration+1 {
		t.Fatal("explicit recovery failed", err)
	}
	if safeStatePath(filepath.Join(before.StateDirectory, "workers", "secret.json"), before.StateDirectory) {
		t.Fatal("secret workspace path accepted")
	}
}
