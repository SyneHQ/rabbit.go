//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"rabbit.go/client/internal/tunnel"
)

var ErrProvision = errors.New("runtime provisioning failed; verify the trusted app, current registration, and private credential")
var ErrUncertain = errors.New("registration acknowledgement is uncertain; do not retry rotation or enrollment; obtain a fresh enrollment token for this same installation and explicitly recover")
var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var enrollmentSecret = regexp.MustCompile(`^nbe1\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$`)
var runtimeSecret = regexp.MustCompile(`^nbc1\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$`)

type EnrollmentRequest struct {
	Version          int    `json:"version"`
	AppOrigin        string `json:"appOrigin"`
	AppCAFile        string `json:"appCAFile,omitempty"`
	PythonExecutable string `json:"pythonExecutable"`
	StateDirectory   string `json:"stateDirectory"`
	ServerAddress    string `json:"serverAddress"`
	CAFile           string `json:"caFile,omitempty"`
	ServerName       string `json:"serverName,omitempty"`
	RuntimeID        string `json:"runtimeId"`
	TeamID           string `json:"teamId"`
	EnrollmentToken  string `json:"enrollmentToken"`
}

type Descriptor struct {
	Version           int             `json:"version"`
	LedgerGeneration  string          `json:"ledgerGeneration"`
	EnvironmentSHA256 string          `json:"environmentSha256"`
	Compatibility     json.RawMessage `json:"compatibility"`
}

type RuntimeWire struct {
	ID                   string     `json:"id"`
	TeamID               string     `json:"teamId"`
	Provider             string     `json:"provider"`
	Name                 string     `json:"name"`
	EnrollmentState      string     `json:"enrollmentState"`
	InstallationID       string     `json:"installationId"`
	CredentialGeneration int64      `json:"credentialGeneration"`
	PolicyRevision       int64      `json:"policyRevision"`
	Policy               Policy     `json:"policy"`
	PolicySHA256         string     `json:"policySha256"`
	LedgerGeneration     string     `json:"ledgerGeneration"`
	EnvironmentSHA256    string     `json:"environmentSha256"`
	RevokedAt            *time.Time `json:"revokedAt"`
	CreatedAt            time.Time  `json:"createdAt"`
}
type provisioningResponse struct {
	Runtime    RuntimeWire `json:"runtime"`
	Credential string      `json:"credential,omitempty"`
	ExpiresAt  time.Time   `json:"expiresAt"`
	Capability *struct {
		Version   int64  `json:"version"`
		Algorithm string `json:"algorithm"`
		KeyBase64 string `json:"keyBase64"`
	} `json:"capability,omitempty"`
}

type registryClient struct {
	origin string
	client *http.Client
}

func registry(origin, caFile string) (*registryClient, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || parsed.Opaque != "" {
		return nil, ErrConfiguration
	}
	configuration := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		if !filepath.IsAbs(caFile) {
			return nil, ErrConfiguration
		}
		contents, err := os.ReadFile(caFile)
		if err != nil || len(contents) > 1024*1024 {
			return nil, ErrConfiguration
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(contents) {
			return nil, ErrConfiguration
		}
		configuration.RootCAs = pool
	}
	transport := &http.Transport{TLSClientConfig: configuration, DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384}
	return &registryClient{origin: strings.TrimSuffix(origin, "/"), client: &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (r *registryClient) post(ctx context.Context, operation, credential string, body any) (provisioningResponse, error) {
	var result provisioningResponse
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > 4096 {
		return result, ErrConfiguration
	}
	// A reader without GetBody prevents HTTP from replaying a credential mutation.
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.origin+"/api/notebook-runtimes-v2/"+operation, io.NopCloser(bytes.NewReader(encoded)))
	if err != nil {
		return result, ErrProvision
	}
	request.ContentLength = int64(len(encoded))
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return result, ErrProvision
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, ErrProvision
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(data) > 16384 || strictJSON(data, &result) != nil {
		return result, ErrProvision
	}
	return result, nil
}

func policyDigest(policy Policy) string {
	encoded, _ := json.Marshal(map[string]any{"version": policy.Version, "executionEnabled": policy.ExecutionEnabled, "maxExecutionSeconds": policy.MaxExecutionSeconds, "allowFileInputs": policy.AllowFileInputs})
	sum := sha256.Sum256(append([]byte("syne:notebook:runtime-policy:v2\n"), encoded...))
	return hex.EncodeToString(sum[:])
}

func validateResponse(c Config, response provisioningResponse, generation int64) error {
	row := response.Runtime
	s := c.Registration.RuntimeScope
	if row.ID != s.RuntimeID || row.TeamID != s.TeamID || row.InstallationID != s.InstallationID || row.LedgerGeneration != s.LedgerGeneration || row.EnvironmentSHA256 != s.EnvironmentSHA256 ||
		row.Provider != "customer" || row.EnrollmentState != "active" || row.RevokedAt != nil || row.CredentialGeneration != generation || generation < 1 || generation >= 2147483647 ||
		row.PolicyRevision < c.Registration.PolicyRevision || row.PolicyRevision < 1 || row.PolicyRevision > 9007199254740991 || row.Policy.Version != 1 || row.Policy.MaxExecutionSeconds < 1 || row.Policy.MaxExecutionSeconds > 120 ||
		row.PolicySHA256 != policyDigest(row.Policy) || !response.ExpiresAt.After(time.Now()) || response.ExpiresAt.After(time.Now().Add(25*time.Hour)) {
		return ErrProvision
	}
	if row.PolicyRevision == s.PolicyRevision && s.PolicyRevision > 0 && row.Policy != c.Policy {
		return ErrProvision
	}
	return nil
}

func describeHelper(ctx context.Context, c Config) (Descriptor, error) {
	var result Descriptor
	if !filepath.IsAbs(c.PythonExecutable) || !filepath.IsAbs(c.StateDirectory) || privateDirectory(c.StateDirectory) != nil {
		return result, ErrConfiguration
	}
	info, err := os.Stat(c.PythonExecutable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return result, ErrConfiguration
	}
	timeout, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(timeout, c.PythonExecutable, "-I", "-m", "notebook_runtime.local_serve", "describe", "--state-dir", c.StateDirectory)
	command.Dir = c.StateDirectory
	command.Env = privateEnvironment(c)
	command.Stderr = io.Discard
	var output boundedBuffer
	command.Stdout = &output
	if command.Run() != nil || output.exceeded || strictJSON(output.Bytes(), &result) != nil || result.Version != 1 || !identifier.MatchString(result.LedgerGeneration) || !digest.MatchString(result.EnvironmentSHA256) {
		return result, ErrHelper
	}
	return result, nil
}

type boundedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 16384 {
		b.exceeded = true
		return 0, ErrHelper
	}
	return b.Buffer.Write(data)
}

func credentialScope(c Config) map[string]any {
	return map[string]any{"runtimeId": c.Registration.RuntimeID, "teamId": c.Registration.TeamID, "installationId": c.Registration.InstallationID, "credentialGeneration": c.Registration.CredentialGeneration}
}
func bootstrapLocked(ctx context.Context, path string, c Config) (Config, error) {
	if c.PendingOperation != "" || !runtimeSecret.MatchString(c.Registration.Credential) || c.Registration.CredentialGeneration < 1 {
		return c, ErrUncertain
	}
	client, err := registry(c.AppOrigin, c.AppCAFile)
	if err != nil {
		return c, err
	}
	descriptor, err := describeHelper(ctx, c)
	if err != nil {
		return c, err
	}
	if descriptor.LedgerGeneration != c.Registration.LedgerGeneration || descriptor.EnvironmentSHA256 != c.Registration.EnvironmentSHA256 {
		return c, ErrHelper
	}
	response, err := client.post(ctx, "bootstrap", c.Registration.Credential, credentialScope(c))
	if err != nil {
		return c, err
	}
	if validateResponse(c, response, c.Registration.CredentialGeneration) != nil || response.Credential != "" || response.Capability == nil {
		return c, ErrProvision
	}
	capability := response.Capability
	key, err := base64.StdEncoding.Strict().DecodeString(capability.KeyBase64)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != capability.KeyBase64 || capability.Algorithm != "HMAC-SHA256" || capability.Version < 1 || capability.Version >= 2147483647 || capability.Version < c.CapabilityKeyVersion {
		return c, ErrProvision
	}
	if c.CapabilityKeyVersion == capability.Version && subtle.ConstantTimeCompare([]byte(c.CapabilityKeyBase64), []byte(capability.KeyBase64)) != 1 {
		return c, ErrProvision
	}
	c.Policy = response.Runtime.Policy
	c.Registration.PolicyRevision = response.Runtime.PolicyRevision
	c.CapabilityKeyBase64 = capability.KeyBase64
	c.CapabilityKeyVersion = capability.Version
	c.CredentialExpiresAt = response.ExpiresAt
	if c.validate() != nil {
		return c, ErrProvision
	}
	if err := saveState(path, c); err != nil {
		return c, err
	}
	return c, nil
}

func readState(path string) (Config, error) {
	var c Config
	err := privateRead(path, &c)
	if err != nil || c.Version != 2 || !filepath.IsAbs(c.StateDirectory) || !filepath.IsAbs(c.PythonExecutable) || privateDirectory(c.StateDirectory) != nil || !safeStatePath(path, c.StateDirectory) || (c.PendingOperation != "" && c.PendingOperation != "enroll" && c.PendingOperation != "rotate") {
		return c, ErrConfiguration
	}
	return c, nil
}

// Bootstrap refreshes only provisioning. It never starts a helper or an execution.
func Bootstrap(ctx context.Context, path string) (Config, error) {
	c, err := readState(path)
	if err != nil {
		return c, err
	}
	unlock, err := lockState(c.StateDirectory)
	if err != nil {
		return c, err
	}
	defer unlock()
	return bootstrapLocked(ctx, path, c)
}

// Start holds the state lock through bootstrap, helper readiness, and transport.
func Start(ctx context.Context, path string, output io.Writer) error {
	c, err := readState(path)
	if err != nil {
		return err
	}
	unlock, err := lockState(c.StateDirectory)
	if err != nil {
		return err
	}
	defer unlock()
	c, err = bootstrapLocked(ctx, path, c)
	if err != nil {
		return err
	}
	return runHelper(ctx, c, output)
}

func Rotate(ctx context.Context, path string) (Config, error) {
	c, err := readState(path)
	if err != nil {
		return c, err
	}
	unlock, err := lockState(c.StateDirectory)
	if err != nil {
		return c, err
	}
	defer unlock()
	if c.PendingOperation != "" || !runtimeSecret.MatchString(c.Registration.Credential) {
		return c, ErrUncertain
	}
	client, err := registry(c.AppOrigin, c.AppCAFile)
	if err != nil {
		return c, err
	}
	c.PendingOperation = "rotate"
	if err := saveState(path, c); err != nil {
		return c, err
	}
	response, err := client.post(ctx, "rotate", c.Registration.Credential, credentialScope(c))
	if err != nil {
		return c, ErrUncertain
	}
	if validateResponse(c, response, c.Registration.CredentialGeneration+1) != nil || !runtimeSecret.MatchString(response.Credential) || response.Capability != nil {
		return c, ErrUncertain
	}
	c.Registration.Credential = response.Credential
	c.Registration.CredentialGeneration = response.Runtime.CredentialGeneration
	c.Policy = response.Runtime.Policy
	c.Registration.PolicyRevision = response.Runtime.PolicyRevision
	c.CredentialExpiresAt = response.ExpiresAt
	c.PendingOperation = ""
	if err := saveState(path, c); err != nil {
		return c, ErrUncertain
	}
	return bootstrapLocked(ctx, path, c)
}

func Enroll(ctx context.Context, requestPath, statePath string, recover bool) (Config, error) {
	var request EnrollmentRequest
	var c Config
	if privateRead(requestPath, &request) != nil || request.Version != 2 || !identifier.MatchString(request.RuntimeID) || !identifier.MatchString(request.TeamID) || !enrollmentSecret.MatchString(request.EnrollmentToken) ||
		!filepath.IsAbs(statePath) || !safeStatePath(statePath, request.StateDirectory) || !safeStatePath(requestPath, request.StateDirectory) || request.ServerAddress == "" || privateDirectory(request.StateDirectory) != nil || privateDirectory(filepath.Dir(statePath)) != nil {
		return c, ErrConfiguration
	}
	client, err := registry(request.AppOrigin, request.AppCAFile)
	if err != nil {
		return c, err
	}
	unlock, err := lockState(request.StateDirectory)
	if err != nil {
		return c, err
	}
	defer unlock()
	c = Config{Version: 2, AppOrigin: request.AppOrigin, AppCAFile: request.AppCAFile, PythonExecutable: request.PythonExecutable, StateDirectory: request.StateDirectory,
		ServerAddress: request.ServerAddress, CAFile: request.CAFile, ServerName: request.ServerName}
	descriptor, err := describeHelper(ctx, c)
	if err != nil {
		return c, err
	}
	installation := make([]byte, 16)
	if _, err = rand.Read(installation); err != nil {
		return c, ErrConfiguration
	}
	c.Registration.RuntimeScope = tunnel.RuntimeScope{RuntimeID: request.RuntimeID, TeamID: request.TeamID, InstallationID: "nbi_" + hex.EncodeToString(installation), Service: "notebook-v2", LedgerGeneration: descriptor.LedgerGeneration, EnvironmentSHA256: descriptor.EnvironmentSHA256}
	if _, err = os.Lstat(statePath); err == nil {
		previous, err := readState(statePath)
		if err != nil || !recover {
			return c, ErrConfiguration
		}
		if previous.AppOrigin != c.AppOrigin || previous.AppCAFile != c.AppCAFile || previous.PythonExecutable != c.PythonExecutable || previous.StateDirectory != c.StateDirectory || previous.ServerAddress != c.ServerAddress || previous.CAFile != c.CAFile || previous.ServerName != c.ServerName ||
			previous.Registration.RuntimeID != c.Registration.RuntimeID || previous.Registration.TeamID != c.Registration.TeamID || previous.Registration.LedgerGeneration != c.Registration.LedgerGeneration || previous.Registration.EnvironmentSHA256 != c.Registration.EnvironmentSHA256 {
			return c, ErrConfiguration
		}
		c = previous
	} else if !os.IsNotExist(err) || recover {
		return c, ErrConfiguration
	}
	c.PendingOperation = "enroll"
	if err := saveState(statePath, c); err != nil {
		return c, err
	}
	response, err := client.post(ctx, "enroll", request.EnrollmentToken, map[string]any{"runtimeId": c.Registration.RuntimeID, "teamId": c.Registration.TeamID, "installationId": c.Registration.InstallationID, "ledgerGeneration": c.Registration.LedgerGeneration, "environmentSha256": c.Registration.EnvironmentSHA256})
	if err != nil {
		return c, ErrUncertain
	}
	// A new administrator token can recover an uncertain rotation: generation may
	// advance, but installation, ledger, environment, and runtime stay immutable.
	if response.Runtime.CredentialGeneration <= c.Registration.CredentialGeneration || validateResponse(c, response, response.Runtime.CredentialGeneration) != nil || !runtimeSecret.MatchString(response.Credential) || response.Capability != nil {
		return c, ErrUncertain
	}
	c.Registration.Credential = response.Credential
	c.Registration.CredentialGeneration = response.Runtime.CredentialGeneration
	c.Registration.PolicyRevision = response.Runtime.PolicyRevision
	c.Policy = response.Runtime.Policy
	c.CredentialExpiresAt = response.ExpiresAt
	c.PendingOperation = ""
	if err := saveState(statePath, c); err != nil {
		return c, ErrUncertain
	}
	return bootstrapLocked(ctx, statePath, c)
}

func safeStatePath(path, stateDirectory string) bool {
	if !filepath.IsAbs(path) || !filepath.IsAbs(stateDirectory) {
		return false
	}
	relative, err := filepath.Rel(filepath.Join(stateDirectory, "workers"), filepath.Clean(path))
	return err == nil && (relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
