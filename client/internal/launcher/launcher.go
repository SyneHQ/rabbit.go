//go:build linux || darwin

// Package launcher supervises a dedicated local notebook helper. It is not a sandbox.
package launcher

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"rabbit.go/client/internal/tunnel"
)

var ErrConfiguration = errors.New("invalid private notebook launcher configuration")
var ErrHelper = errors.New("local notebook helper stopped or failed identity verification")
var ErrBusy = errors.New("another launcher owns this runtime state; stop it before changing registration")

type Policy struct {
	Version             int  `json:"version"`
	ExecutionEnabled    bool `json:"executionEnabled"`
	MaxExecutionSeconds int  `json:"maxExecutionSeconds"`
	AllowFileInputs     bool `json:"allowFileInputs"`
}
type Config struct {
	Version              int                        `json:"version"`
	AppOrigin            string                     `json:"appOrigin,omitempty"`
	AppCAFile            string                     `json:"appCAFile,omitempty"`
	CapabilityKeyVersion int64                      `json:"capabilityKeyVersion,omitempty"`
	CredentialExpiresAt  time.Time                  `json:"credentialExpiresAt"`
	PendingOperation     string                     `json:"pendingOperation,omitempty"`
	PythonExecutable     string                     `json:"pythonExecutable"`
	StateDirectory       string                     `json:"stateDirectory"`
	ServerAddress        string                     `json:"serverAddress"`
	CAFile               string                     `json:"caFile"`
	ServerName           string                     `json:"serverName"`
	Registration         tunnel.RuntimeRegistration `json:"registration"`
	Policy               Policy                     `json:"policy"`
	CapabilityKeyBase64  string                     `json:"capabilityKeyBase64"`
}
type Ready struct {
	Version           int    `json:"version"`
	Status            string `json:"status"`
	Port              int    `json:"port"`
	RuntimeID         string `json:"runtimeId"`
	TeamID            string `json:"teamId"`
	LedgerGeneration  string `json:"ledgerGeneration"`
	EnvironmentSHA256 string `json:"environmentSha256"`
}

func Load(path string) (Config, error) {
	var config Config
	if err := privateRead(path, &config); err != nil {
		return config, err
	}
	return config, config.validate()
}

func (c Config) validate() error {
	key, err := base64.StdEncoding.Strict().DecodeString(c.CapabilityKeyBase64)
	if c.PendingOperation != "" || err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != c.CapabilityKeyBase64 || c.Version != 2 || !filepath.IsAbs(c.PythonExecutable) || !filepath.IsAbs(c.StateDirectory) ||
		c.Policy.Version != 1 || c.Policy.MaxExecutionSeconds < 1 || c.Policy.MaxExecutionSeconds > 120 || c.ServerAddress == "" {
		return ErrConfiguration
	}
	info, err := os.Stat(c.PythonExecutable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return ErrConfiguration
	}
	state, err := os.Lstat(c.StateDirectory)
	if err != nil || !state.IsDir() || state.Mode()&os.ModeSymlink != 0 || state.Mode().Perm()&0077 != 0 {
		return ErrConfiguration
	}
	if stat, ok := state.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return ErrConfiguration
	}
	client := tunnel.RuntimeClient{Dial: tunnel.TunnelClientConfig{ServerAddress: c.ServerAddress}, Registration: c.Registration, HelperAddress: "127.0.0.1:1024"}
	if client.Validate() != nil {
		return ErrConfiguration
	}
	return nil
}

func privateEnvironment(c Config) []string {
	return []string{"PATH=" + filepath.Dir(c.PythonExecutable) + ":/usr/bin:/bin", "HOME=" + c.StateDirectory, "TMPDIR=" + c.StateDirectory,
		"PYTHONUNBUFFERED=1", "PYTHONDONTWRITEBYTECODE=1", "OPENBLAS_NUM_THREADS=1", "OMP_NUM_THREADS=1"}
}

func readReady(reader io.Reader) (Ready, error) {
	var ready Ready
	line, err := bufio.NewReaderSize(reader, 16385).ReadSlice('\n')
	if err != nil || len(line) > 16384 {
		return ready, ErrHelper
	}
	if strictJSON(line, &ready) != nil || ready.Version != 1 || ready.Status != "ready" || ready.Port < 1024 || ready.Port > 65535 {
		return ready, ErrHelper
	}
	return ready, nil
}

func (r Ready) matches(c Config) bool {
	s := c.Registration.RuntimeScope
	return r.RuntimeID == s.RuntimeID && r.TeamID == s.TeamID && r.LedgerGeneration == s.LedgerGeneration && r.EnvironmentSHA256 == s.EnvironmentSHA256
}

// Run starts the fixed helper entrypoint, validates its actual ledger/environment,
// then connects Rabbit. A helper restart never replays an execution request.
func Run(ctx context.Context, c Config, readyOutput io.Writer) error {
	if err := c.validate(); err != nil {
		return err
	}
	unlock, err := lockState(c.StateDirectory)
	if err != nil {
		return err
	}
	defer unlock()
	return runHelper(ctx, c, readyOutput)
}

func runHelper(ctx context.Context, c Config, readyOutput io.Writer) error {
	directory, err := os.MkdirTemp(c.StateDirectory, "launcher-")
	if err != nil {
		return ErrConfiguration
	}
	defer os.RemoveAll(directory)
	registration := c.Registration.RuntimeScope
	node := map[string]any{"version": 1, "enabled": true, "stateDirectory": c.StateDirectory, "listenPort": 0,
		"runtime": map[string]any{"provider": "customer", "id": registration.RuntimeID, "policyRevision": registration.PolicyRevision,
			"ledgerGeneration": registration.LedgerGeneration, "environmentSha256": registration.EnvironmentSHA256, "kernelGeneration": nil},
		"teamId": registration.TeamID, "capabilityKeyBase64": c.CapabilityKeyBase64, "policy": c.Policy}
	data, _ := json.Marshal(node)
	file := filepath.Join(directory, "helper.json")
	if os.WriteFile(file, data, 0600) != nil {
		return ErrConfiguration
	}
	command := exec.Command(c.PythonExecutable, "-I", "-m", "notebook_runtime.local_serve", "serve", "--config", file)
	command.Dir = c.StateDirectory
	command.Env = privateEnvironment(c)
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return ErrHelper
	}
	if command.Start() != nil {
		return ErrHelper
	}
	exited := make(chan struct{})
	var waitError error
	go func() { waitError = command.Wait(); close(exited) }()
	defer func() {
		select {
		case <-exited:
			return
		default:
		}
		_ = command.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(45 * time.Second)
		defer timer.Stop()
		select {
		case <-exited:
			return
		case <-timer.C:
		}
		_ = command.Process.Kill()
		<-exited
	}()
	ready := make(chan struct {
		value Ready
		err   error
	}, 1)
	go func() {
		value, err := readReady(stdout)
		ready <- struct {
			value Ready
			err   error
		}{value, err}
	}()
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	var value Ready
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-exited:
		_ = waitError
		return ErrHelper
	case <-timer.C:
		return ErrHelper
	case result := <-ready:
		if result.err != nil || !result.value.matches(c) {
			return ErrHelper
		}
		value = result.value
	}
	if readyOutput != nil {
		if json.NewEncoder(readyOutput).Encode(value) != nil {
			return ErrHelper
		}
	}
	// Drain later diagnostics without allowing a full pipe to stall shutdown.
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
	connectionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := tunnel.RuntimeClient{Dial: tunnel.TunnelClientConfig{ServerAddress: c.ServerAddress, CAFile: c.CAFile, ServerName: c.ServerName}, Registration: c.Registration,
		HelperAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(value.Port))}
	connectionDone := make(chan error, 1)
	go func() { connectionDone <- client.Run(connectionCtx) }()
	select {
	case <-ctx.Done():
		cancel()
		<-connectionDone
		return ctx.Err()
	case <-exited:
		cancel()
		<-connectionDone
		return ErrHelper
	case err := <-connectionDone:
		return err
	}
}
