package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type acceptanceOutput struct{ bytes.Buffer }

func (b *acceptanceOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errors.New("acceptance output limit exceeded")
	}
	return b.Buffer.Write(p)
}

// This opt-in harness uses actual external app authority routes and a separately
// owned public coordinator driver. It never logs the private bootstrap config.
func TestRuntimePublicExternalAuthorityAcceptance(t *testing.T) {
	configPath := os.Getenv("NOTEBOOK_PUBLIC_ACCEPTANCE_CONFIG")
	if configPath == "" {
		t.Skip("requires private external app acceptance configuration")
	}
	file, err := os.OpenFile(configPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("private acceptance config unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		t.Fatal("acceptance config must be a bounded private regular file")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Nlink != 1 || int(owner.Uid) != os.Getuid() {
		t.Fatal("acceptance config ownership is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	var values map[string]any
	if err != nil || len(data) > 65536 || json.Unmarshal(data, &values) != nil {
		t.Fatal("invalid private acceptance configuration")
	}
	text := func(key string) string {
		value, ok := values[key].(string)
		if !ok || value == "" || strings.ContainsAny(value, "\r\n\x00") {
			t.Fatalf("missing or invalid acceptance field %s", key)
		}
		return value
	}
	binary := os.Getenv("RABBIT_RUNTIME_CLIENT_TEST_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("requires absolute built Rabbit client path")
	}
	authority, err := NewHTTPAuthority(strings.TrimSuffix(text("appLocalOrigin"), "/")+"/api/internal/notebook-runtimes-v2", text("serviceToken"), true)
	if err != nil {
		t.Fatal("external app authority configuration rejected")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal("broker secret generation failed")
	}
	brokerToken := hex.EncodeToString(secret)
	router, err := NewRouter(authority, brokerToken)
	if err != nil {
		t.Fatal("external authority router failed")
	}
	address, certificate, _ := nativeTLSRouter(t, router)
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	state := filepath.Join(root, "helper-state")
	_ = os.Mkdir(state, 0700)
	ca := filepath.Join(root, "rabbit-ca.pem")
	if os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0600) != nil {
		t.Fatal("could not save private Rabbit trust certificate")
	}
	request := map[string]any{"version": 2, "appOrigin": text("appOrigin"), "appCAFile": text("appCAFile"),
		"pythonExecutable": text("pythonExecutable"), "stateDirectory": state, "serverAddress": address, "caFile": ca,
		"runtimeId": text("runtimeId"), "teamId": text("teamId"), "enrollmentToken": text("enrollmentToken")}
	writePrivate := func(path string, value any) {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil || os.WriteFile(path, encoded, 0600) != nil {
			t.Fatal("could not save private acceptance state")
		}
	}
	requestPath, runtimePath := filepath.Join(root, "enrollment.json"), filepath.Join(root, "runtime.json")
	writePrivate(requestPath, request)
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	enroll := exec.CommandContext(ctx, binary, "runtime-enroll", "--request-file", requestPath, "--config", runtimePath)
	var enrollOutput acceptanceOutput
	enroll.Stdout, enroll.Stderr = &enrollOutput, &enrollOutput
	if enroll.Run() != nil {
		t.Fatal("external app enrollment/bootstrap failed; inspect the owned app service logs")
	}
	command := exec.Command(binary, "runtime-start", "--config", runtimePath)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal("launcher output unavailable")
	}
	command.Stderr = io.Discard
	if command.Start() != nil {
		t.Fatal("launcher failed to start")
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	defer func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(50 * time.Second):
			_ = command.Process.Kill()
			<-exited
			t.Error("launcher cleanup exceeded deadline")
		}
	}()
	ready := make(chan bool, 1)
	go func() {
		line, err := bufio.NewReaderSize(stdout, 16385).ReadSlice('\n')
		var payload map[string]any
		ready <- err == nil && len(line) <= 16384 && json.Unmarshal(line, &payload) == nil && payload["status"] == "ready"
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("helper did not return verified readiness")
		}
	case <-ctx.Done():
		t.Fatal("helper startup timed out")
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		router.mu.Lock()
		registered := len(router.sessions) == 1
		router.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual app authority did not accept Rabbit registration")
		}
		time.Sleep(20 * time.Millisecond)
	}
	values["rabbitAddress"], values["rabbitCAFile"], values["rabbitBrokerToken"] = address, ca, brokerToken
	values["runtimeConfigPath"] = runtimePath
	driverConfig := filepath.Join(root, "driver.json")
	writePrivate(driverConfig, values)
	python, ok := values["driverPython"].(string)
	if !ok || python == "" {
		python = text("pythonExecutable")
	}
	driver := exec.CommandContext(ctx, python, text("driverPath"), "--config", driverConfig)
	driver.Dir = text("koleRoot")
	driver.Env = []string{"PATH=" + filepath.Dir(python) + ":/usr/bin:/bin", "HOME=" + root, "TMPDIR=" + root,
		"PYTHONUNBUFFERED=1", "PYTHONDONTWRITEBYTECODE=1"}
	var output acceptanceOutput
	driver.Stdout, driver.Stderr = &output, io.Discard
	if driver.Run() != nil {
		t.Fatal("public coordinator acceptance driver failed; inspect its private evidence output")
	}
	var proof map[string]any
	if json.Unmarshal(output.Bytes(), &proof) != nil || proof["status"] != "passed" {
		t.Fatal("public coordinator driver did not return a bounded passed result")
	}
	t.Log("actual external app authority enrollment/bootstrap and Rabbit registration accepted; public coordinator driver returned passed")
}
