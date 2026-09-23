package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// This authority fixture speaks the real app enrollment/bootstrap contract over
// verified HTTPS. The launcher, Rabbit TLS router and Python/Jupyter helper are real.
type nativeRegistry struct {
	sync.Mutex
	scope       Scope
	credential  string
	key         []byte
	enrollToken string
	expires     time.Time
	denied      atomic.Bool
	enrolls     int
	bootstraps  int
}

func (n *nativeRegistry) Authorize(_ context.Context, r Registration) (time.Time, error) {
	n.Lock()
	defer n.Unlock()
	if n.denied.Load() || r.Scope != n.scope || r.Credential != n.credential {
		return time.Time{}, ErrUnavailable
	}
	return time.Now().Add(10 * time.Second), nil
}
func (n *nativeRegistry) policy() map[string]any {
	return map[string]any{"version": 1, "executionEnabled": true, "maxExecutionSeconds": 20, "allowFileInputs": true}
}
func (n *nativeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	n.Lock()
	defer n.Unlock()
	var body map[string]any
	if json.NewDecoder(io.LimitReader(r.Body, 4097)).Decode(&body) != nil {
		w.WriteHeader(400)
		return
	}
	operation := strings.TrimPrefix(r.URL.Path, "/api/notebook-runtimes-v2/")
	if operation == "enroll" {
		if n.enrolls != 0 || r.Header.Get("Authorization") != "Bearer "+n.enrollToken || body["runtimeId"] != "native_runtime" || body["teamId"] != "native_team" {
			w.WriteHeader(401)
			return
		}
		n.scope = Scope{RuntimeID: "native_runtime", TeamID: "native_team", InstallationID: body["installationId"].(string), Service: "notebook-v2", CredentialGeneration: 1, PolicyRevision: 2, LedgerGeneration: body["ledgerGeneration"].(string), EnvironmentSHA256: body["environmentSha256"].(string)}
		n.enrolls++
	} else if operation == "bootstrap" {
		if r.Header.Get("Authorization") != "Bearer "+n.credential || body["runtimeId"] != n.scope.RuntimeID || body["teamId"] != n.scope.TeamID || body["installationId"] != n.scope.InstallationID || body["credentialGeneration"] != float64(n.scope.CredentialGeneration) {
			w.WriteHeader(401)
			return
		}
		n.bootstraps++
	} else {
		w.WriteHeader(404)
		return
	}
	policyBytes, _ := json.Marshal(n.policy())
	policyHash := sha256.Sum256(append([]byte("syne:notebook:runtime-policy:v2\n"), policyBytes...))
	row := map[string]any{"id": n.scope.RuntimeID, "teamId": n.scope.TeamID, "provider": "customer", "name": "Native acceptance", "enrollmentState": "active", "installationId": n.scope.InstallationID,
		"credentialGeneration": n.scope.CredentialGeneration, "policyRevision": n.scope.PolicyRevision, "policy": n.policy(), "policySha256": hex.EncodeToString(policyHash[:]), "ledgerGeneration": n.scope.LedgerGeneration, "environmentSha256": n.scope.EnvironmentSHA256, "revokedAt": nil, "createdAt": time.Now().UTC()}
	response := map[string]any{"runtime": row, "expiresAt": n.expires}
	if operation == "enroll" {
		response["credential"] = n.credential
	} else {
		response["capability"] = map[string]any{"version": 1, "algorithm": "HMAC-SHA256", "keyBase64": base64.StdEncoding.EncodeToString(n.key)}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func nativeTLSRouter(t *testing.T, r *Router) (string, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert, certificates := certificateServer.Certificate(), certificateServer.TLS.Certificates
	certificateServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certificates, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	var handlers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				reader := bufio.NewReader(connection)
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				frame, err := reader.ReadString('\n')
				if err != nil {
					connection.Close()
					return
				}
				r.Handle(strings.TrimSuffix(frame, "\n"), connection, reader)
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; r.Close(); handlers.Wait() })
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return listener.Addr().String(), cert, pool
}

type nativeBridge struct {
	address string
	roots   *x509.CertPool
	scope   Scope
}

func (b nativeBridge) open() (net.Conn, *bufio.Reader, error) {
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", b.address, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: b.roots, ServerName: "127.0.0.1"})
	if err != nil {
		return nil, nil, err
	}
	_ = connection.SetDeadline(time.Now().Add(60 * time.Second))
	data, _ := json.Marshal(OpenRequest{Scope: b.scope, BrokerToken: brokerSecret})
	_, err = connection.Write(append([]byte(OpenFrame+"\n"), append(data, '\n')...))
	if err != nil {
		connection.Close()
		return nil, nil, err
	}
	reader := bufio.NewReader(connection)
	line, err := reader.ReadString('\n')
	if err != nil || line != "READY\n" {
		connection.Close()
		return nil, nil, ErrUnavailable
	}
	return connection, reader, nil
}
func (b nativeBridge) request(method, path, token string, body any) (*http.Response, net.Conn, error) {
	connection, reader, err := b.open()
	if err != nil {
		return nil, nil, err
	}
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	request, _ := http.NewRequest(method, "http://notebook"+path, bytes.NewReader(encoded))
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if err = request.Write(connection); err != nil {
		connection.Close()
		return nil, nil, err
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		connection.Close()
		return nil, nil, err
	}
	return response, connection, nil
}
func (b nativeBridge) json(t *testing.T, method, path, token string, body any) map[string]any {
	t.Helper()
	response, connection, err := b.request(method, path, token, body)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("node response status=%d error=%v", response.StatusCode, err)
	}
	var value map[string]any
	if json.Unmarshal(data, &value) != nil {
		t.Fatal("invalid node JSON")
	}
	return value
}
func nativeBinding(scope Scope, code string, kernel any) map[string]any {
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	codeHash := sha256.Sum256([]byte(code))
	return map[string]any{"version": 2, "executionId": hex.EncodeToString(random), "actorId": "native_actor", "teamId": scope.TeamID,
		"notebook": map[string]any{"kind": "chat", "id": "native_chat", "cellId": nil, "revisionSha256": strings.Repeat("b", 64)},
		"runtime":  map[string]any{"provider": "customer", "id": scope.RuntimeID, "policyRevision": scope.PolicyRevision, "ledgerGeneration": scope.LedgerGeneration, "environmentSha256": scope.EnvironmentSHA256, "kernelGeneration": kernel}, "codeSha256": hex.EncodeToString(codeHash[:]), "inputs": []any{}}
}
func nativeCapability(key []byte, binding map[string]any, action string, retrieval ...map[string]any) string {
	data, _ := json.Marshal(binding)
	hash := sha256.Sum256(append([]byte("syne:notebook:execution-binding:v2\n"), data...))
	runtime := binding["runtime"].(map[string]any)
	payload := map[string]any{"version": 2, "action": action, "executionId": binding["executionId"], "bindingSha256": hex.EncodeToString(hash[:]), "actorId": binding["actorId"], "teamId": binding["teamId"], "runtimeId": runtime["id"], "provider": runtime["provider"], "policyRevision": runtime["policyRevision"], "ledgerGeneration": runtime["ledgerGeneration"], "environmentSha256": runtime["environmentSha256"], "issuedAt": time.Now().Unix(), "expiresAt": time.Now().Unix() + 120}
	for _, fields := range retrieval {
		for name, value := range fields {
			payload[name] = value
		}
	}
	encoded, _ := json.Marshal(payload)
	value := base64.RawURLEncoding.EncodeToString(encoded)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("syne:notebook:capability:v2\n" + value))
	return value + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestRuntimeLauncherNativeTLSIntegration(t *testing.T) {
	binary, python := os.Getenv("RABBIT_RUNTIME_CLIENT_TEST_BINARY"), os.Getenv("RABBIT_RUNTIME_HELPER_TEST_PYTHON")
	if binary == "" || python == "" {
		t.Skip("requires explicitly built Rabbit client and installed native helper Python")
	}
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	state := filepath.Join(root, "helper-state")
	_ = os.Mkdir(state, 0700)
	authority := &nativeRegistry{credential: "nbc1." + strings.Repeat("c", 32) + "." + strings.Repeat("d", 43), enrollToken: "nbe1." + strings.Repeat("a", 32) + "." + strings.Repeat("b", 43), key: bytes.Repeat([]byte{42}, 32), expires: time.Now().Add(24 * time.Hour).UTC()}
	app := httptest.NewTLSServer(http.HandlerFunc(authority.serve))
	defer app.Close()
	router, err := NewRouter(authority, brokerSecret)
	if err != nil {
		t.Fatal(err)
	}
	address, certificate, pool := nativeTLSRouter(t, router)
	ca := filepath.Join(root, "rabbit-ca.pem")
	appCA := filepath.Join(root, "app-ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0600)
	_ = os.WriteFile(appCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: app.Certificate().Raw}), 0600)
	request := map[string]any{"version": 2, "appOrigin": app.URL, "appCAFile": appCA, "pythonExecutable": python, "stateDirectory": state, "serverAddress": address, "caFile": ca, "runtimeId": "native_runtime", "teamId": "native_team", "enrollmentToken": authority.enrollToken}
	requestPath, configPath := filepath.Join(root, "request.json"), filepath.Join(root, "runtime.json")
	encoded, _ := json.Marshal(request)
	_ = os.WriteFile(requestPath, encoded, 0600)
	enrollment := exec.Command(binary, "runtime-enroll", "--request-file", requestPath, "--config", configPath)
	enrolled, err := enrollment.CombinedOutput()
	if err != nil {
		t.Fatalf("enrollment failed: %v", err)
	}
	if bytes.Contains(enrolled, authority.key) || bytes.Contains(enrolled, []byte(authority.credential)) || bytes.Contains(enrolled, []byte(authority.enrollToken)) {
		t.Fatal("provisioning leaked credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.Command(binary, "runtime-start", "--config", configPath)
	command.Env = append(os.Environ(), "AWS_SECRET_ACCESS_KEY=must-not-enter-helper", "KOLE_SERVICE_TOKEN=must-not-enter-helper")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = io.Discard
	if command.Start() != nil {
		t.Fatal("launcher start failed")
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
			t.Error("launcher did not shut down helper")
		}
	}()
	ready := make(chan []byte, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadBytes('\n'); ready <- line }()
	select {
	case value := <-ready:
		if len(value) == 0 || bytes.Contains(value, []byte(authority.credential)) {
			t.Fatal("invalid launcher readiness")
		}
	case <-ctx.Done():
		t.Fatal("launcher readiness timed out")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		router.mu.Lock()
		registered := len(router.sessions) == 1
		router.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("launcher did not register through TLS")
		}
		time.Sleep(20 * time.Millisecond)
	}
	authority.Lock()
	scope := authority.scope
	bootstraps := authority.bootstraps
	authority.Unlock()
	if bootstraps != 2 {
		t.Fatal("start did not bootstrap before registration")
	}
	bridge := nativeBridge{address: address, roots: pool, scope: scope}
	code := "import os,time\nfrom pathlib import Path\nassert not any(k in os.environ for k in ['AWS_SECRET_ACCESS_KEY','KOLE_SERVICE_TOKEN','NOTEBOOK_RUNTIME_CAPABILITY_KEY'])\nPath('forecast.csv').write_text('period,value\\n2026,42\\n')\nprint('first',flush=True)\ntime.sleep(3)\nprint('second',flush=True)\n"
	binding := nativeBinding(scope, code, nil)
	path := "/v2/executions/" + binding["executionId"].(string)
	token := func(action string) string { return nativeCapability(authority.key, binding, action) }
	ack := bridge.json(t, "POST", path, token("submit"), map[string]any{"binding": binding, "code": code, "inputs": []any{}})
	if ack["state"] != "accepted" {
		t.Fatal("missing durable acceptance")
	}
	response, connection, err := bridge.request("GET", path+"/events?after=0", token("events"), nil)
	if err != nil || response.StatusCode != 200 {
		t.Fatal("event subscription failed", err)
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var first map[string]any
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data: ") {
			var event map[string]any
			_ = json.Unmarshal([]byte(scanner.Text()[6:]), &event)
			if event["kind"] == "output" {
				first = event
				break
			}
		}
	}
	connection.Close()
	response.Body.Close()
	if first == nil {
		t.Fatal("no actual early output")
	}
	if bridge.json(t, "GET", path, token("observe"), nil)["state"] != "running" {
		t.Fatal("output only arrived after execution")
	}
	after := int(first["sequence"].(float64))
	response, connection, err = bridge.request("GET", path+"/events?after="+fmtInt(after), token("events"), nil)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	connection.Close()
	response.Body.Close()
	if err != nil || !bytes.Contains(contents, []byte("event: terminal")) {
		t.Fatal("cursor reconnect failed", err)
	}
	terminal := bridge.json(t, "GET", path, token("observe"), nil)
	result := terminal["result"].(map[string]any)
	if terminal["state"] != "terminal" || result["status"] != "ok" || result["execution_count"] != float64(1) {
		t.Fatal("native execution failed")
	}
	duplicate := bridge.json(t, "POST", path, token("submit"), map[string]any{"binding": binding, "code": code, "inputs": []any{}})
	if duplicate["state"] != "terminal" || duplicate["result"].(map[string]any)["execution_count"] != float64(1) {
		t.Fatal("execution replayed")
	}
	snapshotHash := terminal["receipt"].(map[string]any)["snapshotSha256"].(string)
	snapshotToken := nativeCapability(authority.key, binding, "snapshot", map[string]any{"snapshotSha256": snapshotHash})
	snapshotPath := path + "/snapshot?snapshotSha256=" + snapshotHash
	snapshot := bridge.json(t, "GET", snapshotPath, snapshotToken, nil)
	snapshotBytes, _ := json.Marshal(snapshot["snapshot"])
	actualHash := sha256.Sum256(snapshotBytes)
	if hex.EncodeToString(actualHash[:]) != snapshotHash {
		t.Fatal("immutable snapshot does not match terminal receipt")
	}
	fileBytes, err := base64.StdEncoding.DecodeString(snapshot["snapshot"].(map[string]any)["forecast.csv"].(string))
	if err != nil || string(fileBytes) != "period,value\n2026,42\n" {
		t.Fatal("receipt-bound forecast artifact changed")
	}
	artifactToken := nativeCapability(authority.key, binding, "artifact", map[string]any{"snapshotSha256": snapshotHash, "artifactPath": "forecast.csv"})
	artifactPath := path + "/artifact?snapshotSha256=" + snapshotHash + "&path=forecast.csv"
	artifact := bridge.json(t, "GET", artifactPath, artifactToken, nil)
	if artifact["contentBase64"] != snapshot["snapshot"].(map[string]any)["forecast.csv"] {
		t.Fatal("artifact differs from its saved snapshot")
	}
	cancelCode := "import time\nPath('forecast.csv').write_text('replaced by later execution')\nprint('cancel_started',flush=True)\ntime.sleep(30)\n"
	cancelBinding := nativeBinding(scope, cancelCode, terminal["kernelGeneration"])
	cancelPath := "/v2/executions/" + cancelBinding["executionId"].(string)
	cancelToken := func(action string) string { return nativeCapability(authority.key, cancelBinding, action) }
	bridge.json(t, "POST", cancelPath, cancelToken("submit"), map[string]any{"binding": cancelBinding, "code": cancelCode, "inputs": []any{}})
	response, connection, err = bridge.request("GET", cancelPath+"/events?after=0", cancelToken("events"), nil)
	if err != nil {
		t.Fatal(err)
	}
	scanner = bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "event: output") {
			break
		}
	}
	connection.Close()
	response.Body.Close()
	bridge.json(t, "POST", cancelPath+"/cancel", cancelToken("cancel"), map[string]any{})
	for i := 0; i < 100; i++ {
		observed := bridge.json(t, "GET", cancelPath, cancelToken("observe"), nil)
		if observed["state"] == "terminal" {
			if observed["result"].(map[string]any)["status"] != "cancelled" {
				t.Fatal("cancel was not confirmed")
			}
			break
		}
		if i == 99 {
			t.Fatal("cancel did not settle")
		}
		time.Sleep(30 * time.Millisecond)
	}
	oldSnapshot := bridge.json(t, "GET", snapshotPath, snapshotToken, nil)
	oldSnapshotBytes, _ := json.Marshal(oldSnapshot["snapshot"])
	if !bytes.Equal(oldSnapshotBytes, snapshotBytes) {
		t.Fatal("later notebook execution replaced an immutable saved snapshot")
	}
	oldArtifact := bridge.json(t, "GET", artifactPath, artifactToken, nil)
	if oldArtifact["contentBase64"] != artifact["contentBase64"] {
		t.Fatal("later notebook execution replaced an immutable artifact")
	}
	authority.denied.Store(true)
	if conn, _, err := bridge.open(); err == nil {
		conn.Close()
		t.Fatal("revoked runtime remained routable")
	}
	t.Log("verified HTTPS enrollment/bootstrap -> Go launcher -> Rabbit TLS -> real native Jupyter: early output, cursor reconnect, no duplicate execution, receipt-bound immutable snapshots/artifacts survive later file mutation, exact cancel, revocation; credentials absent from kernel environment")
}
func fmtInt(value int) string { data, _ := json.Marshal(value); return string(data) }
