//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
)

const kelvoFixtureRows = 1000000
const kelvoQueryTimeout = 180 * time.Second

const kelvoRowsSQL = `SELECT id,category,note,active,amount,day FROM kelvo_transport_data ORDER BY id`
const kelvoCTESQL = `WITH grouped AS (
 SELECT category,COUNT(*)::BIGINT AS trips,COUNT(note)::BIGINT AS non_null_notes,
 CAST(SUM(amount) AS NUMERIC(24,2)) AS revenue,MIN(day) AS first_day,MAX(day) AS last_day
 FROM kelvo_transport_data GROUP BY category
), ranked AS (
 SELECT *,ROW_NUMBER() OVER (ORDER BY revenue DESC,category)::BIGINT AS revenue_rank FROM grouped
)
SELECT category,trips,non_null_notes,revenue,first_day,last_day,revenue_rank,
 CASE WHEN category%5=0 THEN NULL ELSE 'segment-'||category::TEXT END AS segment,
 current_setting('transaction_read_only') AS read_only
FROM ranked ORDER BY category`

// This optional gate uses an installed Kelvo binary, without adding Kelvo or
// Arrow dependencies to Rabbit. It proves native PostgreSQL integration, not
// federation, WAN throughput, deployment capacity or shared-tenant isolation.
func TestKelvoPostgresThroughRabbit(t *testing.T) {
	kelvo := os.Getenv("RABBIT_KELVO_TEST_BINARY")
	if kelvo == "" {
		t.Skip("requires RABBIT_KELVO_TEST_BINARY, PyArrow and the transport fixture variables")
	}
	if info, err := os.Stat(kelvo); err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		t.Fatal("RABBIT_KELVO_TEST_BINARY must name an executable regular file")
	}
	python := os.Getenv("RABBIT_KELVO_TEST_PYTHON")
	if python == "" {
		python = "python3"
	}
	version, err := runKelvoFixtureCommand(python, []string{"-c", "import pyarrow; print(pyarrow.__version__)"}, nil, 15*time.Second)
	if err != nil {
		t.Fatalf("configured Kelvo acceptance requires Python with PyArrow: %v", err)
	}
	adminURL := os.Getenv("RABBIT_TRANSPORT_DATABASE_URL")
	if adminURL == "" || os.Getenv("RABBIT_DATABASE_CLIENT_TEST_BINARY") == "" || os.Getenv("RABBIT_TRANSPORT_REDIS_URL") == "" {
		t.Fatal("configured Kelvo acceptance also requires the transport fixture variables")
	}
	relay, ca := newKelvoPostgresRelay(t, adminURL)
	h := newTransportHarnessAt(t, relay)
	fixtureURL, err := url.Parse(h.fixtureDSN)
	if err != nil {
		t.Fatal("invalid generated fixture URL")
	}
	databaseName := strings.TrimPrefix(fixtureURL.Path, "/")
	role := "rabbit_kelvo_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// All generated SQL identifiers and the password use fixed prefixes/hex.
	if _, err := h.fixture.ExecContext(ctx, `CREATE ROLE "`+role+`" LOGIN PASSWORD '`+password+`' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal("could not create dedicated Kelvo reader role")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), transportTimeout)
		defer stop()
		if _, err := h.fixture.ExecContext(cleanup, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1 AND datname=$2 AND pid<>pg_backend_pid()`, role, databaseName); err != nil {
			t.Errorf("cannot terminate owned Kelvo fixture connections: %v", err)
		}
		for _, statement := range []string{`DROP OWNED BY "` + role + `"`, `DROP ROLE "` + role + `"`} {
			if _, err := h.fixture.ExecContext(cleanup, statement); err != nil {
				t.Errorf("cannot remove owned Kelvo reader role: %v", err)
			}
		}
	})
	for _, statement := range []string{
		`CREATE UNLOGGED TABLE kelvo_transport_data AS SELECT i::BIGINT AS id,(i%97)::INTEGER AS category,
		 CASE WHEN i%17=0 THEN NULL ELSE 'value-'||LPAD(i::TEXT,7,'0') END::TEXT AS note,
		 i%2=0 AS active,(i::NUMERIC/100)::NUMERIC(18,2) AS amount,
		 DATE '2024-01-01'+(i%365)::INTEGER AS day FROM generate_series(1,1000000) AS source(i)`,
		`GRANT CONNECT ON DATABASE "` + databaseName + `" TO "` + role + `"`,
		`GRANT USAGE ON SCHEMA public TO "` + role + `"`,
		`GRANT SELECT ON kelvo_transport_data TO "` + role + `"`,
		`ALTER ROLE "` + role + `" IN DATABASE "` + databaseName + `" SET statement_timeout='150s'`,
		`ALTER ROLE "` + role + `" IN DATABASE "` + databaseName + `" SET lock_timeout='5s'`,
		`ANALYZE kelvo_transport_data`,
	} {
		if _, err := h.fixture.ExecContext(ctx, statement); err != nil {
			t.Fatalf("Kelvo fixture initialization failed: %v", err)
		}
	}
	var postgresVersion string
	if err := h.fixture.QueryRowContext(ctx, `SELECT version()`).Scan(&postgresVersion); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := h.fixture.QueryRowContext(ctx, `SELECT COUNT(*) FROM kelvo_transport_data`).Scan(&rows); err != nil || rows != kelvoFixtureRows {
		t.Fatalf("fixture row count: %d %v", rows, err)
	}
	dir := t.TempDir()
	catalog := "sources:\n  - id: fixture\n    type: postgres\n    dsn_env: KELVO_SOURCE_FIXTURE_DSN\n    options:\n      tls_ca_pem: |\n"
	for _, line := range strings.Split(strings.TrimSpace(string(ca)), "\n") {
		catalog += "        " + line + "\n"
	}
	configPath := filepath.Join(dir, "kelvo.yml")
	if err := os.WriteFile(configPath, []byte(catalog), 0600); err != nil {
		t.Fatal(err)
	}
	baseEnv := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir, "GOMAXPROCS=2"}
	if libraryPath := os.Getenv("LD_LIBRARY_PATH"); libraryPath != "" {
		baseEnv = append(baseEnv, "LD_LIBRARY_PATH="+libraryPath)
	}
	kelvoVersion, err := runKelvoFixtureCommand(kelvo, []string{"version"}, baseEnv, 15*time.Second)
	if err != nil {
		t.Fatalf("Kelvo version check failed: %v", err)
	}
	report := map[string]any{
		"scope":         "synthetic PostgreSQL fixture; native Kelvo CLI; verified source TLS; loopback direct versus Rabbit TLS tunnel",
		"kelvo_version": strings.TrimSpace(kelvoVersion), "kelvo_binary_sha256": fixtureFileHash(t, kelvo),
		"pyarrow_version": strings.TrimSpace(version), "postgres_version": postgresVersion, "rows": rows,
		"rabbit_client_binary_sha256": fixtureFileHash(t, os.Getenv("RABBIT_DATABASE_CLIENT_TEST_BINARY")),
	}
	outputs := make(map[string]string)
	measurements := make(map[string]any)
	for _, path := range []struct{ name, address string }{{"direct", relay}, {"rabbit", h.rabbit}} {
		dsn := &url.URL{Scheme: "postgres", Host: path.address, Path: "/" + databaseName, User: url.UserPassword(role, password)}
		dsn.RawQuery = "sslmode=verify-full&connect_timeout=10"
		env := append(append([]string(nil), baseEnv...), "KELVO_SOURCE_FIXTURE_DSN="+dsn.String())
		for _, workflow := range []struct{ name, query string }{{"cte", kelvoCTESQL}, {"rows", kelvoRowsSQL}} {
			name := path.name + "_" + workflow.name
			out := filepath.Join(dir, name+".arrow")
			args := []string{"query", "--config", configPath, "--mode", "native", "--connection", "fixture", "--sql", workflow.query,
				"--out", out, "--max-rows", strconv.Itoa(kelvoFixtureRows), "--max-bytes", "268435456", "--memory-mb", "256", "--threads", "2", "--timeout", "150s"}
			started := time.Now()
			stats, err := runKelvoFixtureCommand(kelvo, args, env, kelvoQueryTimeout)
			elapsed := time.Since(started)
			if err != nil {
				t.Fatalf("Kelvo %s query failed: %v\n%s", name, err, strings.ReplaceAll(stats, password, "[redacted]"))
			}
			info, err := os.Stat(out)
			if err != nil || info.Size() == 0 || info.Size() > 268435456 {
				t.Fatalf("invalid %s Arrow result file", name)
			}
			measurements[name] = map[string]any{"elapsed_ns": elapsed.Nanoseconds(), "arrow_bytes": info.Size(), "arrow_file_sha256": fixtureFileHash(t, out), "query_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(workflow.query)))}
			outputs[name] = out
		}
	}
	_, thisFile, _, _ := runtime.Caller(0)
	decoder := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "scripts", "kelvo_transport_acceptance.py")
	decoded, err := runKelvoFixtureCommand(python, []string{decoder,
		"--direct-cte", outputs["direct_cte"], "--rabbit-cte", outputs["rabbit_cte"],
		"--direct-rows", outputs["direct_rows"], "--rabbit-rows", outputs["rabbit_rows"]}, nil, kelvoQueryTimeout)
	if err != nil {
		t.Fatalf("Kelvo Arrow acceptance failed: %v\n%s", err, decoded)
	}
	var verified map[string]any
	if err := json.Unmarshal([]byte(decoded), &verified); err != nil {
		t.Fatalf("invalid decoder receipt: %v", err)
	}
	report["measurements"], report["verification"] = measurements, verified
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("KELVO_TRANSPORT_ACCEPTANCE %s", encoded)
}

func runKelvoFixtureCommand(binary string, args, env []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	if env != nil {
		command.Env = env
	}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	output := &transportOutput{}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	return output.String(), err
}

func fixtureFileHash(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// The fixture PG server is reached only over its Unix socket. This small relay
// implements PostgreSQL SSLRequest so both tested paths use identical verified
// source TLS even when the disposable PG fixture has no TLS configuration.
func newKelvoPostgresRelay(t *testing.T, adminURL string) (string, []byte) {
	t.Helper()
	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal("invalid PostgreSQL fixture URL")
	}
	socketDir := parsed.Query().Get("host")
	port := parsed.Port()
	if port == "" {
		port = parsed.Query().Get("port")
	}
	if port == "" {
		port = "5432"
	}
	if !filepath.IsAbs(socketDir) || strings.ContainsAny(port, "/\\") {
		t.Fatal("Kelvo acceptance requires a disposable PostgreSQL Unix-socket URL")
	}
	socket := filepath.Join(socketDir, ".s.PGSQL."+port)
	if info, err := os.Stat(socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("PostgreSQL fixture Unix socket is unavailable")
	}
	certPEM, _, cert, _ := transportCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var workers sync.WaitGroup
	closed := false
	connections := make(map[net.Conn]struct{})
	track := func(conn net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			conn.Close()
			return false
		}
		connections[conn] = struct{}{}
		return true
	}
	untrack := func(conn net.Conn) {
		conn.Close()
		mu.Lock()
		delete(connections, conn)
		mu.Unlock()
	}
	slots := make(chan struct{}, 8)
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			if !track(raw) {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				untrack(raw)
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				defer untrack(raw)
				_ = raw.SetDeadline(time.Now().Add(kelvoQueryTimeout))
				var request [8]byte
				if _, err := io.ReadFull(raw, request[:]); err != nil || binary.BigEndian.Uint32(request[:4]) != 8 || binary.BigEndian.Uint32(request[4:]) != 80877103 {
					return
				}
				if _, err := raw.Write([]byte("S")); err != nil {
					return
				}
				client := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				err = client.HandshakeContext(ctx)
				cancel()
				if err != nil {
					return
				}
				upstream, err := net.DialTimeout("unix", socket, 5*time.Second)
				if err != nil || !track(upstream) {
					return
				}
				defer untrack(upstream)
				_ = upstream.SetDeadline(time.Now().Add(kelvoQueryTimeout))
				done := make(chan struct{}, 2)
				copyStream := func(dst, src net.Conn) {
					_, err := io.Copy(dst, src)
					if err == nil {
						if half, ok := dst.(interface{ CloseWrite() error }); ok {
							err = half.CloseWrite()
						}
					}
					if err != nil {
						dst.Close()
						src.Close()
					}
					done <- struct{}{}
				}
				go copyStream(client, upstream)
				go copyStream(upstream, client)
				<-done
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		listener.Close()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		finished := make(chan struct{})
		go func() { workers.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("PostgreSQL TLS fixture relay did not stop")
		}
	})
	return listener.Addr().String(), certPEM
}
