package server

// These opt-in checks exercise the actual client process and server over TCP/TLS.
// Run benchmarks with fixed iterations, for example -benchtime=5x -count=5.
// Numbers include a loopback source, checksum verification and metadata inserts;
// they do not establish database, WAN or deployment capacity.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
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
	"github.com/redis/go-redis/v9"
)

const transportPayloadLimit = 64 << 20
const transportSeed = uint64(0xe7037ed1a0b428db)
const transportTimeout = 30 * time.Second

// The byte corpus is deterministic and has high entropy. Each request includes
// the corpus seed so an accidentally mismatched source cannot silently pass.
func transportCorpus() []byte {
	data := make([]byte, transportPayloadLimit)
	state := transportSeed
	for i := 0; i < len(data); i += 8 {
		state ^= state >> 12
		state ^= state << 25
		state ^= state >> 27
		binary.LittleEndian.PutUint64(data[i:], state*0x2545f4914f6cdd1d)
	}
	return data
}

type transportOutput struct {
	mu   sync.Mutex
	data []byte
}

func (o *transportOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(p)
	if remaining := 64<<10 - len(o.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		o.data = append(o.data, p...)
	}
	return n, nil
}

func (o *transportOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.data)
}

type transportSource struct {
	listener net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closed   bool
	wg       sync.WaitGroup
}

func newTransportSource(tb testing.TB, corpus []byte, tlsConfig *tls.Config) *transportSource {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	source := &transportSource{listener: listener, conns: make(map[net.Conn]struct{})}
	source.wg.Add(1)
	go func() {
		defer source.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			source.mu.Lock()
			if source.closed {
				source.mu.Unlock()
				conn.Close()
				return
			}
			source.conns[conn] = struct{}{}
			source.wg.Add(1)
			source.mu.Unlock()
			go func() {
				defer source.wg.Done()
				defer func() {
					conn.Close()
					source.mu.Lock()
					delete(source.conns, conn)
					source.mu.Unlock()
				}()
				conn.SetDeadline(time.Now().Add(transportTimeout))
				var request [16]byte
				if _, err := io.ReadFull(conn, request[:]); err != nil {
					return
				}
				size, seed := binary.LittleEndian.Uint64(request[:8]), binary.LittleEndian.Uint64(request[8:])
				if size == 0 || size > uint64(len(corpus)) || seed != transportSeed {
					return
				}
				// A response is impossible until the entire tunnel preserves EOF.
				var extra [1]byte
				if n, err := conn.Read(extra[:]); n != 0 || err != io.EOF {
					return
				}
				if _, err := io.Copy(conn, bytes.NewReader(corpus[:int(size)])); err != nil {
					return
				}
				if half, ok := conn.(interface{ CloseWrite() error }); ok {
					half.CloseWrite()
				}
			}()
		}
	}()
	tb.Cleanup(func() {
		source.mu.Lock()
		source.closed = true
		listener.Close()
		for conn := range source.conns {
			conn.Close()
		}
		source.mu.Unlock()
		done := make(chan struct{})
		go func() { source.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(transportTimeout):
			tb.Error("source fixture did not stop within its connection deadline")
		}
	})
	return source
}

type transportHarness struct {
	fixture    *sql.DB
	fixtureDSN string
	server     *Server
	plain      string
	directTLS  string
	rabbit     string
	clientTLS  *tls.Config
	corpus     []byte
	clientLog  *transportOutput
}

func transportCertificate(tb testing.TB) ([]byte, []byte, tls.Certificate, *x509.CertPool) {
	tb.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rabbit-transport-fixture"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		tb.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		tb.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		tb.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		tb.Fatal("fixture certificate was not accepted")
	}
	return certPEM, keyPEM, cert, roots
}

func newTransportHarness(tb testing.TB) *transportHarness {
	return newTransportHarnessAt(tb, "")
}

func newTransportHarnessAt(tb testing.TB, sourceAddress string) *transportHarness {
	tb.Helper()
	binaryPath := os.Getenv("RABBIT_DATABASE_CLIENT_TEST_BINARY")
	adminURL := os.Getenv("RABBIT_TRANSPORT_DATABASE_URL")
	redisURL := os.Getenv("RABBIT_TRANSPORT_REDIS_URL")
	if binaryPath == "" || adminURL == "" || redisURL == "" {
		tb.Skip("requires RABBIT_DATABASE_CLIENT_TEST_BINARY, RABBIT_TRANSPORT_DATABASE_URL and RABBIT_TRANSPORT_REDIS_URL")
	}
	if info, err := os.Stat(binaryPath); err != nil || info.IsDir() || info.Mode()&0111 == 0 {
		tb.Fatal("RABBIT_DATABASE_CLIENT_TEST_BINARY must name an executable client")
	}
	adminDSN, err := url.Parse(adminURL)
	if err != nil || (adminDSN.Scheme != "postgres" && adminDSN.Scheme != "postgresql") {
		tb.Fatal("RABBIT_TRANSPORT_DATABASE_URL must be a PostgreSQL URL")
	}
	admin, err := sql.Open("postgres", adminURL)
	if err != nil {
		tb.Fatal("cannot open transport fixture administrator connection")
	}
	tb.Cleanup(func() { admin.Close() })
	admin.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), transportTimeout)
	defer cancel()
	name := "rabbit_transport_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	// The identifier consists only of a fixed prefix and generated hex digits.
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		tb.Fatalf("cannot create isolated transport fixture database: %v", err)
	}
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), transportTimeout)
		defer cancel()
		if _, err := admin.ExecContext(ctx, `DROP DATABASE "`+name+`" WITH (FORCE)`); err != nil {
			tb.Errorf("failed to remove owned fixture database %s: %v", name, err)
		}
	})
	fixtureDSN := *adminDSN
	fixtureDSN.Path, fixtureDSN.RawPath = "/"+name, ""
	fixture, err := sql.Open("postgres", fixtureDSN.String())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { fixture.Close() })
	fixture.SetMaxOpenConns(1)
	// The external metadata database owns Team. The repository migration's
	// standalone Team definition lacks fields used by its current auth queries.
	_, err = fixture.ExecContext(ctx, `CREATE TABLE public."Team" (
		id text PRIMARY KEY, name text NOT NULL UNIQUE, description text NOT NULL DEFAULT '',
		deleted boolean NOT NULL DEFAULT false, is_active boolean NOT NULL DEFAULT true,
		"createdAt" timestamptz NOT NULL DEFAULT NOW(), "updatedAt" timestamptz NOT NULL DEFAULT NOW(),
		created_at timestamptz NOT NULL DEFAULT NOW(), updated_at timestamptz NOT NULL DEFAULT NOW())`)
	if err != nil {
		tb.Fatal(err)
	}
	_, thisFile, _, _ := runtime.Caller(0)
	migration, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "database", "migrations.sql"))
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := fixture.ExecContext(ctx, string(migration)); err != nil {
		tb.Fatalf("transport fixture migration failed: %v", err)
	}
	redisOptions, err := redis.ParseURL(redisURL)
	if err != nil {
		tb.Fatal("invalid RABBIT_TRANSPORT_REDIS_URL")
	}
	redisOptions.ContextTimeoutEnabled = true
	redisClient := redis.NewClient(redisOptions)
	// Delete only keys whose IDs belong to sessions in this newly created DB.
	tb.Cleanup(func() {
		defer redisClient.Close()
		ctx, cancel := context.WithTimeout(context.Background(), transportTimeout)
		defer cancel()
		rows, err := fixture.QueryContext(ctx, `SELECT id::text FROM connection_sessions`)
		if err != nil {
			tb.Errorf("cannot enumerate owned Redis session keys: %v", err)
			return
		}
		var keys []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				tb.Error(err)
				continue
			}
			keys = append(keys, "session:"+id)
		}
		if err := rows.Err(); err != nil {
			tb.Error(err)
		}
		rows.Close()
		if len(keys) > 0 {
			if err := redisClient.Del(ctx, keys...).Err(); err != nil {
				tb.Errorf("cannot remove owned Redis session keys: %v", err)
			}
		}
	})
	certPEM, keyPEM, cert, roots := transportCertificate(tb)
	caPath := filepath.Join(tb.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0600); err != nil {
		tb.Fatal(err)
	}
	for key, value := range map[string]string{
		"DATABASE_URL": fixtureDSN.String(), "REDIS_URL": redisURL,
		"RABBIT_TLS_CERT_PEM": string(certPEM), "RABBIT_TLS_KEY_PEM": string(keyPEM),
		"RABBIT_TLS_CERT_FILE": "", "RABBIT_TLS_KEY_FILE": "",
		"RABBIT_NOTEBOOK_AUTHORITY_URL": "", "TRUSTED_NETWORKS": "", "ENVIRONMENT": "production",
	} {
		tb.Setenv(key, value)
	}
	oldLogOutput := log.Writer()
	log.SetOutput(io.Discard)
	tb.Cleanup(func() { log.SetOutput(oldLogOutput) })
	corpus := transportCorpus()
	plain := newTransportSource(tb, corpus, nil)
	tlsSource := newTransportSource(tb, corpus, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	token, tokenID, assignmentID, team := uuid.NewString(), uuid.New(), uuid.New(), uuid.NewString()
	if _, err := fixture.ExecContext(ctx, `INSERT INTO "Team"(id,name) VALUES($1,$1)`, team); err != nil {
		tb.Fatal(err)
	}
	if _, err := fixture.ExecContext(ctx, `INSERT INTO team_tokens(id,team_id,token,name,description) VALUES($1,$2,$3,'transport fixture','')`, tokenID, team, token); err != nil {
		tb.Fatal(err)
	}
	if _, err := fixture.ExecContext(ctx, `INSERT INTO port_assignments(id,team_id,token_id,port,is_reserved) VALUES($1,$2,$3,$4,true)`, assignmentID, team, tokenID, port); err != nil {
		tb.Fatal(err)
	}
	srv, err := NewServer(Config{BindAddress: "127.0.0.1", ControlPort: "0"})
	if err != nil {
		tb.Fatalf("transport fixture server failed: %v", err)
	}
	tb.Cleanup(func() {
		done := make(chan error, 1)
		go func() { done <- srv.Stop() }()
		select {
		case err := <-done:
			if err != nil {
				tb.Error(err)
			}
		case <-time.After(transportTimeout):
			tb.Error("Rabbit fixture server exceeded its shutdown deadline")
		}
	})
	if err := srv.Start(); err != nil {
		tb.Fatal(err)
	}
	if sourceAddress == "" {
		sourceAddress = plain.listener.Addr().String()
	}
	_, localPort, err := net.SplitHostPort(sourceAddress)
	if err != nil {
		tb.Fatal("source fixture address must contain a host and port")
	}
	output := &transportOutput{}
	command := exec.Command(binaryPath, "tunnel", "--server", srv.controlListener.Addr().String(),
		"--local-port", localPort, "--ca-file", caPath, "--server-name", "localhost",
		"--max-retries", "1", "--timeout", "10s", "--health-interval", "1h")
	// The native client does not need metadata DB credentials or server TLS keys.
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"RABBIT_TOKEN=" + token, "GOMAXPROCS=" + strconv.Itoa(runtime.GOMAXPROCS(0))}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		tb.Fatalf("could not start native Rabbit client: %v", err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	tb.Cleanup(func() {
		command.Process.Signal(syscall.SIGTERM)
		select {
		case <-processDone:
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			select {
			case <-processDone:
			case <-time.After(5 * time.Second):
				tb.Error("native client did not exit after Kill")
			}
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(output.String(), "Tunnel established") {
		select {
		case err := <-processDone:
			processDone <- err // Leave the process result available to cleanup.
			tb.Fatalf("native client exited before readiness: %v\n%s", err, output.String())
		default:
		}
		if time.Now().After(deadline) {
			tb.Fatalf("native client did not become ready\n%s", output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	return &transportHarness{fixture: fixture, fixtureDSN: fixtureDSN.String(), server: srv, corpus: corpus, clientLog: output,
		plain: plain.listener.Addr().String(), directTLS: tlsSource.listener.Addr().String(),
		rabbit:    net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		clientTLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost", ClientSessionCache: tls.NewLRUClientSessionCache(8)},
	}
}

type transportTiming struct {
	dial, firstByte, transfer time.Duration
}

func (h *transportHarness) transfer(mode string, size int, want [32]byte) (timing transportTiming, err error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), transportTimeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var conn net.Conn
	switch mode {
	case "tcp":
		conn, err = dialer.DialContext(ctx, "tcp", h.plain)
	case "tls":
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: h.clientTLS}).DialContext(ctx, "tcp", h.directTLS)
	case "rabbit":
		conn, err = dialer.DialContext(ctx, "tcp", h.rabbit)
	default:
		return timing, fmt.Errorf("unknown transport %q", mode)
	}
	if err != nil {
		return timing, err
	}
	defer conn.Close()
	timing.dial = time.Since(started)
	conn.SetDeadline(started.Add(transportTimeout))
	var request [16]byte
	binary.LittleEndian.PutUint64(request[:8], uint64(size))
	binary.LittleEndian.PutUint64(request[8:], transportSeed)
	if _, err = io.Copy(conn, bytes.NewReader(request[:])); err != nil {
		return timing, err
	}
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return timing, fmt.Errorf("transport does not support request half-close")
	}
	if err = half.CloseWrite(); err != nil {
		return timing, err
	}
	var first [1]byte
	if _, err = io.ReadFull(conn, first[:]); err != nil {
		return timing, fmt.Errorf("first response byte: %w", err)
	}
	firstAt := time.Now()
	timing.firstByte = firstAt.Sub(started)
	digest := sha256.New()
	digest.Write(first[:])
	// The extra byte permits detecting an oversized result without unbounded reads.
	n, err := io.Copy(digest, io.LimitReader(conn, int64(size)))
	timing.transfer = time.Since(firstAt)
	if err != nil || n != int64(size-1) {
		return timing, fmt.Errorf("response length=%d want=%d: %v", n+1, size, err)
	}
	var actual [32]byte
	copy(actual[:], digest.Sum(nil))
	if actual != want {
		return timing, fmt.Errorf("response SHA-256 mismatch")
	}
	return timing, nil
}

func (h *transportHarness) wave(mode string, size, concurrency int, want [32]byte) (transportTiming, time.Duration, error) {
	type result struct {
		timing transportTiming
		err    error
	}
	results := make(chan result, concurrency)
	start := make(chan struct{})
	for range concurrency {
		go func() {
			<-start
			timing, err := h.transfer(mode, size, want)
			results <- result{timing, err}
		}()
	}
	started := time.Now()
	close(start)
	var total transportTiming
	var firstError error
	for range concurrency {
		result := <-results
		total.dial += result.timing.dial
		total.firstByte += result.timing.firstByte
		total.transfer += result.timing.transfer
		if result.err != nil && firstError == nil {
			firstError = result.err
		}
	}
	return total, time.Since(started), firstError
}

func TestNativeDatabaseTransport(t *testing.T) {
	h := newTransportHarness(t)
	for _, size := range []int{1024, transportPayloadLimit} {
		want := sha256.Sum256(h.corpus[:size])
		for _, concurrency := range []int{1, 10} {
			for _, mode := range []string{"tcp", "tls", "rabbit"} {
				t.Run(fmt.Sprintf("%s/bytes%d/c%d", mode, size, concurrency), func(t *testing.T) {
					timing, elapsed, err := h.wave(mode, size, concurrency, want)
					if err != nil {
						t.Fatalf("%s native transport failed: %v\n%s", mode, err, h.clientLog.String())
					}
					t.Logf("streams=%d bytes/stream=%d elapsed=%s mean_dial=%s mean_first_byte=%s mean_transfer=%s exact_sha256=%x", concurrency, size, elapsed,
						timing.dial/time.Duration(concurrency), timing.firstByte/time.Duration(concurrency), timing.transfer/time.Duration(concurrency), want)
				})
			}
		}
	}
}

func BenchmarkNativeDatabaseTransport(b *testing.B) {
	h := newTransportHarness(b)
	for _, size := range []int{1024, transportPayloadLimit} {
		want := sha256.Sum256(h.corpus[:size])
		for _, concurrency := range []int{1, 10} {
			for _, mode := range []string{"tcp", "tls", "rabbit"} {
				b.Run(fmt.Sprintf("%s/bytes%d/c%d", mode, size, concurrency), func(b *testing.B) {
					if b.N > 25 {
						b.Fatal("use fixed -benchtime=Nx with N<=25; adaptive large-transfer sampling is intentionally bounded")
					}
					if _, _, err := h.wave(mode, size, concurrency, want); err != nil {
						b.Fatalf("warmup failed: %v", err)
					}
					b.SetBytes(int64(size * concurrency))
					b.ResetTimer()
					var total transportTiming
					for range b.N {
						timing, _, err := h.wave(mode, size, concurrency, want)
						if err != nil {
							b.Fatalf("measured transfer failed: %v", err)
						}
						total.dial += timing.dial
						total.firstByte += timing.firstByte
						total.transfer += timing.transfer
					}
					b.StopTimer()
					streams := float64(b.N * concurrency)
					b.ReportMetric(float64(total.dial.Nanoseconds())/streams, "dial-ns/stream")
					b.ReportMetric(float64(total.firstByte.Nanoseconds())/streams, "first-byte-ns/stream")
					b.ReportMetric(float64(total.transfer.Nanoseconds())/streams, "transfer-ns/stream")
				})
			}
		}
	}
}
