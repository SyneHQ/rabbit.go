//go:build linux

package server

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestKelvoPrivateNativeMySQL(t *testing.T) {
	helper, socket := os.Getenv("RABBIT_KELVO_NATIVE_HELPER"), os.Getenv("RABBIT_TRANSPORT_MYSQL_SOCKET")
	caPath, password := os.Getenv("RABBIT_TRANSPORT_MYSQL_CA"), os.Getenv("RABBIT_TRANSPORT_MYSQL_PASSWORD")
	if helper == "" || socket == "" || caPath == "" || password == "" {
		t.Skip("requires the native Kelvo helper and optional owned MySQL fixture")
	}
	if info, err := os.Stat(helper); err != nil || info.IsDir() || info.Mode()&0111 == 0 {
		t.Fatal("RABBIT_KELVO_NATIVE_HELPER must name an executable test binary")
	}
	ca, err := os.ReadFile(caPath)
	if err != nil || len(ca) == 0 || len(ca) > 64<<10 {
		t.Fatal("cannot read the generated MySQL source CA")
	}
	var accepted atomic.Int32
	relay := nativeMySQLUnixRelay(t, socket, &accepted)
	f := newNativePrivateFixture(t, relay)
	for _, mode := range []string{"rows", "denied-source", "denied-tenant", "hostname"} {
		t.Run(mode, func(t *testing.T) {
			before := accepted.Load()
			var input map[string]json.RawMessage
			if json.Unmarshal(kelvoNativeInput(t, f, ca, mode), &input) != nil {
				t.Fatal("cannot extend the native fixture input")
			}
			input["mysql_password"], _ = json.Marshal(password)
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal("cannot encode native MySQL fixture input")
			}
			result := runKelvoNativeHelperNamed(t, helper, encoded, "TestRabbitNativeMySQLHelper")
			wantMode, wantOpens := mode, int32(1)
			if strings.HasPrefix(mode, "denied-") {
				wantMode, wantOpens = "denied", 0
			}
			if result.Mode != wantMode || result.Opens != wantOpens || accepted.Load()-before != wantOpens {
				t.Fatal("native MySQL authority or customer-dial count changed")
			}
			if mode == "rows" && result.Rows != 100000 {
				t.Fatal("native MySQL row evidence is incomplete")
			}
		})
	}
}

// MySQL owns the complete source TLS handshake. This relay changes only TCP to
// the fixture's private Unix socket; it never decrypts or parses database data.
func nativeMySQLUnixRelay(t *testing.T, socket string, accepted *atomic.Int32) string {
	t.Helper()
	if info, err := os.Stat(socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("owned MySQL fixture socket is unavailable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot open the private MySQL fixture relay")
	}
	var mu sync.Mutex
	var workers sync.WaitGroup
	closed := false
	connections := make(map[net.Conn]bool)
	track := func(conn net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			_ = conn.Close()
			return false
		}
		connections[conn] = true
		return true
	}
	untrack := func(conn net.Conn) {
		_ = conn.Close()
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
			accepted.Add(1)
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
				upstream, err := net.DialTimeout("unix", socket, 5*time.Second)
				if err != nil || !track(upstream) {
					return
				}
				defer untrack(upstream)
				_ = raw.SetDeadline(time.Now().Add(45 * time.Second))
				_ = upstream.SetDeadline(time.Now().Add(45 * time.Second))
				done := make(chan struct{}, 2)
				copyStream := func(dst, src net.Conn) {
					_, err := io.Copy(dst, src)
					if err == nil {
						if half, ok := dst.(interface{ CloseWrite() error }); ok {
							err = half.CloseWrite()
						}
					}
					if err != nil {
						_ = dst.Close()
						_ = src.Close()
					}
					done <- struct{}{}
				}
				go copyStream(raw, upstream)
				go copyStream(upstream, raw)
				<-done
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		_ = listener.Close()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		joined := make(chan struct{})
		go func() { workers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(10 * time.Second):
			t.Error("native MySQL fixture relay did not join")
		}
	})
	return listener.Addr().String()
}
