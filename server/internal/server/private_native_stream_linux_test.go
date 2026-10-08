//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestNativePrivateConnectHalfClose(t *testing.T) {
	f := newNativePrivateFixture(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := f.dialer().DialContext(ctx, "tcp", f.claims.Authority)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	const size = 1 << 20
	var request [16]byte
	binary.LittleEndian.PutUint64(request[:8], size)
	binary.LittleEndian.PutUint64(request[8:], transportSeed)
	if _, err := conn.Write(request[:]); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// This source sends no response until it sees EOF on the request. A full
	// close would lose the response; preserving bytes alone cannot pass this.
	data, err := io.ReadAll(io.LimitReader(conn, size+1))
	if err != nil || len(data) != size || sha256.Sum256(data) != sha256.Sum256(f.h.corpus[:size]) {
		t.Fatal("actual Rabbit client did not preserve private request half-close", len(data), err)
	}
}

func TestNativePrivateConnectRedis(t *testing.T) {
	value := os.Getenv("RABBIT_TRANSPORT_REDIS_URL")
	if value == "" || os.Getenv("RABBIT_DATABASE_CLIENT_TEST_BINARY") == "" || os.Getenv("RABBIT_TRANSPORT_DATABASE_URL") == "" {
		t.Skip("requires native Rabbit client and owned PostgreSQL/Redis fixtures")
	}
	options, err := redis.ParseURL(value)
	if err != nil || options.Network != "unix" {
		t.Fatal("Redis source qualification requires the owned Unix-socket fixture")
	}
	_, _, certificate, roots := transportCertificate(t)
	relay := nativeRedisTLSRelay(t, options.Addr, certificate)
	f := newNativePrivateFixture(t, relay)
	admin := redis.NewClient(options)
	t.Cleanup(func() { admin.Close() })
	key := "rabbit-private-fixture:" + uuid.NewString()
	want := bytes.Repeat([]byte("private-redis-value\x00"), 16384)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := admin.Set(ctx, key, want, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := admin.Del(cleanup, key).Err(); err != nil {
			t.Error("cannot delete owned Redis fixture key", err)
		}
	})
	dialer := f.dialer()
	client := redis.NewClient(&redis.Options{Addr: f.claims.Authority, PoolSize: 1, MaxRetries: -1, ContextTimeoutEnabled: true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			source := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"})
			if err := source.HandshakeContext(ctx); err != nil {
				source.Close()
				return nil, err
			}
			return source, nil
		}})
	t.Cleanup(func() { client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	got, err := client.Get(ctx, key).Bytes()
	if err != nil || !bytes.Equal(got, want) || dialer.opens.Load() != 1 {
		t.Fatal("native Redis bytes changed through private CONNECT", len(got), err)
	}
}

// The existing Redis container remains network-isolated. This bounded local TLS
// endpoint terminates source TLS and forwards only to its exact Unix socket.
func nativeRedisTLSRelay(t *testing.T, socket string, certificate tls.Certificate) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	source := &transportSource{listener: listener, conns: make(map[net.Conn]struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	slots := make(chan struct{}, 4)
	source.wg.Add(1)
	go func() {
		defer source.wg.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			source.mu.Lock()
			if source.closed {
				source.mu.Unlock()
				client.Close()
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				source.mu.Unlock()
				client.Close()
				continue
			}
			source.conns[client] = struct{}{}
			source.wg.Add(1)
			source.mu.Unlock()
			go func() {
				defer source.wg.Done()
				defer func() {
					<-slots
					client.Close()
					source.mu.Lock()
					delete(source.conns, client)
					source.mu.Unlock()
				}()
				client.SetDeadline(time.Now().Add(30 * time.Second))
				if err := client.(*tls.Conn).HandshakeContext(ctx); err != nil {
					return
				}
				upstream, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
				if err != nil {
					return
				}
				defer upstream.Close()
				source.mu.Lock()
				if source.closed {
					source.mu.Unlock()
					return
				}
				source.conns[upstream] = struct{}{}
				source.mu.Unlock()
				defer func() { source.mu.Lock(); delete(source.conns, upstream); source.mu.Unlock() }()
				upstream.SetDeadline(time.Now().Add(30 * time.Second))
				done := make(chan struct{}, 2)
				copyStream := func(dst, src net.Conn) {
					_, err := io.Copy(dst, src)
					if err == nil {
						err = dst.(interface{ CloseWrite() error }).CloseWrite()
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
		cancel()
		source.mu.Lock()
		source.closed = true
		listener.Close()
		for conn := range source.conns {
			closeShutdownConnection(conn)
		}
		source.mu.Unlock()
		done := make(chan struct{})
		go func() { source.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Redis source relay did not join")
		}
	})
	return listener.Addr().String()
}
