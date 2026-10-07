package middleware

import (
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

// This fixture measures wrapper work only. It does not move network bytes and
// must not be reported as tunnel throughput. The file also runs on ecf8753.
type benchmarkDeadlineConn struct {
	net.Conn
	updates int
}

func (c *benchmarkDeadlineConn) Read(b []byte) (int, error)  { return len(b), nil }
func (c *benchmarkDeadlineConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *benchmarkDeadlineConn) SetReadDeadline(time.Time) error {
	c.updates++
	return nil
}
func (c *benchmarkDeadlineConn) SetWriteDeadline(time.Time) error {
	c.updates++
	return nil
}
func (c *benchmarkDeadlineConn) SetDeadline(time.Time) error {
	c.updates += 2
	return nil
}

func BenchmarkSecurityDeadlineUpdates(b *testing.B) {
	for _, mode := range []string{"Idle", "Explicit"} {
		b.Run(mode, func(b *testing.B) {
			probe := &benchmarkDeadlineConn{}
			sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: 30 * time.Minute}}
			conn := sm.WrapConnection(probe)
			if mode == "Explicit" {
				if err := conn.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
					b.Fatal(err)
				}
			}
			data := make([]byte, 32768)
			probe.updates = 0
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := conn.Read(data); err != nil {
					b.Fatal(err)
				}
				if _, err := conn.Write(data); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(probe.updates)/float64(b.N), "deadline_updates/op")
		})
	}
}

// This companion includes real net.Pipe timers and synchronous copies. It is
// still a local memory transport, not a substitute for TCP/TLS measurements.
func BenchmarkSecurityIdlePipeRoundTrip(b *testing.B) {
	a, peer := net.Pipe()
	b.Cleanup(func() { _ = a.Close(); _ = peer.Close() })
	sm := &SecurityMiddleware{config: SecurityConfig{IdleTimeout: time.Minute}}
	conn := sm.WrapConnection(a)
	echoDone := make(chan error, 1)
	go func() {
		data := make([]byte, 4096)
		for {
			if _, err := io.ReadFull(peer, data); err != nil {
				echoDone <- err
				return
			}
			if _, err := peer.Write(data); err != nil {
				echoDone <- err
				return
			}
		}
	}()
	b.Cleanup(func() { _ = peer.Close(); _ = a.Close(); <-echoDone })
	data := make([]byte, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := conn.Write(data); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAdmissionHistory(b *testing.B) {
	for _, count := range []int{100, 10000} {
		b.Run(fmt.Sprintf("Entries_%d", count), func(b *testing.B) {
			now := time.Now()
			sm := &SecurityMiddleware{config: SecurityConfig{ConnectionWindow: time.Hour, BurstWindow: time.Minute, BurstThreshold: count + 1}}
			stats := &IPStats{HourlyConnections: make([]time.Time, count)}
			for i := range stats.HourlyConnections {
				stats.HourlyConnections[i] = now.Add(-time.Duration(count-i) * time.Millisecond)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sm.cleanOldConnections(stats, now)
				if sm.detectBurst(stats, now) {
					b.Fatal("fixture unexpectedly exceeded burst limit")
				}
			}
		})
	}
}

type benchmarkAdmissionConn struct{ net.Conn }

var benchmarkRemoteAddress = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5432}

func (benchmarkAdmissionConn) RemoteAddr() net.Addr { return benchmarkRemoteAddress }

func BenchmarkTrustedAdmission(b *testing.B) {
	// Baseline logged every admission. Discard output equally in both versions
	// so storage speed cannot dominate this bounded in-process comparison.
	output := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(output) })
	config := DefaultSecurityConfig()
	config.TrustedNetworks = []string{"127.0.0.0/8"}
	sm := NewSecurityMiddleware(config)
	b.Cleanup(sm.Stop)
	conn := benchmarkAdmissionConn{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if err := sm.ValidateConnection(conn); err != nil {
			b.Fatal(err)
		}
		sm.RecordConnectionClosed(conn)
		// Keep the unsafe baseline history bounded too. This is a repeated
		// window of 1,024 admissions, not an unbounded memory stress test.
		if i%1024 == 1023 {
			sm.ipStats["127.0.0.1"].HourlyConnections = nil
		}
	}
}
