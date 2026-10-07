package middleware

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type admissionConn struct {
	net.Conn
	address *net.TCPAddr
}

func (c admissionConn) RemoteAddr() net.Addr { return c.address }

func testAdmissionConn() net.Conn {
	return admissionConn{address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5432}}
}

func TestGlobalConnectionLimitConfiguration(t *testing.T) {
	original, exists := os.LookupEnv("RABBIT_MAX_CONNECTIONS")
	t.Cleanup(func() {
		if exists {
			_ = os.Setenv("RABBIT_MAX_CONNECTIONS", original)
		} else {
			_ = os.Unsetenv("RABBIT_MAX_CONNECTIONS")
		}
	})
	_ = os.Unsetenv("RABBIT_MAX_CONNECTIONS")
	config, err := SecurityConfigFromEnv()
	if err != nil || config.MaxGlobalConnections != 4096 || config.MaxConnectionsPerIP != 100 {
		t.Fatalf("unexpected default limits: %+v %v", config, err)
	}
	for _, value := range []string{"1", "1000000", "8192"} {
		t.Setenv("RABBIT_MAX_CONNECTIONS", value)
		if _, err := SecurityConfigFromEnv(); err != nil {
			t.Fatalf("valid limit %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"", "0", "-1", "1000001", "1.0", " 64", "+64", "064", "999999999999999999999"} {
		t.Setenv("RABBIT_MAX_CONNECTIONS", value)
		if _, err := SecurityConfigFromEnv(); err == nil {
			t.Fatalf("invalid limit %q accepted", value)
		}
	}
}

func TestTrustedConnectionsRespectGlobalCapacity(t *testing.T) {
	config := DefaultSecurityConfig()
	config.TrustedNetworks = []string{"127.0.0.0/8"}
	config.MaxGlobalConnections = 2
	config.MaxConnectionsPerIP = 1
	config.MaxConnectionsPerHour = 1
	config.BurstThreshold = 1
	sm := NewSecurityMiddleware(config)
	defer sm.Stop()
	conn := testAdmissionConn()
	for range 2 {
		if err := sm.ValidateConnection(conn); err != nil {
			t.Fatalf("trusted admission below global capacity: %v", err)
		}
	}
	if err := sm.ValidateConnection(conn); err == nil {
		t.Fatal("trusted admission bypassed global capacity")
	}
	stats := sm.ipStats["127.0.0.1"]
	if sm.globalConnections != 2 || stats.CurrentConnections != 2 || len(stats.HourlyConnections) != 0 {
		t.Fatal("rejected admission changed counters or trusted traffic retained rate history")
	}
	sm.RecordConnectionClosed(conn)
	if err := sm.ValidateConnection(conn); err != nil {
		t.Fatalf("released capacity was not reusable: %v", err)
	}
	sm.RecordConnectionClosed(conn)
	sm.RecordConnectionClosed(conn)
	if sm.globalConnections != 0 || stats.CurrentConnections != 0 {
		t.Fatal("connections remained counted after close")
	}
}

func TestTrustedConnectionsDoNotAccumulateRateHistory(t *testing.T) {
	config := DefaultSecurityConfig()
	config.TrustedNetworks = []string{"127.0.0.0/8"}
	sm := NewSecurityMiddleware(config)
	defer sm.Stop()
	// The constructor owns its trust list independently of the caller.
	config.TrustedNetworks[0] = "192.0.2.0/24"
	conn := testAdmissionConn()
	for range 1000 {
		if err := sm.ValidateConnection(conn); err != nil {
			t.Fatal(err)
		}
		sm.RecordConnectionClosed(conn)
	}
	stats := sm.ipStats["127.0.0.1"]
	if cap(stats.HourlyConnections) != 0 || len(stats.Violations) != 0 || sm.globalConnections != 0 {
		t.Fatal("trusted traffic accumulated admission history or active connections")
	}
	if err := sm.RemoveTrustedNetwork("127.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	if err := sm.ValidateConnection(conn); err != nil {
		t.Fatal(err)
	}
	if len(stats.HourlyConnections) != 1 {
		t.Fatal("removed trusted network still bypasses rate accounting")
	}
	sm.RecordConnectionClosed(conn)
}

func TestUntrustedAdmissionRetainsRateAndBurstLimits(t *testing.T) {
	for _, limit := range []string{"hourly", "burst", "concurrent"} {
		t.Run(limit, func(t *testing.T) {
			config := DefaultSecurityConfig()
			config.TrustedNetworks = nil
			switch limit {
			case "hourly":
				config.MaxConnectionsPerHour = 2
			case "burst":
				config.BurstThreshold = 2
			case "concurrent":
				config.MaxConnectionsPerIP = 2
			}
			sm := NewSecurityMiddleware(config)
			defer sm.Stop()
			conn := testAdmissionConn()
			for range 2 {
				if err := sm.ValidateConnection(conn); err != nil {
					t.Fatal(err)
				}
				if limit != "concurrent" {
					sm.RecordConnectionClosed(conn)
				}
			}
			before := sm.globalConnections
			if err := sm.ValidateConnection(conn); err == nil {
				t.Fatalf("%s limit allowed excess admission", limit)
			}
			if sm.globalConnections != before {
				t.Fatal("rejected admission consumed capacity")
			}
		})
	}
}

func TestHistoryPruningPreservesWindowBoundaries(t *testing.T) {
	now := time.Now()
	sm := &SecurityMiddleware{config: SecurityConfig{ConnectionWindow: time.Hour, BurstWindow: time.Minute, BurstThreshold: 2}}
	live := now.Add(-time.Second)
	stats := &IPStats{HourlyConnections: []time.Time{now.Add(-2 * time.Hour), now.Add(-time.Hour), now.Add(-time.Minute), live, now}}
	sm.cleanOldConnections(stats, now)
	if len(stats.HourlyConnections) != 3 || !stats.HourlyConnections[1].Equal(live) || !sm.detectBurst(stats, now) {
		t.Fatal("expired prefix removal lost live timestamps or burst boundary")
	}
	first := &stats.HourlyConnections[0]
	sm.cleanOldConnections(stats, now)
	if &stats.HourlyConnections[0] != first {
		t.Fatal("unchanged live history was copied")
	}
	stats.Violations = []time.Time{now.Add(-2 * time.Hour), now.Add(-time.Hour), live}
	sm.cleanOldViolations(stats, now)
	if len(stats.Violations) != 1 || !stats.Violations[0].Equal(live) {
		t.Fatal("violation window boundary changed")
	}
	sm.cleanOldConnections(stats, now.Add(2*time.Hour))
	if len(stats.HourlyConnections) != 0 {
		t.Fatal("fully expired history was retained")
	}
}

func TestConcurrentTrustChangesAdmissionAndStop(t *testing.T) {
	config := DefaultSecurityConfig()
	config.TrustedNetworks = nil
	sm := NewSecurityMiddleware(config)
	conn := testAdmissionConn()
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				if sm.ValidateConnection(conn) == nil {
					sm.RecordConnectionClosed(conn)
				}
				_ = sm.GetStats()
				_ = sm.ListTrustedNetworks()
			}
		})
	}
	workers.Go(func() {
		for range 100 {
			if err := sm.AddTrustedNetwork("127.0.0.0/8"); err != nil {
				t.Error(err)
			}
			if err := sm.RemoveTrustedNetwork("127.0.0.0/8"); err != nil {
				t.Error(err)
			}
		}
	})
	workers.Wait()
	if sm.globalConnections != 0 || sm.ipStats["127.0.0.1"].CurrentConnections != 0 {
		t.Fatal("concurrent trust updates leaked active connection counts")
	}
	for range 8 {
		workers.Go(sm.Stop)
	}
	workers.Wait()
}
