package middleware

import (
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// SecurityConfig holds configuration for security middleware
type SecurityConfig struct {
	// Rate limiting
	MaxConnectionsPerIP   int           `yaml:"max_connections_per_ip"`   // Maximum concurrent connections per IP
	MaxConnectionsPerHour int           `yaml:"max_connections_per_hour"` // Maximum new connections per IP per hour
	ConnectionWindow      time.Duration `yaml:"connection_window"`        // Time window for rate limiting

	// DDoS protection
	MaxGlobalConnections int           `yaml:"max_connections"` // Maximum global concurrent connections
	BurstThreshold       int           `yaml:"burst_threshold"` // Threshold for burst detection
	BurstWindow          time.Duration `yaml:"burst_window"`    // Window for burst detection

	// Timeouts
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"` // Timeout for initial handshake
	IdleTimeout      time.Duration `yaml:"idle_timeout"`      // Timeout for idle connections

	// Blacklist
	BlacklistDuration    time.Duration `yaml:"blacklist_duration"`      // How long to blacklist IPs
	MaxViolationsPerHour int           `yaml:"max_violations_per_hour"` // Max violations before blacklisting

	// Whitelist
	TrustedNetworks []string `yaml:"trusted_networks"` // List of trusted IP networks/ranges (CIDR notation)
}

// DefaultSecurityConfig returns a default security configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		MaxConnectionsPerIP:   100,
		MaxConnectionsPerHour: 10000,
		ConnectionWindow:      time.Hour,
		MaxGlobalConnections:  4096,
		BurstThreshold:        10000,
		BurstWindow:           time.Minute,
		HandshakeTimeout:      10 * time.Second,
		IdleTimeout:           30 * time.Minute,
		BlacklistDuration:     time.Hour,
		MaxViolationsPerHour:  100,
		TrustedNetworks:       strings.Split(os.Getenv("TRUSTED_NETWORKS"), ","),
	}
}

// SecurityConfigFromEnv applies the operator's process-wide admission ceiling.
// The default is a safety ceiling, not a promise that a host can sustain it.
func SecurityConfigFromEnv() (SecurityConfig, error) {
	return ApplySecurityEnv(DefaultSecurityConfig())
}

// IPStats tracks statistics for an IP address
type IPStats struct {
	CurrentConnections int
	HourlyConnections  []time.Time
	Violations         []time.Time
	LastActivity       time.Time
	IsBlacklisted      bool
	BlacklistUntil     time.Time
}

// SecurityMiddleware provides security controls for TCP connections
type SecurityMiddleware struct {
	config            SecurityConfig
	ipStats           map[string]*IPStats
	globalConnections int
	mu                sync.RWMutex
	trustedNets       []*net.IPNet

	// Cleanup ticker
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	cleanupDone   chan struct{}
	stopOnce      sync.Once
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(config SecurityConfig) *SecurityMiddleware {
	// Runtime trust updates must not mutate the caller's configuration slice.
	config.TrustedNetworks = append([]string(nil), config.TrustedNetworks...)
	sm := &SecurityMiddleware{
		config:      config,
		ipStats:     make(map[string]*IPStats),
		stopCleanup: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}

	// Parse trusted networks
	sm.parseTrustedNetworks()

	// Start cleanup goroutine
	sm.cleanupTicker = time.NewTicker(5 * time.Minute)
	go sm.cleanupRoutine()

	return sm
}

// parseTrustedNetworks parses the trusted network CIDR strings
func (sm *SecurityMiddleware) parseTrustedNetworks() {
	sm.trustedNets = make([]*net.IPNet, 0, len(sm.config.TrustedNetworks))

	for _, cidr := range sm.config.TrustedNetworks {
		if strings.TrimSpace(cidr) == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("⚠️ Invalid trusted network CIDR '%s': %v", cidr, err)
			continue
		}
		sm.trustedNets = append(sm.trustedNets, network)
	}

	log.Printf("🔒 Loaded %d trusted networks", len(sm.trustedNets))
}

// isTrustedIP requires sm.mu to be held while checking runtime trust updates.
func (sm *SecurityMiddleware) isTrustedIP(ip net.IP) bool {
	for _, network := range sm.trustedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateConnection checks if a connection should be allowed
func (sm *SecurityMiddleware) ValidateConnection(conn net.Conn) error {
	clientAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	clientIP := clientAddr.IP.String()

	sm.mu.Lock()
	defer sm.mu.Unlock()
	// Trust bypasses per-IP rate limits, never the process capacity limit.
	// Reject before allocating per-IP state when the server is already full.
	if sm.globalConnections >= sm.config.MaxGlobalConnections {
		return fmt.Errorf("server connection limit reached")
	}

	// Initialize IP stats if not exists
	if sm.ipStats[clientIP] == nil {
		sm.ipStats[clientIP] = &IPStats{}
	}

	stats := sm.ipStats[clientIP]
	now := time.Now()
	if sm.isTrustedIP(clientAddr.IP) {
		stats.CurrentConnections++
		stats.LastActivity = now
		// A trusted client needs no rate history. In particular, pooled DB
		// connections must not grow a timestamp slice without a per-IP bound.
		stats.HourlyConnections = nil
		sm.globalConnections++
		return nil
	}

	// Check if IP is blacklisted
	if stats.IsBlacklisted && now.Before(stats.BlacklistUntil) {
		return fmt.Errorf("IP %s is blacklisted until %v", clientIP, stats.BlacklistUntil)
	}

	// Remove blacklist if expired
	if stats.IsBlacklisted && !now.Before(stats.BlacklistUntil) {
		stats.IsBlacklisted = false
		log.Printf("🔓 IP %s removed from blacklist", clientIP)
	}

	// Check per-IP concurrent connection limit
	if stats.CurrentConnections >= sm.config.MaxConnectionsPerIP {
		sm.recordViolation(clientIP, stats, "per-IP concurrent connection limit exceeded")
		return fmt.Errorf("too many concurrent connections from IP %s", clientIP)
	}

	// Clean old hourly connections
	sm.cleanOldConnections(stats, now)

	// Check hourly connection limit
	if len(stats.HourlyConnections) >= sm.config.MaxConnectionsPerHour {
		sm.recordViolation(clientIP, stats, "hourly connection limit exceeded")
		return fmt.Errorf("hourly connection limit exceeded for IP %s", clientIP)
	}

	// Check for burst attacks
	if sm.detectBurst(stats, now) {
		sm.recordViolation(clientIP, stats, "burst attack detected")
		return fmt.Errorf("burst attack detected from IP %s", clientIP)
	}

	// All checks passed - allow connection
	stats.CurrentConnections++
	stats.HourlyConnections = append(stats.HourlyConnections, now)
	stats.LastActivity = now
	sm.globalConnections++

	return nil
}

// RecordConnectionClosed should be called when a connection is closed
func (sm *SecurityMiddleware) RecordConnectionClosed(conn net.Conn) {
	clientAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}

	clientIP := clientAddr.IP.String()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if stats := sm.ipStats[clientIP]; stats != nil {
		if stats.CurrentConnections > 0 {
			stats.CurrentConnections--
			if sm.globalConnections > 0 {
				sm.globalConnections--
			}
		}
		stats.LastActivity = time.Now()
	}
}

// recordViolation records a security violation for an IP
func (sm *SecurityMiddleware) recordViolation(clientIP string, stats *IPStats, reason string) {
	now := time.Now()
	stats.Violations = append(stats.Violations, now)

	// Clean old violations
	sm.cleanOldViolations(stats, now)

	log.Printf("⚠️ Security violation from %s: %s (violations: %d)",
		clientIP, reason, len(stats.Violations))

	// Check if IP should be blacklisted
	if len(stats.Violations) >= sm.config.MaxViolationsPerHour {
		stats.IsBlacklisted = true
		stats.BlacklistUntil = now.Add(sm.config.BlacklistDuration)
		log.Printf("🚫 IP %s blacklisted until %v (violations: %d)",
			clientIP, stats.BlacklistUntil, len(stats.Violations))
	}
}

// detectBurst detects burst attacks based on connection patterns
func (sm *SecurityMiddleware) detectBurst(stats *IPStats, now time.Time) bool {
	burstStart := now.Add(-sm.config.BurstWindow)
	first := sort.Search(len(stats.HourlyConnections), func(i int) bool {
		return stats.HourlyConnections[i].After(burstStart)
	})
	return len(stats.HourlyConnections)-first >= sm.config.BurstThreshold
}

// Timestamp histories are appended in time order under sm.mu. Drop only the
// expired prefix: ordinary admission no longer copies the entire live window.
func pruneHistory(history []time.Time, cutoff time.Time) []time.Time {
	first := sort.Search(len(history), func(i int) bool { return history[i].After(cutoff) })
	if first == 0 {
		return history
	}
	clear(history[:first])
	if first == len(history) {
		return history[:0]
	}
	return history[first:]
}

// cleanOldConnections removes connections older than the window
func (sm *SecurityMiddleware) cleanOldConnections(stats *IPStats, now time.Time) {
	stats.HourlyConnections = pruneHistory(stats.HourlyConnections, now.Add(-sm.config.ConnectionWindow))
}

// cleanOldViolations removes violations older than one hour
func (sm *SecurityMiddleware) cleanOldViolations(stats *IPStats, now time.Time) {
	stats.Violations = pruneHistory(stats.Violations, now.Add(-time.Hour))
}

// cleanupRoutine periodically cleans up old data
func (sm *SecurityMiddleware) cleanupRoutine() {
	defer close(sm.cleanupDone)
	for {
		select {
		case <-sm.cleanupTicker.C:
			sm.cleanup()
		case <-sm.stopCleanup:
			return
		}
	}
}

// cleanup removes old and inactive IP statistics
func (sm *SecurityMiddleware) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-24 * time.Hour) // Keep data for 24 hours

	for ip, stats := range sm.ipStats {
		// Remove IPs with no recent activity and no current connections
		if stats.LastActivity.Before(cutoff) && stats.CurrentConnections == 0 && !stats.IsBlacklisted {
			delete(sm.ipStats, ip)
			continue
		}

		// Clean old data for remaining IPs
		sm.cleanOldConnections(stats, now)
		sm.cleanOldViolations(stats, now)
	}

	log.Printf("🧹 Security middleware cleanup completed (tracking %d IPs)", len(sm.ipStats))
}

// GetStats returns current security statistics
func (sm *SecurityMiddleware) GetStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	totalIPs := len(sm.ipStats)
	blacklistedIPs := 0
	totalViolations := 0
	trustedIPs := 0

	for ip, stats := range sm.ipStats {
		if stats.IsBlacklisted {
			blacklistedIPs++
		}
		totalViolations += len(stats.Violations)

		// Check if this IP is trusted
		if ipAddr := net.ParseIP(ip); ipAddr != nil && sm.isTrustedIP(ipAddr) {
			trustedIPs++
		}
	}

	return map[string]interface{}{
		"global_connections": sm.globalConnections,
		"tracked_ips":        totalIPs,
		"trusted_ips":        trustedIPs,
		"blacklisted_ips":    blacklistedIPs,
		"total_violations":   totalViolations,
		"max_global_conns":   sm.config.MaxGlobalConnections,
		"max_ip_conns":       sm.config.MaxConnectionsPerIP,
		"trusted_networks":   len(sm.trustedNets),
	}
}

// AddTrustedNetwork adds a new trusted network at runtime
func (sm *SecurityMiddleware) AddTrustedNetwork(cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %v", err)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.trustedNets = append(sm.trustedNets, network)
	sm.config.TrustedNetworks = append(sm.config.TrustedNetworks, cidr)

	log.Printf("🔒 Added trusted network: %s", cidr)
	return nil
}

// RemoveTrustedNetwork removes a trusted network at runtime
func (sm *SecurityMiddleware) RemoveTrustedNetwork(cidr string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Remove from config slice
	for i, network := range sm.config.TrustedNetworks {
		if network == cidr {
			sm.config.TrustedNetworks = append(sm.config.TrustedNetworks[:i], sm.config.TrustedNetworks[i+1:]...)
			break
		}
	}

	// Rebuild trusted networks
	sm.trustedNets = sm.trustedNets[:0]
	for _, networkCIDR := range sm.config.TrustedNetworks {
		_, network, err := net.ParseCIDR(networkCIDR)
		if err != nil {
			continue
		}
		sm.trustedNets = append(sm.trustedNets, network)
	}

	log.Printf("🔒 Removed trusted network: %s", cidr)
	return nil
}

// ListTrustedNetworks returns the list of trusted networks
func (sm *SecurityMiddleware) ListTrustedNetworks() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	networks := make([]string, len(sm.config.TrustedNetworks))
	copy(networks, sm.config.TrustedNetworks)
	return networks
}

// Stop shuts down the security middleware
func (sm *SecurityMiddleware) Stop() {
	sm.stopOnce.Do(func() {
		if sm.cleanupTicker != nil {
			sm.cleanupTicker.Stop()
		}
		if sm.stopCleanup != nil {
			close(sm.stopCleanup)
		}
	})
	if sm.cleanupDone != nil {
		<-sm.cleanupDone
	}
}

// WrapConnection wraps a connection with security checks and timeouts
func (sm *SecurityMiddleware) WrapConnection(conn net.Conn) net.Conn {
	return &secureConnection{
		Conn: conn,
		sm:   sm,
	}
}

type connectionDeadline struct {
	explicit time.Time
	applied  time.Time
}

// secureConnection wraps a net.Conn with security features
type secureConnection struct {
	net.Conn
	sm                          *SecurityMiddleware
	deadlineMu                  sync.Mutex
	readDeadline, writeDeadline connectionDeadline
	closeOnce                   sync.Once
	closeErr                    error
}

// Coalescing reduces runtime poller updates during continuous transfers. Every
// operation still checks its deadline. An idle deadline is never earlier than
// IdleTimeout from that check, and never more than min(IdleTimeout/16, 1s) later.
// Explicit deadlines are exact upper bounds, including already-expired ones.
// Never retry an I/O timeout: in particular, a TLS write timeout is fatal.
func (sc *secureConnection) deadlineTarget(state connectionDeadline, now time.Time, force bool) (time.Time, bool) {
	idleTimeout := sc.sm.config.IdleTimeout
	slack := idleTimeout / 16
	if slack < 0 {
		slack = 0
	} else if slack > time.Second {
		slack = time.Second
	}
	earliest := now.Add(idleTimeout)
	latest := earliest.Add(slack)
	if !state.explicit.IsZero() {
		if state.explicit.Before(earliest) {
			earliest = state.explicit
		}
		if state.explicit.Before(latest) {
			latest = state.explicit
		}
	}
	if !force && !state.applied.IsZero() && !state.applied.Before(earliest) && !state.applied.After(latest) {
		return state.applied, false
	}
	return latest, true
}

func (sc *secureConnection) applyReadDeadline(now time.Time, force bool) error {
	target, update := sc.deadlineTarget(sc.readDeadline, now, force)
	if !update {
		return nil
	}
	if err := sc.Conn.SetReadDeadline(target); err != nil {
		sc.readDeadline.applied = time.Time{}
		return err
	}
	sc.readDeadline.applied = target
	return nil
}

func (sc *secureConnection) applyWriteDeadline(now time.Time, force bool) error {
	target, update := sc.deadlineTarget(sc.writeDeadline, now, force)
	if !update {
		return nil
	}
	if err := sc.Conn.SetWriteDeadline(target); err != nil {
		sc.writeDeadline.applied = time.Time{}
		return err
	}
	sc.writeDeadline.applied = target
	return nil
}

func (sc *secureConnection) SetReadDeadline(t time.Time) error {
	sc.deadlineMu.Lock()
	defer sc.deadlineMu.Unlock()
	sc.readDeadline.explicit = t
	return sc.applyReadDeadline(time.Now(), true)
}

func (sc *secureConnection) SetWriteDeadline(t time.Time) error {
	sc.deadlineMu.Lock()
	defer sc.deadlineMu.Unlock()
	sc.writeDeadline.explicit = t
	return sc.applyWriteDeadline(time.Now(), true)
}

func (sc *secureConnection) SetDeadline(t time.Time) error {
	sc.deadlineMu.Lock()
	defer sc.deadlineMu.Unlock()
	sc.readDeadline.explicit, sc.writeDeadline.explicit = t, t
	target, _ := sc.deadlineTarget(sc.readDeadline, time.Now(), true)
	if err := sc.Conn.SetDeadline(target); err != nil {
		sc.readDeadline.applied, sc.writeDeadline.applied = time.Time{}, time.Time{}
		return err
	}
	sc.readDeadline.applied, sc.writeDeadline.applied = target, target
	return nil
}

func (sc *secureConnection) Read(b []byte) (int, error) {
	sc.deadlineMu.Lock()
	err := sc.applyReadDeadline(time.Now(), false)
	sc.deadlineMu.Unlock()
	if err != nil {
		return 0, err
	}
	return sc.Conn.Read(b)
}

func (sc *secureConnection) Write(b []byte) (int, error) {
	sc.deadlineMu.Lock()
	err := sc.applyWriteDeadline(time.Now(), false)
	sc.deadlineMu.Unlock()
	if err != nil {
		return 0, err
	}
	return sc.Conn.Write(b)
}

func (sc *secureConnection) CloseWrite() error {
	if conn, ok := sc.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return fmt.Errorf("connection does not support half-close")
}

func (sc *secureConnection) Close() error {
	sc.closeOnce.Do(func() {
		sc.sm.RecordConnectionClosed(sc.Conn)
		sc.closeErr = sc.Conn.Close()
	})
	return sc.closeErr
}
