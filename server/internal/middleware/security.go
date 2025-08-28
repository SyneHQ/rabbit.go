package middleware

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// SecurityConfig holds configuration for security middleware
type SecurityConfig struct {
	// Rate limiting
	MaxConnectionsPerIP   int           // Maximum concurrent connections per IP
	MaxConnectionsPerHour int           // Maximum new connections per IP per hour
	ConnectionWindow      time.Duration // Time window for rate limiting

	// DDoS protection
	MaxGlobalConnections int           // Maximum global concurrent connections
	BurstThreshold       int           // Threshold for burst detection
	BurstWindow          time.Duration // Window for burst detection

	// Timeouts
	HandshakeTimeout time.Duration // Timeout for initial handshake
	IdleTimeout      time.Duration // Timeout for idle connections

	// Blacklist
	BlacklistDuration    time.Duration // How long to blacklist IPs
	MaxViolationsPerHour int           // Max violations before blacklisting

	// Whitelist
	TrustedNetworks []string // List of trusted IP networks/ranges (CIDR notation)
}

// DefaultSecurityConfig returns a default security configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		MaxConnectionsPerIP:   10,
		MaxConnectionsPerHour: 100,
		ConnectionWindow:      time.Hour,
		MaxGlobalConnections:  1000,
		BurstThreshold:        20,
		BurstWindow:           time.Minute,
		HandshakeTimeout:      30 * time.Second,
		IdleTimeout:           5 * time.Minute,
		BlacklistDuration:     time.Hour,
		MaxViolationsPerHour:  5,
		TrustedNetworks:       []string{"172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"},
	}
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
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(config SecurityConfig) *SecurityMiddleware {
	sm := &SecurityMiddleware{
		config:      config,
		ipStats:     make(map[string]*IPStats),
		stopCleanup: make(chan struct{}),
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
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("⚠️ Invalid trusted network CIDR '%s': %v", cidr, err)
			continue
		}
		sm.trustedNets = append(sm.trustedNets, network)
	}

	log.Printf("🔒 Loaded %d trusted networks", len(sm.trustedNets))
}

// isTrustedIP checks if an IP is in the trusted networks
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

	// Check if IP is trusted - if so, allow with minimal logging
	if sm.isTrustedIP(clientAddr.IP) {
		sm.mu.Lock()
		sm.globalConnections++
		sm.mu.Unlock()

		// Still track basic stats for trusted IPs but don't apply restrictions
		sm.updateTrustedIPStats(clientIP)

		log.Printf("🔐 Trusted connection allowed from %s (global: %d)", clientIP, sm.globalConnections)
		return nil
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Initialize IP stats if not exists
	if sm.ipStats[clientIP] == nil {
		sm.ipStats[clientIP] = &IPStats{
			HourlyConnections: make([]time.Time, 0),
			Violations:        make([]time.Time, 0),
		}
	}

	stats := sm.ipStats[clientIP]
	now := time.Now()

	// Check if IP is blacklisted
	if stats.IsBlacklisted && now.Before(stats.BlacklistUntil) {
		return fmt.Errorf("IP %s is blacklisted until %v", clientIP, stats.BlacklistUntil)
	}

	// Remove blacklist if expired
	if stats.IsBlacklisted && now.After(stats.BlacklistUntil) {
		stats.IsBlacklisted = false
		log.Printf("🔓 IP %s removed from blacklist", clientIP)
	}

	// Check global connection limit
	if sm.globalConnections >= sm.config.MaxGlobalConnections {
		sm.recordViolation(clientIP, stats, "global connection limit exceeded")
		return fmt.Errorf("server connection limit reached")
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

	log.Printf("🔐 Connection allowed from %s (concurrent: %d, hourly: %d, global: %d)",
		clientIP, stats.CurrentConnections, len(stats.HourlyConnections), sm.globalConnections)

	return nil
}

// updateTrustedIPStats updates basic stats for trusted IPs without restrictions
func (sm *SecurityMiddleware) updateTrustedIPStats(clientIP string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Initialize IP stats if not exists
	if sm.ipStats[clientIP] == nil {
		sm.ipStats[clientIP] = &IPStats{
			HourlyConnections: make([]time.Time, 0),
			Violations:        make([]time.Time, 0),
		}
	}

	stats := sm.ipStats[clientIP]
	now := time.Now()

	stats.CurrentConnections++
	stats.HourlyConnections = append(stats.HourlyConnections, now)
	stats.LastActivity = now

	// Clean old data periodically
	sm.cleanOldConnections(stats, now)
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
		}
		stats.LastActivity = time.Now()
	}

	if sm.globalConnections > 0 {
		sm.globalConnections--
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
	burstConnections := 0

	for _, connTime := range stats.HourlyConnections {
		if connTime.After(burstStart) {
			burstConnections++
		}
	}

	return burstConnections >= sm.config.BurstThreshold
}

// cleanOldConnections removes connections older than the window
func (sm *SecurityMiddleware) cleanOldConnections(stats *IPStats, now time.Time) {
	cutoff := now.Add(-sm.config.ConnectionWindow)
	validConnections := make([]time.Time, 0)

	for _, connTime := range stats.HourlyConnections {
		if connTime.After(cutoff) {
			validConnections = append(validConnections, connTime)
		}
	}

	stats.HourlyConnections = validConnections
}

// cleanOldViolations removes violations older than one hour
func (sm *SecurityMiddleware) cleanOldViolations(stats *IPStats, now time.Time) {
	cutoff := now.Add(-time.Hour)
	validViolations := make([]time.Time, 0)

	for _, violationTime := range stats.Violations {
		if violationTime.After(cutoff) {
			validViolations = append(validViolations, violationTime)
		}
	}

	stats.Violations = validViolations
}

// cleanupRoutine periodically cleans up old data
func (sm *SecurityMiddleware) cleanupRoutine() {
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
	if sm.cleanupTicker != nil {
		sm.cleanupTicker.Stop()
	}
	close(sm.stopCleanup)
}

// WrapConnection wraps a connection with security checks and timeouts
func (sm *SecurityMiddleware) WrapConnection(conn net.Conn) net.Conn {
	return &secureConnection{
		Conn:    conn,
		sm:      sm,
		created: time.Now(),
	}
}

// secureConnection wraps a net.Conn with security features
type secureConnection struct {
	net.Conn
	sm      *SecurityMiddleware
	created time.Time
}

// Read implements net.Conn with idle timeout
func (sc *secureConnection) Read(b []byte) (n int, err error) {
	// Set read deadline for idle timeout
	sc.SetReadDeadline(time.Now().Add(sc.sm.config.IdleTimeout))
	return sc.Conn.Read(b)
}

// Write implements net.Conn with idle timeout
func (sc *secureConnection) Write(b []byte) (n int, err error) {
	// Set write deadline for idle timeout
	sc.SetWriteDeadline(time.Now().Add(sc.sm.config.IdleTimeout))
	return sc.Conn.Write(b)
}

// Close implements net.Conn and records the connection closure
func (sc *secureConnection) Close() error {
	sc.sm.RecordConnectionClosed(sc.Conn)
	return sc.Conn.Close()
}
