package middleware

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ApplySecurityEnv applies explicit environment settings after file settings.
func ApplySecurityEnv(config SecurityConfig) (SecurityConfig, error) {
	for _, setting := range []struct {
		name   string
		target *int
	}{
		{"RABBIT_MAX_CONNECTIONS", &config.MaxGlobalConnections},
		{"RABBIT_MAX_CONNECTIONS_PER_IP", &config.MaxConnectionsPerIP},
		{"RABBIT_MAX_CONNECTIONS_PER_HOUR", &config.MaxConnectionsPerHour},
		{"RABBIT_BURST_THRESHOLD", &config.BurstThreshold},
		{"RABBIT_MAX_VIOLATIONS_PER_HOUR", &config.MaxViolationsPerHour},
	} {
		value, exists := os.LookupEnv(setting.name)
		if !exists {
			continue
		}
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000000 || strconv.Itoa(parsed) != value {
			return SecurityConfig{}, fmt.Errorf("%s must be an integer between 1 and 1000000", setting.name)
		}
		*setting.target = parsed
	}
	for _, setting := range []struct {
		name   string
		target *time.Duration
	}{
		{"RABBIT_CONNECTION_WINDOW", &config.ConnectionWindow}, {"RABBIT_BURST_WINDOW", &config.BurstWindow},
		{"RABBIT_HANDSHAKE_TIMEOUT", &config.HandshakeTimeout}, {"RABBIT_IDLE_TIMEOUT", &config.IdleTimeout},
		{"RABBIT_BLACKLIST_DURATION", &config.BlacklistDuration},
	} {
		value, exists := os.LookupEnv(setting.name)
		if !exists {
			continue
		}
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return SecurityConfig{}, fmt.Errorf("%s must be a duration such as 30s", setting.name)
		}
		*setting.target = parsed
	}
	if value, exists := os.LookupEnv("TRUSTED_NETWORKS"); exists {
		config.TrustedNetworks = strings.Split(value, ",")
	}
	return config, ValidateSecurityConfig(config)
}

func ValidateSecurityConfig(config SecurityConfig) error {
	for name, value := range map[string]int{"max_connections": config.MaxGlobalConnections, "max_connections_per_ip": config.MaxConnectionsPerIP, "max_connections_per_hour": config.MaxConnectionsPerHour, "burst_threshold": config.BurstThreshold, "max_violations_per_hour": config.MaxViolationsPerHour} {
		if value < 1 || value > 1000000 {
			return fmt.Errorf("%s must be between 1 and 1000000", name)
		}
	}
	for name, value := range map[string]time.Duration{"connection_window": config.ConnectionWindow, "burst_window": config.BurstWindow, "handshake_timeout": config.HandshakeTimeout, "idle_timeout": config.IdleTimeout, "blacklist_duration": config.BlacklistDuration} {
		if value < time.Millisecond || value > 24*time.Hour {
			return fmt.Errorf("%s must be between 1ms and 24h", name)
		}
	}
	for _, network := range config.TrustedNetworks {
		if strings.TrimSpace(network) == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(network); err != nil {
			return fmt.Errorf("trusted_networks must contain CIDR networks")
		}
	}
	return nil
}
