package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOperatorConfigDefaultsAndPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rabbit.yml")
	if err := os.WriteFile(path, []byte("security:\n  max_connections: 12\n  max_connections_per_ip: 4\n  idle_timeout: 45s\npairing_timeout: 3s\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RABBIT_MAX_CONNECTIONS", "17")
	t.Setenv("RABBIT_HANDSHAKE_TIMEOUT", "5s")
	config, err := LoadOperatorConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Security.MaxGlobalConnections != 17 || config.Security.MaxConnectionsPerIP != 4 || config.Security.IdleTimeout != 45*time.Second || config.Security.HandshakeTimeout != 5*time.Second || config.PairingTimeout != 3*time.Second {
		t.Fatalf("settings were ignored: %+v", config)
	}
}

func TestOperatorConfigRejectsInvalidSettings(t *testing.T) {
	for _, value := range []string{"security:\n  max_connections: 0\n", "security:\n  idle_timeout: 0s\n", "security:\n  trusted_networks: [not-a-cidr]\n", "security:\n  unknown_limit: 10\n", "pairing_timeout: 2h\n", "security: {}\n---\nsecurity: {}\n", "security:\n  max_connections: 10\n  max_connections: 11\n"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rabbit.yml")
			if err := os.WriteFile(path, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOperatorConfig(path); err == nil {
				t.Fatal("invalid operator configuration accepted")
			}
		})
	}
}

func TestOperatorConfigRejectsInvalidEnvironment(t *testing.T) {
	for _, setting := range []struct{ name, value string }{{"RABBIT_MAX_CONNECTIONS_PER_IP", "0"}, {"RABBIT_IDLE_TIMEOUT", "forever"}, {"RABBIT_CONTROL_WRITE_TIMEOUT", "0s"}, {"TRUSTED_NETWORKS", "invalid"}} {
		t.Run(setting.name, func(t *testing.T) {
			t.Setenv(setting.name, setting.value)
			if _, err := LoadOperatorConfig(""); err == nil {
				t.Fatal("invalid environment accepted")
			}
		})
	}
}
