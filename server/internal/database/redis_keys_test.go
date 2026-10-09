package database

import (
	"strings"
	"testing"
)

func TestRedisKeyPrefixValidation(t *testing.T) {
	for _, prefix := range []string{"", "a:", "rabbit:production:", "RABBIT_1:eu-west:", strings.Repeat("a", 127) + ":"} {
		if err := validateRedisKeyPrefix(prefix); err != nil {
			t.Fatalf("valid Redis key prefix rejected: %v", err)
		}
	}
	for _, prefix := range []string{":", "rabbit", ":rabbit:", "_rabbit:", strings.Repeat("a", 128) + ":", "rabbit:*:", "rabbit:?:", "rabbit:[a]:", "rabbit:]a:", "rabbit:\\:", "rabbit:\x00:", "rabbit:\n:", "rabbit: :", "rédis:"} {
		if err := validateRedisKeyPrefix(prefix); err == nil {
			t.Fatal("invalid Redis key prefix accepted")
		}
		// Configuration must fail before attempting either database connection.
		if _, err := NewDatabase(Config{RedisKeyPrefix: prefix}); err == nil || !strings.Contains(err.Error(), "RABBIT_REDIS_KEY_PREFIX") {
			t.Fatal("invalid prefix reached database initialization")
		}
	}
}

func TestRedisKeyPrefixEnvironment(t *testing.T) {
	t.Setenv("RABBIT_REDIS_KEY_PREFIX", "rabbit:production:")
	if got := GetConfigFromEnv().RedisKeyPrefix; got != "rabbit:production:" {
		t.Fatal("Redis key prefix environment value was not loaded")
	}
	t.Setenv("RABBIT_REDIS_KEY_PREFIX", "")
	if got := GetConfigFromEnv().RedisKeyPrefix; got != "" {
		t.Fatal("empty Redis key prefix changed legacy behavior")
	}
}
