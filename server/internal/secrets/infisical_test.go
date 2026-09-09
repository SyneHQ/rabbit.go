package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHydrationBeforeStartupWithoutNetwork(t *testing.T) {
	cfg := map[string]string{}
	get := func(key string) string { return cfg[key] }
	called := false
	fetch := func(context.Context, Config) error { called = true; return nil }
	if err := Hydrate(get, fetch); err != nil || called {
		t.Fatal("disabled hydration contacted provider")
	}
	cfg["INFISICAL_CLIENT_ID"] = "id"
	if Hydrate(get, fetch) == nil || called {
		t.Fatal("partial config did not fail closed")
	}
	cfg["INFISICAL_CLIENT_SECRET"] = "secret-canary"
	cfg["INFISICAL_PROJECT_ID"] = "project"
	cfg["INFISICAL_ENV"] = "production"
	if err := Hydrate(get, fetch); err != nil || !called {
		t.Fatal("valid configuration not loaded")
	}
	err := Hydrate(get, func(context.Context, Config) error { return errors.New("secret-canary") })
	if err == nil || strings.Contains(err.Error(), "secret-canary") {
		t.Fatal("provider errors must fail closed without secret disclosure")
	}
}
