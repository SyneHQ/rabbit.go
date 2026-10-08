package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperatorStatsHasSeparateAuthentication(t *testing.T) {
	operator, application := strings.Repeat("o", 32), strings.Repeat("a", 32)
	t.Setenv("RABBIT_SERVICE_TOKEN", application)
	api := NewAPIServer(nil, "127.0.0.1", "0", "0")
	for _, tc := range []struct {
		name, configured, supplied string
		want                       int
	}{{"disabled", "", operator, 404}, {"missing", operator, "", 401}, {"wrong", operator, strings.Repeat("x", 32), 401}, {"application", operator, application, 401}, {"operator", operator, operator, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RABBIT_OPERATOR_TOKEN", tc.configured)
			request := httptest.NewRequest(http.MethodGet, "/operator/transport-stats", nil)
			request.Header.Set("X-Operator-Token", tc.supplied)
			response := httptest.NewRecorder()
			api.server.Handler.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status %d, want %d", response.Code, tc.want)
			}
		})
	}
	for _, token := range []string{"short", strings.Repeat("x", 513), application} {
		t.Setenv("RABBIT_OPERATOR_TOKEN", token)
		if err := validateOperatorToken(); err == nil {
			t.Fatal("invalid operator token accepted")
		}
	}
}

func TestOperatorTokenCannotReuseEnabledNotebookCredentials(t *testing.T) {
	token := strings.Repeat("n", 32)
	t.Setenv("RABBIT_OPERATOR_TOKEN", token)
	t.Setenv("RABBIT_SERVICE_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RABBIT_NOTEBOOK_AUTHORITY_URL", "https://authority.example")
	for _, name := range []string{"RABBIT_NOTEBOOK_BROKER_TOKEN", "NOTEBOOK_RUNTIME_SERVICE_TOKEN"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, token)
			if err := validateOperatorToken(); err == nil {
				t.Fatal("operator token reused notebook credentials")
			}
			api := NewAPIServer(nil, "127.0.0.1", "0", "0")
			request := httptest.NewRequest(http.MethodGet, "/operator/transport-stats", nil)
			request.Header.Set("X-Operator-Token", token)
			response := httptest.NewRecorder()
			api.server.Handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatal("notebook credential accessed operator stats")
			}
		})
	}
}
