package server

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/gorilla/mux"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeMembership struct {
	allow bool
	admin bool
}

func (f *fakeMembership) AuthorizeTeam(_ context.Context, user, team string, admin bool) (bool, error) {
	f.admin = admin
	return f.allow && user == "user-a" && team == "team-a", nil
}
func TestManagementAuthorization(t *testing.T) {
	token := strings.Repeat("a", 32)
	for _, test := range []struct {
		name, token, user, team, path, method string
		allowed                               bool
		want                                  int
	}{
		{"missing", "", "user-a", "team-a", "/api/v1/teams/team-a/tokens", "GET", true, 401},
		{"forged", "bad", "user-a", "team-a", "/api/v1/teams/team-a/tokens", "GET", true, 401},
		{"foreign", token, "user-a", "team-a", "/api/v1/teams/team-b/tokens", "GET", true, 403},
		{"revoked", token, "user-a", "team-a", "/api/v1/teams/team-a/tokens", "GET", false, 403},
		{"legitimate", token, "user-a", "team-a", "/api/v1/teams/team-a/tokens", "GET", true, 204},
		{"enumeration", token, "user-a", "team-a", "/api/v1/teams", "GET", true, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := mux.NewRouter()
			r.Use(managementAuth(token, &fakeMembership{allow: test.allowed}))
			r.HandleFunc("/api/v1/teams/{teamId}/tokens", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
			r.HandleFunc("/api/v1/teams", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
			req := httptest.NewRequest(test.method, test.path, nil)
			req.Header.Set("X-Service-Token", test.token)
			req.Header.Set("X-User-ID", test.user)
			req.Header.Set("X-Team-ID", test.team)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != test.want {
				t.Fatalf("got %d want %d", w.Code, test.want)
			}
		})
	}
}
func TestListTokenNeverSerializesSecret(t *testing.T) {
	raw, _ := json.Marshal(TokenInfo{Token: "secret-canary", TokenID: "visible"})
	if strings.Contains(string(raw), "secret-canary") || strings.Contains(string(raw), `"token"`) {
		t.Fatal("list exposes token")
	}
	created, _ := json.Marshal(TokenData{Token: "one-time"})
	if !strings.Contains(string(created), "one-time") {
		t.Fatal("creation must reveal token once")
	}
}

func TestDataPairingCapabilityIsConsumedOnce(t *testing.T) {
	s := &Server{pendingConns: map[string]chan net.Conn{"capability": make(chan net.Conn, 1)}}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s.handleDataConnection(a, "DATA:capability")
	if _, exists := s.pendingConns["capability"]; exists {
		t.Fatal("capability still reusable")
	}
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	s.handleDataConnection(c, "DATA:capability")
	if _, err := d.Write([]byte("x")); err == nil {
		t.Fatal("replayed capability accepted")
	}
}
func TestControlFramesAreBoundedAndPairIDsRandom(t *testing.T) {
	if _, err := readControlLine(bufio.NewReader(strings.NewReader(strings.Repeat("x", 100000) + "\n"))); err == nil {
		t.Fatal("oversized handshake accepted")
	}
	a, err := generateTunnelID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := generateTunnelID()
	if len(a) != 64 || a == b {
		t.Fatal("pairing IDs lack fresh 256-bit randomness")
	}
}
