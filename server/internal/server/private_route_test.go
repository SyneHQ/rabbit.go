package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rabbit.go/transport"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func TestPrivateRouteDiscoveryUsesExistingTeamAuthorization(t *testing.T) {
	serviceToken := strings.Repeat("x", 32)
	tokenID := uuid.NewString()
	wanted := transport.RouteInfo{Tenant: "team-a", TokenID: tokenID, TokenGeneration: strings.Repeat("1", 64), TunnelID: strings.Repeat("2", 64), ControlOwner: strings.Repeat("3", 64)}
	for _, test := range []struct {
		name, team, token string
		member            bool
		status            int
	}{
		{"authorized", "team-a", serviceToken, true, 200},
		{"wrong team", "other", serviceToken, true, 403},
		{"revoked membership", "team-a", serviceToken, false, 403},
		{"missing service", "team-a", "", true, 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			api := &APIServer{privateRoute: func(team, token string) (transport.RouteInfo, bool) {
				calls++
				return wanted, team == wanted.Tenant && token == wanted.TokenID
			}}
			router := mux.NewRouter()
			router.Use(managementAuth(serviceToken, &fakeMembership{allow: test.member}))
			router.HandleFunc("/api/v1/teams/{teamId}/tokens/{tokenId}/route", api.getPrivateRoute).Methods(http.MethodGet)
			request := httptest.NewRequest(http.MethodGet, "/api/v1/teams/team-a/tokens/"+tokenID+"/route", nil)
			request.Header.Set("X-Service-Token", test.token)
			request.Header.Set("X-User-ID", "user-a")
			request.Header.Set("X-Team-ID", test.team)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatal("unexpected route discovery outcome", response.Code)
			}
			if test.status != 200 {
				if calls != 0 {
					t.Fatal("unauthorized discovery touched route state")
				}
				return
			}
			var actual transport.RouteInfo
			if json.Unmarshal(response.Body.Bytes(), &actual) != nil || actual != wanted || response.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatal("route discovery changed scope or caching")
			}
		})
	}
}
