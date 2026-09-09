package server

import (
	"context"
	"crypto/subtle"
	"github.com/gorilla/mux"
	"net/http"
	"os"
)

type membershipChecker interface {
	AuthorizeTeam(context.Context, string, string, bool) (bool, error)
}

func managementAuth(token string, checker membershipChecker) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/health" && r.Method == http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			if len(token) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Service-Token")), []byte(token)) != 1 {
				http.Error(w, "unauthorized", 401)
				return
			}
			team, user := r.Header.Get("X-Team-ID"), r.Header.Get("X-User-ID")
			if team == "" || user == "" {
				http.Error(w, "unauthorized", 401)
				return
			}
			if target := mux.Vars(r)["teamId"]; target != "" && target != team {
				http.Error(w, "access denied", 403)
				return
			}
			// Cross-tenant enumeration and server statistics are operator-only, outside the app API.
			if r.URL.Path == "/api/v1/teams" || r.URL.Path == "/api/v1/stats" {
				http.Error(w, "access denied", 403)
				return
			}
			ok, err := checker.AuthorizeTeam(r.Context(), user, team, r.Method != http.MethodGet)
			if err != nil {
				http.Error(w, "authorization unavailable", 503)
				return
			}
			if !ok {
				http.Error(w, "access denied", 403)
				return
			}
			w.Header().Set("Cache-Control", "private, no-store")
			next.ServeHTTP(w, r)
		})
	}
}
func (api *APIServer) authorize(next http.Handler) http.Handler {
	return managementAuth(os.Getenv("RABBIT_SERVICE_TOKEN"), api.dbService)(next)
}
