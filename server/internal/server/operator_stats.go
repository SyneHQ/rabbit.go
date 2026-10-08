package server

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
)

func validateOperatorToken() error {
	token := os.Getenv("RABBIT_OPERATOR_TOKEN")
	if token == "" {
		return nil
	}
	if len(token) < 32 || len(token) > 512 {
		return fmt.Errorf("RABBIT_OPERATOR_TOKEN must contain 32 to 512 bytes")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(os.Getenv("RABBIT_SERVICE_TOKEN"))) == 1 {
		return fmt.Errorf("operator and application service tokens must be different")
	}
	if os.Getenv("RABBIT_NOTEBOOK_AUTHORITY_URL") != "" {
		for _, name := range []string{"RABBIT_NOTEBOOK_BROKER_TOKEN", "NOTEBOOK_RUNTIME_SERVICE_TOKEN"} {
			if subtle.ConstantTimeCompare([]byte(token), []byte(os.Getenv(name))) == 1 {
				return fmt.Errorf("operator and notebook service tokens must be different")
			}
		}
	}
	return nil
}

func (api *APIServer) operatorTransportStats(w http.ResponseWriter, r *http.Request) {
	token := os.Getenv("RABBIT_OPERATOR_TOKEN")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	provided := r.Header.Get("X-Operator-Token")
	if validateOperatorToken() != nil || len(provided) > 512 || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	stats := map[string]interface{}{}
	if api.runtimeStats != nil {
		stats = api.runtimeStats()
	}
	respondWithJSON(w, http.StatusOK, stats)
}
