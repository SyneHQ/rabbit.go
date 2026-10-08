package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"

	"rabbit.go/transport"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Server.mu protects both generation fields and the current control owner.
func (t *Tunnel) privateRouteLocked() transport.RouteInfo {
	owner := ""
	if t.tokenEpoch != "" && t.controlEpoch != 0 && t.Client != nil {
		digest := sha256.Sum256([]byte(t.tokenEpoch + "/" + strconv.FormatUint(t.controlEpoch, 10)))
		owner = hex.EncodeToString(digest[:])
	}
	return transport.RouteInfo{Tenant: t.TeamID, TokenID: t.TokenID, TokenGeneration: t.tokenEpoch, TunnelID: t.ID, ControlOwner: owner}
}

func (s *Server) privateRouteInfo(tenant, tokenID string) (transport.RouteInfo, bool) {
	if s.private == nil {
		return transport.RouteInfo{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, tunnel := range s.tunnels {
		if tunnel.TeamID == tenant && tunnel.TokenID == tokenID && s.controlOwnerActiveLocked(tunnel, tunnel.Client) {
			route := tunnel.privateRouteLocked()
			return route, route.Validate() == nil
		}
	}
	return transport.RouteInfo{}, false
}

// Discovery uses the existing management service and team-membership checks.
// Knowing this snapshot grants no source access and cannot open a data stream.
func (api *APIServer) getPrivateRoute(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if _, err := uuid.Parse(vars["tokenId"]); err != nil {
		http.Error(w, "invalid token ID", http.StatusBadRequest)
		return
	}
	if api.privateRoute == nil {
		http.Error(w, "private route unavailable", http.StatusNotFound)
		return
	}
	route, ok := api.privateRoute(vars["teamId"], vars["tokenId"])
	if !ok {
		http.Error(w, "private route unavailable", http.StatusNotFound)
		return
	}
	respondWithJSON(w, http.StatusOK, route)
}

func (s *Server) privateOwnerLocked(claims transport.OpenClaims) (*Tunnel, net.Conn, bool) {
	t := s.tunnels[claims.TunnelID]
	if t == nil || !s.controlOwnerActiveLocked(t, t.Client) {
		return nil, nil, false
	}
	route := t.privateRouteLocked()
	if route.Validate() != nil || route.Tenant != claims.Tenant || route.TokenID != claims.TokenID ||
		route.TokenGeneration != claims.TokenGeneration || route.ControlOwner != claims.ControlOwner {
		return nil, nil, false
	}
	return t, t.Client, true
}
