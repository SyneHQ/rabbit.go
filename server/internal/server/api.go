package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"rabbit.go/internal/database"

	"github.com/gorilla/mux"
)

// APIServer represents the HTTP API server
type APIServer struct {
	server    *http.Server
	dbService *database.Service
}

// TokenGenerationRequest represents the request body for token generation
type TokenGenerationRequest struct {
	TeamID        string `json:"team_id"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	ExpiresInDays int    `json:"expires_in_days,omitempty"`
}

// TokenGenerationResponse represents the response for token generation
type TokenGenerationResponse struct {
	Success bool       `json:"success"`
	Message string     `json:"message,omitempty"`
	Error   string     `json:"error,omitempty"`
	Data    *TokenData `json:"data,omitempty"`
}

// TokenData represents the token information
type TokenData struct {
	TokenID      string     `json:"token_id"`
	TeamID       string     `json:"team_id"`
	TeamName     string     `json:"team_name"`
	TokenName    string     `json:"token_name"`
	Token        string     `json:"token"`
	Description  string     `json:"description"`
	AssignedPort int        `json:"assigned_port"`
	Protocol     string     `json:"protocol"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// TeamListResponse represents the response for listing teams
type TeamListResponse struct {
	Success bool       `json:"success"`
	Message string     `json:"message,omitempty"`
	Error   string     `json:"error,omitempty"`
	Data    []TeamInfo `json:"data,omitempty"`
}

// TeamTokenResponse represents the response for a team's token
type TeamTokenResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Error   string      `json:"error,omitempty"`
	Data    []TokenInfo `json:"data,omitempty"`
}

// TeamInfo represents team information with tokens and ports
type TeamInfo struct {
	TeamID      string      `json:"team_id"`
	TeamName    string      `json:"team_name"`
	Description string      `json:"description"`
	CreatedAt   time.Time   `json:"created_at"`
	Tokens      []TokenInfo `json:"tokens"`
}

// TokenInfo represents token information
type TokenInfo struct {
	TokenID     string     `json:"token_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Port        int        `json:"port"`
	Protocol    string     `json:"protocol"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// StatsResponse represents database statistics
type StatsResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// NewAPIServer creates a new API server instance
func NewAPIServer(dbService *database.Service, bindAddress string, apiPort string) *APIServer {
	router := mux.NewRouter()

	apiServer := &APIServer{
		dbService: dbService,
	}

	// Setup routes
	apiServer.setupRoutes(router)

	// Create HTTP server
	apiServer.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%s", bindAddress, apiPort),
		Handler:      router,
		WriteTimeout: 30 * time.Second,
		ReadTimeout:  30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return apiServer
}

// setupRoutes configures all HTTP API routes
func (api *APIServer) setupRoutes(router *mux.Router) {
	// Add CORS middleware
	router.Use(corsMiddleware)
	router.Use(loggingMiddleware)

	// API routes
	v1 := router.PathPrefix("/api/v1").Subrouter()

	// Token management
	v1.HandleFunc("/tokens/generate", api.generateToken).Methods("POST")
	v1.HandleFunc("/teams", api.listTeams).Methods("GET")
	v1.HandleFunc("/teams/{teamId}/tokens", api.getTeamTokens).Methods("GET")
	v1.HandleFunc("/stats", api.getStats).Methods("GET")
	v1.HandleFunc("/health", api.healthCheck).Methods("GET")

	// Root endpoint
	router.HandleFunc("/", api.homeEndpoint).Methods("GET")
}

// Start starts the API server
func (api *APIServer) Start() error {
	log.Printf("🌐 API server starting on %s", api.server.Addr)
	log.Printf("📋 Available endpoints:")
	log.Printf("   GET  / - API information")
	log.Printf("   GET  /api/v1/health - Health check")
	log.Printf("   GET  /api/v1/teams - List teams with tokens")
	log.Printf("   GET  /api/v1/stats - Database statistics")
	log.Printf("   POST /api/v1/tokens/generate - Generate new token")
	log.Printf("   GET  /api/v1/teams/:teamId/tokens - Get team's tokens")

	return api.server.ListenAndServe()
}

// Stop stops the API server
func (api *APIServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return api.server.Shutdown(ctx)
}

// generateToken handles POST /api/v1/tokens/generate
func (api *APIServer) generateToken(w http.ResponseWriter, r *http.Request) {
	var req TokenGenerationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithJSON(w, http.StatusBadRequest, TokenGenerationResponse{
			Success: false,
			Error:   "Invalid JSON request body",
		})
		return
	}

	// Validate required fields
	if req.TeamID == "" {
		respondWithJSON(w, http.StatusBadRequest, TokenGenerationResponse{
			Success: false,
			Error:   "team_id is required",
		})
		return
	}

	if req.Name == "" {
		respondWithJSON(w, http.StatusBadRequest, TokenGenerationResponse{
			Success: false,
			Error:   "name is required",
		})
		return
	}

	ctx := context.Background()

	// Verify team exists
	team, err := api.dbService.GetTeamByID(ctx, req.TeamID)
	if err != nil {
		respondWithJSON(w, http.StatusNotFound, TokenGenerationResponse{
			Success: false,
			Error:   "team not found",
		})
		return
	}

	// Calculate expiration
	var expiresAt *time.Time
	if req.ExpiresInDays > 0 {
		expires := time.Now().AddDate(0, 0, req.ExpiresInDays)
		expiresAt = &expires
	}

	// Generate token
	token, assignment, err := api.dbService.GenerateTokenForTeam(ctx, req.TeamID, req.Name, req.Description, expiresAt)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, TokenGenerationResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to generate token: %v", err),
		})
		return
	}

	// Prepare response
	response := TokenGenerationResponse{
		Success: true,
		Message: "Token generated successfully",
		Data: &TokenData{
			TokenID:      token.ID.String(),
			TeamID:       team.ID,
			TeamName:     team.Name,
			TokenName:    token.Name,
			Token:        token.Token,
			Description:  token.Description,
			AssignedPort: assignment.Port,
			Protocol:     assignment.Protocol,
			CreatedAt:    token.CreatedAt,
			ExpiresAt:    token.ExpiresAt,
		},
	}

	log.Printf("✅ Token generated via API for team %s: %s (port: %d)", team.Name, token.Name, assignment.Port)

	respondWithJSON(w, http.StatusCreated, response)
}

// getTeamTokens handles GET /api/v1/teams/:teamId/tokens
func (api *APIServer) getTeamTokens(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	teamId := vars["teamId"]

	ctx := context.Background()
	_, err := api.dbService.GetTeamByID(ctx, teamId)
	if err != nil {
		respondWithJSON(w, http.StatusNotFound, TeamTokenResponse{
			Success: false,
			Error:   "team not found",
		})
		return
	}

	teamTokens, err := api.dbService.ListTokensByTeamID(ctx, teamId)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, TeamTokenResponse{
			Success: false,
			Error:   "failed to get team tokens",
		})
		return
	}

	portAssignments, err := api.dbService.ListPortAssignmentsByTeamID(ctx, teamId)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, TeamTokenResponse{
			Success: false,
			Error:   "failed to get team port assignments",
		})
		return
	}

	portAssignmentsMap := make(map[string]database.PortAssignment)
	for _, assignment := range portAssignments {
		portAssignmentsMap[assignment.ID.String()] = assignment
	}

	var tokenInfos []TokenInfo
	for _, token := range teamTokens {
		portAssignment, ok := portAssignmentsMap[token.ID.String()]
		if !ok {
			portAssignment = database.PortAssignment{}
		}
		tokenInfos = append(tokenInfos, TokenInfo{
			TokenID:     token.ID.String(),
			Name:        token.Name,
			Description: token.Description,
			Port:        portAssignment.Port,
			Protocol:    portAssignment.Protocol,
			CreatedAt:   token.CreatedAt,
			LastUsedAt:  token.LastUsedAt,
			ExpiresAt:   token.ExpiresAt,
		})
	}

	response := TeamTokenResponse{
		Success: true,
		Message: "Team tokens retrieved successfully",
		Data:    tokenInfos,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// listTeams handles GET /api/v1/teams
func (api *APIServer) listTeams(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	teamInfo, err := api.dbService.ListTeamsWithTokens(ctx)
	if err != nil {
		log.Printf("❌ Failed to list teams: %v", err)
		respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to retrieve teams",
		})
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Teams retrieved successfully",
		"data":    teamInfo,
	})
}

// getStats handles GET /api/v1/stats
func (api *APIServer) getStats(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	stats, err := api.dbService.GetDatabaseStats(ctx)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, StatsResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to get stats: %v", err),
		})
		return
	}

	response := StatsResponse{
		Success: true,
		Message: "Statistics retrieved successfully",
		Data:    stats,
	}

	log.Printf("📊 Database stats requested via API")

	respondWithJSON(w, http.StatusOK, response)
}

// healthCheck handles GET /api/v1/health
func (api *APIServer) healthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	err := api.dbService.HealthCheck(ctx)
	if err != nil {
		respondWithJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"success": false,
			"status":  "unhealthy",
			"error":   err.Error(),
		})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"status":    "healthy",
		"message":   "All systems operational",
		"timestamp": time.Now().UTC(),
	})
}

// homeEndpoint handles GET /
func (api *APIServer) homeEndpoint(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"service":     "rabbit.go-api",
		"version":     "1.0.0",
		"description": "Database-backed token management API for Syne Tunneler",
		"endpoints": map[string]string{
			"health":         "GET /api/v1/health",
			"teams":          "GET /api/v1/teams",
			"stats":          "GET /api/v1/stats",
			"generate_token": "POST /api/v1/tokens/generate",
		},
		"timestamp": time.Now().UTC(),
	}

	respondWithJSON(w, http.StatusOK, info)
}

// Utility functions

// respondWithJSON writes a JSON response
func respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// corsMiddleware adds CORS headers
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		log.Printf("🌐 %s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}
