package database

import (
	"time"

	"github.com/google/uuid"
)

// Team represents a team that can create tunnel connections
type Team struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	IsActive    bool      `json:"is_active" db:"is_active"`
}

// TeamToken represents an authentication token for a team
type TeamToken struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TeamID      string     `json:"team_id" db:"team_id"`
	Token       string     `json:"token" db:"token"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description" db:"description"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at" db:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at" db:"last_used_at"`
	IsActive    bool       `json:"is_active" db:"is_active"`

	// Relations
	Team *Team `json:"team,omitempty"`
}

// PortAssignment represents a port assigned to a team token
type PortAssignment struct {
	ID         uuid.UUID `json:"id" db:"id"`
	TeamID     string    `json:"team_id" db:"team_id"`
	TokenID    uuid.UUID `json:"token_id" db:"token_id"`
	Port       int       `json:"port" db:"port"`
	Protocol   string    `json:"protocol" db:"protocol"` // tcp, udp, http, https
	IsReserved bool      `json:"is_reserved" db:"is_reserved"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`

	// Relations
	Team  *Team      `json:"team,omitempty"`
	Token *TeamToken `json:"token,omitempty"`
}

// ConnectionLog represents a log entry for tunnel connections
type ConnectionLog struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	TeamID         string     `json:"team_id" db:"team_id"`
	TokenID        uuid.UUID  `json:"token_id" db:"token_id"`
	PortAssignID   uuid.UUID  `json:"port_assign_id" db:"port_assign_id"`
	SessionID      uuid.UUID  `json:"session_id" db:"session_id"`
	ClientIP       string     `json:"client_ip" db:"client_ip"`
	ClientPort     int        `json:"client_port" db:"client_port"`
	ServerPort     int        `json:"server_port" db:"server_port"`
	Protocol       string     `json:"protocol" db:"protocol"`
	StartedAt      time.Time  `json:"started_at" db:"started_at"`
	EndedAt        *time.Time `json:"ended_at" db:"ended_at"`
	BytesReceived  int64      `json:"bytes_received" db:"bytes_received"`
	BytesSent      int64      `json:"bytes_sent" db:"bytes_sent"`
	ConnectionTime *int64     `json:"connection_time_ms" db:"connection_time_ms"` // Duration in milliseconds
	Status         string     `json:"status" db:"status"`                         // active, closed, error, timeout
	ErrorMessage   *string    `json:"error_message" db:"error_message"`
	UserAgent      *string    `json:"user_agent" db:"user_agent"`
	RequestPath    *string    `json:"request_path" db:"request_path"` // For HTTP connections

	// Relations
	Team           *Team           `json:"team,omitempty"`
	Token          *TeamToken      `json:"token,omitempty"`
	PortAssignment *PortAssignment `json:"port_assignment,omitempty"`
}

// ConnectionSession represents an active connection session
type ConnectionSession struct {
	ID           uuid.UUID `json:"id" db:"id"`
	TeamID       string    `json:"team_id" db:"team_id"`
	TokenID      uuid.UUID `json:"token_id" db:"token_id"`
	PortAssignID uuid.UUID `json:"port_assign_id" db:"port_assign_id"`
	ClientIP     string    `json:"client_ip" db:"client_ip"`
	ServerPort   int       `json:"server_port" db:"server_port"`
	Protocol     string    `json:"protocol" db:"protocol"`
	StartedAt    time.Time `json:"started_at" db:"started_at"`
	LastSeenAt   time.Time `json:"last_seen_at" db:"last_seen_at"`
	Status       string    `json:"status" db:"status"` // active, inactive
}

// ConnectionStats represents aggregated connection statistics
type ConnectionStats struct {
	TeamID             string    `json:"team_id"`
	TotalConnections   int64     `json:"total_connections"`
	ActiveConnections  int64     `json:"active_connections"`
	TotalBytesReceived int64     `json:"total_bytes_received"`
	TotalBytesSent     int64     `json:"total_bytes_sent"`
	AvgConnectionTime  float64   `json:"avg_connection_time_ms"`
	Date               time.Time `json:"date"`
}
