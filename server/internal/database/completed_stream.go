package database

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// RecordCompletedStream writes one completed audit record. It never creates an active stream or reactivates a session.
func (s *Service) RecordCompletedStream(ctx context.Context, record ConnectionLog) error {
	if record.ID == uuid.Nil || record.SessionID == uuid.Nil || record.EndedAt == nil || record.EndedAt.Before(record.StartedAt) || record.BytesReceived < 0 || record.BytesSent < 0 {
		return fmt.Errorf("invalid completed stream record")
	}
	if record.Status != "closed" && record.Status != "error" && record.Status != "timeout" {
		return fmt.Errorf("completed stream status must be closed, error or timeout")
	}
	_, err := s.db.DB.ExecContext(ctx, `
  WITH inserted AS (
   INSERT INTO connection_logs(id,team_id,token_id,port_assign_id,session_id,client_ip,client_port,server_port,protocol,started_at,ended_at,bytes_received,bytes_sent,connection_time_ms,status,error_message)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
   ON CONFLICT(id) DO NOTHING RETURNING session_id
  )
  UPDATE connection_sessions SET last_seen_at=GREATEST(last_seen_at,$11)
  WHERE id IN (SELECT session_id FROM inserted) AND status='active'`,
		record.ID, record.TeamID, record.TokenID, record.PortAssignID, record.SessionID, record.ClientIP, record.ClientPort, record.ServerPort, record.Protocol, record.StartedAt, record.EndedAt, record.BytesReceived, record.BytesSent, record.EndedAt.Sub(record.StartedAt).Milliseconds(), record.Status, record.ErrorMessage)
	if err != nil {
		return fmt.Errorf("write completed stream audit: %w", err)
	}
	return nil
}
