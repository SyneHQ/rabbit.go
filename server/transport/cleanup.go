// Copyright 2026 SYNEHQ. SPDX-License-Identifier: Apache-2.0
package transport

import (
	"errors"
	"time"
)

const (
	CleanupVersion        = 1
	CleanupPath           = "/v1/private-transport/cleanup-issue"
	CleanupLeasePath      = "/v1/private-transport/cleanup-lease"
	PostgresCancel        = "postgres_cancel"
	MaxCleanupLifetime    = 5 * time.Second
	PostgresAbortHeader   = "Rabbit-Postgres-Abort"
	PostgresAbortRequired = "required-v1"
	AcceptedOpenHeader    = "Rabbit-Accepted-Open"
	AcceptedOpenRequired  = "required-v1"
	MaxAcceptedOpenBytes  = 4096
	MaxAbortTokenBytes    = 4096
)

var ErrCleanup = errors.New("private source cleanup authority is invalid")

// Scope comes from the issuer's retained data-open record. Neither a receipt
// nor a terminal job permits the caller to reconstruct that record.
type CleanupRequest struct {
	Version          int    `json:"version"`
	DataTicketSHA256 string `json:"data_ticket_sha256"`
	AcceptedOpen     string `json:"accepted_open"`
	OpenID           string `json:"open_id"`
	Protocol         string `json:"protocol"`
}

func (r CleanupRequest) Validate() error {
	if r.Version != CleanupVersion || !cleanupHex(r.DataTicketSHA256, 64) || len(r.AcceptedOpen) == 0 || len(r.AcceptedOpen) > MaxAcceptedOpenBytes || !cleanupHex(r.OpenID, 64) || r.Protocol != PostgresCancel {
		return ErrCleanup
	}
	return nil
}

type CleanupResponse struct {
	Version       int    `json:"version"`
	RequestSHA256 string `json:"request_sha256"`
	Token         string `json:"token"`
}

// Rabbit may repeat a cleanup lease read. Only cleanup issuance consumes its
// one-use slot. A read cannot start, renew or extend a cleanup deadline.
type CleanupLeaseRequest struct {
	Version          int    `json:"version"`
	DataTicketSHA256 string `json:"data_ticket_sha256"`
	AcceptedOpen     string `json:"accepted_open"`
}

func (r CleanupLeaseRequest) Validate() error {
	if r.Version != CleanupVersion || !cleanupHex(r.DataTicketSHA256, 64) || len(r.AcceptedOpen) == 0 || len(r.AcceptedOpen) > MaxAcceptedOpenBytes {
		return ErrCleanup
	}
	return nil
}

type CleanupLeaseResponse struct {
	ValidUntil            int64 `json:"valid_until"`
	CancellationStartedAt int64 `json:"cancellation_started_at"`
}

func (r CleanupLeaseResponse) ValidateAt(now time.Time) error {
	if r.CancellationStartedAt <= 0 || r.CancellationStartedAt > now.Unix() || r.ValidUntil <= now.Unix() || r.ValidUntil-r.CancellationStartedAt > int64(MaxCleanupLifetime/time.Second) {
		return ErrCleanup
	}
	return nil
}

func cleanupHex(value string, n int) bool {
	if len(value) != n {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func cleanupName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
