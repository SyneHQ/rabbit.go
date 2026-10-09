// Copyright 2026 SYNEHQ. SPDX-License-Identifier: Apache-2.0
package transport

import (
	"crypto/ed25519"
	"time"
)

const acceptedOpenType = "rabbit-accepted-source+jwt"

type AcceptedOpenClaims struct {
	Version          int    `json:"version"`
	DataTicketSHA256 string `json:"data_ticket_sha256"`
	AcceptanceID     string `json:"acceptance_id"`
	AcceptedAt       int64  `json:"accepted_at"`
	ExpiresAt        int64  `json:"expires_at"`
}
type AcceptedOpenTrust struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

func (c AcceptedOpenClaims) ValidateAt(now time.Time) error {
	if c.Version != CleanupVersion || !cleanupHex(c.DataTicketSHA256, 64) || !cleanupHex(c.AcceptanceID, 32) || c.AcceptedAt <= 0 || c.AcceptedAt > now.Unix() || c.ExpiresAt <= now.Unix() || c.ExpiresAt-c.AcceptedAt > int64(24*time.Hour/time.Second) {
		return ErrCleanup
	}
	return nil
}

// Sign only after both source-stream halves are paired and owned. ExpiresAt
// must not exceed the original source session or worker certificate deadline.
func SignAcceptedOpen(c AcceptedOpenClaims, keyID string, key ed25519.PrivateKey) (string, error) {
	if !cleanupName(keyID) || c.ValidateAt(time.Unix(c.AcceptedAt, 0)) != nil {
		return "", ErrCleanup
	}
	return signClaims(c, keyID, acceptedOpenType, key)
}

// Verify proves Rabbit's signed acceptance at AcceptedAt. It does not prove
// current physical custody, backend identity, source authorization or replay
// consumption. Select trust from the original operator-configured route.
func VerifyAcceptedOpen(token string, trust AcceptedOpenTrust, expectedDataDigest string, now time.Time) (AcceptedOpenClaims, error) {
	var c AcceptedOpenClaims
	if len(token) > MaxAcceptedOpenBytes || !cleanupName(trust.KeyID) || verifySignedClaims(token, acceptedOpenType, Trust{Issuer: trust.KeyID, PublicKey: trust.PublicKey}, &c) != nil || c.ValidateAt(now) != nil || c.DataTicketSHA256 != expectedDataDigest {
		return AcceptedOpenClaims{}, ErrCleanup
	}
	return c, nil
}

// SessionDeadline bounds an accepted receipt by the original worker certificate
// chain and session. A receipt does not extend the separately renewed data lease.
func (v VerifiedOpen) SessionDeadline() time.Time {
	if v.digest == "" {
		return time.Time{}
	}
	return minTime(time.Unix(v.claims.SessionExpiresAt, 0), v.peerUntil)
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
