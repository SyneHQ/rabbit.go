package transport

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"time"
)

const (
	ReservationVersion = 2
	MaxAuxiliaryTTL    = MaxLeaseTTL
	reservationType    = "rabbit-connect-reservation+jwt"
)

// ReservationClaims is the dormant version-2 contract. An empty parent digest
// identifies a data open; an auxiliary open refers to one exact data ticket.
// This grants bounded same-source capacity, not proof of PostgreSQL cancellation.
// Version-1 listeners reject these tickets. No runtime enables this contract yet.
type ReservationClaims struct {
	OpenClaims
	ParentOpenSHA256 string `json:"parent_open_sha256,omitempty"`
}

// VerifiedReservation proves signed scope only. The caller still needs current
// route ownership, live authority, parent custody and reserved socket admission.
// Its parent may have passed its admission deadline while retaining a live session.
type VerifiedReservation struct {
	claims    ReservationClaims
	digest    string
	peerUntil time.Time
}

func (v VerifiedReservation) Claims() ReservationClaims { return v.claims }
func (v VerifiedReservation) Digest() string            { return v.digest }

func SignReservation(c ReservationClaims, key ed25519.PrivateKey) (string, error) {
	if validateReservationClaims(c, time.Unix(c.IssuedAt, 0)) != nil {
		return "", ErrAuthority
	}
	return signClaims(c, c.Issuer, reservationType, key)
}

func VerifyReservationData(token, authority string, trust Trust, state tls.ConnectionState, now time.Time) (VerifiedReservation, error) {
	v, err := verifyReservation(token, authority, trust, state, now)
	if err != nil || v.claims.ParentOpenSHA256 != "" {
		return VerifiedReservation{}, ErrAuthority
	}
	return v, nil
}

// VerifyReservationAuxiliary binds an auxiliary ticket to a verified data open.
// A matching digest is not evidence that the parent still owns active resources;
// that separate custody check must succeed before either socket is admitted.
func VerifyReservationAuxiliary(token, authority string, trust Trust, state tls.ConnectionState, parent VerifiedReservation, now time.Time) (VerifiedReservation, error) {
	v, err := verifyReservation(token, authority, trust, state, now)
	if err != nil || parent.digest == "" || parent.claims.ParentOpenSHA256 != "" ||
		v.claims.ParentOpenSHA256 != parent.digest || v.claims.ID == parent.claims.ID ||
		v.claims.IssuedAt < parent.claims.IssuedAt || !now.Before(parent.peerUntil) ||
		v.claims.SessionExpiresAt > parent.claims.SessionExpiresAt ||
		time.Unix(v.claims.SessionExpiresAt, 0).After(parent.peerUntil) {
		return VerifiedReservation{}, ErrAuthority
	}
	actual, expected := v.claims.OpenClaims, parent.claims.OpenClaims
	actual.ID, actual.IssuedAt, actual.ExpiresAt, actual.SessionExpiresAt = expected.ID, expected.IssuedAt, expected.ExpiresAt, expected.SessionExpiresAt
	if actual != expected {
		return VerifiedReservation{}, ErrAuthority
	}
	if parent.peerUntil.Before(v.peerUntil) {
		v.peerUntil = parent.peerUntil
	}
	return v, nil
}

func verifyReservation(token, authority string, trust Trust, state tls.ConnectionState, now time.Time) (VerifiedReservation, error) {
	var claims ReservationClaims
	if !ValidAuthority(authority) || verifySignedClaims(token, reservationType, trust, &claims) != nil ||
		validateReservationClaims(claims, now) != nil || claims.Issuer != trust.Issuer || claims.Audience != trust.Audience ||
		claims.ClusterTenant != trust.ClusterTenant || claims.ServicePrincipal != trust.ServicePrincipal ||
		claims.WorkerIdentity != trust.WorkerIdentity || claims.Authority != authority {
		return VerifiedReservation{}, ErrAuthority
	}
	until, valid := peerDeadline(state, claims.WorkerIdentity, claims.WorkerCertSHA256, now)
	if !valid || (claims.ParentOpenSHA256 != "" && time.Unix(claims.SessionExpiresAt, 0).After(until)) {
		return VerifiedReservation{}, ErrAuthority
	}
	sum := sha256.Sum256([]byte(token))
	return VerifiedReservation{claims: claims, digest: hex.EncodeToString(sum[:]), peerUntil: until}, nil
}

func validateReservationClaims(c ReservationClaims, now time.Time) error {
	base := c.OpenClaims
	base.Version = Version
	if c.Version != ReservationVersion || validateClaims(base, now) != nil {
		return ErrAuthority
	}
	if c.ParentOpenSHA256 != "" && (!hexValue(c.ParentOpenSHA256, 64) || c.SessionExpiresAt-c.IssuedAt > int64(MaxAuxiliaryTTL/time.Second)) {
		return ErrAuthority
	}
	return nil
}

func (v VerifiedReservation) LeaseDeadline(digest string, validUntil int64, now time.Time) (time.Time, error) {
	base := VerifiedOpen{claims: v.claims.OpenClaims, digest: v.digest, peerUntil: v.peerUntil}
	return base.LeaseDeadline(digest, validUntil, now)
}
