package transport

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVersionOneSigningBytesRemainUnchanged(t *testing.T) {
	claims, trust, key, state, now := grantFixture(t)
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	// This is the original version-1 wire algorithm, before helper extraction.
	header := `{"alg":"EdDSA","typ":"rabbit-connect+jwt","kid":"application"}`
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	original := unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(unsigned)))
	if current := mustSign(t, claims, key); current != original {
		t.Fatal("version-1 signed wire bytes changed")
	}
	if _, err := VerifyOpen(original, claims.Authority, trust, state, now); err != nil {
		t.Fatal("original version-1 wire token rejected", err)
	}
}

func reservationFixture(t *testing.T) (ReservationClaims, Trust, ed25519.PrivateKey, tls.ConnectionState, time.Time, VerifiedReservation) {
	t.Helper()
	base, trust, key, state, now := grantFixture(t)
	base.Version = ReservationVersion
	claims := ReservationClaims{OpenClaims: base}
	parent, err := VerifyReservationData(signReservation(t, claims, key), claims.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	return claims, trust, key, state, now, parent
}

func signReservation(t *testing.T, claims ReservationClaims, key ed25519.PrivateKey) string {
	t.Helper()
	token, err := SignReservation(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func auxiliaryClaims(parent VerifiedReservation, at time.Time) ReservationClaims {
	claims := parent.Claims()
	claims.ParentOpenSHA256 = parent.Digest()
	claims.ID = strings.Repeat("a", 64)
	claims.IssuedAt = at.Unix()
	claims.ExpiresAt = at.Add(5 * time.Second).Unix()
	claims.SessionExpiresAt = at.Add(MaxAuxiliaryTTL).Unix()
	return claims
}

func TestReservationVersionsAndRolesCannotBeSubstituted(t *testing.T) {
	claims, trust, key, state, now, parent := reservationFixture(t)
	v2 := signReservation(t, claims, key)
	if _, err := VerifyOpen(v2, claims.Authority, trust, state, now); !errors.Is(err, ErrAuthority) {
		t.Fatal("version-1 ingress accepted a reservation ticket")
	}
	v1 := claims.OpenClaims
	v1.Version = Version
	if _, err := VerifyReservationData(mustSign(t, v1, key), claims.Authority, trust, state, now); !errors.Is(err, ErrAuthority) {
		t.Fatal("version-1 ticket gained reservation authority")
	}
	aux := auxiliaryClaims(parent, now)
	token := signReservation(t, aux, key)
	if _, err := VerifyReservationData(token, aux.Authority, trust, state, now); !errors.Is(err, ErrAuthority) {
		t.Fatal("auxiliary ticket admitted as data")
	}
	if _, err := VerifyReservationAuxiliary(v2, claims.Authority, trust, state, parent, now); !errors.Is(err, ErrAuthority) {
		t.Fatal("data ticket admitted as auxiliary")
	}
	verified, err := VerifyReservationAuxiliary(token, aux.Authority, trust, state, parent, now)
	if err != nil || verified.Claims() != aux {
		t.Fatal("valid auxiliary binding rejected", err)
	}
	if _, err := VerifyReservationAuxiliary(token, aux.Authority, trust, state, verified, now); !errors.Is(err, ErrAuthority) {
		t.Fatal("auxiliary ticket became a parent")
	}
	if _, err := VerifyReservationAuxiliary(token, aux.Authority, trust, state, VerifiedReservation{}, now); !errors.Is(err, ErrAuthority) {
		t.Fatal("unverified parent accepted")
	}
}

func TestReservationRejectsSignedAmbiguousJSON(t *testing.T) {
	_, trust, key, state, now, parent := reservationFixture(t)
	claims := auxiliaryClaims(parent, now)
	payload, _ := json.Marshal(claims)
	header, _ := json.Marshal(joseHeader{"EdDSA", reservationType, claims.Issuer})
	parentField := `"parent_open_sha256":"` + parent.Digest() + `"`
	for name, body := range map[string]string{
		"duplicate-parent":         strings.Replace(string(payload), parentField, parentField+","+parentField, 1),
		"case-alias":               strings.Replace(string(payload), parentField, parentField+`,"PARENT_OPEN_SHA256":"`+parent.Digest()+`"`, 1),
		"unknown":                  strings.TrimSuffix(string(payload), "}") + `,"cancellation":true}`,
		"duplicate-embedded-scope": strings.Replace(string(payload), `"tenant":"tenant-a"`, `"tenant":"tenant-a","tenant":"other"`, 1),
		"second-document":          string(payload) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString([]byte(body))
			token := unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(unsigned)))
			if _, err := VerifyReservationAuxiliary(token, claims.Authority, trust, state, parent, now); !errors.Is(err, ErrAuthority) {
				t.Fatal("ambiguous signed reservation accepted")
			}
		})
	}
}

func TestReservationAuxiliaryPinsEveryParentBinding(t *testing.T) {
	_, trust, key, state, now, parent := reservationFixture(t)
	changes := map[string]func(*ReservationClaims){
		"parent":      func(c *ReservationClaims) { c.ParentOpenSHA256 = strings.Repeat("b", 64) },
		"reused-jti":  func(c *ReservationClaims) { c.ID = parent.Claims().ID },
		"issuer":      func(c *ReservationClaims) { c.Issuer = "other" },
		"audience":    func(c *ReservationClaims) { c.Audience = "other" },
		"cluster":     func(c *ReservationClaims) { c.ClusterTenant = "other" },
		"principal":   func(c *ReservationClaims) { c.ServicePrincipal = "other" },
		"tenant":      func(c *ReservationClaims) { c.Tenant = "other" },
		"source":      func(c *ReservationClaims) { c.Source = "other" },
		"revision":    func(c *ReservationClaims) { c.SourceRevision = strings.Repeat("b", 64) },
		"token":       func(c *ReservationClaims) { c.TokenID = "other" },
		"generation":  func(c *ReservationClaims) { c.TokenGeneration = strings.Repeat("b", 64) },
		"tunnel":      func(c *ReservationClaims) { c.TunnelID = strings.Repeat("b", 64) },
		"control":     func(c *ReservationClaims) { c.ControlOwner = strings.Repeat("b", 64) },
		"authority":   func(c *ReservationClaims) { c.Authority = "other.internal:5432" },
		"identity":    func(c *ReservationClaims) { c.WorkerIdentity += "/other" },
		"certificate": func(c *ReservationClaims) { c.WorkerCertSHA256 = strings.Repeat("b", 64) },
		"kind":        func(c *ReservationClaims) { c.Execution.Kind = "operation" },
		"execution":   func(c *ReservationClaims) { c.Execution.ID = "other" },
		"grant":       func(c *ReservationClaims) { c.Execution.GrantSHA256 = strings.Repeat("b", 64) },
		"worker":      func(c *ReservationClaims) { c.Execution.Worker = "other" },
		"incarnation": func(c *ReservationClaims) { c.Execution.Owner = strings.Repeat("b", 32) },
		"attempt":     func(c *ReservationClaims) { c.Execution.Claim = strings.Repeat("b", 32) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			claims := auxiliaryClaims(parent, now)
			change(&claims)
			token := signReservation(t, claims, key)
			if _, err := VerifyReservationAuxiliary(token, claims.Authority, trust, state, parent, now); !errors.Is(err, ErrAuthority) {
				t.Fatal("foreign parent binding accepted")
			}
		})
	}
}

func TestReservationUsesParentSessionNotAdmissionDeadline(t *testing.T) {
	_, trust, key, state, now, parent := reservationFixture(t)
	later := now.Add(time.Minute)
	claims := auxiliaryClaims(parent, later)
	verified, err := VerifyReservationAuxiliary(signReservation(t, claims, key), claims.Authority, trust, state, parent, later)
	if err != nil {
		t.Fatal("live parent session rejected after data admission expired", err)
	}
	if _, err := verified.LeaseDeadline(verified.Digest(), claims.SessionExpiresAt, later); err != nil {
		t.Fatal("bounded lease rejected", err)
	}
	if _, err := verified.LeaseDeadline(verified.Digest(), claims.SessionExpiresAt+1, later); !errors.Is(err, ErrAuthority) {
		t.Fatal("auxiliary session extended")
	}
	for name, at := range map[string]time.Time{"before-parent": now.Add(-time.Second), "past-session": now.Add(time.Hour - 5*time.Second)} {
		t.Run(name, func(t *testing.T) {
			claims := auxiliaryClaims(parent, at)
			if _, err := VerifyReservationAuxiliary(signReservation(t, claims, key), claims.Authority, trust, state, parent, at); !errors.Is(err, ErrAuthority) {
				t.Fatal("parent lifetime extended")
			}
		})
	}
	shortPeer := parent
	shortPeer.peerUntil = later.Add(10 * time.Second)
	if _, err := VerifyReservationAuxiliary(signReservation(t, claims, key), claims.Authority, trust, state, shortPeer, later); !errors.Is(err, ErrAuthority) {
		t.Fatal("parent certificate lifetime extended")
	}
	for _, change := range []func(*ReservationClaims){
		func(c *ReservationClaims) { c.ParentOpenSHA256 = strings.Repeat("A", 64) },
		func(c *ReservationClaims) { c.SessionExpiresAt = c.IssuedAt + 16 },
		func(c *ReservationClaims) { c.Version = Version },
	} {
		invalid := claims
		change(&invalid)
		if _, err := SignReservation(invalid, key); !errors.Is(err, ErrAuthority) {
			t.Fatal("invalid reservation shape accepted")
		}
	}
}

func TestReservationReplaysShareVersionOneNamespaceAndCapacity(t *testing.T) {
	claims, trust, key, state, now, parent := reservationFixture(t)
	v1 := claims.OpenClaims
	v1.Version = Version
	legacy, err := VerifyOpen(mustSign(t, v1, key), v1.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewReplayRegistry(1)
	if err := registry.Consume(legacy, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.ConsumeReservation(parent, now); !errors.Is(err, ErrReplay) {
		t.Fatal("version change bypassed replay custody")
	}
	aux := auxiliaryClaims(parent, now)
	verified, err := VerifyReservationAuxiliary(signReservation(t, aux, key), aux.Authority, trust, state, parent, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ConsumeReservation(verified, now); !errors.Is(err, ErrCapacity) {
		t.Fatal("auxiliary ticket bypassed aggregate replay cap")
	}
	registry, _ = NewReplayRegistry(2)
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			if err := registry.ConsumeReservation(verified, now); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrReplay) {
				t.Errorf("unexpected replay result: %v", err)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("auxiliary ticket consumed more than once")
	}
	if err := registry.ConsumeReservation(VerifiedReservation{}, now); !errors.Is(err, ErrAuthority) {
		t.Fatal("unverified reservation consumed")
	}
}
