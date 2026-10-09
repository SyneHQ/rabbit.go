// Copyright 2026 SYNEHQ. SPDX-License-Identifier: Apache-2.0
package transport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func cleanupFixture() (ed25519.PrivateKey, AcceptedOpenClaims, PostgresAbortClaims) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	accepted := AcceptedOpenClaims{1, strings.Repeat("a", 64), strings.Repeat("b", 32), 2000000000, 2000000060}
	abort := PostgresAbortClaims{1, "fixture-issuer", "fixture-rabbit", strings.Repeat("c", 64), 2000000001, 2000000005, accepted.DataTicketSHA256, accepted.AcceptanceID, "spiffe://fixture.invalid/worker/one", strings.Repeat("d", 64), 2000000000, PostgresCancel}
	return key, accepted, abort
}
func fixtureBinding(c PostgresAbortClaims) AbortBinding {
	return AbortBinding{c.DataTicketSHA256, c.AcceptanceID, c.WorkerIdentity, c.WorkerCertSHA256}
}
func rawCleanupToken(key ed25519.PrivateKey, header, body string) string {
	raw := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(body))
	return raw + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(raw)))
}

func TestCleanupPublicVectors(t *testing.T) {
	key, accepted, abort := cleanupFixture()
	var vector struct{ SeedHex, PublicKeyHex, AcceptedToken, AbortToken string }
	raw, err := os.ReadFile("testdata/cleanup-v1.json")
	if err != nil || json.Unmarshal(raw, &vector) != nil {
		t.Fatal("cannot read public cleanup vectors", err)
	}
	if vector.SeedHex != hex.EncodeToString(key.Seed()) || vector.PublicKeyHex != hex.EncodeToString(key.Public().(ed25519.PublicKey)) {
		t.Fatal("fixture key changed")
	}
	a, err := SignAcceptedOpen(accepted, "fixture-route", key)
	if err != nil || a != vector.AcceptedToken {
		t.Fatal("accepted receipt vector changed", err)
	}
	b, err := SignPostgresAbort(abort, key)
	if err != nil || b != vector.AbortToken {
		t.Fatal("abort vector changed", err)
	}
	if got, err := VerifyAcceptedOpen(a, AcceptedOpenTrust{"fixture-route", key.Public().(ed25519.PublicKey)}, accepted.DataTicketSHA256, time.Unix(2000000001, 0)); err != nil || got != accepted {
		t.Fatal("accepted vector rejected", err)
	}
	if got, err := VerifyPostgresAbort(b, AbortTrust{abort.Issuer, abort.Audience, key.Public().(ed25519.PublicKey)}, fixtureBinding(abort), time.Unix(2000000001, 0)); err != nil || got != abort {
		t.Fatal("abort vector rejected", err)
	}
}

func TestAcceptedOpenRejectsWrongTrustAndBinding(t *testing.T) {
	key, c, _ := cleanupFixture()
	good, _ := SignAcceptedOpen(c, "fixture-route", key)
	for _, name := range []string{"key", "kid", "digest", "expired", "future", "forged", "wrong-type", "duplicate", "unknown", "malformed", "padding"} {
		t.Run(name, func(t *testing.T) {
			token, digest, now := good, c.DataTicketSHA256, time.Unix(c.AcceptedAt, 0)
			trust := AcceptedOpenTrust{"fixture-route", key.Public().(ed25519.PublicKey)}
			switch name {
			case "key":
				trust.PublicKey = ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
			case "kid":
				trust.KeyID = "rotated-route"
			case "digest":
				digest = strings.Repeat("e", 64)
			case "expired":
				now = time.Unix(c.ExpiresAt, 0)
			case "future":
				now = time.Unix(c.AcceptedAt-1, 0)
			case "forged":
				token = token[:len(token)-8] + "AAAAAAAA"
			case "padding":
				token += "="
			default:
				raw, _ := json.Marshal(c)
				body := string(raw)
				header := `{ "alg":"EdDSA", "typ":"rabbit-accepted-source+jwt", "kid":"fixture-route" }`
				if name == "wrong-type" {
					header = strings.Replace(header, "rabbit-accepted-source+jwt", "rabbit-postgres-abort+jwt", 1)
				}
				if name == "duplicate" {
					body = strings.TrimSuffix(body, "}") + `,"version":1}`
				}
				if name == "unknown" {
					body = strings.TrimSuffix(body, "}") + `,"unknown":true}`
				}
				if name == "malformed" {
					body = `{`
				}
				token = rawCleanupToken(key, header, body)
			}
			if _, err := VerifyAcceptedOpen(token, trust, digest, now); err == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
}

func TestPostgresAbortRejectsWrongBindingAndDeadline(t *testing.T) {
	key, _, base := cleanupFixture()
	for _, name := range []string{"issuer", "audience", "digest", "acceptance", "worker", "certificate", "expired", "future", "extended", "mysql", "duplicate", "wrong-type", "rotated-key"} {
		t.Run(name, func(t *testing.T) {
			c, b, now := base, fixtureBinding(base), time.Unix(base.IssuedAt, 0)
			trust := AbortTrust{base.Issuer, base.Audience, key.Public().(ed25519.PublicKey)}
			switch name {
			case "issuer":
				trust.Issuer = "another-issuer"
			case "audience":
				trust.Audience = "another-audience"
			case "digest":
				b.DataTicketSHA256 = strings.Repeat("e", 64)
			case "acceptance":
				b.AcceptanceID = strings.Repeat("e", 32)
			case "worker":
				b.WorkerIdentity = "spiffe://fixture.invalid/worker/two"
			case "certificate":
				b.WorkerCertSHA256 = strings.Repeat("e", 64)
			case "expired":
				now = time.Unix(c.ExpiresAt, 0)
			case "future":
				now = time.Unix(c.IssuedAt-1, 0)
			case "extended":
				c.ExpiresAt++
			case "mysql":
				c.Protocol = "mysql_cancel"
			case "rotated-key":
				trust.PublicKey = ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
			}
			raw, _ := json.Marshal(c)
			body := string(raw)
			header := `{ "alg":"EdDSA", "typ":"rabbit-postgres-abort+jwt", "kid":"fixture-issuer" }`
			if name == "duplicate" {
				body = strings.TrimSuffix(body, "}") + `,"jti":"` + c.ID + `"}`
			}
			if name == "wrong-type" {
				header = strings.Replace(header, "rabbit-postgres-abort+jwt", "rabbit-accepted-source+jwt", 1)
			}
			token := rawCleanupToken(key, header, body)
			if _, err := VerifyPostgresAbort(token, trust, b, now); err == nil {
				t.Fatal("invalid abort accepted")
			}
		})
	}
}

func TestCleanupRequestsRejectInvalidInputs(t *testing.T) {
	_, c, _ := cleanupFixture()
	good := CleanupRequest{1, c.DataTicketSHA256, "signed-receipt", strings.Repeat("c", 64), PostgresCancel}
	if good.Validate() != nil {
		t.Fatal("valid request rejected")
	}
	for _, name := range []string{"version", "digest", "receipt", "size", "open", "mysql"} {
		c := good
		switch name {
		case "version":
			c.Version = 2
		case "digest":
			c.DataTicketSHA256 = ""
		case "receipt":
			c.AcceptedOpen = ""
		case "size":
			c.AcceptedOpen = strings.Repeat("x", MaxAcceptedOpenBytes+1)
		case "open":
			c.OpenID = ""
		case "mysql":
			c.Protocol = "mysql_cancel"
		}
		if c.Validate() == nil {
			t.Fatal("invalid request accepted", name)
		}
	}
	for _, c := range []CleanupLeaseResponse{{2000000006, 2000000000}, {2000000000, 1999999999}, {2000000005, 2000000002}, {2000000005, 0}} {
		if c.ValidateAt(time.Unix(2000000001, 0)) == nil {
			t.Fatal("invalid cleanup cutoff accepted", c)
		}
	}
}
