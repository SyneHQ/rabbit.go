// Package transport defines scoped authority for private database CONNECT opens.
// It does not resolve destinations, open sockets or establish execution custody.
package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	Version       = 1
	MaxTokenBytes = 8192
	MaxOpenTTL    = time.Minute
	MaxSessionTTL = 24 * time.Hour
	MaxLeaseTTL   = 15 * time.Second
)

var ErrAuthority = errors.New("private transport authority is invalid or expired")

// Execution binds a physical connection to one authorized execution attempt.
// Worker, Owner and Claim identify the worker and its exact incarnation/attempt;
// ID and GrantSHA256 identify the query or operation and its signed authority.
type Execution struct {
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	GrantSHA256 string `json:"grant_sha256"`
	Worker      string `json:"worker_id"`
	Owner       string `json:"owner"`
	Claim       string `json:"claim"`
}

// OpenClaims authorizes exactly one physical source connection. ExpiresAt is
// the admission deadline, not the lifetime of an already-authorized session.
// A live authority lease must govern the session until SessionExpiresAt.
type OpenClaims struct {
	Version          int       `json:"version"`
	Issuer           string    `json:"iss"`
	Audience         string    `json:"aud"`
	ID               string    `json:"jti"`
	IssuedAt         int64     `json:"iat"`
	ExpiresAt        int64     `json:"exp"`
	SessionExpiresAt int64     `json:"session_expires_at"`
	ClusterTenant    string    `json:"cluster_tenant"`
	ServicePrincipal string    `json:"service_principal"`
	Tenant           string    `json:"tenant"`
	Source           string    `json:"source"`
	SourceRevision   string    `json:"source_revision"`
	TokenID          string    `json:"token_id"`
	TokenGeneration  string    `json:"token_generation"`
	TunnelID         string    `json:"tunnel_id"`
	ControlOwner     string    `json:"control_owner"`
	Authority        string    `json:"authority"`
	WorkerIdentity   string    `json:"worker_identity"`
	WorkerCertSHA256 string    `json:"worker_cert_sha256"`
	Execution        Execution `json:"execution"`
}

// Trust is selected from operator configuration. A query cannot supply it.
// One entry pins an issuer, service, cluster and exact authenticated worker URI.
type Trust struct {
	Issuer, Audience, ClusterTenant, ServicePrincipal, WorkerIdentity string
	PublicKey                                                         ed25519.PublicKey
}

// VerifiedOpen is immutable outside this package. Verification alone does not
// consume the ticket, establish a live lease or prove current tunnel ownership.
type VerifiedOpen struct {
	claims    OpenClaims
	digest    string
	peerUntil time.Time
}

func (v VerifiedOpen) Claims() OpenClaims { return v.claims }
func (v VerifiedOpen) Digest() string     { return v.digest }

type joseHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// SignOpen creates a compact Ed25519 JWT with a protocol-specific type.
// The issuer supplies a cryptographically random 256-bit one-use ID.
func SignOpen(c OpenClaims, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize || validateClaims(c, time.Unix(c.IssuedAt, 0)) != nil {
		return "", ErrAuthority
	}
	return signClaims(c, c.Issuer, "rabbit-connect+jwt", key)
}

// VerifyOpen checks the signed scope and the completed, verified mTLS handshake.
// The caller must use its own TLS configuration with client verification enabled.
func VerifyOpen(token, authority string, trust Trust, state tls.ConnectionState, now time.Time) (VerifiedOpen, error) {
	deny := func() (VerifiedOpen, error) { return VerifiedOpen{}, ErrAuthority }
	if len(token) == 0 || len(token) > MaxTokenBytes || len(trust.PublicKey) != ed25519.PublicKeySize || !ValidAuthority(authority) {
		return deny()
	}
	var claims OpenClaims
	if verifySignedClaims(token, "rabbit-connect+jwt", trust, &claims) != nil ||
		validateClaims(claims, now) != nil || claims.Issuer != trust.Issuer || claims.Audience != trust.Audience ||
		claims.ClusterTenant != trust.ClusterTenant || claims.ServicePrincipal != trust.ServicePrincipal ||
		claims.WorkerIdentity != trust.WorkerIdentity || claims.Authority != authority {
		return deny()
	}
	until, ok := peerDeadline(state, claims.WorkerIdentity, claims.WorkerCertSHA256, now)
	if !ok {
		return deny()
	}
	sum := sha256.Sum256([]byte(token))
	return VerifiedOpen{claims: claims, digest: hex.EncodeToString(sum[:]), peerUntil: until}, nil
}

// LeaseDeadline checks a live authority response. The authority must bind that
// response to Digest and recheck revocation, source revision and execution custody.
// Its lease cannot outlive the session grant, verified certificate or short TTL.
func (v VerifiedOpen) LeaseDeadline(digest string, validUntil int64, now time.Time) (time.Time, error) {
	until := time.Unix(validUntil, 0)
	if v.digest == "" || digest != v.digest || !until.After(now) || until.After(now.Add(MaxLeaseTTL)) ||
		until.After(time.Unix(v.claims.SessionExpiresAt, 0)) || until.After(v.peerUntil) {
		return time.Time{}, ErrAuthority
	}
	return until, nil
}

func validateClaims(c OpenClaims, now time.Time) error {
	if c.Version != Version || c.IssuedAt <= 0 || c.IssuedAt > now.Unix() || c.ExpiresAt <= now.Unix() ||
		c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(MaxOpenTTL/time.Second) ||
		c.SessionExpiresAt < c.ExpiresAt || c.SessionExpiresAt-c.IssuedAt > int64(MaxSessionTTL/time.Second) ||
		!hexValue(c.ID, 64) || !hexValue(c.SourceRevision, 64) || !hexValue(c.TokenGeneration, 64) ||
		!hexValue(c.TunnelID, 64) || !hexValue(c.ControlOwner, 64) || !hexValue(c.WorkerCertSHA256, 64) ||
		!ValidAuthority(c.Authority) || !textValue(c.WorkerIdentity, 512) {
		return ErrAuthority
	}
	for _, value := range []string{c.Issuer, c.Audience, c.ClusterTenant, c.ServicePrincipal, c.Tenant, c.Source, c.TokenID} {
		if !textValue(value, 128) {
			return ErrAuthority
		}
	}
	e := c.Execution
	if (e.Kind != "query" && e.Kind != "operation") || !textValue(e.ID, 128) || !textValue(e.Worker, 32) ||
		!hexValue(e.GrantSHA256, 64) || !hexValue(e.Owner, 32) || !hexValue(e.Claim, 32) {
		return ErrAuthority
	}
	return nil
}

// ValidAuthority accepts one canonical host:port and never performs DNS lookup.
// Source TLS must still verify this original hostname inside the native driver.
func ValidAuthority(authority string) bool {
	if len(authority) == 0 || len(authority) > 320 {
		return false
	}
	host, port, err := net.SplitHostPort(authority)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port || host == "" || net.JoinHostPort(host, port) != authority {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == "" && address.String() == host && !address.IsUnspecified() && !address.IsMulticast()
	}
	if len(host) > 253 || host != strings.ToLower(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func peerDeadline(state tls.ConnectionState, identity, digest string, now time.Time) (time.Time, bool) {
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return time.Time{}, false
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].String() != identity {
		return time.Time{}, false
	}
	sum := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(sum[:]) != digest {
		return time.Time{}, false
	}
	// A verified chain must start with this exact leaf. Bound its lifetime by
	// every certificate in that chain, including intermediate certificates.
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil || !bytes.Equal(chain[0].Raw, leaf.Raw) {
			continue
		}
		until, valid := leaf.NotAfter, true
		for _, cert := range chain {
			if cert == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				valid = false
				break
			}
			if cert.NotAfter.Before(until) {
				until = cert.NotAfter
			}
		}
		if valid {
			return until, true
		}
	}
	return time.Time{}, false
}

func hexValue(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func textValue(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if char <= 32 || char >= 127 {
			return false
		}
	}
	return true
}

func decodeStrict(data []byte, out any) error {
	if len(data) == 0 || len(data) > MaxTokenBytes {
		return ErrAuthority
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrAuthority
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrAuthority
	}
	d = json.NewDecoder(bytes.NewReader(data))
	if uniqueJSON(d, 0) != nil {
		return ErrAuthority
	}
	return nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 4 {
		return ErrAuthority
	}
	token, err := d.Token()
	if err != nil {
		return ErrAuthority
	}
	if token != json.Delim('{') {
		if _, compound := token.(json.Delim); compound {
			return ErrAuthority
		}
		return nil
	}
	seen := make(map[string]bool)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || name != strings.ToLower(name) || seen[name] {
			return ErrAuthority
		}
		seen[name] = true
		if uniqueJSON(d, depth+1) != nil {
			return ErrAuthority
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return ErrAuthority
	}
	return nil
}
