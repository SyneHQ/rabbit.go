package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"
)

// LeaseRequest reaches only the operator-selected authority over verified mTLS.
// The authority verifies the signed ticket, exact source-to-token mapping and
// live execution custody. It must not extend the underlying execution lease.
type LeaseRequest struct {
	Version int    `json:"version"`
	Token   string `json:"token"`
	Digest  string `json:"open_sha256"`
}

type LeaseResponse struct {
	Version    int    `json:"version"`
	Digest     string `json:"open_sha256"`
	ValidUntil int64  `json:"valid_until"`
}

type LeaseAuthority interface {
	Authorize(context.Context, string, VerifiedOpen) (time.Time, error)
}

// ReservationLeaseAuthority renews signed version-2 scope. Its caller still
// owns the exact parent, route and socket reservation. This interface does not
// enable reserved ingress or prove that a source query has stopped.
type ReservationLeaseAuthority interface {
	AuthorizeReservation(context.Context, string, VerifiedReservation) (time.Time, error)
}

type HTTPLeaseAuthority struct {
	endpoint    string
	client      *http.Client
	transport   *http.Transport
	clientChain []*x509.Certificate
}

// NewHTTPLeaseAuthority accepts operator configuration, never a query URL.
func NewHTTPLeaseAuthority(endpoint string, config *tls.Config) (*HTTPLeaseAuthority, error) {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		config == nil || config.InsecureSkipVerify || config.RootCAs == nil || len(config.Certificates) != 1 || config.MinVersion != tls.VersionTLS13 || config.GetClientCertificate != nil {
		return nil, ErrAuthority
	}
	tlsConfig := config.Clone()
	// Keep an immutable identity for pooled connections. Dynamic certificate
	// callbacks require a separate rotation contract and are not accepted here.
	certificate := config.Certificates[0]
	certificate.Certificate = make([][]byte, len(config.Certificates[0].Certificate))
	var clientChain []*x509.Certificate
	for index, raw := range config.Certificates[0].Certificate {
		certificate.Certificate[index] = bytes.Clone(raw)
		parsed, err := x509.ParseCertificate(certificate.Certificate[index])
		if err != nil {
			return nil, ErrAuthority
		}
		clientChain = append(clientChain, parsed)
	}
	if _, valid := certificateDeadline(clientChain, time.Now()); !valid {
		return nil, ErrAuthority
	}
	tlsConfig.Certificates = []tls.Certificate{certificate}
	if tlsConfig.ServerName != "" && tlsConfig.ServerName != u.Hostname() {
		return nil, ErrAuthority
	}
	tlsConfig.ServerName = u.Hostname()
	t := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true,
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second,
		MaxResponseHeaderBytes: 8192, MaxIdleConns: 32, MaxIdleConnsPerHost: 16,
		MaxConnsPerHost: 64, IdleConnTimeout: time.Minute,
	}
	return &HTTPLeaseAuthority{endpoint: endpoint, transport: t, clientChain: clientChain, client: &http.Client{
		Transport: t, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (a *HTTPLeaseAuthority) Close() { a.transport.CloseIdleConnections() }

func (a *HTTPLeaseAuthority) Authorize(ctx context.Context, token string, open VerifiedOpen) (time.Time, error) {
	return a.authorize(ctx, token, Version, open.Digest(), open.LeaseDeadline)
}

// AuthorizeReservation preserves token and open_sha256 while requiring an
// explicit version-2 response. A version-1 authority cannot renew this scope.
func (a *HTTPLeaseAuthority) AuthorizeReservation(ctx context.Context, token string, open VerifiedReservation) (time.Time, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes || open.claims.Version != ReservationVersion {
		return time.Time{}, ErrAuthority
	}
	sum := sha256.Sum256([]byte(token))
	if hex.EncodeToString(sum[:]) != open.Digest() {
		return time.Time{}, ErrAuthority
	}
	return a.authorize(ctx, token, ReservationVersion, open.Digest(), open.LeaseDeadline)
}

func (a *HTTPLeaseAuthority) authorize(ctx context.Context, token string, version int, digest string, leaseDeadline func(string, int64, time.Time) (time.Time, error)) (time.Time, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes || digest == "" {
		return time.Time{}, ErrAuthority
	}
	if _, valid := certificateDeadline(a.clientChain, time.Now()); !valid {
		return time.Time{}, ErrAuthority
	}
	data, err := json.Marshal(LeaseRequest{Version: version, Token: token, Digest: digest})
	if err != nil {
		return time.Time{}, ErrAuthority
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(data))
	if err != nil {
		return time.Time{}, ErrAuthority
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	response, err := a.client.Do(r)
	if err != nil {
		return time.Time{}, ErrAuthority
	}
	defer response.Body.Close()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return time.Time{}, ErrAuthority
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 4097))
	var result LeaseResponse
	if err != nil || len(data) > 4096 || decodeStrict(data, &result) != nil || result.Version != version {
		return time.Time{}, ErrAuthority
	}
	now := time.Now()
	clientUntil, clientValid := certificateDeadline(a.clientChain, now)
	peerUntil, peerValid := authorityPeerDeadline(response.TLS, now)
	if !clientValid || !peerValid {
		return time.Time{}, ErrAuthority
	}
	until, err := leaseDeadline(result.Digest, result.ValidUntil, now)
	if err != nil {
		return time.Time{}, err
	}
	if clientUntil.Before(until) {
		until = clientUntil
	}
	if peerUntil.Before(until) {
		until = peerUntil
	}
	return until, nil
}

// A pooled TLS connection does not repeat certificate validity checks. Authority
// responses must still come from a chain that is valid when the lease is read.
func authorityPeerDeadline(state *tls.ConnectionState, now time.Time) (time.Time, bool) {
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return time.Time{}, false
	}
	for _, chain := range state.VerifiedChains {
		if until, valid := certificateDeadline(chain, now); valid {
			return until, true
		}
	}
	return time.Time{}, false
}

func certificateDeadline(chain []*x509.Certificate, now time.Time) (time.Time, bool) {
	if len(chain) == 0 {
		return time.Time{}, false
	}
	var until time.Time
	for _, cert := range chain {
		if cert == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return time.Time{}, false
		}
		if until.IsZero() || cert.NotAfter.Before(until) {
			until = cert.NotAfter
		}
	}
	return until, true
}
