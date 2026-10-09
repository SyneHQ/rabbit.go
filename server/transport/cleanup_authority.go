package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"
)

// CleanupAuthority reads a fixed cleanup deadline. It must check current source,
// token, route and attempt fences without requiring a running DATA grant.
type CleanupAuthority interface {
	ReadCleanupLease(context.Context, CleanupLeaseRequest) (CleanupLeaseResponse, error)
	AuthorizeCleanup(context.Context, CleanupLeaseRequest, PostgresAbortClaims) (time.Time, error)
}

func (a *HTTPLeaseAuthority) AuthorizeCleanup(ctx context.Context, request CleanupLeaseRequest, claims PostgresAbortClaims) (time.Time, error) {
	if claims.ValidateAt(time.Now()) != nil || request.DataTicketSHA256 != claims.DataTicketSHA256 {
		return time.Time{}, ErrCleanup
	}
	result, err := a.ReadCleanupLease(ctx, request)
	if err != nil || result.CancellationStartedAt != claims.CancellationStartedAt || result.ValidUntil > claims.ExpiresAt {
		return time.Time{}, ErrCleanup
	}
	return time.Unix(result.ValidUntil, 0), nil
}

func (a *HTTPLeaseAuthority) ReadCleanupLease(ctx context.Context, request CleanupLeaseRequest) (CleanupLeaseResponse, error) {
	deny := func() (CleanupLeaseResponse, error) { return CleanupLeaseResponse{}, ErrCleanup }
	if request.Validate() != nil {
		return deny()
	}
	if _, valid := certificateDeadline(a.clientChain, time.Now()); !valid {
		return deny()
	}
	data, err := json.Marshal(request)
	if err != nil {
		return deny()
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(data))
	if err != nil {
		return deny()
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	response, err := a.client.Do(r)
	if err != nil {
		return deny()
	}
	defer response.Body.Close()
	kind, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" || response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return deny()
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 4097))
	var result CleanupLeaseResponse
	now := time.Now()
	if err != nil || len(data) > 4096 || decodeStrict(data, &result) != nil || result.ValidateAt(now) != nil {
		return deny()
	}
	clientUntil, ok := certificateDeadline(a.clientChain, now)
	peerUntil, peerOK := authorityPeerDeadline(response.TLS, now)
	if !ok || !peerOK {
		return deny()
	}
	result.ValidUntil = minTime(time.Unix(result.ValidUntil, 0), minTime(clientUntil, peerUntil)).Unix()
	if result.ValidateAt(now) != nil {
		return deny()
	}
	return result, nil
}

// VerifiedAbortPeerDeadline prevents a cleanup response from outliving the
// authenticated worker certificate. It does not establish physical custody.
func VerifiedAbortPeerDeadline(state tls.ConnectionState, c PostgresAbortClaims, now time.Time) (time.Time, error) {
	until, ok := peerDeadline(state, c.WorkerIdentity, c.WorkerCertSHA256, now)
	if !ok {
		return time.Time{}, ErrCleanup
	}
	return minTime(until, time.Unix(c.ExpiresAt, 0)), nil
}
