package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCleanupAuthorityRejectsUncertainOrExtendedLease(t *testing.T) {
	for _, mode := range []string{"valid", "denied", "network", "unknown", "duplicate", "extended", "future", "expired-peer", "expired-client", "unverified-peer", "encoding"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			client := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
			peer := *client
			if mode == "expired-client" {
				client.NotAfter = now
			}
			if mode == "expired-peer" {
				peer.NotAfter = now
			}
			request := CleanupLeaseRequest{Version: 1, DataTicketSHA256: strings.Repeat("a", 64), AcceptedOpen: "retained-signed-receipt"}
			a := &HTTPLeaseAuthority{endpoint: "https://authority.test/cleanup", clientChain: []*x509.Certificate{client}, client: &http.Client{Transport: authorityRoundTrip(func(r *http.Request) (*http.Response, error) {
				if mode == "expired-client" {
					t.Fatal("expired client sent request")
				}
				var got CleanupLeaseRequest
				if json.NewDecoder(r.Body).Decode(&got) != nil || got != request {
					t.Fatal("cleanup request binding changed")
				}
				if mode == "network" {
					return nil, errors.New("fixture network failure")
				}
				start, until := now.Unix(), now.Unix()+4
				if mode == "extended" {
					until = start + 6
				}
				if mode == "future" {
					start = now.Unix() + 1
				}
				body := fmt.Sprintf(`{"valid_until":%d,"cancellation_started_at":%d}`, until, start)
				if mode == "unknown" {
					body = strings.TrimSuffix(body, "}") + `,"unknown":true}`
				}
				if mode == "duplicate" {
					body = strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"valid_until":%d}`, until)
				}
				status := 200
				if mode == "denied" {
					status = 403
				}
				state := &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{&peer}}}
				if mode == "unverified-peer" {
					state.VerifiedChains = nil
				}
				header := http.Header{"Content-Type": {"application/json"}}
				if mode == "encoding" {
					header.Set("Content-Encoding", "gzip")
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), TLS: state}, nil
			})}}
			_, err := a.ReadCleanupLease(context.Background(), request)
			if (err == nil) != (mode == "valid") {
				t.Fatal("cleanup authority validation changed", mode, err)
			}
		})
	}
}
func TestOnlyExplicitDataDenialPermitsCleanupNegotiation(t *testing.T) {
	claims, trust, key, state, now := grantFixture(t)
	token := mustSign(t, claims, key)
	open, err := VerifyOpen(token, claims.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{403, 500, 200} {
		a := &HTTPLeaseAuthority{endpoint: "https://authority.test/lease", clientChain: []*x509.Certificate{{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}}, client: &http.Client{Transport: authorityRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("invalid"))}, nil
		})}}
		_, err := a.Authorize(context.Background(), token, open)
		if errors.Is(err, ErrLeaseDenied) != (status == 403) {
			t.Fatal("ambiguous failure treated as explicit denial", status, err)
		}
	}
}
