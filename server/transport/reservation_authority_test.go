package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

var _ ReservationLeaseAuthority = (*HTTPLeaseAuthority)(nil)

func reservationAuthorityFixture(t *testing.T, token string, open VerifiedReservation, client, peer *x509.Certificate, validUntil int64) *HTTPLeaseAuthority {
	t.Helper()
	return &HTTPLeaseAuthority{endpoint: "https://authority.test/lease", clientChain: []*x509.Certificate{client},
		client: &http.Client{Transport: authorityRoundTrip(func(r *http.Request) (*http.Response, error) {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf(`{"version":2,"token":%q,"open_sha256":%q}`, token, open.Digest())
			if string(data) != want {
				t.Fatal("reservation authority request changed its version, ticket or digest")
			}
			body, err := json.Marshal(LeaseResponse{Version: ReservationVersion, Digest: open.Digest(), ValidUntil: validUntil})
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(string(body))),
				TLS:  &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{peer}}}}, nil
		})}}
}

func TestReservationAuthorityRejectsUnverifiedOrSubstitutedTicketBeforeRequest(t *testing.T) {
	claims, _, key, _, _, open := reservationFixture(t)
	token := signReservation(t, claims, key)
	wrongVersion := open
	wrongVersion.claims.Version = Version
	for name, value := range map[string]struct {
		token string
		open  VerifiedReservation
	}{
		"unverified": {token, VerifiedReservation{}},
		"version":    {token, wrongVersion},
		"different":  {token + "a", open},
		"empty":      {"", open},
		"oversize":   {strings.Repeat("a", MaxTokenBytes+1), open},
	} {
		t.Run(name, func(t *testing.T) {
			// No HTTP client is present: invalid scope must fail before network I/O.
			a := &HTTPLeaseAuthority{}
			if _, err := a.AuthorizeReservation(context.Background(), value.token, value.open); err == nil {
				t.Fatal("invalid reservation scope sent to authority")
			}
		})
	}
}

func TestReservationAuthorityPreservesDataAndAuxiliarySessionBounds(t *testing.T) {
	claims, trust, key, state, now, _ := reservationFixture(t)
	claims.ExpiresAt = now.Add(5 * time.Second).Unix()
	claims.SessionExpiresAt = now.Add(9 * time.Second).Unix()
	token := signReservation(t, claims, key)
	parent, err := VerifyReservationData(token, claims.Authority, trust, state, now)
	if err != nil {
		t.Fatal(err)
	}
	auxClaims := auxiliaryClaims(parent, now)
	auxClaims.SessionExpiresAt = now.Add(8 * time.Second).Unix()
	auxToken := signReservation(t, auxClaims, key)
	auxiliary, err := VerifyReservationAuxiliary(auxToken, claims.Authority, trust, state, parent, now)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	for name, value := range map[string]struct {
		token string
		open  VerifiedReservation
	}{"data": {token, parent}, "auxiliary": {auxToken, auxiliary}} {
		t.Run(name, func(t *testing.T) {
			for _, seconds := range []int{3, 10} {
				until := now.Add(time.Duration(seconds) * time.Second).Unix()
				a := reservationAuthorityFixture(t, value.token, value.open, cert, cert, until)
				got, err := a.AuthorizeReservation(context.Background(), value.token, value.open)
				if (err == nil) != (seconds == 3) || (err == nil && got.Unix() != until) {
					t.Fatal("authority changed the signed session deadline", seconds, got, err)
				}
			}
		})
	}
}

func TestReservationAuthorityRenewsAfterAdmissionWhileSessionRemainsLive(t *testing.T) {
	claims, trust, key, state, now, _ := reservationFixture(t)
	admission := now.Add(-40 * time.Second)
	claims.IssuedAt = admission.Unix()
	claims.ExpiresAt = admission.Add(30 * time.Second).Unix()
	claims.SessionExpiresAt = now.Add(time.Minute).Unix()
	token := signReservation(t, claims, key)
	open, err := VerifyReservationData(token, claims.Authority, trust, state, admission)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{NotBefore: admission.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	until := time.Now().Unix() + 5
	a := reservationAuthorityFixture(t, token, open, cert, cert, until)
	if got, err := a.AuthorizeReservation(context.Background(), token, open); err != nil || got.Unix() != until {
		t.Fatal("live reservation incorrectly reused its expired admission deadline", got, err)
	}
}

func TestReservationAuthorityCannotOutliveEitherTLSIdentity(t *testing.T) {
	claims, _, key, _, now, open := reservationFixture(t)
	token := signReservation(t, claims, key)
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			nearExpiry := time.Now().Add(4 * time.Second).Truncate(time.Second)
			client := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
			peer := *client
			if side == "client" {
				client.NotAfter = nearExpiry
			} else {
				peer.NotAfter = nearExpiry
			}
			a := reservationAuthorityFixture(t, token, open, client, &peer, time.Now().Unix()+10)
			if got, err := a.AuthorizeReservation(context.Background(), token, open); err != nil || !got.Equal(nearExpiry) {
				t.Fatal("reservation outlived authority identity", got, err)
			}
			if side == "client" {
				client.NotAfter = time.Now()
				a.client = nil // An expired client identity must fail before sending.
			} else {
				peer.NotAfter = time.Now()
			}
			if _, err := a.AuthorizeReservation(context.Background(), token, open); err == nil {
				t.Fatal("expired authority identity renewed a reservation")
			}
		})
	}
}
