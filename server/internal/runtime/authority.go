package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var ErrUnavailable = errors.New("runtime unavailable")
var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Scope struct {
	RuntimeID            string `json:"runtimeId"`
	TeamID               string `json:"teamId"`
	InstallationID       string `json:"installationId"`
	Service              string `json:"service"`
	CredentialGeneration int64  `json:"credentialGeneration"`
	PolicyRevision       int64  `json:"policyRevision"`
	LedgerGeneration     string `json:"ledgerGeneration"`
	EnvironmentSHA256    string `json:"environmentSha256"`
}

func (s Scope) valid() bool {
	return identifier.MatchString(s.RuntimeID) && identifier.MatchString(s.TeamID) && identifier.MatchString(s.InstallationID) &&
		identifier.MatchString(s.LedgerGeneration) && digest.MatchString(s.EnvironmentSHA256) && s.Service == "notebook-v2" &&
		s.CredentialGeneration > 0 && s.CredentialGeneration < 2147483647 && s.PolicyRevision > 0 && s.PolicyRevision <= 9007199254740991
}

type Registration struct {
	Scope
	Credential string `json:"credential"`
}

type Authorizer interface {
	Authorize(context.Context, Registration) (time.Time, error)
}

type HTTPAuthority struct {
	endpoint, token string
	client          *http.Client
}

// Only operator configuration selects the authority. Runtime frames cannot supply URLs.
func NewHTTPAuthority(endpoint, token string, allowLocal bool) (*HTTPAuthority, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(token) < 32 {
		return nil, ErrUnavailable
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !allowLocal || ip == nil || !ip.IsLoopback() {
			return nil, ErrUnavailable
		}
	}
	return &HTTPAuthority{endpoint: endpoint, token: token, client: &http.Client{
		Timeout:       2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (a *HTTPAuthority) Authorize(ctx context.Context, registration Registration) (time.Time, error) {
	if !registration.Scope.valid() || len(registration.Credential) < 32 || len(registration.Credential) > 100 {
		return time.Time{}, ErrUnavailable
	}
	input := struct {
		Registration
		Op string `json:"op"`
	}{registration, "authorize"}
	body, _ := json.Marshal(input)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return time.Time{}, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	response, err := a.client.Do(req)
	if err != nil {
		return time.Time{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return time.Time{}, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		return time.Time{}, ErrUnavailable
	}
	var result struct {
		Authorized      bool      `json:"authorized"`
		Service         string    `json:"service"`
		AuthorizedUntil time.Time `json:"expiresAt"`
		Runtime         struct {
			ID string `json:"id"`
			Scope
			Provider        string     `json:"provider"`
			EnrollmentState string     `json:"enrollmentState"`
			RevokedAt       *time.Time `json:"revokedAt"`
			Policy          struct {
				ExecutionEnabled bool `json:"executionEnabled"`
			} `json:"policy"`
		} `json:"runtime"`
	}
	if json.Unmarshal(data, &result) != nil {
		return time.Time{}, ErrUnavailable
	}
	actual := result.Runtime.Scope
	actual.RuntimeID, actual.Service = result.Runtime.ID, result.Service
	now := time.Now()
	if !result.Authorized || actual != registration.Scope || result.Runtime.Provider != "customer" ||
		result.Runtime.EnrollmentState != "active" || result.Runtime.RevokedAt != nil ||
		!result.AuthorizedUntil.After(now) || result.AuthorizedUntil.After(now.Add(10*time.Second)) {
		return time.Time{}, ErrUnavailable
	}
	return result.AuthorizedUntil, nil
}
