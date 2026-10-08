package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rabbit.go/transport"
)

const privateRoutePath = "/v1/private-transport/route"

func validPrivateIssuer(identity string, trust []PrivateTrust) bool {
	u, err := url.Parse(identity)
	if err != nil || len(identity) > 512 || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	for _, c := range identity {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	for _, entry := range trust {
		if entry.WorkerIdentity == identity {
			return false
		}
	}
	return true
}

func (p *privateConnect) routeIssuer(state tls.ConnectionState, now time.Time) bool {
	if p.issuerIdentity == "" || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return false
	}
	for _, entry := range p.trust {
		if entry.WorkerIdentity == p.issuerIdentity {
			return false
		}
	}
	leaf := state.PeerCertificates[0]
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != p.issuerIdentity {
		return false
	}
	for _, chain := range state.VerifiedChains {
		valid := len(chain) > 0 && bytes.Equal(chain[0].Raw, leaf.Raw)
		for _, cert := range chain {
			valid = valid && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
		}
		if valid {
			return true
		}
	}
	return false
}

// Route discovery accepts one bounded JSON request per authenticated socket.
// It does not accept user headers or authorize a database stream.
func readPrivateRoute(reader *bufio.Reader) (tenant, token string, err error) {
	remaining := privateHeaderLimit
	line := func() (string, error) {
		raw, err := reader.ReadSlice('\n')
		remaining -= len(raw)
		if err != nil || remaining < 0 || !bytes.HasSuffix(raw, []byte("\r\n")) {
			return "", errPrivateRequest
		}
		value := string(raw[:len(raw)-2])
		if strings.ContainsAny(value, "\r\n\x00") {
			return "", errPrivateRequest
		}
		return value, nil
	}
	first, err := line()
	if err != nil || first != "POST "+privateRoutePath+" HTTP/1.1" {
		return "", "", errPrivateRequest
	}
	seen := map[string]bool{}
	size := 0
	complete := false
	for count := 0; count < 9; count++ {
		value, err := line()
		if err != nil {
			return "", "", errPrivateRequest
		}
		if value == "" {
			complete = true
			break
		}
		key, value, ok := strings.Cut(value, ":")
		key = strings.ToLower(key)
		value = strings.Trim(value, " \t")
		if !ok || seen[key] {
			return "", "", errPrivateRequest
		}
		seen[key] = true
		switch key {
		case "host":
			if !transport.ValidAuthority(value) {
				return "", "", errPrivateRequest
			}
		case "content-type":
			if value != "application/json" {
				return "", "", errPrivateRequest
			}
		case "content-length":
			size, err = strconv.Atoi(value)
			if err != nil || size < 1 || size > 1024 || strconv.Itoa(size) != value {
				return "", "", errPrivateRequest
			}
		case "connection":
			if value != "close" {
				return "", "", errPrivateRequest
			}
		case "user-agent":
			if len(value) > 256 {
				return "", "", errPrivateRequest
			}
		case "accept-encoding":
			if value != "gzip" && value != "identity" {
				return "", "", errPrivateRequest
			}
		default:
			return "", "", errPrivateRequest
		}
	}
	if !complete || !seen["host"] || !seen["content-type"] || size == 0 {
		return "", "", errPrivateRequest
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil {
		return "", "", errPrivateRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", "", errPrivateRequest
	}
	fields := map[string]bool{}
	version := 0
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || fields[name] {
			return "", "", errPrivateRequest
		}
		fields[name] = true
		switch name {
		case "version":
			err = decoder.Decode(&version)
		case "tenant":
			err = decoder.Decode(&tenant)
		case "token_id":
			err = decoder.Decode(&token)
		default:
			return "", "", errPrivateRequest
		}
		if err != nil {
			return "", "", errPrivateRequest
		}
	}
	closing, err := decoder.Token()
	var extra any
	parsed, parseErr := uuid.Parse(token)
	if err != nil || closing != json.Delim('}') || decoder.Decode(&extra) != io.EOF || version != 1 || len(fields) != 3 || parseErr != nil || parsed.String() != token || tenant == "" || len(tenant) > 128 {
		return "", "", errPrivateRequest
	}
	for _, c := range tenant {
		if c <= 32 || c >= 127 {
			return "", "", errPrivateRequest
		}
	}
	return tenant, token, nil
}

func (s *Server) handlePrivateRoute(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, state tls.ConnectionState) {
	if !s.private.routeIssuer(state, time.Now()) {
		privateFailure(conn, "403 Forbidden")
		return
	}
	tenant, token, err := readPrivateRoute(reader)
	if err != nil {
		privateFailure(conn, "400 Bad Request")
		return
	}
	route, ok := s.privateRouteInfo(tenant, token)
	if !ok || s.private.tokenActive == nil {
		privateFailure(conn, "404 Not Found")
		return
	}
	s.mu.RLock()
	tunnel := s.tunnels[route.TunnelID]
	s.mu.RUnlock()
	if tunnel == nil {
		privateFailure(conn, "404 Not Found")
		return
	}
	check, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	until, err := s.private.tokenActive(check, tunnel)
	current, active := s.privateRouteInfo(tenant, token)
	if err != nil || check.Err() != nil || (!until.IsZero() && !until.After(time.Now())) || !active || current != route || !s.private.routeIssuer(state, time.Now()) {
		privateFailure(conn, "404 Not Found")
		return
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		privateFailure(conn, "503 Service Unavailable")
		return
	}
	for _, chain := range state.VerifiedChains {
		for _, cert := range chain {
			if cert.NotAfter.Before(deadline) {
				deadline = cert.NotAfter
			}
		}
	}
	if !until.IsZero() && until.Before(deadline) {
		deadline = until
	}
	if !deadline.After(time.Now()) || conn.SetWriteDeadline(deadline) != nil {
		return
	}
	body, err := json.Marshal(struct {
		Version int                 `json:"version"`
		Route   transport.RouteInfo `json:"route"`
	}{1, route})
	if err != nil || len(body) > 8192 {
		privateFailure(conn, "503 Service Unavailable")
		return
	}
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: private, no-store\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}
