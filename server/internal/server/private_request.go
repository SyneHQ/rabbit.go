package server

import (
	"bufio"
	"errors"
	"net"
	"strings"

	"rabbit.go/transport"
)

const privateHeaderLimit = 16 << 10

var errPrivateRequest = errors.New("invalid private CONNECT request")

// This listener owns one HTTP/1.1 CONNECT per socket. The bounded reader retains
// any source bytes received with the headers for the existing database relay.
func readPrivateConnect(reader *bufio.Reader) (authority, token string, err error) {
	authority, token, mode, err := readPrivateConnectMode(reader)
	if err == nil && mode != "" {
		err = errPrivateRequest
	}
	return authority, token, err
}

func readPrivateConnectMode(reader *bufio.Reader) (authority, token, mode string, err error) {
	remaining := privateHeaderLimit
	readLine := func() (string, error) {
		raw, err := reader.ReadSlice('\n')
		remaining -= len(raw)
		if err != nil || remaining < 0 || !strings.HasSuffix(string(raw), "\r\n") {
			return "", errPrivateRequest
		}
		line := strings.TrimSuffix(string(raw), "\r\n")
		if strings.ContainsAny(line, "\r\n\x00") {
			return "", errPrivateRequest
		}
		return line, nil
	}
	line, err := readLine()
	if err != nil {
		return "", "", "", err
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] != "CONNECT" || parts[2] != "HTTP/1.1" || !transport.ValidAuthority(parts[1]) {
		return "", "", "", errPrivateRequest
	}
	authority = parts[1]
	seen := make(map[string]bool, 3)
	for count := 0; count < 8; count++ {
		line, err = readLine()
		if err != nil {
			return "", "", "", err
		}
		if line == "" {
			if !seen["host"] || token == "" {
				return "", "", "", errPrivateRequest
			}
			return authority, token, mode, nil
		}
		key, value, ok := strings.Cut(line, ":")
		key = strings.ToLower(key)
		if !ok || seen[key] {
			return "", "", "", errPrivateRequest
		}
		seen[key] = true
		value = strings.Trim(value, " \t")
		switch key {
		case "host":
			if value != authority {
				return "", "", "", errPrivateRequest
			}
		case "proxy-authorization":
			if !strings.HasPrefix(value, "Bearer ") {
				return "", "", "", errPrivateRequest
			}
			token = strings.TrimPrefix(value, "Bearer ")
			if len(token) == 0 || len(token) > transport.MaxTokenBytes || strings.ContainsAny(token, " \t") {
				return "", "", "", errPrivateRequest
			}
		case "rabbit-accepted-open", "rabbit-postgres-abort":
			if value != "required-v1" || mode != "" {
				return "", "", "", errPrivateRequest
			}
			mode = key
		case "user-agent":
			if len(value) > 256 {
				return "", "", "", errPrivateRequest
			}
		default:
			// In particular, bodies, chunking, proxy chaining and upgrades are
			// not legal on this dedicated protocol endpoint.
			return "", "", "", errPrivateRequest
		}
	}
	return "", "", "", errPrivateRequest
}

func privateFailure(conn net.Conn, status string) {
	_, _ = conn.Write([]byte("HTTP/1.1 " + status + "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
}
