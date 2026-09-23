package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

var runtimeIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var runtimeDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var errRuntimeTransport = errors.New("runtime transport unavailable")

type RuntimeScope struct {
	RuntimeID            string `json:"runtimeId"`
	TeamID               string `json:"teamId"`
	InstallationID       string `json:"installationId"`
	Service              string `json:"service"`
	CredentialGeneration int64  `json:"credentialGeneration"`
	PolicyRevision       int64  `json:"policyRevision"`
	LedgerGeneration     string `json:"ledgerGeneration"`
	EnvironmentSHA256    string `json:"environmentSha256"`
}
type RuntimeRegistration struct {
	RuntimeScope
	Credential string `json:"credential"`
}
type RuntimeClient struct {
	Dial          TunnelClientConfig
	Registration  RuntimeRegistration
	HelperAddress string
}

func (c *RuntimeClient) Validate() error { return c.validate() }

func (c *RuntimeClient) validate() error {
	s := c.Registration.RuntimeScope
	host, port, err := net.SplitHostPort(c.HelperAddress)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() || port == "0" || port == "" || c.Dial.InsecureLocal ||
		!runtimeIdentifier.MatchString(s.RuntimeID) || !runtimeIdentifier.MatchString(s.TeamID) || !runtimeIdentifier.MatchString(s.InstallationID) ||
		!runtimeIdentifier.MatchString(s.LedgerGeneration) || !runtimeDigest.MatchString(s.EnvironmentSHA256) || s.Service != "notebook-v2" ||
		s.CredentialGeneration < 1 || s.CredentialGeneration >= 2147483647 || s.PolicyRevision < 1 || s.PolicyRevision > 9007199254740991 ||
		len(c.Registration.Credential) < 32 || len(c.Registration.Credential) > 100 {
		return errRuntimeTransport
	}
	return nil
}

// Run reconnects transport only. It never resubmits a notebook request.
func (c *RuntimeClient) Run(ctx context.Context) error {
	if err := c.validate(); err != nil {
		return err
	}
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		_ = c.runOnce(ctx)
		if time.Since(started) > 20*time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if delay < 10*time.Second {
			delay *= 2
			if delay > 10*time.Second {
				delay = 10 * time.Second
			}
		}
	}
	return ctx.Err()
}

func (c *RuntimeClient) dial() (net.Conn, error) {
	config := c.Dial
	config.ConnectionTimeout = 5 * time.Second
	return (&TunnelClient{Config: config}).dialServer()
}
func runtimeWrite(conn net.Conn, frame string, value any) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) > 4000 {
		return errRuntimeTransport
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(conn, frame+"\n"+string(body)+"\n")
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}
func runtimeLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 4096 {
		return "", errRuntimeTransport
	}
	return strings.TrimSuffix(string(line), "\n"), nil
}
func (c *RuntimeClient) runOnce(parent context.Context) error {
	conn, err := c.dial()
	if err != nil {
		return errRuntimeTransport
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if runtimeWrite(conn, "RUNTIME-V2", c.Registration) != nil {
		return errRuntimeTransport
	}
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := runtimeLine(reader)
	if err != nil || line != "READY" {
		return errRuntimeTransport
	}
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if _, err := io.WriteString(conn, "PING\n"); err != nil {
					cancel()
					return
				}
				_ = conn.SetWriteDeadline(time.Time{})
			}
		}
	}()
	semaphore := make(chan struct{}, 8)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := runtimeLine(reader)
		if err != nil {
			return errRuntimeTransport
		}
		if line == "PONG" {
			continue
		}
		id, ok := strings.CutPrefix(line, "OPEN ")
		if !ok || !runtimeDigest.MatchString(id) {
			return errRuntimeTransport
		}
		select {
		case semaphore <- struct{}{}:
		default:
			return errRuntimeTransport
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer func() { <-semaphore }(); c.connectData(ctx, id) }()
	}
}

func (c *RuntimeClient) connectData(ctx context.Context, id string) {
	conn, err := c.dial()
	if err != nil {
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	request := struct {
		RuntimeRegistration
		ConnectionID string `json:"connectionId"`
	}{c.Registration, id}
	if runtimeWrite(conn, "RUNTIME-DATA-V2", request) != nil {
		return
	}
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := runtimeLine(reader)
	if err != nil || line != "PAIRED" {
		return
	}
	local, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", c.HelperAddress)
	if err != nil {
		return
	}
	defer local.Close()
	stopLocal := context.AfterFunc(ctx, func() { local.Close() })
	defer stopLocal()
	_ = conn.SetDeadline(time.Now().Add(180 * time.Second))
	_ = local.SetDeadline(time.Now().Add(180 * time.Second))
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(local, reader); conn.Close(); local.Close(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, local); conn.Close(); local.Close(); done <- struct{}{} }()
	<-done
	<-done
}
