package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

type tlsConfigKey struct {
	address    string
	serverName string
	caFile     string
	caDigest   [32]byte
}

func (tc *TunnelClient) dialServer() (net.Conn, error) {
	return tc.dialServerContext(context.Background())
}

func (tc *TunnelClient) dialServerContext(ctx context.Context) (net.Conn, error) {
	address := tc.Config.ServerAddress
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		address = net.JoinHostPort(address, "9999")
	}
	dialer := &net.Dialer{Timeout: tc.Config.ConnectionTimeout}
	if tc.Config.InsecureLocal {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("plaintext is restricted to literal loopback addresses")
		}
		return dialer.DialContext(ctx, "tcp", address)
	}
	config, err := tc.serverTLSConfig(ctx, address, host)
	if err != nil {
		return nil, err
	}
	return (&tls.Dialer{NetDialer: dialer, Config: config}).DialContext(ctx, "tcp", address)
}

// serverTLSConfig reuses parsed roots and session tickets within one client.
// Re-read a regular custom CA (at most 1 MiB) on every dial to detect replacement.
// Changed trust or identity discards the old cache before another handshake.
// System roots follow Go's process-wide trust-store caching; restart to reload.
func (tc *TunnelClient) serverTLSConfig(ctx context.Context, address, host string) (*tls.Config, error) {
	key := tlsConfigKey{address: address, serverName: tc.Config.ServerName, caFile: tc.Config.CAFile}
	if key.serverName == "" {
		key.serverName = host
	}
	var pem []byte
	if key.caFile != "" {
		var err error
		pem, err = readCAFile(ctx, key.caFile)
		if err != nil {
			return nil, err
		}
		key.caDigest = sha256.Sum256(pem)
	}
	tc.tlsMu.Lock()
	defer tc.tlsMu.Unlock()
	if tc.tlsConfig != nil && tc.tlsKey == key {
		return tc.tlsConfig, nil
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: key.serverName,
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
	}
	if key.caFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid tunnel CA file")
		}
		config.RootCAs = pool
	}
	tc.tlsKey, tc.tlsConfig = key, config
	return config, nil
}
