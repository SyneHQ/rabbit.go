package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
)

func (tc *TunnelClient) dialServer() (net.Conn, error) {
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
		return dialer.Dial("tcp", address)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: tc.Config.ServerName}
	if config.ServerName == "" {
		config.ServerName = host
	}
	if tc.Config.CAFile != "" {
		pem, err := os.ReadFile(tc.Config.CAFile)
		if err != nil {
			return nil, errors.New("cannot read tunnel CA file")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid tunnel CA file")
		}
		config.RootCAs = pool
	}
	return tls.DialWithDialer(dialer, "tcp", address, config)
}
