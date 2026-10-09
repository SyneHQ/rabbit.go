package server

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
)

// managementListener enables TLS when either management certificate setting is
// present. Incomplete or invalid settings must never fall back to plaintext.
func managementListener(address string) (net.Listener, error) {
	certFile := os.Getenv("RABBIT_API_TLS_CERT_FILE")
	keyFile := os.Getenv("RABBIT_API_TLS_KEY_FILE")
	if certFile == "" && keyFile == "" {
		return net.Listen("tcp", address)
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("Rabbit management TLS requires both certificate and key files")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, errors.New("Rabbit management TLS certificate or key is invalid")
	}
	return tls.Listen("tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
}

func controlListener(address string) (net.Listener, error) {
	var cert tls.Certificate
	var err error
	certPEM, keyPEM := os.Getenv("RABBIT_TLS_CERT_PEM"), os.Getenv("RABBIT_TLS_KEY_PEM")
	certFile, keyFile := os.Getenv("RABBIT_TLS_CERT_FILE"), os.Getenv("RABBIT_TLS_KEY_FILE")
	switch {
	case certPEM != "" || keyPEM != "":
		cert, err = tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	case certFile != "" || keyFile != "":
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	default:
		host, _, splitErr := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if splitErr == nil && ip != nil && ip.IsLoopback() && os.Getenv("RABBIT_ALLOW_INSECURE_LOCAL") == "true" && os.Getenv("ENVIRONMENT") != "production" {
			return net.Listen("tcp", address)
		}
		return nil, errors.New("Rabbit requires TLS certificates; plaintext is allowed only with explicit local development configuration")
	}
	if err != nil {
		return nil, errors.New("invalid Rabbit TLS certificate configuration")
	}
	return tls.Listen("tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
}
