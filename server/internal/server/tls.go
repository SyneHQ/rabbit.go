package server

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
)

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
