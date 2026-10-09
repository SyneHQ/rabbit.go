package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"rabbit.go/transport"
)

// PrivateConnectConfig is installation-owned. Only files reference private keys.
// Worker identity entries do not authorize any source without the live issuer.
type PrivateConnectConfig struct {
	IssuerIdentity         string         `yaml:"issuer_identity"`
	Listen                 string         `yaml:"listen"`
	PrivateInterface       string         `yaml:"private_interface"`
	CertificateFile        string         `yaml:"certificate_file"`
	PrivateKeyFile         string         `yaml:"private_key_file"`
	PrivateKeyGroup        *uint32        `yaml:"private_key_group"`
	ClientCAFile           string         `yaml:"client_ca_file"`
	AuthorityURL           string         `yaml:"authority_url"`
	AuthorityCAFile        string         `yaml:"authority_ca_file"`
	AuthorityCertificate   string         `yaml:"authority_certificate_file"`
	AuthorityPrivateKey    string         `yaml:"authority_private_key_file"`
	AcceptedKeyID          string         `yaml:"accepted_key_id"`
	AcceptedPrivateKeyFile string         `yaml:"accepted_private_key_file"`
	CleanupAuthorityURL    string         `yaml:"cleanup_authority_url"`
	ReplayCapacity         int            `yaml:"replay_capacity"`
	Trust                  []PrivateTrust `yaml:"trust"`
}

type PrivateTrust struct {
	Issuer           string `yaml:"issuer"`
	Audience         string `yaml:"audience"`
	ClusterTenant    string `yaml:"cluster_tenant"`
	ServicePrincipal string `yaml:"service_principal"`
	WorkerIdentity   string `yaml:"worker_identity"`
	PublicKeyHex     string `yaml:"public_key_hex"`
}

type privateConnect struct {
	issuerIdentity string
	acceptedKeyID  string
	acceptedKey    ed25519.PrivateKey
	accepted       map[string]*acceptedPrivateParent
	acceptedLimit  int
	cleanup        transport.CleanupAuthority
	address        string
	tls            *tls.Config
	trust          []transport.Trust
	replays        *transport.ReplayRegistry
	authority      transport.LeaseAuthority
	tokenActive    func(context.Context, *Tunnel) (time.Time, error)
	close          func()
	failed         atomic.Bool
}

func loadPrivateConnect(config *PrivateConnectConfig) (*privateConnect, error) {
	if config == nil {
		return nil, nil
	}
	fail := func() (*privateConnect, error) { return nil, fmt.Errorf("invalid private CONNECT configuration") }
	address, err := privateBindAddress(config.Listen, config.PrivateInterface)
	if err != nil || len(config.Trust) < 1 || len(config.Trust) > 64 {
		return fail()
	}
	if config.IssuerIdentity != "" && !validPrivateIssuer(config.IssuerIdentity, config.Trust) {
		return fail()
	}
	if config.PrivateKeyGroup != nil && !operatorGroupMember(*config.PrivateKeyGroup) {
		return fail()
	}
	replayCapacity := config.ReplayCapacity
	if replayCapacity == 0 {
		replayCapacity = 16384
	}
	replays, err := transport.NewReplayRegistry(replayCapacity)
	if err != nil {
		return fail()
	}
	certificate, err := privateCertificate(config.CertificateFile, config.PrivateKeyFile, config.PrivateKeyGroup)
	if err != nil {
		return fail()
	}
	clientCA, err := privateCA(config.ClientCAFile)
	if err != nil {
		return fail()
	}
	authorityCA, err := privateCA(config.AuthorityCAFile)
	if err != nil {
		return fail()
	}
	authorityCertificate, err := privateCertificate(config.AuthorityCertificate, config.AuthorityPrivateKey, config.PrivateKeyGroup)
	if err != nil {
		return fail()
	}
	result := &privateConnect{address: address, replays: replays, issuerIdentity: config.IssuerIdentity,
		tls: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: clientCA, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}},
	}
	seen := make(map[string]bool)
	for _, entry := range config.Trust {
		key, err := hex.DecodeString(entry.PublicKeyHex)
		identity, identityErr := url.Parse(entry.WorkerIdentity)
		if err != nil || len(key) != ed25519.PublicKeySize || identityErr != nil || identity.Scheme != "spiffe" || identity.Host == "" || identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" {
			return fail()
		}
		for index, value := range []string{entry.Issuer, entry.Audience, entry.ClusterTenant, entry.ServicePrincipal, entry.WorkerIdentity} {
			limit := 128
			if index == 4 {
				limit = 512
			}
			if value == "" || len(value) > limit {
				return fail()
			}
			for _, char := range value {
				if char <= 32 || char >= 127 {
					return fail()
				}
			}
		}
		identityKey := entry.Issuer + "\x00" + entry.Audience + "\x00" + entry.ClusterTenant + "\x00" + entry.ServicePrincipal + "\x00" + entry.WorkerIdentity
		if seen[identityKey] {
			return fail()
		}
		seen[identityKey] = true
		result.trust = append(result.trust, transport.Trust{Issuer: entry.Issuer, Audience: entry.Audience,
			ClusterTenant: entry.ClusterTenant, ServicePrincipal: entry.ServicePrincipal, WorkerIdentity: entry.WorkerIdentity, PublicKey: key})
	}
	authority, err := transport.NewHTTPLeaseAuthority(config.AuthorityURL, &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: authorityCA, Certificates: []tls.Certificate{authorityCertificate}})
	if err != nil {
		return fail()
	}
	result.authority, result.close = authority, authority.Close
	if config.AcceptedKeyID != "" || config.AcceptedPrivateKeyFile != "" || config.CleanupAuthorityURL != "" {
		keyData, keyErr := privateFileForGroup(config.AcceptedPrivateKeyFile, true, config.PrivateKeyGroup)
		block, rest := pem.Decode(keyData)
		if keyErr != nil || block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" || config.AcceptedKeyID == "" || config.CleanupAuthorityURL == "" {
			authority.Close()
			return fail()
		}
		parsed, keyErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		key, ok := parsed.(ed25519.PrivateKey)
		if keyErr != nil || !ok {
			authority.Close()
			return fail()
		}
		for _, trust := range result.trust {
			if bytes.Equal(key.Public().(ed25519.PublicKey), trust.PublicKey) {
				authority.Close()
				return fail()
			}
		}
		now := time.Now().Unix()
		_, keyErr = transport.SignAcceptedOpen(transport.AcceptedOpenClaims{Version: 1, DataTicketSHA256: strings.Repeat("a", 64), AcceptanceID: strings.Repeat("b", 32), AcceptedAt: now, ExpiresAt: now + 1}, config.AcceptedKeyID, key)
		if keyErr != nil || len(config.AcceptedKeyID) > 128 || strings.ContainsAny(config.AcceptedKeyID, " \t\r\n") {
			authority.Close()
			return fail()
		}
		cleanup, cleanupErr := transport.NewHTTPLeaseAuthority(config.CleanupAuthorityURL, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: authorityCA, Certificates: []tls.Certificate{authorityCertificate}})
		if cleanupErr != nil {
			authority.Close()
			return fail()
		}
		result.acceptedKeyID, result.acceptedKey = config.AcceptedKeyID, key
		result.accepted = make(map[string]*acceptedPrivateParent)
		result.acceptedLimit = replayCapacity
		result.cleanup = cleanup
		result.close = func() { authority.Close(); cleanup.Close() }
	}
	return result, nil
}

func privateFile(path string, secret bool) ([]byte, error) {
	return privateFileForGroup(path, secret, nil)
}

func privateFileForGroup(path string, secret bool, trustedGroup *uint32) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, transport.ErrAuthority
	}
	file, err := openOperatorFile(path)
	if err != nil {
		return nil, transport.ErrAuthority
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 || info.Mode().Perm()&0022 != 0 || !operatorFileOwnerAllowed(info) {
		return nil, transport.ErrAuthority
	}
	if secret && info.Mode().Perm()&0077 != 0 && (info.Mode().Perm()&0077 != 0040 || trustedGroup == nil || !operatorGroupMember(*trustedGroup) || !operatorFileGroupAllowed(info, *trustedGroup)) {
		return nil, transport.ErrAuthority
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return nil, transport.ErrAuthority
	}
	return data, nil
}

func privateCertificate(certFile, keyFile string, trustedGroup *uint32) (tls.Certificate, error) {
	cert, err := privateFile(certFile, false)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := privateFileForGroup(keyFile, true, trustedGroup)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(cert, key)
}

func privateCA(path string) (*x509.CertPool, error) {
	data, err := privateFile(path, false)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, transport.ErrAuthority
	}
	return pool, nil
}
