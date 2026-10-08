package transport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
)

func signClaims(claims any, issuer, tokenType string, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", ErrAuthority
	}
	header, _ := json.Marshal(joseHeader{"EdDSA", tokenType, issuer})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", ErrAuthority
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	token := unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(unsigned)))
	if len(token) > MaxTokenBytes {
		return "", ErrAuthority
	}
	return token, nil
}

func verifySignedClaims(token, tokenType string, trust Trust, claims any) error {
	if len(token) == 0 || len(token) > MaxTokenBytes || len(trust.PublicKey) != ed25519.PublicKeySize {
		return ErrAuthority
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrAuthority
	}
	decode := base64.RawURLEncoding.Strict().DecodeString
	headerBytes, e1 := decode(parts[0])
	payload, e2 := decode(parts[1])
	signature, e3 := decode(parts[2])
	if e1 != nil || e2 != nil || e3 != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(trust.PublicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return ErrAuthority
	}
	var header joseHeader
	if decodeStrict(headerBytes, &header) != nil || decodeStrict(payload, claims) != nil ||
		header.Algorithm != "EdDSA" || header.Type != tokenType || header.KeyID != trust.Issuer {
		return ErrAuthority
	}
	return nil
}
