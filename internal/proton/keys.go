package proton

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Credential is a new key pair for one certificate.
// WGPrivate is the WireGuard private key (base64). It must go only into the WireGuard file.
type Credential struct {
	EdPublic  []byte
	WGPrivate string
	WGPublic  string
}

// NewCredential makes a random Ed25519 seed. The WireGuard key derives from the seed
// as the Proton web client does: clamp(SHA-512(seed)[:32]).
func NewCredential() (*Credential, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return credentialFromSeed(seed)
}

func credentialFromSeed(seed []byte) (*Credential, error) {
	edPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	priv := x25519FromSeed(seed)
	ec, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("x25519 key: %w", err)
	}
	return &Credential{EdPublic: edPub, WGPrivate: b64(priv), WGPublic: b64(ec.PublicKey().Bytes())}, nil
}

func x25519FromSeed(seed []byte) []byte {
	h := sha512.Sum512(seed)
	k := make([]byte, 32)
	copy(k, h[:32])
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}

// PublicFromPrivate returns the WireGuard public key (base64) for a private key (base64).
func PublicFromPrivate(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		return "", fmt.Errorf("private key is not base64: %w", err)
	}
	ec, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return b64(ec.PublicKey().Bytes()), nil
}
