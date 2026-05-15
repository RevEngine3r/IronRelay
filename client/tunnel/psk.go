// Package tunnel — PSK (pre-shared key) helpers.
//
// PSK uses AES-256-GCM with a 32-byte key derived directly from the
// 64-hex tunnel_key config field. Each call to Seal generates a fresh
// 12-byte random nonce prepended to the ciphertext; Open reads and
// verifies it. The wire format is:
//
//	[ 12-byte nonce | ciphertext+tag ]
//
// base64-encoded for the GS relay text path; raw bytes for CF Worker.
package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const nonceLen = 12

// PSK holds the AES-256-GCM cipher for sealing/opening relay batches.
type PSK struct {
	aead cipher.AEAD
}

// NewPSK creates a PSK from a 64-character hex string (32 bytes).
func NewPSK(hexKey string) (*PSK, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("psk: invalid hex key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("psk: key must be 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	block, err := aes.NewCipher(b)
	if err != nil {
		return nil, fmt.Errorf("psk: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("psk: new gcm: %w", err)
	}
	return &PSK{aead: aead}, nil
}

// Seal encrypts plain and returns the base64-encoded [ nonce | ciphertext+tag ].
// Use for the GS relay path (text/plain response expected).
func (p *PSK) Seal(plain []byte) (string, error) {
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("psk: rand nonce: %w", err)
	}
	ct := p.aead.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// SealRaw encrypts plain and returns the raw [ nonce | ciphertext+tag ] bytes.
// Use for the CF Worker path (binary response expected).
func (p *PSK) SealRaw(plain []byte) ([]byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("psk: rand nonce: %w", err)
	}
	return p.aead.Seal(nonce, nonce, plain, nil), nil
}

// Open decodes the base64 ciphertext, verifies the GCM tag, and returns plain.
func (p *PSK) Open(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("psk: base64 decode: %w", err)
	}
	return p.openRaw(raw)
}

// OpenRaw decodes raw [ nonce | ciphertext+tag ] bytes and returns plain.
func (p *PSK) OpenRaw(raw []byte) ([]byte, error) {
	return p.openRaw(raw)
}

func (p *PSK) openRaw(raw []byte) ([]byte, error) {
	if len(raw) < nonceLen+p.aead.Overhead() {
		return nil, fmt.Errorf("psk: ciphertext too short (%d bytes)", len(raw))
	}
	nonce, ct := raw[:nonceLen], raw[nonceLen:]
	plain, err := p.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("psk: decrypt failed (wrong key or tampered data): %w", err)
	}
	return plain, nil
}
