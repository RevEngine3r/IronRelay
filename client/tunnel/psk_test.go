package tunnel

import (
	"bytes"
	"strings"
	"testing"
)

func testKey() string {
	return strings.Repeat("ab", 32) // 64 hex chars = 32 bytes
}

func TestPSK_RoundTrip(t *testing.T) {
	p, err := NewPSK(testKey())
	if err != nil {
		t.Fatalf("NewPSK: %v", err)
	}
	plain := []byte("hello ironrelay frames")

	// base64 path
	b64, err := p.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := p.Open(b64)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round-trip mismatch: got %q want %q", got, plain)
	}

	// raw path
	raw, err := p.SealRaw(plain)
	if err != nil {
		t.Fatalf("SealRaw: %v", err)
	}
	got2, err := p.OpenRaw(raw)
	if err != nil {
		t.Fatalf("OpenRaw: %v", err)
	}
	if !bytes.Equal(got2, plain) {
		t.Errorf("raw round-trip mismatch: got %q want %q", got2, plain)
	}
}

func TestPSK_Tamper(t *testing.T) {
	p, _ := NewPSK(testKey())
	raw, _ := p.SealRaw([]byte("secret"))
	raw[len(raw)-1] ^= 0xff // flip last byte of GCM tag
	if _, err := p.OpenRaw(raw); err == nil {
		t.Error("expected error on tampered ciphertext")
	}
}

func TestPSK_WrongKey(t *testing.T) {
	p1, _ := NewPSK(testKey())
	p2, _ := NewPSK(strings.Repeat("cd", 32))
	b64, _ := p1.Seal([]byte("secret"))
	if _, err := p2.Open(b64); err == nil {
		t.Error("expected error with wrong key")
	}
}

func TestPSK_UniqueNonces(t *testing.T) {
	p, _ := NewPSK(testKey())
	a, _ := p.SealRaw([]byte("x"))
	b, _ := p.SealRaw([]byte("x"))
	if bytes.Equal(a[:12], b[:12]) {
		t.Error("two Seal calls should produce different nonces")
	}
}

func TestNewPSK_BadKey(t *testing.T) {
	if _, err := NewPSK("tooshort"); err == nil {
		t.Error("expected error for short key")
	}
	if _, err := NewPSK("gggg" + strings.Repeat("ab", 30)); err == nil {
		t.Error("expected error for invalid hex")
	}
}
