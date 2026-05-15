package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func validKey() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return hex.EncodeToString(b)
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "ironrelay.json")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_Valid(t *testing.T) {
	p := writeConfig(t, `{
		"script_keys": [{"id": "AKfycbABC123", "account": "a"}],
		"tunnel_key": "`+validKey()+`"
	}`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	urls := cfg.ScriptURLs()
	if len(urls) != 1 {
		t.Fatalf("expected 1 url, got %d", len(urls))
	}
	const want = "https://script.google.com/macros/s/AKfycbABC123/exec"
	if urls[0] != want {
		t.Errorf("url: got %q, want %q", urls[0], want)
	}
}

func TestLoad_MultiDeploy(t *testing.T) {
	p := writeConfig(t, `{
		"script_keys": [
			{"id": "ID1", "account": "a"},
			{"id": "ID2", "account": "a"},
			{"id": "ID3", "account": "b"}
		],
		"tunnel_key": "`+validKey()+`"
	}`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ScriptURLs()) != 3 {
		t.Errorf("expected 3 urls, got %d", len(cfg.ScriptURLs()))
	}
}

func TestLoad_MissingKey(t *testing.T) {
	p := writeConfig(t, `{"script_keys": [{"id": "X"}]}`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for missing tunnel_key")
	}
}

func TestLoad_BadKeyLength(t *testing.T) {
	p := writeConfig(t, `{"script_keys": [{"id": "X"}], "tunnel_key": "deadbeef"}`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for short tunnel_key")
	}
}

func TestLoad_NoEndpoints(t *testing.T) {
	p := writeConfig(t, `{"tunnel_key": "`+validKey()+`"}`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for no endpoints")
	}
}

func TestLoad_Defaults(t *testing.T) {
	p := writeConfig(t, `{"script_keys":[{"id":"X"}],"tunnel_key":"`+validKey()+`"}`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SocksHost != "127.0.0.1" {
		t.Errorf("default socks_host: got %q", cfg.SocksHost)
	}
	if cfg.SocksPort != 1080 {
		t.Errorf("default socks_port: got %d", cfg.SocksPort)
	}
	if cfg.PollMS != 50 {
		t.Errorf("default poll_ms: got %d", cfg.PollMS)
	}
	if len(cfg.SNI) == 0 {
		t.Error("default SNI should not be empty")
	}
}

func TestLoad_RelayURL(t *testing.T) {
	p := writeConfig(t, `{"relay_url":"https://x.workers.dev/tunnel","tunnel_key":"`+validKey()+`"}`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RelayURL == "" {
		t.Error("relay_url not loaded")
	}
}
