// Package config loads and validates the IronRelay client configuration.
// Config file path defaults to ironrelay.json in the working directory;
// override with -config flag.
package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const gsExecBase = "https://script.google.com/macros/s/%s/exec"

// ScriptKey is one Apps Script deployment entry.
type ScriptKey struct {
	ID      string `json:"id"`      // deployment ID only — URL is built automatically
	Account string `json:"account"` // optional label for per-account quota tracking
}

// Config is the top-level config struct, loaded from ironrelay.json.
type Config struct {
	// Relay endpoints
	ScriptKeys []ScriptKey `json:"script_keys"` // GS deploy IDs (auto-expanded to full URLs)
	RelayURL   string      `json:"relay_url"`   // direct CF Worker URL (alternative to script_keys)

	// PSK — 64 hex chars = 32-byte AES-256-GCM key; MUST match server
	TunnelKey string `json:"tunnel_key"`

	// SOCKS5 listener
	SocksHost string `json:"socks_host"` // default: 127.0.0.1
	SocksPort int    `json:"socks_port"` // default: 1080

	// Domain fronting
	GoogleHost string   `json:"google_host"` // Google edge IP, e.g. "216.239.38.120:443"
	SNI        []string `json:"sni"`         // SNI host list

	// SOCKS5 auth (RFC 1929) — both must be set or both omitted
	SocksUser string `json:"socks_user"`
	SocksPass string `json:"socks_pass"`

	// Tuning
	CoalesceStepMS    int  `json:"coalesce_step_ms"`    // 0 = disabled
	IdleSlotsPerBucket int `json:"idle_slots_per_bucket"` // default 1, max 3
	DebugTiming        bool `json:"debug_timing"`
	PollMS             int  `json:"poll_ms"`              // default 50
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

// Validate checks required fields and value constraints.
func (c *Config) Validate() error {
	if len(c.ScriptKeys) == 0 && c.RelayURL == "" {
		return fmt.Errorf("at least one entry in script_keys or a relay_url is required")
	}
	for i, sk := range c.ScriptKeys {
		if strings.TrimSpace(sk.ID) == "" {
			return fmt.Errorf("script_keys[%d].id is empty", i)
		}
	}
	if c.TunnelKey == "" {
		return fmt.Errorf("tunnel_key is required (generate with: ironrelay -keygen)")
	}
	b, err := hex.DecodeString(c.TunnelKey)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("tunnel_key must be 64 hex characters (32 bytes); generate with: ironrelay -keygen")
	}
	if (c.SocksUser == "") != (c.SocksPass == "") {
		return fmt.Errorf("socks_user and socks_pass must both be set or both be empty")
	}
	if c.IdleSlotsPerBucket > 3 {
		return fmt.Errorf("idle_slots_per_bucket max is 3 (got %d)", c.IdleSlotsPerBucket)
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.SocksHost == "" {
		c.SocksHost = "127.0.0.1"
	}
	if c.SocksPort == 0 {
		c.SocksPort = 1080
	}
	if c.PollMS == 0 {
		c.PollMS = 50
	}
	if c.IdleSlotsPerBucket == 0 {
		c.IdleSlotsPerBucket = 1
	}
	if len(c.SNI) == 0 {
		c.SNI = []string{"www.google.com", "mail.google.com", "accounts.google.com"}
	}
}

// ScriptURLs expands each deploy ID into its full Apps Script exec URL.
// e.g. "AKfycb..." → "https://script.google.com/macros/s/AKfycb.../exec"
func (c *Config) ScriptURLs() []string {
	urls := make([]string, 0, len(c.ScriptKeys))
	for _, sk := range c.ScriptKeys {
		id := strings.TrimSpace(sk.ID)
		if id != "" {
			urls = append(urls, fmt.Sprintf(gsExecBase, id))
		}
	}
	return urls
}

// ScriptAccounts returns the account labels in the same order as ScriptURLs.
func (c *Config) ScriptAccounts() []string {
	accts := make([]string, len(c.ScriptKeys))
	for i, sk := range c.ScriptKeys {
		accts[i] = sk.Account
	}
	return accts
}

// ListenAddr returns "host:port" for the SOCKS5 listener.
func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.SocksHost, c.SocksPort)
}
