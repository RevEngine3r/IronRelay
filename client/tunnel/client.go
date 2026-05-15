// Package tunnel manages the HTTP long-poll loop and per-session state.
//
// Outbound frame batches are AES-256-GCM sealed with the shared PSK before
// being POSTed; inbound response bodies are unsealed before frame parsing.
//
// Relay modes:
//  1. GS relay (script_keys): response is text/plain base64(nonce+ct);
//     Send body is also base64-encoded.
//  2. CF Worker (relay_url): response is raw binary (nonce+ct);
//     Send body is raw binary.
//
// Multiple endpoints are round-robined; failing endpoints are blacklisted
// with exponential backoff (3s base → 1h max).
package tunnel

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RevEngine3r/IronRelay/client/config"
	"github.com/RevEngine3r/IronRelay/client/frame"
	"github.com/RevEngine3r/IronRelay/client/fronting"
)

const (
	endpointBlacklistBase = 3 * time.Second
	endpointBlacklistMax  = 1 * time.Hour
	maxFramesPerPoll      = 64
)

// endpoint tracks one relay URL plus its health state.
type endpoint struct {
	url             string
	account         string
	blacklistedTill time.Time
	failCount       int
}

// Session holds the pipe between the SOCKS5 handler and the poll loop.
type Session struct {
	id      frame.SessionID
	downRx  chan []byte
	closeCh chan struct{}
	once    sync.Once
}

func (s *Session) Close() { s.once.Do(func() { close(s.closeCh) }) }
func (s *Session) Done() <-chan struct{}   { return s.closeCh }
func (s *Session) DownRx() <-chan []byte  { return s.downRx }

// Client is the tunnel entry point used by the SOCKS5 server.
type Client struct {
	psk    *PSK
	gsMode bool // true = GS relay (base64); false = CF Worker (binary)

	httpClients []*http.Client
	rrIdx       atomic.Uint64

	endpointMu   sync.Mutex
	endpoints    []endpoint
	nextEndpoint int

	mu       sync.Mutex
	sessions map[frame.SessionID]*Session
	outbound chan *frame.Frame

	pollMS int
}

// NewClient constructs a plain direct client (no config file).
func NewClient(relayURL, token string, pollMS int) *Client {
	c := &Client{
		httpClients: []*http.Client{{Timeout: 30 * time.Second}},
		endpoints:   []endpoint{{url: relayURL}},
		sessions:    make(map[frame.SessionID]*Session),
		outbound:    make(chan *frame.Frame, 4096),
		pollMS:      pollMS,
		gsMode:      false,
	}
	// Legacy token-based auth (no PSK encryption)
	if token != "" {
		// store token in account field as a sentinel — handled in poll()
		c.endpoints[0].account = "__token__:" + token
	}
	go c.pollLoop()
	return c
}

// NewClientFromConfig constructs a fully-configured client from a loaded Config.
func NewClientFromConfig(cfg *config.Config) (*Client, error) {
	psk, err := NewPSK(cfg.TunnelKey)
	if err != nil {
		return nil, fmt.Errorf("tunnel: %w", err)
	}

	// Build endpoint list
	var endpoints []endpoint
	gsMode := false
	if len(cfg.ScriptKeys) > 0 {
		urls := cfg.ScriptURLs()
		accts := cfg.ScriptAccounts()
		for i, u := range urls {
			ep := endpoint{url: u}
			if i < len(accts) {
				ep.account = accts[i]
			}
			endpoints = append(endpoints, ep)
		}
		gsMode = true
	} else {
		endpoints = []endpoint{{url: cfg.RelayURL}}
	}

	// Build HTTP clients (fronted or direct)
	var httpClients []*http.Client
	if cfg.GoogleHost != "" || len(cfg.SNI) > 0 {
		fcfg := fronting.Config{
			GoogleIP: cfg.GoogleHost,
			SNIHosts: cfg.SNI,
		}
		httpClients = fronting.NewClients(fcfg, 25*time.Second, "")
		log.Printf("[tunnel] domain fronting enabled sni=%v", cfg.SNI)
	} else {
		httpClients = []*http.Client{{Timeout: 30 * time.Second}}
	}

	c := &Client{
		psk:         psk,
		gsMode:      gsMode,
		httpClients: httpClients,
		endpoints:   endpoints,
		sessions:    make(map[frame.SessionID]*Session),
		outbound:    make(chan *frame.Frame, 4096),
		pollMS:      cfg.PollMS,
	}
	log.Printf("[tunnel] %d endpoint(s), gs_mode=%v", len(endpoints), gsMode)
	go c.pollLoop()
	return c, nil
}

// NewClientFronted constructs a fronted client (legacy; prefer NewClientFromConfig).
func NewClientFronted(relayURL, token string, pollMS int, cfg fronting.Config, pollTimeout time.Duration, probeURL string) *Client {
	clients := fronting.NewClients(cfg, pollTimeout, probeURL)
	c := &Client{
		httpClients: clients,
		endpoints:   []endpoint{{url: relayURL}},
		sessions:    make(map[frame.SessionID]*Session),
		outbound:    make(chan *frame.Frame, 4096),
		pollMS:      pollMS,
	}
	if token != "" {
		c.endpoints[0].account = "__token__:" + token
	}
	go c.pollLoop()
	return c
}

// ---------- endpoint round-robin + blacklist ---------------------------------

func (c *Client) pickEndpoint() (int, string) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	n := len(c.endpoints)
	if n == 0 {
		return -1, ""
	}
	now := time.Now()
	start := c.nextEndpoint % n
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if !c.endpoints[idx].blacklistedTill.After(now) {
			c.nextEndpoint = (idx + 1) % n
			return idx, c.endpoints[idx].url
		}
	}
	// All blacklisted: pick soonest to recover.
	chosen, soonest := 0, c.endpoints[0].blacklistedTill
	for i := 1; i < n; i++ {
		if c.endpoints[i].blacklistedTill.Before(soonest) {
			chosen, soonest = i, c.endpoints[i].blacklistedTill
		}
	}
	c.nextEndpoint = (chosen + 1) % n
	return chosen, c.endpoints[chosen].url
}

func (c *Client) markSuccess(idx int) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if idx < 0 || idx >= len(c.endpoints) {
		return
	}
	was := c.endpoints[idx].failCount
	c.endpoints[idx].failCount = 0
	c.endpoints[idx].blacklistedTill = time.Time{}
	if was > 0 {
		log.Printf("[tunnel] endpoint %s recovered", shortKey(c.endpoints[idx].url))
	}
}

func (c *Client) markFailure(idx int) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if idx < 0 || idx >= len(c.endpoints) {
		return
	}
	ep := &c.endpoints[idx]
	was := ep.failCount == 0
	ep.failCount++
	ttl := blacklistTTL(ep.failCount)
	ep.blacklistedTill = time.Now().Add(ttl)
	if was {
		log.Printf("[tunnel] endpoint %s blacklisted for %s", shortKey(ep.url), ttl.Round(100*time.Millisecond))
	}
}

func blacklistTTL(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	base := endpointBlacklistBase
	for i := 1; i < n && i < 8; i++ {
		base *= 2
	}
	if base > endpointBlacklistMax {
		return endpointBlacklistMax
	}
	return base
}

func shortKey(u string) string {
	parts := strings.Split(strings.TrimRight(u, "/"), "/")
	for i, p := range parts {
		if p == "s" && i+1 < len(parts) {
			id := parts[i+1]
			if len(id) > 14 {
				return id[:6] + "..." + id[len(id)-6:]
			}
			return id
		}
	}
	return u
}

// ---------- session management -----------------------------------------------

func (c *Client) OpenSession(target string) *Session {
	var id frame.SessionID
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	s := &Session{
		id:      id,
		downRx:  make(chan []byte, 256),
		closeCh: make(chan struct{}),
	}
	c.mu.Lock()
	c.sessions[id] = s
	c.mu.Unlock()
	c.outbound <- &frame.Frame{Cmd: frame.CmdSYN, SessionID: id, Payload: []byte(target)}
	return s
}

func (c *Client) Send(s *Session, data []byte) {
	if len(data) == 0 {
		return
	}
	p := make([]byte, len(data))
	copy(p, data)
	c.outbound <- &frame.Frame{Cmd: frame.CmdDATA, SessionID: s.id, Payload: p}
}

func (c *Client) CloseSession(s *Session) {
	c.outbound <- &frame.Frame{Cmd: frame.CmdFIN, SessionID: s.id}
	c.mu.Lock()
	delete(c.sessions, s.id)
	c.mu.Unlock()
	s.Close()
}

// ---------- poll loop --------------------------------------------------------

func (c *Client) pollLoop() {
	ticker := time.NewTicker(time.Duration(c.pollMS) * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		c.poll()
	}
}

func (c *Client) nextHTTPClient() *http.Client {
	idx := c.rrIdx.Add(1) - 1
	return c.httpClients[idx%uint64(len(c.httpClients))]
}

func (c *Client) poll() {
	// Drain up to maxFramesPerPoll outbound frames into a binary batch.
	var raw bytes.Buffer
	for i := 0; i < maxFramesPerPoll; i++ {
		select {
		case f := <-c.outbound:
			if err := f.WriteTo(&raw); err != nil {
				log.Printf("[tunnel] encode: %v", err)
			}
		default:
			goto send
		}
	}
send:
	ep_idx, epURL := c.pickEndpoint()
	if epURL == "" {
		return
	}

	// Build request body, optionally PSK-sealed.
	var body []byte
	var contentType string
	if c.psk != nil && c.gsMode {
		// GS path: seal and base64-encode for text/plain transit.
		b64, err := c.psk.Seal(raw.Bytes())
		if err != nil {
			log.Printf("[tunnel] psk seal: %v", err)
			return
		}
		body = []byte(b64)
		contentType = "text/plain"
	} else if c.psk != nil {
		// CF Worker path: seal as raw bytes.
		sealed, err := c.psk.SealRaw(raw.Bytes())
		if err != nil {
			log.Printf("[tunnel] psk seal: %v", err)
			return
		}
		body = sealed
		contentType = "application/octet-stream"
	} else {
		// No PSK (legacy -token mode).
		body = raw.Bytes()
		contentType = "application/octet-stream"
	}

	req, err := http.NewRequest(http.MethodPost, epURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("[tunnel] build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", contentType)

	// Legacy token header (non-PSK mode).
	if len(c.endpoints) > 0 && strings.HasPrefix(c.endpoints[ep_idx].account, "__token__:") {
		tok := strings.TrimPrefix(c.endpoints[ep_idx].account, "__token__:")
		req.Header.Set("X-Relay-Token", tok)
	}

	resp, err := c.nextHTTPClient().Do(req)
	if err != nil {
		log.Printf("[tunnel] POST %s: %v", shortKey(epURL), err)
		c.markFailure(ep_idx)
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		c.markSuccess(ep_idx)
		return
	case http.StatusForbidden:
		log.Printf("[tunnel] 403 from %s — wrong PSK or quota exhausted", shortKey(epURL))
		c.markFailure(ep_idx)
		return
	case http.StatusOK:
		// fall through
	default:
		log.Printf("[tunnel] HTTP %d from %s", resp.StatusCode, shortKey(epURL))
		c.markFailure(ep_idx)
		return
	}

	// Read and PSK-unseal the response.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[tunnel] read body: %v", err)
		c.markFailure(ep_idx)
		return
	}

	var frames []byte
	ct := resp.Header.Get("Content-Type")
	if c.psk != nil && (strings.Contains(ct, "text/plain") || strings.Contains(ct, "text/html")) {
		// GS relay: base64 ciphertext → open.
		plain, err := c.psk.Open(strings.TrimSpace(string(respBody)))
		if err != nil {
			log.Printf("[tunnel] psk open (gs): %v", err)
			c.markFailure(ep_idx)
			return
		}
		frames = plain
	} else if c.psk != nil {
		// CF Worker: raw ciphertext → open.
		plain, err := c.psk.OpenRaw(respBody)
		if err != nil {
			log.Printf("[tunnel] psk open (cf): %v", err)
			c.markFailure(ep_idx)
			return
		}
		frames = plain
	} else {
		// No PSK — legacy path.
		frames = respBody
	}

	c.markSuccess(ep_idx)
	c.decodeResponse(bytes.NewReader(frames))
}

func (c *Client) decodeResponse(r io.Reader) {
	for {
		f, err := frame.ReadFrom(r)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Printf("[tunnel] decode: %v", err)
			}
			return
		}
		switch f.Cmd {
		case frame.CmdACK:
			c.routeACK(f)
		case frame.CmdFIN:
			c.routeFIN(f)
		default:
			log.Printf("[tunnel] unexpected cmd 0x%02x from server", f.Cmd)
		}
	}
}

func (c *Client) routeACK(f *frame.Frame) {
	c.mu.Lock()
	s, ok := c.sessions[f.SessionID]
	c.mu.Unlock()
	if !ok {
		return
	}
	select {
	case s.downRx <- f.Payload:
	default:
		log.Printf("[tunnel] downRx full for session %x, dropping", f.SessionID[:4])
	}
}

func (c *Client) routeFIN(f *frame.Frame) {
	c.mu.Lock()
	s, ok := c.sessions[f.SessionID]
	if ok {
		delete(c.sessions, f.SessionID)
	}
	c.mu.Unlock()
	if ok {
		s.Close()
	}
}
