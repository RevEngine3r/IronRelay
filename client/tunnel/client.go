// Package tunnel manages the HTTP long-poll loop and per-session state.
//
// Two transport modes are supported:
//
//  1. Direct: plain http.Client → CF Worker (binary response body)
//  2. Fronted: NewClientFronted() uses Google-based domain fronting.
//     The relay (Apps Script or CF Worker) returns text/plain base64 when
//     reached via Apps Script ContentService, so decodeResponse detects
//     the Content-Type and base64-decodes before parsing frames.
package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RevEngine3r/IronRelay/client/frame"
	"github.com/RevEngine3r/IronRelay/client/fronting"
)

// Session holds the pipe between the SOCKS5 handler and the poll loop.
type Session struct {
	id      frame.SessionID
	downRx  chan []byte     // ACK bytes from remote → SOCKS5 writer
	upTx    chan *frame.Frame // frames queued for next POST
	closeCh chan struct{}
	once    sync.Once
}

func (s *Session) Close() {
	s.once.Do(func() { close(s.closeCh) })
}

func (s *Session) Done() <-chan struct{} { return s.closeCh }

// DownRx returns the channel on which inbound ACK payloads are delivered.
func (s *Session) DownRx() <-chan []byte { return s.downRx }

// Client is the tunnel entry point used by the SOCKS5 server.
type Client struct {
	relayURL string
	token    string
	pollMS   int

	// httpClients holds one client per fronted SNI (or just one for direct).
	// Requests are distributed in round-robin via rrIdx.
	httpClients []*http.Client
	rrIdx       atomic.Uint64

	mu       sync.Mutex
	sessions map[frame.SessionID]*Session

	outbound chan *frame.Frame // shared queue drained by the poll loop
}

// NewClient constructs a direct (non-fronted) Client.
func NewClient(relayURL, token string, pollMS int) *Client {
	return newClient(relayURL, token, pollMS, []*http.Client{
		{Timeout: 30 * time.Second},
	})
}

// NewClientFronted constructs a Client using Google-based domain fronting.
// cfg describes the Google IP and SNI hosts; pollTimeout should comfortably
// exceed the server's long-poll window; probeURL is the /healthz endpoint
// used for SNI latency probing (pass "" to skip).
func NewClientFronted(relayURL, token string, pollMS int, cfg fronting.Config, pollTimeout time.Duration, probeURL string) *Client {
	clients := fronting.NewClients(cfg, pollTimeout, probeURL)
	return newClient(relayURL, token, pollMS, clients)
}

func newClient(relayURL, token string, pollMS int, httpClients []*http.Client) *Client {
	c := &Client{
		relayURL:    relayURL,
		token:       token,
		pollMS:      pollMS,
		httpClients: httpClients,
		sessions:    make(map[frame.SessionID]*Session),
		outbound:    make(chan *frame.Frame, 4096),
	}
	go c.pollLoop()
	return c
}

// nextHTTPClient returns clients in round-robin order.
func (c *Client) nextHTTPClient() *http.Client {
	idx := c.rrIdx.Add(1) - 1
	return c.httpClients[idx%uint64(len(c.httpClients))]
}

// OpenSession allocates a new session and enqueues the SYN frame.
func (c *Client) OpenSession(target string) *Session {
	var id frame.SessionID
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	s := &Session{
		id:      id,
		downRx:  make(chan []byte, 256),
		upTx:    make(chan *frame.Frame, 256),
		closeCh: make(chan struct{}),
	}
	c.mu.Lock()
	c.sessions[id] = s
	c.mu.Unlock()
	c.outbound <- &frame.Frame{Cmd: frame.CmdSYN, SessionID: id, Payload: []byte(target)}
	return s
}

// Send enqueues a DATA frame for the session.
func (c *Client) Send(s *Session, data []byte) {
	if len(data) == 0 {
		return
	}
	p := make([]byte, len(data))
	copy(p, data)
	c.outbound <- &frame.Frame{Cmd: frame.CmdDATA, SessionID: s.id, Payload: p}
}

// CloseSession enqueues a FIN and removes the session.
func (c *Client) CloseSession(s *Session) {
	c.outbound <- &frame.Frame{Cmd: frame.CmdFIN, SessionID: s.id}
	c.mu.Lock()
	delete(c.sessions, s.id)
	c.mu.Unlock()
	s.Close()
}

func (c *Client) pollLoop() {
	ticker := time.NewTicker(time.Duration(c.pollMS) * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		c.poll()
	}
}

const maxFramesPerPoll = 64

func (c *Client) poll() {
	var buf bytes.Buffer
	for i := 0; i < maxFramesPerPoll; i++ {
		select {
		case f := <-c.outbound:
			if err := f.WriteTo(&buf); err != nil {
				log.Printf("[tunnel] encode: %v", err)
			}
		default:
			goto send
		}
	}
send:
	req, err := http.NewRequest(http.MethodPost, c.relayURL, &buf)
	if err != nil {
		log.Printf("[tunnel] build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.token != "" {
		req.Header.Set("X-Relay-Token", c.token)
	}

	resp, err := c.nextHTTPClient().Do(req)
	if err != nil {
		log.Printf("[tunnel] POST: %v", err)
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return
	case http.StatusOK:
		// fall through
	default:
		log.Printf("[tunnel] relay returned HTTP %d", resp.StatusCode)
		return
	}

	// Apps Script ContentService wraps the binary batch as base64 text/plain.
	// CF Worker responds with raw application/octet-stream.
	// Detect by Content-Type and decode accordingly.
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/plain") || strings.Contains(ct, "text/html") {
		// GS relay path: read the whole body, strip whitespace, base64-decode.
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[tunnel] read body: %v", err)
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			log.Printf("[tunnel] base64 decode: %v", err)
			return
		}
		c.decodeResponse(bytes.NewReader(decoded))
	} else {
		// CF Worker path: stream binary body directly.
		c.decodeResponse(resp.Body)
	}
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
