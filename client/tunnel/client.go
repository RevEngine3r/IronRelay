// Package tunnel manages the HTTP long-poll loop and per-session state.
//
// One shared goroutine continuously POSTs to the relay URL:
//   - Drains pending outbound frames from all active sessions
//   - Reads inbound ACK/FIN frames from the response body
//   - Routes ACK payload bytes back to the correct session pipe
package tunnel

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/RevEngine3r/IronRelay/client/frame"
)

// Session holds the pipe between the SOCKS5 handler and the poll loop.
type Session struct {
	id      frame.SessionID
	downRx  chan []byte // ACK bytes from remote → SOCKS5 writer
	upTx    chan *frame.Frame // frames queued for next POST
	closeCh chan struct{}
	once    sync.Once
}

func (s *Session) Close() {
	s.once.Do(func() { close(s.closeCh) })
}

func (s *Session) Done() <-chan struct{} { return s.closeCh }

// Client is the tunnel entry point used by the SOCKS5 server.
type Client struct {
	relayURL string
	token    string
	pollMS   int
	httpC    *http.Client

	mu       sync.Mutex
	sessions map[frame.SessionID]*Session

	// outbound is the shared queue drained by the poll loop.
	outbound chan *frame.Frame
}

// NewClient constructs a Client and starts the background poll loop.
func NewClient(relayURL, token string, pollMS int) *Client {
	c := &Client{
		relayURL: relayURL,
		token:    token,
		pollMS:   pollMS,
		httpC:    &http.Client{Timeout: 30 * time.Second},
		sessions: make(map[frame.SessionID]*Session),
		outbound: make(chan *frame.Frame, 4096),
	}
	go c.pollLoop()
	return c
}

// OpenSession allocates a new session and enqueues the SYN frame.
// Returns the session so the caller can read ACK bytes and detect closure.
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

// pollLoop runs forever: sleep pollMS → drain outbound → POST → handle response.
func (c *Client) pollLoop() {
	ticker := time.NewTicker(time.Duration(c.pollMS) * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		c.poll()
	}
}

const maxFramesPerPoll = 64

func (c *Client) poll() {
	// Drain up to maxFramesPerPoll outbound frames.
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
	// Always POST even if buf is empty — server may have queued ACK frames.
	req, err := http.NewRequest(http.MethodPost, c.relayURL, &buf)
	if err != nil {
		log.Printf("[tunnel] build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.token != "" {
		req.Header.Set("X-Relay-Token", c.token)
	}

	resp, err := c.httpC.Do(req)
	if err != nil {
		log.Printf("[tunnel] POST: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return // no downstream frames
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("[tunnel] relay returned HTTP %d", resp.StatusCode)
		return
	}

	// Decode all frames from the response body.
	c.decodeResponse(resp.Body)
}

func (c *Client) decodeResponse(r io.Reader) {
	for {
		f, err := frame.ReadFrom(r)
		if err != nil {
			// EOF is normal end-of-batch; other errors are logged.
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
