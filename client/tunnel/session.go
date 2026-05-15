package tunnel

import "sync"

// Close signals that this session is done. Safe to call multiple times.
func (s *Session) Close() { s.once.Do(func() { close(s.closeCh) }) }

// Done returns a channel that is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.closeCh }

// DownRx exposes the downstream receive channel to the SOCKS5 handler.
func (s *Session) DownRx() <-chan []byte { return s.downRx }

// ensure sync is used (once is declared on Session struct in client.go)
var _ sync.Once
