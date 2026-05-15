package tunnel

// DownRx exposes the downstream receive channel to the SOCKS5 handler.
func (s *Session) DownRx() <-chan []byte { return s.downRx }
