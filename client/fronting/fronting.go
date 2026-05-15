// Package fronting implements Google-based domain fronting:
// dial a Google IP, present an innocuous SNI (e.g. www.google.com),
// but send the real Host in the HTTP request so Google's CDN routes
// to script.google.com / the CF Worker URL.
//
// Ported from GooseRelayVPN internal/carrier/fronting.go.
package fronting

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const (
	// workersPerEndpoint mirrors the poll-loop concurrency so each SNI
	// can keep one warm idle conn per worker.
	workersPerEndpoint = 4

	probeOKBody = "IronRelay forwarder OK"
)

// Config describes how to reach the relay URL without revealing the real
// destination to a passive on-path observer.
//
// GoogleIP is the raw IP:port of a Google edge node; if empty the dialer
// resolves each SNIHost normally.
//
// SNIHosts is a list of innocuous Google domains shown in the TLS ClientHello.
// Each host gets its own connection pool → its own throttle bucket on Google CDN.
// Requests are distributed across them in round-robin order.
type Config struct {
	GoogleIP string   // "ip:443"  — leave empty for normal resolution
	SNIHosts []string // e.g. ["www.google.com", "mail.google.com"]
}

// NewClients returns one *http.Client per SNI host.
// Each client is independently probed; slow outliers (>3× median) are dropped.
// pollTimeout should be longer than the server's long-poll window.
// probeURL is a GET endpoint that returns probeOKBody on 200; pass "" to skip probing.
func NewClients(cfg Config, pollTimeout time.Duration, probeURL string) []*http.Client {
	hosts := cfg.SNIHosts
	if len(hosts) == 0 {
		hosts = []string{"www.google.com"}
	}

	// Per-SNI TLS session caches — cross-SNI tickets are useless.
	caches := make(map[string]tls.ClientSessionCache, len(hosts))
	for _, sni := range hosts {
		if _, ok := caches[sni]; !ok {
			caches[sni] = tls.NewLRUClientSessionCache(8)
		}
	}

	clients := make([]*http.Client, len(hosts))
	for i, sni := range hosts {
		clients[i] = newClient(cfg.GoogleIP, sni, pollTimeout, caches[sni])
	}

	if probeURL != "" {
		hosts, clients = filterByProbe(hosts, clients, probeURL)
	}

	// Prewarm TLS session tickets in the background so first real polls
	// skip the full handshake round-trip (~140 ms saved per cold conn).
	prewarm(cfg.GoogleIP, hosts, caches)
	return clients
}

// ----- probing ---------------------------------------------------------------

type probeResult struct {
	index   int
	host    string
	client  *http.Client
	samples []time.Duration
	err     error
}

func (r probeResult) ok() bool            { return len(r.samples) > 0 }
func (r probeResult) latency() time.Duration {
	if len(r.samples) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), r.samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func filterByProbe(hosts []string, clients []*http.Client, probeURL string) ([]string, []*http.Client) {
	if len(hosts) <= 1 {
		return hosts, clients
	}
	results := runProbes(hosts, clients, probeURL)
	keep := selectIndexes(results)
	if len(keep) == 0 {
		return hosts, clients
	}
	logDecision(results, keep)

	keptHosts := make([]string, 0, len(keep))
	keptClients := make([]*http.Client, 0, len(keep))
	set := make(map[int]struct{}, len(keep))
	for _, idx := range keep {
		set[idx] = struct{}{}
		keptHosts = append(keptHosts, hosts[idx])
		keptClients = append(keptClients, clients[idx])
	}
	return keptHosts, keptClients
}

func runProbes(hosts []string, clients []*http.Client, probeURL string) []probeResult {
	const (
		samples = 2
		timeout = 8 * time.Second
	)
	results := make([]probeResult, len(hosts))
	ch := make(chan probeResult, len(hosts))

	for i, host := range hosts {
		c := clients[i]
		go func(idx int, sni string, hc *http.Client) {
			res := probeResult{index: idx, host: sni, client: hc}
			for s := 0; s < samples; s++ {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					cancel()
					res.err = err
					break
				}
				start := time.Now()
				resp, err := hc.Do(req)
				if err != nil {
					cancel()
					res.err = err
					continue
				}
				body, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				cancel()
				if readErr != nil {
					res.err = readErr
					continue
				}
				if err := validateProbe(resp.StatusCode, body); err != nil {
					res.err = err
					continue
				}
				res.samples = append(res.samples, time.Since(start))
			}
			ch <- res
		}(i, host, c)
	}

	for range hosts {
		res := <-ch
		results[res.index] = res
	}
	return results
}

func validateProbe(status int, body []byte) error {
	if status != http.StatusOK {
		return fmt.Errorf("probe: status %d", status)
	}
	if strings.TrimSpace(string(body)) != probeOKBody {
		return fmt.Errorf("probe: unexpected body %q", strings.TrimSpace(string(body)))
	}
	return nil
}

func selectIndexes(results []probeResult) []int {
	if len(results) <= 1 {
		return allIndexes(len(results))
	}
	ok := make([]probeResult, 0, len(results))
	for _, r := range results {
		if r.ok() {
			ok = append(ok, r)
		}
	}
	if len(ok) == 0 {
		return allIndexes(len(results))
	}
	if len(ok) == 1 {
		return []int{ok[0].index}
	}

	lats := make([]time.Duration, 0, len(ok))
	for _, r := range ok {
		lats = append(lats, r.latency())
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	median := lats[len(lats)/2]

	if len(ok) <= 2 || median <= 0 {
		return indexesOf(ok)
	}
	threshold := 3 * median
	kept := make([]int, 0, len(ok))
	for _, r := range ok {
		if r.latency() <= threshold {
			kept = append(kept, r.index)
		}
	}
	if len(kept) < 2 {
		return indexesOf(ok)
	}
	return kept
}

func allIndexes(n int) []int {
	ids := make([]int, n)
	for i := range ids {
		ids[i] = i
	}
	return ids
}

func indexesOf(rs []probeResult) []int {
	ids := make([]int, 0, len(rs))
	for _, r := range rs {
		ids = append(ids, r.index)
	}
	return ids
}

func logDecision(results []probeResult, keep []int) {
	set := make(map[int]struct{}, len(keep))
	for _, idx := range keep {
		set[idx] = struct{}{}
	}
	lats := make([]time.Duration, 0)
	for _, r := range results {
		if r.ok() {
			lats = append(lats, r.latency())
		}
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	median := time.Duration(0)
	if len(lats) > 0 {
		median = lats[len(lats)/2]
	}
	for _, r := range results {
		action := "drop"
		if _, ok := set[r.index]; ok {
			action = "keep"
		}
		if r.ok() {
			log.Printf("[fronting] probe %s sni=%s ttfb=%s samples=%d",
				action, r.host, r.latency().Round(time.Millisecond), len(r.samples))
		} else {
			log.Printf("[fronting] probe %s sni=%s err=%v", action, r.host, r.err)
		}
	}
	log.Printf("[fronting] kept %d/%d sni hosts median_ttfb=%s",
		len(keep), len(results), median.Round(time.Millisecond))
}

// ----- TLS prewarm -----------------------------------------------------------

// prewarm fires one raw TLS dial per SNI in the background to capture the
// TLS 1.3 NewSessionTicket frame (which arrives post-handshake). Subsequent
// polls resume the session, saving ~140 ms per cold connection.
func prewarm(googleIP string, sniHosts []string, caches map[string]tls.ClientSessionCache) {
	const (
		dialTimeout  = 3 * time.Second
		ticketWindow = 500 * time.Millisecond
		budget       = 5 * time.Second
	)
	dialer := &net.Dialer{Timeout: dialTimeout}
	for _, sni := range sniHosts {
		go func(sniHost string, cache tls.ClientSessionCache) {
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			addr := googleIP
			if addr == "" {
				addr = net.JoinHostPort(sniHost, "443")
			}
			rawConn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return
			}
			defer rawConn.Close()
			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName:         sniHost,
				MinVersion:         tls.VersionTLS13,
				ClientSessionCache: cache,
				NextProtos:         []string{"h2", "http/1.1"},
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return
			}
			// Read briefly so the post-handshake NewSessionTicket frame is
			// consumed and stored. The read always times out — that's fine.
			_ = tlsConn.SetReadDeadline(time.Now().Add(ticketWindow))
			var buf [1]byte
			_, _ = tlsConn.Read(buf[:])
		}(sni, caches[sni])
	}
}

// ----- http.Client construction ----------------------------------------------

func newClient(googleIP, sniHost string, pollTimeout time.Duration, sessionCache tls.ClientSessionCache) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if googleIP != "" {
				return dialer.DialContext(ctx, "tcp", googleIP)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sniHost,
			MinVersion:         tls.VersionTLS13,
			ClientSessionCache: sessionCache,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   workersPerEndpoint * 2,
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// HTTP/2 tuning: fast dead-peer detection + large DATA frames
	// (cuts framing overhead ~64× on bulk responses).
	if h2t, err := http2.ConfigureTransports(transport); err == nil && h2t != nil {
		h2t.ReadIdleTimeout = 30 * time.Second
		h2t.PingTimeout = 15 * time.Second
		h2t.MaxReadFrameSize = 1 << 20 // 1 MiB
	}

	return &http.Client{Transport: transport, Timeout: pollTimeout}
}
