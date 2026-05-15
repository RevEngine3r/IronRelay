package main

import (
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/RevEngine3r/IronRelay/client/fronting"
	"github.com/RevEngine3r/IronRelay/client/socks5"
	"github.com/RevEngine3r/IronRelay/client/tunnel"
)

func main() {
	// Core flags
	relayURL := flag.String("relay", "", "Relay URL: CF Worker or Apps Script /exec (required)")
	token := flag.String("token", "", "X-Relay-Token shared secret")
	listen := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	pollMS := flag.Int("poll", 50, "Poll interval in milliseconds")

	// Domain fronting flags
	useFront := flag.Bool("front", false, "Enable Google domain fronting")
	googleIP := flag.String("google-ip", "", "Google edge IP:port (e.g. 142.250.80.100:443); leave empty to resolve SNI hosts")
	sniList := flag.String("sni", "www.google.com,mail.google.com,accounts.google.com",
		"Comma-separated SNI hosts for domain fronting")
	probeURL := flag.String("probe", "", "Optional healthz URL for startup SNI latency probe")
	pollTimeout := flag.Duration("poll-timeout", 25*time.Second, "Per-request ceiling (must exceed server long-poll window)")

	flag.Parse()

	if *relayURL == "" {
		log.Println("ERROR: -relay is required")
		flag.Usage()
		os.Exit(1)
	}

	var client *tunnel.Client
	if *useFront {
		sniHosts := strings.Split(*sniList, ",")
		cfg := fronting.Config{
			GoogleIP: *googleIP,
			SNIHosts: sniHosts,
		}
		log.Printf("[ironrelay] domain fronting enabled sni=%v google-ip=%q", sniHosts, *googleIP)
		client = tunnel.NewClientFronted(*relayURL, *token, *pollMS, cfg, *pollTimeout, *probeURL)
	} else {
		client = tunnel.NewClient(*relayURL, *token, *pollMS)
	}

	srv := socks5.NewServer(*listen, client)
	log.Printf("[ironrelay] SOCKS5 listening on %s", *listen)
	log.Printf("[ironrelay] relay: %s", *relayURL)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[ironrelay] fatal: %v", err)
	}
}
