package main

import (
	"flag"
	"log"
	"os"

	"github.com/RevEngine3r/IronRelay/client/socks5"
	"github.com/RevEngine3r/IronRelay/client/tunnel"
)

func main() {
	relayURL := flag.String("relay", "", "Google Apps Script /exec URL (required)")
	token := flag.String("token", "", "Shared relay token (must match CF Worker RELAY_TOKEN)")
	listen := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	pollMS := flag.Int("poll", 50, "Poll interval in milliseconds")
	flag.Parse()

	if *relayURL == "" {
		log.Println("ERROR: -relay is required")
		flag.Usage()
		os.Exit(1)
	}

	client := tunnel.NewClient(*relayURL, *token, *pollMS)
	srv := socks5.NewServer(*listen, client)

	log.Printf("[ironrelay] SOCKS5 listening on %s", *listen)
	log.Printf("[ironrelay] relay: %s", *relayURL)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[ironrelay] fatal: %v", err)
	}
}
