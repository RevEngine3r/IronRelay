package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/RevEngine3r/IronRelay/client/config"
	"github.com/RevEngine3r/IronRelay/client/fronting"
	"github.com/RevEngine3r/IronRelay/client/socks5"
	"github.com/RevEngine3r/IronRelay/client/tunnel"
)

func main() {
	// Utility flag: generate a fresh PSK key and exit.
	keygen := flag.Bool("keygen", false, "Print a fresh 64-hex PSK key and exit")

	// Config file (preferred)
	cfgPath := flag.String("config", "ironrelay.json", "Path to config JSON file")

	// Legacy flags — override config file when set explicitly.
	relayURL := flag.String("relay", "", "Relay URL (overrides config relay_url)")
	token := flag.String("token", "", "Relay token header (legacy; prefer tunnel_key in config)")
	listen := flag.String("listen", "", "SOCKS5 listen addr (overrides config socks_host:socks_port)")
	pollMS := flag.Int("poll", 0, "Poll interval ms (overrides config poll_ms)")

	// Legacy fronting flags
	useFront := flag.Bool("front", false, "Enable Google domain fronting (overrides config)")
	googleIP := flag.String("google-ip", "", "Google edge IP:port")
	sniList := flag.String("sni", "", "Comma-separated SNI hosts")
	probeURL := flag.String("probe", "", "Healthz URL for SNI probe")
	pollTimeout := flag.Duration("poll-timeout", 25*time.Second, "Per-request ceiling")

	flag.Parse()

	if *keygen {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("keygen: %v", err)
		}
		fmt.Println(hex.EncodeToString(b))
		os.Exit(0)
	}

	// --- Config file path ---
	// Try loading config file; fall back gracefully if it doesn't exist
	// and legacy flags are provided instead.
	var cfg *config.Config
	if _, err := os.Stat(*cfgPath); err == nil {
		loaded, err := config.Load(*cfgPath)
		if err != nil {
			log.Fatalf("[ironrelay] config: %v", err)
		}
		cfg = loaded
		log.Printf("[ironrelay] loaded config from %s", *cfgPath)
	}

	// Apply flag overrides on top of config.
	if cfg != nil {
		if *relayURL != "" {
			cfg.RelayURL = *relayURL
		}
		if *listen != "" {
			// parse host:port override
			parts := strings.SplitN(*listen, ":", 2)
			cfg.SocksHost = parts[0]
			if len(parts) == 2 {
				fmt.Sscanf(parts[1], "%d", &cfg.SocksPort)
			}
		}
		if *pollMS != 0 {
			cfg.PollMS = *pollMS
		}
		if *useFront && *googleIP != "" {
			cfg.GoogleHost = *googleIP
		}
		if *sniList != "" {
			cfg.SNI = strings.Split(*sniList, ",")
		}
	}

	var client *tunnel.Client

	if cfg != nil {
		// Config-file path
		var err error
		client, err = tunnel.NewClientFromConfig(cfg)
		if err != nil {
			log.Fatalf("[ironrelay] %v", err)
		}
	} else {
		// Legacy flags-only path
		if *relayURL == "" {
			log.Println("ERROR: provide -config ironrelay.json or -relay <url>")
			flag.Usage()
			os.Exit(1)
		}
		if *useFront {
			sniHosts := strings.Split(*sniList, ",")
			if *sniList == "" {
				sniHosts = []string{"www.google.com", "mail.google.com", "accounts.google.com"}
			}
			cfgF := fronting.Config{GoogleIP: *googleIP, SNIHosts: sniHosts}
			log.Printf("[ironrelay] domain fronting sni=%v", sniHosts)
			client = tunnel.NewClientFronted(*relayURL, *token, *pollMS, cfgF, *pollTimeout, *probeURL)
		} else {
			p := 50
			if *pollMS != 0 {
				p = *pollMS
			}
			client = tunnel.NewClient(*relayURL, *token, p)
		}
	}

	listenAddr := "127.0.0.1:1080"
	if cfg != nil {
		listenAddr = cfg.ListenAddr()
	}
	if *listen != "" {
		listenAddr = *listen
	}

	srv := socks5.NewServer(listenAddr, client)
	log.Printf("[ironrelay] SOCKS5 listening on %s", listenAddr)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[ironrelay] fatal: %v", err)
	}
}
