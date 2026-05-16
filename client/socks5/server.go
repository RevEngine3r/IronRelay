// Package socks5 implements a minimal SOCKS5 server (CONNECT only).
//
// Each accepted connection:
//  1. Completes the SOCKS5 handshake
//  2. Calls tunnel.Client.OpenSession with the target "host:port"
//  3. Bidirectionally copies data between the local TCP conn and the session
package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/RevEngine3r/IronRelay/client/tunnel"
)

// Server is a SOCKS5 listener.
type Server struct {
	addr   string
	client *tunnel.Client
}

// NewServer creates a Server that uses c to tunnel CONNECT requests.
func NewServer(addr string, c *tunnel.Client) *Server {
	return &Server{addr: addr, client: c}
}

// ListenAndServe binds and accepts connections until the process exits.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[socks5] accept: %v", err)
			continue
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		log.Printf("[socks5] set deadline: %v", err)
		return
	}

	target, err := handshake(conn)
	if err != nil {
		log.Printf("[socks5] handshake: %v", err)
		return
	}

	// Remove the deadline — data transfer may take arbitrary time.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		log.Printf("[socks5] clear deadline: %v", err)
		return
	}

	sess := s.client.OpenSession(target)
	defer s.client.CloseSession(sess)

	// Reply success: BND.ADDR = 0.0.0.0, BND.PORT = 0
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		log.Printf("[socks5] write reply: %v", err)
		return
	}

	// upstream: local conn → tunnel
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				s.client.Send(sess, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// downstream: tunnel → local conn
	for {
		select {
		case data := <-sess.DownRx():
			if _, err := conn.Write(data); err != nil {
				return
			}
		case <-sess.Done():
			return
		}
	}
}

// handshake completes SOCKS5 negotiation and returns the CONNECT target.
func handshake(conn net.Conn) (string, error) {
	// Version + method selection
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != 0x05 {
		return "", fmt.Errorf("not SOCKS5 (got 0x%02x)", header[0])
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}
	// No auth
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", fmt.Errorf("write method select: %w", err)
	}

	// Request
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", err
	}
	if req[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("only CONNECT supported (cmd=0x%02x)", req[1])
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		ipv4 := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipv4); err != nil {
			return "", fmt.Errorf("read ipv4: %w", err)
		}
		host = net.IP(ipv4).String()
	case 0x03: // domain
		lenB := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenB); err != nil {
			return "", fmt.Errorf("read domain len: %w", err)
		}
		name := make([]byte, lenB[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		host = string(name)
	case 0x04: // IPv6
		ipv6 := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipv6); err != nil {
			return "", fmt.Errorf("read ipv6: %w", err)
		}
		host = "[" + net.IP(ipv6).String() + "]"
	default:
		return "", fmt.Errorf("unsupported addr type 0x%02x", req[3])
	}

	portB := make([]byte, 2)
	if _, err := io.ReadFull(conn, portB); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portB)

	return fmt.Sprintf("%s:%d", host, port), nil
}
