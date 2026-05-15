// Package frame implements the IronRelay binary frame format.
//
// Wire layout (21-byte fixed header + variable payload):
//
//	[1B cmd] [16B session_id] [4B payload_len big-endian] [payload_len bytes]
//
// Commands:
//
//	SYN  (0x01)  open TCP session; payload = "host:port"
//	DATA (0x02)  upstream bytes;   payload = raw TCP bytes
//	FIN  (0x03)  close session;    payload = empty
//	ACK  (0x04)  downstream bytes; payload = raw TCP bytes
package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	CmdSYN  byte = 0x01
	CmdDATA byte = 0x02
	CmdFIN  byte = 0x03
	CmdACK  byte = 0x04

	SessionIDLen = 16
	HeaderSize   = 1 + SessionIDLen + 4 // cmd + session_id + payload_len
)

// SessionID is a 16-byte random identifier for one TCP session.
type SessionID [SessionIDLen]byte

// Frame is one unit of the IronRelay protocol.
type Frame struct {
	Cmd       byte
	SessionID SessionID
	Payload   []byte
}

// WriteTo serialises f into w.
func (f *Frame) WriteTo(w io.Writer) error {
	header := [HeaderSize]byte{}
	header[0] = f.Cmd
	copy(header[1:], f.SessionID[:])
	binary.BigEndian.PutUint32(header[1+SessionIDLen:], uint32(len(f.Payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		_, err := w.Write(f.Payload)
		return err
	}
	return nil
}

// ReadFrom deserialises one frame from r.
func ReadFrom(r io.Reader) (*Frame, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	f := &Frame{}
	f.Cmd = header[0]
	copy(f.SessionID[:], header[1:1+SessionIDLen])
	pLen := binary.BigEndian.Uint32(header[1+SessionIDLen:])
	if pLen > 0 {
		f.Payload = make([]byte, pLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, fmt.Errorf("frame: read payload: %w", err)
		}
	}
	return f, nil
}
