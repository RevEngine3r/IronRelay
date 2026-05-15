package frame_test

import (
	"bytes"
	"testing"

	"github.com/RevEngine3r/IronRelay/client/frame"
)

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		f    frame.Frame
	}{
		{
			name: "SYN",
			f: frame.Frame{
				Cmd:       frame.CmdSYN,
				SessionID: frame.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Payload:   []byte("example.com:443"),
			},
		},
		{
			name: "DATA",
			f: frame.Frame{
				Cmd:       frame.CmdDATA,
				SessionID: frame.SessionID{0xff},
				Payload:   []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			},
		},
		{
			name: "FIN empty payload",
			f: frame.Frame{
				Cmd:       frame.CmdFIN,
				SessionID: frame.SessionID{0xab, 0xcd},
			},
		},
		{
			name: "ACK",
			f: frame.Frame{
				Cmd:       frame.CmdACK,
				SessionID: frame.SessionID{0x01},
				Payload:   []byte{0x00, 0x01, 0x02, 0x03},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.f.WriteTo(&buf); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}
			got, err := frame.ReadFrom(&buf)
			if err != nil {
				t.Fatalf("ReadFrom: %v", err)
			}
			if got.Cmd != tt.f.Cmd {
				t.Errorf("cmd: got %d want %d", got.Cmd, tt.f.Cmd)
			}
			if got.SessionID != tt.f.SessionID {
				t.Errorf("session_id mismatch")
			}
			if !bytes.Equal(got.Payload, tt.f.Payload) {
				t.Errorf("payload: got %q want %q", got.Payload, tt.f.Payload)
			}
		})
	}
}

func TestMultipleFramesInStream(t *testing.T) {
	var buf bytes.Buffer
	frames := []frame.Frame{
		{Cmd: frame.CmdSYN, SessionID: frame.SessionID{1}, Payload: []byte("host:80")},
		{Cmd: frame.CmdDATA, SessionID: frame.SessionID{1}, Payload: []byte("hello")},
		{Cmd: frame.CmdFIN, SessionID: frame.SessionID{1}},
	}
	for i := range frames {
		if err := frames[i].WriteTo(&buf); err != nil {
			t.Fatal(err)
		}
	}
	for i := range frames {
		got, err := frame.ReadFrom(&buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if got.Cmd != frames[i].Cmd {
			t.Errorf("frame %d cmd mismatch", i)
		}
	}
}
