package fronting

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateProbe(t *testing.T) {
	if err := validateProbe(200, []byte(probeOKBody)); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if err := validateProbe(200, []byte("wrong")); err == nil {
		t.Error("expected error for wrong body")
	}
	if err := validateProbe(500, []byte(probeOKBody)); err == nil {
		t.Error("expected error for non-200")
	}
}

func TestSelectIndexes_AllFail(t *testing.T) {
	results := []probeResult{
		{index: 0, host: "a", err: fmt.Errorf("fail")},
		{index: 1, host: "b", err: fmt.Errorf("fail")},
	}
	keep := selectIndexes(results)
	// Should return all when none succeed
	if len(keep) != 2 {
		t.Errorf("expected 2 kept, got %d", len(keep))
	}
}

func TestSelectIndexes_DropOutlier(t *testing.T) {
	results := []probeResult{
		{index: 0, host: "fast1", samples: []time.Duration{10 * time.Millisecond}},
		{index: 1, host: "fast2", samples: []time.Duration{12 * time.Millisecond}},
		{index: 2, host: "slow", samples: []time.Duration{500 * time.Millisecond}}, // >3× median
	}
	keep := selectIndexes(results)
	for _, k := range keep {
		if k == 2 {
			t.Error("slow outlier should have been dropped")
		}
	}
	if len(keep) < 2 {
		t.Errorf("expected at least 2 kept, got %d", len(keep))
	}
}

func TestNewClients_NoProbe(t *testing.T) {
	cfg := Config{SNIHosts: []string{"www.google.com"}}
	clients := NewClients(cfg, 10*time.Second, "")
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
}

func TestProbeAndFilter(t *testing.T) {
	// Serve probeOKBody on a local HTTPS-like server (HTTP for simplicity in test)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(probeOKBody))
	}))
	defer srv.Close()

	// Use a plain http.Client for testing (no TLS fronting required)
	results := []probeResult{
		{index: 0, host: "host0", client: srv.Client(), samples: []time.Duration{5 * time.Millisecond}},
		{index: 1, host: "host1", client: srv.Client(), samples: []time.Duration{6 * time.Millisecond}},
	}
	keep := selectIndexes(results)
	if len(keep) != 2 {
		t.Errorf("expected 2 kept, got %d", len(keep))
	}
}
