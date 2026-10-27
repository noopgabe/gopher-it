package scan

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/noopgabe/gopher-it/internal/output"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name       string
		spec       string
		aggressive bool
		want       []int
		wantErr    bool
	}{
		{"Single", "22", false, []int{22}, false}, // me be like
		{"List dedupe", "80,80,443", false, []int{80, 443}, false},
		{"Range", "100-103", false, []int{100, 101, 102, 103}, false},
		{"Mixed", "22,80-82", false, []int{22, 80, 81, 82}, false},
		{"Clamps low", "0-2", false, []int{1, 2}, false},
		{"Clamps high", "65533-65535", false, []int{65534, 65535}, false},
		{"Invalid token", "abc", false, nil, true},
		{"Inverted range", "100-50", false, nil, true},
		{"Out of range", "0", false, nil, true},
		{"Empty default", "", false, nil, false},                   // Default 1-1024
		{"Aggressive expands default", "1-1024", true, nil, false}, // 65535 ports. Checked below
		{"Aggressive respects explicit", "22", true, []int{22}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.spec, tt.aggressive)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePorts(%q) error = nil, want error", tt.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePorts(%q) unexpected error: %v", tt.spec, err)
			}
			if tt.name == "Empty default" {
				if len(got) != 1024 || got[0] != 1 || got[len(got)-1] != 1024 {
					t.Fatalf("Default range = %d ports [%d..%d], want 1024", len(got), got[0], got[len(got)-1])
				}
				return
			}
			if tt.name == "Aggressive expands default" {
				if len(got) != 65535 || got[0] != 1 || got[len(got)-1] != 65535 {
					t.Fatalf("Aggressive range = %d ports [%d..%d], want 65535", len(got), got[0], got[len(got)-1])
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestExpandTargets(t *testing.T) {
	tests := []struct {
		name    string
		targets []string
		want    []string
	}{
		{"Plain host passes", []string{"example.com"}, []string{"example.com"}},
		{"CIDR expanded", []string{"10.0.0.0/30"}, []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"Dedupe", []string{"127.0.0.1", "127.0.0.1"}, []string{"127.0.0.1"}},
		{"Bad CIDR skipped", []string{"420.420.420.420/8", "ok"}, []string{"ok"}},
		{"IPv6 CIDR", []string{"::1/128"}, []string{"::1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandTargets(tt.targets)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExpandTargets(%v) = %v, want %v", tt.targets, got, tt.want)
			}
		})
	}
}

func TestExpandTargetsCap(t *testing.T) {
	got := ExpandTargets([]string{"0.0.0.0/8", "10.0.0.0/8"})
	if len(got) != maxExpandedAddrs {
		t.Fatalf("Expansion cap exceeded: %d > %d", len(got), maxExpandedAddrs)
	}
}

func TestSanitizeBanner(t *testing.T) {
	test := []struct {
		name string
		in   []byte
		want string
	}{
		{"Plain", []byte("SSH-2.0-OpenSSH\r\n"), "SSH-2.0-OpenSSH"},
		{"Strips escape", []byte("evil\x1b[31mred\x07"), "evil[31mred]"}, // ding dong
		{"Keeps tab", []byte("a\tb"), "a\tb"},
		{"Empty", []byte{}, ""}, // there's nothing.
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeBanner(tt.in); got != tt.want {
				t.Errorf("sanitizeBanner(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeBannerCapsLength(t *testing.T) {
	in := make([]byte, maxBannerLen*2)
	for i := range in {
		in[i] = 'a'
	}
	if got := sanitizeBanner(in); len(got) != maxBannerLen {
		t.Errorf("len = %d, want %d", len(got), maxBannerLen)
	}
}
func TestProbeTCPWithListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listener: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Write([]byte("HELLO-BANNER\n"))
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	r := probe("127.0.0.1", port, "tcp", Options{Timeout: 2 * time.Second, Banner: true})
	if r.State != "Open" {
		t.Fatalf("State = %q, want open", r.State)
	}
	if r.Banner != "HELLO-BANNER" {
		t.Errorf("banner = %q, want HELLO-BANNER", r.Banner)
	}
}

func TestProbeTCPClosed(t *testing.T) {
	// reserve  a port and then close it so nothing listens
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	r := probe("127.0.0.1", port, "tcp", Options{Timeout: time.Second})
	if r.State != "" {
		t.Fatalf("State = %q, want empty (filtered)", r.State)
	}
}

func TestRunJSONOutput(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listener: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	pr := output.New(true, false, false, false, false) // grrr falsity
	err = Run(context.Background(), Options{
		Targets: []string{"127.0.0.1"},
		Ports:   "0", // invalid
	}, pr)
	if err == nil {
		t.Fatal("Expected invalid port error")
	}

	err = Run(context.Background(), Options{
		Targets: []string{"127.0.0.1"},
		Ports:   portString(port),
		TCP:     true,
		Workers: 4,
		Timeout: 2 * time.Second,
	}, pr)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRunTargetCap(t *testing.T) {
	// A /16 expands to 65536 targets, which exceeds the cap of 4096
	err := Run(context.Background(), Options{
		Targets: []string{"10.0.0.0/16"},
		Ports:   "90",
		TCP:     true,
	}, output.New(true, false, false, false, false))
	if err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("Err = %v, want exceeds cap error", err)
	}
}

func TestRunExport(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listener: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	out := filepath.Join(t.TempDir(), "out.json")
	err = Run(context.Background(), Options{
		Targets: []string{"127.0.0.1"},
		Ports:   portString(port),
		TCP:     true,
		Workers: 2,
		Timeout: 2 * time.Second,
		Export:  out,
	}, output.New(false, false, false, true, false)) // there is 1 imposter among us
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("Read export: %v", err)
	}
	if !strings.Contains(string(data), "\"state\": \"open\"") {
		t.Errorf("export missing open state: %s", data)
	}
}

func TestRunRateLimitPaces(t *testing.T) {
	// 4 closed ports with a 100ms token ticker.
	// at least ~3 ticks needed
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	start := time.Now()
	_ = Run(context.Background(), Options{
		Targets:   []string{"127.0.0.1"},
		Ports:     "1-4",
		TCP:       true,
		Workers:   4,
		Timeout:   200 * time.Millisecond,
		RateLimit: 100,
	}, output.New(false, false, false, true, false))
	_ = port
	elapsed := time.Since(start)
	if elapsed < 200*time.Millisecond {
		t.Errorf("Rate limit not applied: elapsed %s, want >= 200ms", elapsed)
	}
}

func portString(p int) string { return strconv.Itoa(p) }
