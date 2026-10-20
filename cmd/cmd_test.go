package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// test file for testing out all the things and thingamabobbers.

// resetFlags clear every flag back to its default so tests
// don't leak state through the shared cobra/viper globals.
func resetFlags(t *testing.T) {
	t.Helper()
	reset := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
	}
	reset(rootCmd.PersistentFlags())
	reset(scanCmd.PersistentFlags())
	reset(watchCmd.Flags())
	reset(traceCmd.Flags())
	reset(secureCmd.Flags())
	for _, c := range traceCmd.Commands() {
		reset(c.Flags())
	}
	cfgFile = ""
	scanOpts.Targets = nil
	watchOpts.Processes = nil
}

// execute runs rootCmd with args and returns the error.
func execute(t *testing.T, args ...string) error {
	t.Helper()
	resetFlags(t)
	rootCmd.SetArgs(args)
	defer func() {
		rootCmd.SetArgs(nil)
	}()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	go func() { io.Copy(io.Discard, r); w.Close() }()
	defer func() { os.Stdout = old }()
	return rootCmd.ExecuteContext(context.Background())
}

func TestScanRequiresTarget(t *testing.T) {
	err := execute(t, "scan")
	if err == nil || !strings.Contains(err.Error(), "no targets") {
		t.Fatalf("err = %v, want no targets", err)
	}
}

func TestScanRejectsInvalidPorts(t *testing.T) {
	err := execute(t, "scan", "127.0.0.1", "--ports", "abc")
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("err = %v, want invalid port", err)
	}
}

func TestScanAggressiveGate(t *testing.T) {
	err := execute(t, "scan", "127.0.0.1", "aggressive")
	if err == nil || !strings.Contains(err.Error(), "i-am-a-buffoon") {
		t.Fatalf("err = %v, want buffoon gate", err)
	}
}

func TestScanOSFpGate(t *testing.T) {
	err := execute(t, "scan", "127.0.0.1", "--os-fp")
	if err == nil || !strings.Contains(err.Error(), "i-am-a-buffoon") {
		t.Fatalf("err = %v, want buffoon gate", err)
	}
}

func TestScanHasNoSynFlag(t *testing.T) {
	resetFlags(t)
	buffoon = false
	if err := requireBuffoon("test action"); err == nil || !strings.Contains(err.Error(), "i-am-a-buffoon") {
		t.Fatalf("err = %v, want buffoon gate", err)
	}
}

func TestRequireBuffoonWarns(t *testing.T) {
	resetFlags(t)
	buffoon = true
	buffoonWarnOnce = sync.Once{}
	stderr := captureStderr(t, func() {
		if err := requireBuffoon("test action"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(stderr, "VERY STUPID") || !strings.Contains(stderr, "hit Ctrl+C NOW") {
		t.Errorf("warning missing from stderr: %q", stderr)
	}
	buffoon = false
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stderr = old
	return <-done
}

func TestSecureDefaults(t *testing.T) {
	cfg := t.TempDir() + "/empty.toml"
	os.WriteFile(cfg, []byte("# empty\n"), 0644)
	dir := t.TempDir()
	var buf bytes.Buffer
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	go func() { io.Copy(&buf, r); w.Close() }()
	err := execute(t, "secure", "--config", cfg, dir)
	os.Stdout = old
	if err != nil {
		t.Fatalf("secure: %v", err)
	}
}

func TestWatchRejectsBadWebhook(t *testing.T) {
	// For testing, isolate from the user config by pointing at an empty conf file
	cfg := t.TempDir() + "/empty.toml"
	os.WriteFile(cfg, []byte("# empty\n"), 0644)
	err := execute(t, "watch", "--config", cfg, "sshd", "--webhook", "i-am-a-dummy-url")
	if err == nil || !strings.Contains(err.Error(), "invalid webhook") {
		t.Fatalf("err = %v, want invalid webhook", err)
	}
}

func TestReplayRequiresPcap(t *testing.T) {
	err := execute(t, "trace", "replay", "--i-am-a-buffoon", "--sudo")
	if err == nil || !strings.Contains(err.Error(), "--pcap") {
		t.Fatalf("err = %v, want --pcap required", err)
	}
}

func TestBindFlagsNamespacing(t *testing.T) {
	// bindFlags must register keys like scan.ports. Bound flag defaults must be visible thru viper
	if got := viper.GetString("scan.ports"); got != "1-1024" {
		t.Fatalf("scan.ports = %q, want default 1-1024", got)
	}
	if got := viper.GetInt("watch.interval"); got != 60 {
		t.Fatalf("watch.interval = %d, want 60", got)
	}
	if got := viper.GetString("trace.iface"); got != "any" {
		t.Fatalf("trace.iface = %q, want any", got)
	}
	if got := viper.GetBool("secure.deps"); got != false {
		t.Fatalf("secure.deps = %v, want false", got)
	}
}

func TestWatchRequiresProcessesOrCheck(t *testing.T) {
	cfg := t.TempDir() + "/empty.toml"
	os.WriteFile(cfg, []byte("# empty\n"), 0644)
	err := execute(t, "watch", "--config", cfg)
	if err == nil || !strings.Contains(err.Error(), "no processes") {
		t.Fatalf("err = %v, want no processes", err)
	}
}
