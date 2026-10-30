package watch

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// alertServer records the text of every alert posted to it
type alertServer struct {
	*httptest.Server
	mu    sync.Mutex
	texts []string
}

func newAlertServer(t *testing.T) *alertServer {
	t.Helper()
	as := &alertServer{}
	as.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return
		}
		as.mu.Lock()
		as.texts = append(as.texts, payload["text"])
		as.mu.Unlock()
	}))
	t.Cleanup(as.Close)
	return as
}

func (as *alertServer) got() []string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return append([]string(nil), as.texts...)
}

// newFakeChecker returns a checker that reads processes from *procs and posts alerts to a test server.
// Tests can change *procs between checkOnce calls to simulate processes starting and exiting.
func newFakeChecker(t *testing.T, opts Options, procs *[]procInfo) (*checker, *alertServer) {
	t.Helper()
	as := newAlertServer(t)
	opts.Slack = as.URL
	c := newChecker(opts)
	c.list = func() ([]procInfo, error) { return *procs, nil }
	return c, as
}

func TestCPUPercent(t *testing.T) {
	// 0.5 seconds over 1 second elapsed SHOULD equal 50%
	if got := cpuPercent(1.0, 1.5, time.Second); got <= 49.9 || got >= 50.1 {
		t.Errorf("cpuPercent is %f, want 50", got)
	}
	if got := cpuPercent(-1, 1.5, time.Second); got != 0 {
		t.Errorf("Unknown CPU time should give 0, got %f", got)
	}
	if got := cpuPercent(1.0, 1.5, 0); got != 0 {
		t.Errorf("Zero elapsed time should give 0, got %f", got)
	}
}

func TestMatchingPids(t *testing.T) {
	procs := []procInfo{
		{PID: 1, Comm: "nginx"},
		{PID: 2, Comm: "NGINX-worker"},
		{PID: 3, Comm: "sshd"},
	}
	tests := []struct {
		name    string
		needle  string
		wantPID []int
	}{
		{"exact match", "nginx", []int{1, 2}},
		{"case insensitive", "NgInX", []int{1, 2}},
		{"substring", "sshd", []int{3}},
		{"no match", "redis", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchingPids(procs, tt.needle)
			if len(got) != len(tt.wantPID) {
				t.Fatalf("matchingPids(%q) returned %d procs, want %d", tt.needle, len(got), len(tt.wantPID))
			}
			for i, p := range got {
				if p.PID != tt.wantPID[i] {
					t.Errorf("matchingPids(%q)[%d].PID = %d, want %d", tt.needle, i, p.PID, tt.wantPID[i])
				}
			}
		})
	}
}

func TestParsePSTime(t *testing.T) {
	tests := []struct {
		in      string
		want    float64
		wantErr bool
	}{
		{"0:00.05", 0.05, false},
		{"1:23:45", 3600 + 23*60 + 45, false},
		{"2:30", 150, false},
		{"12.5", 12.5, false},
		{"", 0, true},
		{"abc", 0, true},
		{"1:x", 0, true},
		{"x:1:2", 0, true},
		{"1:2:x", 0, true},
		{"1:2:3:4", 0, true},
	}
	for _, tt := range tests {
		got, err := parsePSTime(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parsePSTime(%q) error = nil, want error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePSTime(%q) err = %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parsePSTime(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseTasklistmem(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{"1,024 K", 1},
		{"512 K", 0.5},
		{"12K", 12.0 / 1024},
		{"1,234,567 K", 1234567.0 / 1024},
		{"", 0},
		{"nonsense", 0},
	}
	for _, tt := range tests {
		if got := parseTasklistMem(tt.in); got != tt.want {
			t.Errorf("parseTasklistMem(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSendAlertPostsPayload(t *testing.T) {
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	sendAlert(Options{Slack: srv.URL}, Alert{"Warning", "high memory", "host1", "t"})
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	var payload map[string]string
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("Payload: %v", err)
	}
	if payload["text"] != "Warning: high memory" {
		t.Errorf("Text = %q", payload["text"])
	}
}

func TestSendAlertPostsToSlackAndWebhook(t *testing.T) {
	slack := newAlertServer(t)
	webhook := newAlertServer(t)
	sendAlert(Options{Slack: slack.URL, Webhook: webhook.URL}, Alert{"Critical", "boom", "host1", "t"})

	for name, as := range map[string]*alertServer{"slack": slack, "webhook": webhook} {
		if got := as.got(); len(got) != 1 || got[0] != "Critical: boom" {
			t.Errorf("%s got %v, want [Critical: boom]", name, got)
		}
	}
}

func TestSendAlertSkipsUnreachableURL(t *testing.T) {
	as := newAlertServer(t)
	// port 1 refuses connections, so the Slack post fails and the webhook must still be called
	sendAlert(Options{Slack: "http://127.0.0.1:1", Webhook: as.URL}, Alert{"Critical", "boom", "host1", "t"})
	if got := as.got(); len(got) != 1 || got[0] != "Critical: boom" {
		t.Errorf("webhook got %v, want [Critical: boom]", got)
	}
}

func TestListProcessFindsSelf(t *testing.T) {
	procs, err := listProcesses()
	if err != nil {
		t.Fatalf("listProcesses: %v", err)
	}
	self := os.Getpid()
	var me *procInfo
	for i := range procs {
		if procs[i].PID == self {
			me = &procs[i]
			break
		}
	}
	if me == nil {
		t.Fatalf("own process ID %d not found in the process list (%d entries)", self, len(procs))
	}
	if me.Comm == "" {
		t.Error("own process has an empty Comm")
	}
	if runtime.GOOS == "linux" {
		if me.RSSMB <= 0 {
			t.Errorf("own RSSMB = %f, want > 0", me.RSSMB)
		}
		if me.CPUSeconds < 0 {
			t.Errorf("own CPUSeconds = %f, want >= 0", me.CPUSeconds)
		}
	}
}

func TestCheckOnceMissingProcess(t *testing.T) {
	procs := []procInfo{{PID: 1, Comm: "unrelated"}}
	c, as := newFakeChecker(t, Options{Processes: []string{"iamnotarealprocess"}}, &procs)
	c.checkOnce()

	want := "Critical: process crashed: iamnotarealprocess"
	if got := as.got(); len(got) != 1 || got[0] != want {
		t.Errorf("alerts = %v, want [%s]", got, want)
	}
}

func TestCheckOnceHighMemory(t *testing.T) {
	tests := []struct {
		name      string
		memLimit  float64
		rss       float64
		wantAlert bool
	}{
		{"over limit", 500, 600, true},
		{"under limit", 500, 100, false},
		{"limit disabled", 0, 600, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			procs := []procInfo{{PID: 10, Comm: "app", RSSMB: tt.rss, CPUSeconds: -1}}
			c, as := newFakeChecker(t, Options{Processes: []string{"app"}, MemLimit: tt.memLimit}, &procs)
			c.checkOnce()

			alerts := as.got()
			if !tt.wantAlert {
				if len(alerts) != 0 {
					t.Errorf("alerts = %v, want none", alerts)
				}
				return
			}
			want := "Warning: high memory app pid=10 rss=600.0MB"
			if len(alerts) != 1 || alerts[0] != want {
				t.Errorf("alerts = %v, want [%s]", alerts, want)
			}
		})
	}
}

func TestCheckOnceHighCPU(t *testing.T) {
	tests := []struct {
		name      string
		burned    float64 // CPU seconds used during the simulated 1s between checks
		wantAlert bool
	}{
		{"above limit", 0.9, true},
		{"below limit", 0.1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			procs := []procInfo{{PID: 10, Comm: "app", CPUSeconds: 1.0}}
			c, as := newFakeChecker(t, Options{Processes: []string{"app"}, CPULimit: 50}, &procs)

			// the first sample only sets the baseline, so it can never alert
			c.checkOnce()
			if got := as.got(); len(got) != 0 {
				t.Fatalf("first sample alerted: %v", got)
			}

			// pretend the previous sample was a second ago and advance CPU time by burned seconds
			c.cpuStamp[cpuKey{10}] = time.Now().Add(-time.Second)
			procs[0].CPUSeconds = 1.0 + tt.burned
			c.checkOnce()

			alerts := as.got()
			if !tt.wantAlert {
				if len(alerts) != 0 {
					t.Errorf("alerts = %v, want none", alerts)
				}
				return
			}
			if len(alerts) != 1 || !strings.Contains(alerts[0], "high CPU app pid=10") {
				t.Errorf("alerts = %v, want one high CPU alert", alerts)
			}
		})
	}
}

func TestCheckOnceSkipsUnknownCPU(t *testing.T) {
	procs := []procInfo{{PID: 10, Comm: "app", CPUSeconds: -1}}
	c, as := newFakeChecker(t, Options{Processes: []string{"app"}, CPULimit: 50}, &procs)
	c.checkOnce()
	c.checkOnce()

	if got := as.got(); len(got) != 0 {
		t.Errorf("alerts = %v, want none", got)
	}
	if _, ok := c.cpuBase[cpuKey{10}]; ok {
		t.Error("CPU baseline recorded for a process whose CPU time is unknown")
	}
}

func TestCheckOnceForgetsExitedPIDs(t *testing.T) {
	procs := []procInfo{
		{PID: 10, Comm: "app", CPUSeconds: 1},
		{PID: 11, Comm: "app", CPUSeconds: 1},
	}
	c, _ := newFakeChecker(t, Options{Processes: []string{"app"}, CPULimit: 50}, &procs)
	c.checkOnce()

	procs = procs[1:] // PID 10 exits
	c.checkOnce()

	if _, ok := c.cpuBase[cpuKey{10}]; ok {
		t.Error("cpuBase still holds exited PID 10")
	}
	if _, ok := c.cpuStamp[cpuKey{10}]; ok {
		t.Error("cpuStamp still holds exited PID 10")
	}
	if _, ok := c.cpuBase[cpuKey{11}]; !ok {
		t.Error("cpuBase lost live PID 11")
	}
}

func TestCheckOnceCmdCheck(t *testing.T) {
	tests := []struct {
		name      string
		cmd       string
		wantAlert string
	}{
		{"passes", "exit 0", ""},
		{"fails", "echo disk full; exit 3", "Critical: cmd check failed: disk full (exit status 3)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var procs []procInfo
			c, as := newFakeChecker(t, Options{CmdCheck: tt.cmd}, &procs)
			c.checkOnce()

			alerts := as.got()
			if tt.wantAlert == "" {
				if len(alerts) != 0 {
					t.Errorf("alerts = %v, want none", alerts)
				}
				return
			}
			if len(alerts) != 1 || alerts[0] != tt.wantAlert {
				t.Errorf("alerts = %v, want [%s]", alerts, tt.wantAlert)
			}
		})
	}
}

func TestRunOnceChecksAndReturns(t *testing.T) {
	as := newAlertServer(t)
	err := Run(context.Background(), Options{
		Once:      true,
		Processes: []string{"iamnotarealprocess"},
		Slack:     as.URL,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := as.got(); len(got) != 1 {
		t.Errorf("alerts = %v, want exactly one", got)
	}
}

func TestRunLiveReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// a long interval means the only way out is the cancelled context
	err := Run(ctx, Options{Live: true, Interval: 3600})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run error = %v, want context.Canceled", err)
	}
}
