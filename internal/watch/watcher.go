package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Options struct {
	Interval  int
	Webhook   string
	Slack     string
	Processes []string
	CPULimit  float64
	MemLimit  float64
	CmdCheck  string
	Once      bool
	Live      bool
}

type Alert struct {
	Level   string `json:"level"`
	Message string `json:"message"`
	Host    string `json:"host"`
	Time    string `json:"time"`
}

// procInfo is a snapshot of a single process. CPUSeconds is cumulative. user + cpu time in seconds. its negative when the platform cant provide
type procInfo struct {
	PID        int
	Comm       string
	RSSMB      float64
	CPUSeconds float64
}

// listProcesses is implemented per os in proc_linux.go, proc_darwin.go, etc

var httpClient = &http.Client{Timeout: 10 * time.Second}

func hostname() string { h, _ := os.Hostname(); return h }

func matchingPids(procs []procInfo, name string) []procInfo {
	needle := strings.ToLower(name)
	var out []procInfo
	for _, p := range procs {
		if strings.Contains(strings.ToLower(p.Comm), needle) {
			out = append(out, p)
		}
	}
	return out
}

// cpuPercent converts a CPU-seconds delta into a percent util
func cpuPercent(prevSeconds, currSeconds float64, elapsed time.Duration) float64 {
	if prevSeconds < 0 || currSeconds < 0 || elapsed <= 0 {
		return 0
	}
	return (currSeconds - prevSeconds) / elapsed.Seconds() * 100 // king julien why are seconds so boring
}

func sendAlert(opts Options, a Alert) {
	payload := map[string]string{"text": a.Level + ": " + a.Message}
	b, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Watch: marshal alert: %v\n", err)
		return
	}
	for _, url := range []string{opts.Slack, opts.Webhook} {
		if url == "" {
			continue
		}
		resp, err := httpClient.Post(url, "application/json", bytes.NewReader(b))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Watch: alert post %s: %v\n", url, err)
			continue
		}
		resp.Body.Close()
	}
	fmt.Printf("[%s] %s\n", a.Level, a.Message)
}

type cpuKey struct {
	pid int
}

type checker struct {
	opts     Options
	host     string
	list     func() ([]procInfo, error)
	cpuBase  map[cpuKey]float64
	cpuStamp map[cpuKey]time.Time
}

func newChecker(opts Options) *checker {
	return &checker{
		opts:     opts,
		host:     hostname(),
		list:     listProcesses,
		cpuBase:  map[cpuKey]float64{},
		cpuStamp: map[cpuKey]time.Time{},
	}
}

func (c *checker) alert(level, msg string) {
	sendAlert(c.opts, Alert{level, msg, c.host, time.Now().Format(time.RFC3339)})
}

func (c *checker) checkOnce() {
	procs, err := c.list()
	if err != nil {
		c.alert("Critical", "cannot list processes: "+err.Error())
		return
	}
	now := time.Now()
	seen := map[cpuKey]bool{}
	for _, name := range c.opts.Processes {
		matches := matchingPids(procs, name)
		if len(matches) == 0 {
			c.alert("Critical", "process crashed: "+name)
			continue
		}
		for _, p := range matches {
			key := cpuKey{p.PID}
			seen[key] = true
			if c.opts.MemLimit > 0 && p.RSSMB > c.opts.MemLimit {
				c.alert("Warning", fmt.Sprintf("high memory %s pid=%d rss=%.1fMB", name, p.PID, p.RSSMB))
			}
			if c.opts.CPULimit > 0 && p.CPUSeconds >= 0 {
				prev, ok := c.cpuBase[key]
				stamp := c.cpuStamp[key]
				c.cpuBase[key] = p.CPUSeconds
				c.cpuStamp[key] = now
				if !ok {
					continue
				}
				if pct := cpuPercent(prev, p.CPUSeconds, now.Sub(stamp)); pct > c.opts.CPULimit {
					c.alert("Warning", fmt.Sprintf("high CPU %s pid=%d cpu=%.1f%%", name, p.PID, pct))
				}
			}
		}
	}
	for key := range c.cpuBase {
		if !seen[key] {
			delete(c.cpuBase, key)
			delete(c.cpuStamp, key)
		}
	}
	if c.opts.CmdCheck != "" {
		out, err := exec.Command("sh", "-c", c.opts.CmdCheck).CombinedOutput()
		if err != nil {
			c.alert("Critical", "cmd check failed: "+strings.TrimSpace(string(out))+" ("+err.Error()+")")
		}
	}
}

func Run(ctx context.Context, opts Options) error {
	if _, err := listProcesses(); err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	if opts.Interval <= 0 {
		opts.Interval = 60
	}
	c := newChecker(opts)
	if opts.Once || !opts.Live {
		c.checkOnce()
		return nil
	}
	for {
		c.checkOnce()
		timer := time.NewTimer(time.Duration(opts.Interval) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
