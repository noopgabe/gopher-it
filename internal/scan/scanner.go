/*
This is the scanner file, which is used for scanning.

Is it gonna work? Probably.
*/

package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noopgabe/gopher-it/internal/output"
)

const (
	defaultWorkers   = 200
	defaultTimeout   = 2 * time.Second
	maxTargets       = 4096
	maxExpandedAddrs = 65536
	maxBannerLen     = 256
)

type Result struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Banner  string `json:"banner,omitempty"`
	Service string `json:"service,omitempty"`
}

type Options struct {
	Targets    []string
	Ports      string
	TCP        bool
	UDP        bool
	Banner     bool
	RateLimit  int
	Stealth    bool
	Workers    int
	Timeout    time.Duration
	Export     string
	Aggressive bool
	OSFp       bool
}

// ParsePorts parses a port specfication like "22,80,440-450"
// If aggressive is true and s is the default empty range, then 1-65535 is used
func ParsePorts(s string, aggressive bool) ([]int, error) {
	set := map[int]bool{}
	if s == "" {
		s = "1-1024"
	}
	if aggressive && s == "1-1024" {
		s = "1-65535"
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			a := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(a[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(a[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("Invalid port range: %q", part)
			}
			if lo < 1 {
				lo = 1
			}
			if hi > 65535 {
				hi = 65535 // well hello to you too
			}
			if lo > hi {
				return nil, fmt.Errorf("Invalid port range: %q", part)
			}
			for p := lo; p <= hi; p++ {
				set[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("Invalid port: %q", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("Port %d out of range (1-65535)", p)
			}
			set[p] = true
		}
	}
	if len(set) == 0 {
		return nil, errors.New("No ports in specification")
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// ExpandTargets expands CIDR notations into just individual addresses.
// Plain hostnames pass through just fine. Expansion IS capped.
func ExpandTargets(targets []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, t := range targets {
		if strings.Contains(t, "/") {
			ip, ipn, err := net.ParseCIDR(t)
			if err != nil {
				continue
			}
			for x := ip.Mask(ipn.Mask); ipn.Contains(x); incIP(x) {
				add(x.String())
				if len(out) >= maxExpandedAddrs {
					return out
				}
			}
			continue
		}
		add(t)
	}
	return out
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// resolveTargets expands CIDRs and resolves hostnames, deduplicating results.
func resolveTargets(targets []string) []string {
	expanded := ExpandTargets(targets)
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, t := range expanded {
		if ip := net.ParseIP(t); ip != nil {
			add(t)
			continue
		}
		ips, err := net.LookupIP(t)
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				add(ip.String())
			}
		} else {
			add(t)
		}
	}
	return out
}

type job struct {
	host  string
	port  int
	proto string
}

func Run(ctx context.Context, opts Options, pr output.Printer) error {
	if !opts.TCP && !opts.UDP {
		opts.TCP = true
	}
	if opts.Workers <= 0 {
		opts.Workers = defaultWorkers
	}
	if opts.RateLimit < 0 {
		opts.RateLimit = 0
	}
	if !opts.Aggressive && opts.RateLimit == 0 && opts.Stealth {
		opts.RateLimit = 50
	}
	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}

	ports, err := ParsePorts(opts.Ports, opts.Aggressive)
	if err != nil {
		return err
	}
	targets := resolveTargets(opts.Targets)
	if len(targets) == 0 {
		return errors.New("No targets resolved.")
	}
	if len(targets) > maxTargets && !opts.Aggressive {
		return fmt.Errorf("Target count %d exceeds cap %d. You can use --aggressive to override.", len(targets), maxTargets)
	}

	// Shared token bucket pacing attempts globally.
	var tokens chan struct{}
	if opts.RateLimit > 0 {
		tokens = make(chan struct{}, 1)
		interval := time.Duration(opts.RateLimit) * time.Millisecond
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					select {
					case tokens <- struct{}{}:
					default:
					}
				}
			}
		}()
	}

	jobs := make(chan job, opts.Workers*4)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = []Result{}
	)
}
