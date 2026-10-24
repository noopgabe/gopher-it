/*
This is the scanner file, which is used for scanning.

Is it gonna work? Probably.
*/

package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				if tokens != nil {
					select {
					case <-ctx.Done():
						return
					case <-tokens:
					}
				}
				r := probe(j.host, j.port, j.proto, opts)
				if r.State != "" {
					mu.Lock()
					results = append(results, r)
					mu.Unlock()
				}
			}
		}()
	}

	protos := make([]string, 0, 2)
	if opts.TCP {
		protos = append(protos, "tcp")
	}
	if opts.UDP {
		protos = append(protos, "udp")
	}
	var prodErr error
producing:
	for _, h := range targets {
		for _, p := range ports {
			for _, proto := range protos {
				select {
				case <-ctx.Done():
					prodErr = ctx.Err()
					break producing
				case jobs <- job{host: h, port: p, proto: proto}:
				}
			}
		}
	}
	close(jobs)
	wg.Wait()
	if prodErr != nil {
		return prodErr
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		if results[i].Port < results[j].Port {
			return results[i].Port < results[j].Port
		}
		return results[i].Proto < results[j].Proto
	})

	rows := make([][]string, 0, len(results))
	for _, r := range results {
		rows = append(rows, []string{r.Host, strconv.Itoa(r.Port), r.Proto, r.State, r.Banner})
	}
	pr.PrintTable([]string{"HOST", "PORT", "PROTO", "STATE", "BANNER"}, rows)
	if pr.JSON || pr.YAML {
		pr.PrintAny(results)
	}
	if opts.Export != "" {
		if err := exportJSON(opts.Export, results); err != nil {
			return fmt.Errorf("export: %w", err)
		}
	}
	if len(results) == 0 {
		return errors.New("No open ports found.")
	}
	return nil
}

func exportJSON(path string, results []Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func probe(host string, port int, proto string, opts Options) Result {
	r := Result{Host: host, Port: port, Proto: proto}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if proto == "tcp" {
		conn, err := net.DialTimeout("tcp", addr, opts.Timeout)
		if err != nil {
			return Result{}
		}
		defer conn.Close()
		r.State = "open"
		if opts.Banner {
			conn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, maxBannerLen)
			n, _ := conn.Read(buf)
			if n > 0 {
				r.Banner = sanitizeBanner(buf[:n])
			}
		}
		r.Service = guessService(port)
		return r
	}
	// a connected UDP socket surfaces ICMP port-unreachable as ECONNREFUSED
	// on r/w. timeouts mean they're opened ORRRR filtered.
	conn, err := net.DialTimeout("udp", addr, opts.Timeout)
	if err != nil {
		return Result{}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(opts.Timeout))
	_, _ = conn.Write([]byte("\n"))
	buf := make([]byte, maxBannerLen)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		r.State = "open"
		r.Banner = sanitizeBanner(buf[:n])
		return r
	}
	if isConnRefused(err) {
		r.State = "closed"
		return r
	}
	r.State = "open|filtered"
	return r
}

func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.ECONNREFUSED)
	}
	return false
}

// sanitizeBanner strips control characters so hostile banners
// can't inject terminal escape sequences and it also caps the length
func sanitizeBanner(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\t' || (c >= 0x20 && c < 0x7f) {
			out = append(out, c)
		}
	}
	if len(out) > maxBannerLen {
		out = out[:maxBannerLen]
	}
	return strings.TrimSpace(string(out))
}

func guessService(p int) string {
	m := map[int]string{22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis"}
	return m[p]
}
