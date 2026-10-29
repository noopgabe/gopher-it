package secure

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/mod/modfile"
)

type Finding struct {
	Type     string `json:"type"`
	File     string `json:"file,omitempty"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

type Options struct {
	Path        string
	ScanSecrets bool
	ScanDeps    bool
	Perms       bool
	Anomaly     bool
}

func Run(opts Options) ([]Finding, error) {
	var findings []Finding // wing ding
	if opts.ScanSecrets {
		findings = append(findings, scanSecrets(opts.Path)...)
		findings = append(findings, scanEnv()...)
	}
	if opts.Perms {
		findings = append(findings, auditPerms(opts.Path)...)
	}
	if opts.ScanDeps {
		f, err := depVuln(opts.Path)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f...)
	}
	if opts.Anomaly {
		findings = append(findings, anomalyHints()...)
	}
	return findings, nil
}

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Private key", regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`)},
	{"Generic token", regexp.MustCompile(`(?i)(api[_-]?key|token|secret)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}`)}, // HOW DO PEOPLE USE REGEX
}

var skipDirs = map[string]bool{
	".git":         true,
	".hg":          true,
	".svn":         true,
	"node_modules": true,
	"vendor":       true,
	".gopher-it":   true,
}

func lineOf(data []byte, idx int) int {
	return bytes.Count(data[:idx], []byte("\n")) + 1
}

func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	n := len(data)
	if n > 512 {
		n = 512
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

func scanSecrets(path string) []Finding {
	var out []Finding
	if path == "" {
		path = "."
	}
	filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != path && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2*1024*1024 {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || isBinary(data) {
			return nil
		}
		for _, sp := range secretPatterns {
			loc := sp.re.FindIndex(data)
			if loc != nil {
				out = append(out, Finding{
					Type:     "secret",
					File:     p,
					Detail:   fmt.Sprintf("%s at line %d", sp.name, lineOf(data, loc[0])),
					Severity: "high",
				})
			}
		}
		return nil
	})
	return out
}

func scanEnv() []Finding {
	var out []Finding
	for _, e := range os.Environ() {
		for _, sp := range secretPatterns {
			if sp.re.MatchString(e) {
				out = append(out, Finding{"secret-env", "", sp.name + " in env", "high"})
			}
		}
	}
	return out
}

func auditPerms(path string) []Finding {
	var out []Finding
	if path == "" {
		path = "."
	}
	filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		mode := info.Mode()
		if !d.IsDir() && mode&0002 != 0 {
			out = append(out, Finding{"perms", p, "world-writable file", "medium"}) // finding perms
		}
		if d.IsDir() && mode&0002 != 0 {
			out = append(out, Finding{"perms", p, "world-writable directory", "low"})
		}
		return nil
	})
	for _, f := range []string{"/etc/shadow"} {
		if st, err := os.Stat(f); err == nil {
			if st.Mode().Perm()&0007 != 0 {
				out = append(out, Finding{"perms", f, "overly permissive sensitive file", "high"})
			}
		}
	}
	return out
}

func depVuln(path string) ([]Finding, error) {
	var out []Finding
	gomod := filepath.Join(path, "go.mod")
	raw, err := os.ReadFile(gomod)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Reading go.mod: %w", err)
	}
	f, err := modfile.Parse(gomod, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("Parsing go.mod: %w", err)
	}
	for _, r := range f.Require {
		out = append(out, Finding{
			Type:     "dependency",
			File:     gomod,
			Detail:   "Module " + r.Mod.Path + " " + r.Mod.Version + " (Lookup not performed offline)", // TODO: implement lookup
			Severity: "info",
		})
	}
	return out, nil
}

func anomalyHints() []Finding {
	var out []Finding
	entries, _ := os.ReadDir("/proc")
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := fmt.Sscanf(e.Name(), "%d", new(int)); err != nil {
			continue
		}
		if _, err := os.Stat("/proc/" + e.Name() + "/stat"); err == nil {
			n++
		}
	}
	if n > 500 {
		out = append(out, Finding{"anomaly", "", fmt.Sprintf("high process count: %d", n), "low"})
	}
	return out
}
