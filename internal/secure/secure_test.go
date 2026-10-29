// God has not seen my pain yet

package secure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretPatterns(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		pattern string
		want    bool
	}{
		{"AWS key", "id = AKIAIOSFODNN7EXAMPLE", "AWS access key", true},
		{"Private key", "-----BEGIN RSA PRIVATE KEY-----", "private key", true},
		{"Generic token", `api_key = "abcdefghijklmnopqrstuvwxyz"`, "generic token", true},
		{"No match", "hello world", "AWS access key", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, sp := range secretPatterns {
				if sp.name == tt.pattern && sp.re.MatchString(tt.data) {
					found = true
				}
			}
			if found != tt.want {
				t.Errorf("Pattern %q match(%q) = %v, want %v", tt.pattern, tt.data, found, tt.want)
			}
		})
	}
}

func TestScanSecrets(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "app.go")
	os.WriteFile(secret, []byte("package main\n// token = \"0123456789abcdef0123\"\n"), 0644)
	os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing here"), 0644)

	// binary file with NUL should just be skipped
	os.WriteFile(filepath.Join(dir, "blob.bin"), append([]byte("AKIA1234567890ABCD"), 0), 0644)

	// .git/ contents should be skipped
	gitDir := filepath.Join(dir, ".git")
	os.MkdirAll(gitDir, 0755)
	os.WriteFile(filepath.Join(gitDir, "secret"), []byte("AKIA1234567890ABCD"), 0644)

	findings := scanSecrets(dir)
	var files []string
	for _, f := range findings {
		files = append(files, f.File)
	}
	joined := strings.Join(files, ",")
	if !strings.Contains(joined, "app.go") {
		t.Errorf("Expected app.go finding, got %v", files)
	}
	if strings.Contains(joined, ".git") {
		t.Errorf(".git should be skipped, got %v", files)
	}
	if strings.Contains(joined, "blob.bin") {
		t.Errorf("Binary files should be skipped, got %v", files)
	}
	for _, f := range findings {
		if f.Type == "secret" && f.File == secret && !strings.Contains(f.Detail, "line 2") {
			t.Errorf("Expected line number in detail, got %q", f.Detail)
		}
	}
}

func TestDepVuln(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/foo

go 1.25.0

require (
	github.com/spf13/cobra v1.10.2
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/x/y v1.0.0 //indirect

replace example.com/old v1.0.0 => example.com/new v1.0.1
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	findings, err := depVuln(dir)
	if err != nil {
		t.Fatalf("depVuln: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("Expected 3 findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if strings.Contains(f.Detail, "require") {
			t.Errorf("Bogus require finding: %+v", f)
		}
		if !strings.HasPrefix(f.Detail, "module ") {
			t.Errorf("Unexpected detail: %q", f.Detail)
		}
	}
}

func TestDepVulnMissingFile(t *testing.T) {
	findings, err := depVuln(t.TempDir())
	if err != nil {
		t.Fatalf("Missing go.mod should not error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Expected no findings, got %d", len(findings))
	}
}

func TestAuditPerms(t *testing.T) {
	dir := t.TempDir()
	ww := filepath.Join(dir, "writable")
	os.WriteFile(ww, []byte("x"), 0666) // spooky number
	if err := os.Chmod(ww, 0666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	findings := auditPerms(dir)
	found := false
	for _, f := range findings {
		if f.Detail == "world-writable file" && f.File == ww {
			found = true
		}
	}
	if !found {
		t.Errorf("World-writable file not reported: %+v", findings)
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("hello")) {
		t.Error("Text misdetected as binary")
	}
	if !isBinary([]byte{'a', 0, 'b'}) {
		t.Error("NUL byte not detected")
	}
	if isBinary(nil) {
		t.Error("Empty should not be binary")
	}
}

func TestLineOf(t *testing.T) {
	data := []byte("line1\nline2\nline3")
	if got := lineOf(data, 6); got != 2 {
		t.Errorf("lineOf(6) = %d, want 2", got)
	}
	if got := lineOf(data, 0); got != 1 {
		t.Errorf("lineOf(0) = %d, want 1", got)
	}
}
