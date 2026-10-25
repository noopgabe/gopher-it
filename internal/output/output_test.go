package output

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout // save old stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestPrintTableAlignsHeaders(t *testing.T) {
	p := New(false, false, false, false, false)
	out := captureStdout(t, func() {
		p.PrintTable([]string{"HOST", "PORT", "STATE"}, [][]string{
			{"127.0.0.1", "22", "Open"},
		})
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("Got %d lines, want 2: %q", len(lines), out)
	}
	// the column starts MUST line up between the header and data rows
	if !strings.HasPrefix(lines[0], "HOST") || !strings.HasPrefix(lines[1], "127.0.0.1") {
		t.Fatalf("Unexpected lines: %q / %q", lines[0], lines[1])
	}
	if strings.Index(lines[0], "PORT") != strings.Index(lines[1], "22") {
		t.Errorf("Columns misaligned. Header %q row %q", lines[0], lines[1])
	}
}

func TestPrintTableJSONSilent(t *testing.T) {
	p := New(true, false, false, false, false)
	out := captureStdout(t, func() {
		p.PrintTable([]string{"A"}, [][]string{{"1"}})
	})
	if out != "" {
		t.Errorf("JSON printer emitted table output: %q", out)
	}
}

func TestPrintTableQuiet(t *testing.T) {
	p := New(false, false, false, true, false)
	out := captureStdout(t, func() {
		p.PrintTable([]string{"A"}, [][]string{{"1"}})
	})
	if out != "" {
		t.Errorf("Quiet printer emitted output: %q", out)
	}
}

func TestPrintTableRaggedRows(t *testing.T) {
	p := New(false, false, false, false, false)
	out := captureStdout(t, func() {
		p.PrintTable([]string{"A", "B", "C"}, [][]string{{"1", "2"}})
	})
	if len(strings.Split(strings.TrimRight(out, "\n"), "\n")) != 2 {
		t.Errorf("Ragged row panicked or truncated: %q", out)
	}
}

func TestPrintAnyJSON(t *testing.T) {
	p := New(true, false, false, false, false)
	out := captureStdout(t, func() {
		p.PrintAny(map[string]string{"k": "v"})
	})
	if out != `{"k":"v"}` {
		t.Errorf("JSON output mismatch: %q", out)
	}
}
