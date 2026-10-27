package safeguards

import "testing"

func TestSafeFilter(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{"empty", "", false},
		{"short", "TCP port 80", false},
		{"exactly 512", string(make([]byte, 512)), false},
		{"too long", string(make([]byte, 513)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SafeFilter(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeFilter(%q) error = %v, wantErr %v", tt.expr, err, tt.wantErr)
			}
		})
	}
}
