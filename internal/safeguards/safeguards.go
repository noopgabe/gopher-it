package safeguards

import "fmt"

// safefilter rejects oversized filter expressions before they ever reach the capture engine
func SafeFilter(expr string) (string, error) {
	if len(expr) > 512 {
		return "", fmt.Errorf("Filter expression is too long")
	}
	return expr, nil
}

// safety at its finest
