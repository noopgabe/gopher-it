package watch

import (
	"strconv"
	"strings"
)

// parsePSTime parses ps CPU time strings ("0.00.05", "1:23:45", etc)
func parsePSTime(s string) (float64, error) {
	if s == "" {
		return 0, strconv.ErrSyntax
	}
	switch strings.Count(s, ":") {
	case 2:
		hms := strings.SplitN(s, ":", 3)
		h, err1 := strconv.ParseFloat(hms[0], 64)
		m, err2 := strconv.ParseFloat(hms[1], 64)
		sec, err3 := strconv.ParseFloat(hms[2], 64)
		if err1 != nil || err2 != nil || err3 != nil {
			return 0, strconv.ErrSyntax
		}
		return h*3600 + m*60 + sec, nil
	case 1:
		ms := strings.SplitN(s, ":", 2)
		m, err1 := strconv.ParseFloat(ms[0], 64)
		sec, err2 := strconv.ParseFloat(ms[1], 64)
		if err1 != nil || err2 != nil {
			return 0, strconv.ErrSyntax
		}
		return m*60 + sec, nil
	default:
		return strconv.ParseFloat(s, 64)
	}
}

// parseTasklistMem parses "1,234 K" / "12K" into just mb
func parseTasklistMem(s string) float64 {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " K")
	s = strings.TrimSuffix(s, "K")
	s = strings.ReplaceAll(strings.TrimSpace(s), ",", "")
	kb, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return kb / 1024
}
