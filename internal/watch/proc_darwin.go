//go:build darwin

package watch

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

// listProcesses uses ps on macOS but idk cuz i havent used it for years. output columns:
//
// pid rss(KB) cpu-time comm...
//
// 4 context, comm is everything after cpu-time
func listProcesses() ([]procInfo, error) {
	out, err := exec.Command("ps", "-axo", "pid=,rss=,time=,comm=").Output()
	if err != nil {
		return nil, err
	}
	var procs []procInfo
	for _, line := range bytes.Split(out, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if s == "" {
			continue
		}
		parts := strings.SplitN(s, " ", 4)
		if len(parts) < 4 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			continue
		}
		rssKB, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		secs, err := parsePSTime(strings.TrimSpace(parts[2])) // SECS !!
		if err != nil {
			secs = -1
		}
		procs = append(procs, procInfo{
			PID:        pid,
			Comm:       strings.TrimSpace(parts[3]),
			RSSMB:      rssKB / 1024,
			CPUSeconds: secs,
		})
	}
	return procs, nil
}
