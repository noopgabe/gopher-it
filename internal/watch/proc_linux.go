//go:build linux

package watch

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func listProcesses() ([]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]procInfo, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p := procInfo{PID: pid, CPUSeconds: -1}
		if comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm")); err == nil {
			p.Comm = strings.TrimSpace(string(comm))
		} else {
			continue
		}
		if statm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "statm")); err == nil {
			fields := strings.Fields(string(statm))
			if len(fields) >= 2 {
				if pages, err := strconv.ParseFloat(fields[1], 64); err == nil {
					p.RSSMB = pages * 4096 / 1024 / 1024
				}
			}
		}
		if stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat")); err == nil {
			// cut at the last ')'. comm may contain spaces.
			s := string(stat)
			if i := strings.LastIndexByte(s, ')'); i >= 0 && i+2 < len(s) {
				rest := strings.Fields(s[i+2:])
				if len(rest) >= 13 {
					ut, _ := strconv.ParseFloat(rest[11], 64)
					st, _ := strconv.ParseFloat(rest[12], 64)
					// fun fact, USER_HZ is 100 on linux
					p.CPUSeconds = (ut + st) / 100.0
				}
			}
		}
		out = append(out, p)
	}
	return out, nil
}
