//go:build windows

package watch

import (
	"encoding/csv"
	"os/exec"
	"strconv"
	"strings"
)

// afaikkk CPU time is not available from tasklist
// which is what listProcesses uses so
// CPU time is  -1 and alerts are skipped
func listProcesses() ([]procInfo, error) {
	out, err := exec.Command("tasklist", "/fo", "csv", "nh").Output()
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(strings.NewReader(string(out)))
	r.FieldsPerRecord = 6
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var procs []procInfo
	for _, rec := range records {
		if len(rec) < 5 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rec[1]))
		if err != nil {
			continue
		}
		procs = append(procs, procInfo{
			PID:        pid,
			Comm:       strings.TrimSpace(rec[0]),
			RSSMB:      parseTasklistMem(rec[4]),
			CPUSeconds: -1,
		})
	}
	return procs, nil
}
