//go:build !linux && !darwin && !windows

package watch

import "fmt"

func listProcesses() ([]procInfo, error) {
	return nil, fmt.Errorf("Process listing is not supported on this platform.")
}

// if it's not supported, idk wtf you're doing with your life. stop using
// bsd and just use linux for the love of god
