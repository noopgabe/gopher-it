package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// an hour of programming a day keeps the doctor away

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check capabilities",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("OS/Arch:", runtime.GOOS, runtime.GOARCH)
		fmt.Println("UID:", os.Geteuid())
		if os.Geteuid() == 0 {
			fmt.Println("Root: yes")
		} else {
			fmt.Println("Root: no (some features may need --sudo or sudo)")
		}
		if p := ConfigPath(); p != "" {
			if _, err := os.Stat(p); err == nil {
				fmt.Println("Config:", p)
			} else {
				fmt.Println("Config: not found (it is optional)")
			}
		} else {
			fmt.Println("Config: home directory unavailable")
		}
		fmt.Println("Watch:", watchSupport())
		fmt.Println("CGO enabled, build tag GOPHERIT_C=1 optional:")
	},
}

func watchSupport() string {
	switch runtime.GOOS {
	case "linux":
		return "Supported"
	case "darwin", "windows":
		return "Supported via ps/tasklist fallback"
	default:
		return "Not supported on " + runtime.GOOS
	}
}

func init() { rootCmd.AddCommand(doctorCmd) }
