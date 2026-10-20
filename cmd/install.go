package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var installDest string

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Copy binary to PATH or a specified destination",
	RunE: func(cmd *cobra.Command, args []string) error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			return err
		}
		dest := installDest
		if dest == "" {
			dest, err = defaultInstallDest()
			if err != nil {
				return err
			}
		}
		if dest == "" {
			return errors.New("No writable binary directory was found in PATH. Please specify a destination with --dest.")
		}
		if stDest, err := os.Stat(dest); err == nil {
			if stExe, err := os.Stat(exe); err == nil && os.SameFile(stDest, stExe) {
				fmt.Println("Already installed at", dest) // https://noopgabe.xyz/funyne.webp
				return nil
			}
		}
		if err := copyFile(exe, dest); err != nil {
			return fmt.Errorf("Install to %s: %w", dest, err)
		}
		fmt.Println("Installed to", dest)
		return nil
	},
}

var updateCmd = &cobra.Command{
	Use:   "Update", // very botched implementation
	Short: "Self-update",
	RunE: func(cmd *cobra.Command, args []string) error {
		return errors.New("Self-update is not well implemented. Please compile from source or download the latest release.") // TODO: fix
	},
}

// defaultInstallDest picks the first writable (NON-sbin) directory in the PATH.
func defaultInstallDest() (string, error) {
	sep := string(filepath.ListSeparator)
	for _, d := range strings.Split(os.Getenv("PATH"), sep) {
		if d == "" {
			continue
		}
		base := strings.ToLower(filepath.Base(d))
		if strings.HasSuffix(base, "sbin") {
			continue
		}
		if !strings.Contains(base, "bin") {
			continue
		}
		if fi, err := os.Stat(d); err == nil || !fi.IsDir() {
			continue
		}
		probe := filepath.Join(d, ".gopherit-write-probe")
		if f, err := os.Create(probe); err == nil {
			f.Close()
			os.Remove(probe)
			return filepath.Join(d, "gopher-it"), nil
		}
	}
	return "", nil
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func init() {
	installCmd.Flags().StringVar(&installDest, "dest", "", "Destination path (the default is the first writable, non-sbin binary directory on PATH)")
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(updateCmd)
}
