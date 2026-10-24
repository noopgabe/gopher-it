package cmd

import (
	"fmt"

	"github.com/noopgabe/gopher-it/internal/output"
	"github.com/noopgabe/gopher-it/internal/scan"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var scanOpts scan.Options

var scanCmd = &cobra.Command{
	Use:   "scan [targets...]",
	Short: "Port scanning and recon",
	RunE: func(cmd *cobra.Command, args []string) error {
		syncScanOpts()
		if scanOpts.Aggressive {
			if err := requireBuffoon("Agressive scan"); err != nil {
				return err
			}
		}
		if scanOpts.OSFp {
			if err := requireBuffoon("OS fingerprinting"); err != nil {
				return err
			}
		}
		scanOpts.Targets = append(scanOpts.Targets, args...)
		if len(scanOpts.Targets) == 0 {
			return fmt.Errorf("No targets were specified.")
		}
		pr := output.New(jsonOut, yamlOut, csvOut, quiet, verbose)
		if pr.Verbose {
			fmt.Fprintf(cmd.ErrOrStderr(), "scan: targets=%d ports=%q workers=%d\n",
				len(scanOpts.Targets), scanOpts.Ports, scanOpts.Workers)
		}
		return scan.Run(cmd.Context(), scanOpts, pr)
	},
}

// syncScanOpts overlays viper onto the cobra-bound options struct.
func syncScanOpts() {
	scanOpts.Ports = viper.GetString("scan.ports")
	scanOpts.TCP = viper.GetBool("scan.tcp")
	scanOpts.UDP = viper.GetBool("scan.udp")
	scanOpts.Banner = viper.GetBool("scan.banner")
	scanOpts.Stealth = viper.GetBool("scan.stealth") // I accidentally said Stwealth instead of Stealth, owo
	scanOpts.RateLimit = viper.GetInt("scan.rate")
	scanOpts.Workers = viper.GetInt("scan.workers")
	scanOpts.Aggressive = viper.GetBool("scan.aggressive")
	scanOpts.OSFp = viper.GetBool("scan.os-fp")
	scanOpts.Export = viper.GetString("scan.export")
}

var scanPortsCmd = &cobra.Command{Use: "ports [targets...]", Short: "TCP/UDP port scanning", RunE: scanCmd.RunE}

func init() {
	scanOpts.TCP = true
	f := scanCmd.PersistentFlags()
	f.StringVar(&scanOpts.Ports, "ports", "1-1024", "Port range/list")
	f.BoolVar(&scanOpts.TCP, "tcp", true, "TCP connect scan")                                 // tcp works reliably but slow
	f.BoolVar(&scanOpts.UDP, "udp", true, "UDP connect scan")                                 // udp is just tcp but you're just throwing the packets everywhere and praying it works
	f.BoolVar(&scanOpts.Banner, "banner", false, "Banner grabber")                            // i said the above on my cs quiz and got a 100 so i think im good
	f.BoolVar(&scanOpts.Stealth, "stealth", false, "Stealthy scan")                           // bro thinks he sneaky
	f.IntVar(&scanOpts.RateLimit, "rate", 0, "rate limit ms")                                 // bro thinks he sneaky 2
	f.IntVar(&scanOpts.Workers, "workers", 200, "workers")                                    // workers
	f.BoolVar(&scanOpts.Aggressive, "aggressive", false, "Aggressive scan (may be detected)") // you may be detected
	f.BoolVar(&scanOpts.OSFp, "os-fp", false, "OS fingerprinting (may be detected)")          // fingerprint the target of the OS with the potential to be detected
	f.StringVar(&scanOpts.Export, "export", "", "Export JSON")
	bindFlags("scan", f)
	scanCmd.AddCommand(scanPortsCmd)
	rootCmd.AddCommand(scanCmd)
}

// bindFlags registers every flag under a scoped viper key so
// GOPHERIT_<CMD>_<FLAG> variables and config sections work.
func bindFlags(ns string, fs *pflag.FlagSet) {
	fs.VisitAll(func(fl *pflag.Flag) {
		if err := viper.BindPFlag(ns+"."+fl.Name, fl); err != nil {
			panic(err)
		}
	})
}
