package cmd

import (
	"github.com/noopgabe/gopher-it/internal/output"
	"github.com/noopgabe/gopher-it/internal/secure"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var secureOpts secure.Options
var secureAll bool

var secureCmd = &cobra.Command{
	Use:   "secure [path]",
	Short: "Security tools", // my opsec is unparalleled
	RunE: func(cmd *cobra.Command, args []string) error {
		secureOpts.ScanSecrets = viper.GetBool("secure.secrets")
		secureOpts.ScanDeps = viper.GetBool("secure.deps")
		secureOpts.Perms = viper.GetBool("secure.perms")
		secureOpts.Anomaly = viper.GetBool("secure.anomaly")
		secureOpts.Path = "."
		if len(args) > 0 {
			secureOpts.Path = args[0]
		}
		if secureAll {
			secureOpts.ScanSecrets = true
			secureOpts.ScanDeps = true
			secureOpts.Perms = true
			secureOpts.Anomaly = true
		}
		findings, err := secure.Run(secureOpts)
		if err != nil {
			return err
		}
		rows := make([][]string, 0, len(findings))
		for _, f := range findings {
			rows = append(rows, []string{f.Type, f.Severity, f.File, f.Detail})
		}
		pr := output.New(jsonOut, yamlOut, csvOut, quiet, verbose)
		pr.PrintTable([]string{"TYPE", "SEVERITY", "FILE", "DETAIL"}, rows)
		if jsonOut || yamlOut {
			pr.PrintAny(findings) // findings? more liek wingdings amirite
		}
		return nil
	},
}

func init() {
	secureOpts.ScanSecrets = true
	secureCmd.Flags().BoolVar(&secureOpts.ScanSecrets, "secrets", true, "Secret scanning")
	secureCmd.Flags().BoolVar(&secureOpts.ScanDeps, "deps", false, "Dependency vulnerability scanning")
	secureCmd.Flags().BoolVar(&secureOpts.Perms, "perms", false, "Permission auditing")
	secureCmd.Flags().BoolVar(&secureOpts.Anomaly, "anomaly", false, "Anomaly hints")
	secureCmd.Flags().BoolVar(&secureAll, "all", false, "Run all checks")
	bindFlags("secure", secureCmd.Flags())
	rootCmd.AddCommand(secureCmd)
}
