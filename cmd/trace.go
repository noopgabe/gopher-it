package cmd

import (
	"fmt"
	"os"

	"github.com/noopgabe/gopher-it/internal/safeguards"
	"github.com/noopgabe/gopher-it/internal/trace"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var traceOpts trace.Options

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Packet tracing",
	RunE: func(cmd *cobra.Command, args []string) error {
		syncTraceOpts()
		if traceOpts.ImportPcap == "" && !IsSudo() && os.Geteuid() != 0 {
			return fmt.Errorf("Live capture needs root privileges. You can pass --sudo or run the command with sudo.")
		}
		filter, err := safeguards.SafeFilter(traceOpts.Filter)
		if err != nil {
			return err
		}
		traceOpts.Filter = filter
		if live {
			traceOpts.Duration = 0
		}
		return trace.Run(cmd.Context(), traceOpts)
	},
}

func syncTraceOpts() {
	traceOpts.Iface = viper.GetString("trace.iface")
	traceOpts.Filter = viper.GetString("trace.filter")
	traceOpts.Count = viper.GetInt("trace.count")
	traceOpts.Duration = viper.GetInt("trace.duration")
	traceOpts.ExportPcap = viper.GetString("trace.export")
	traceOpts.ImportPcap = viper.GetString("trace.import")
	traceOpts.Limit = viper.GetInt("trace.limit")
}

func init() {
	traceCmd.Flags().StringVarP(&traceOpts.Iface, "iface", "i", "any", "Interface")
	traceCmd.Flags().StringVarP(&traceOpts.Filter, "filter", "f", "", "Filter expression")
	traceCmd.Flags().IntVarP(&traceOpts.Count, "count", "c", 0, "Packet count (0 for unlimited)")
	traceCmd.Flags().IntVar(&traceOpts.Duration, "duration", 30, "Duration in seconds")
	traceCmd.Flags().StringVar(&traceOpts.ExportPcap, "export", "", "Export pcap")
	traceCmd.Flags().StringVar(&traceOpts.ImportPcap, "import", "", "Import pcap")
	traceCmd.Flags().IntVar(&traceOpts.Limit, "limit", 1000, "Import limit ")
	bindFlags("trace", traceCmd.Flags())
	rootCmd.AddCommand(traceCmd)
}

var (
	replayPcap  string
	replayIface string
)

func init() {
	inj := &cobra.Command{
		Use:   "Replay",
		Short: "Replay pcap (advanced)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireBuffoon("Packet replay"); err != nil {
				return err
			}
			if !IsSudo() {
				return fmt.Errorf("Raw injection needs root privileges. You can pass --sudo or run the command with sudo.")
			}
			if replayPcap == "" {
				return fmt.Errorf("--pcap is required for replay to work.")
			}
			return trace.ReplayPcap(cmd.Context(), replayPcap, replayIface)
		},
	}
	inj.Flags().StringVar(&replayPcap, "pcap", "", "PCAP file to replay")
	inj.Flags().StringVar(&replayIface, "iface", "", "Interface to replay on")
	traceCmd.AddCommand(inj)
}
