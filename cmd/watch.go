package cmd

import (
	"fmt"
	"net/url"

	"github.com/noopgabe/gopher-it/internal/watch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var watchOpts watch.Options

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Host software status monitoring and alerts",
	RunE: func(cmd *cobra.Command, args []string) error {
		syncWatchOpts()
		watchOpts.Processes = append(watchOpts.Processes, args...)
		if len(watchOpts.Processes) == 0 {
			watchOpts.Processes = viper.GetStringSlice("watch.processes")
		}
		if len(watchOpts.Processes) == 0 && watchOpts.CmdCheck == "" {
			return fmt.Errorf("No processes were specified, or --check wasn't passed.")
		}
		for _, u := range []struct{ name, val string }{{"webhook", watchOpts.Webhook}, {"slack", watchOpts.Slack}} {
			if u.val == "" {
				continue
			}
			parsed, err := url.Parse(u.val)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				return fmt.Errorf("invalid %s URL: %q", u.name, u.val)
			}
		}
		watchOpts.Live = live
		if !live {
			watchOpts.Once = true
		}
		return watch.Run(cmd.Context(), watchOpts)
	},
}

func syncWatchOpts() {
	watchOpts.Interval = viper.GetInt("watch.interval")
	watchOpts.Webhook = viper.GetString("watch.webhook")
	watchOpts.Slack = viper.GetString("watch.slack")
	watchOpts.CPULimit = viper.GetFloat64("watch.cpu")
	watchOpts.MemLimit = viper.GetFloat64("watch.mem") // watch meme
	watchOpts.CmdCheck = viper.GetString("watch.check")
}

func init() {
	watchCmd.Flags().IntVar(&watchOpts.Interval, "interval", 60, "Interval in seconds")
	watchCmd.Flags().StringVar(&watchOpts.Webhook, "webhook", "", "Webhook URL")
	watchCmd.Flags().StringVar(&watchOpts.Slack, "slack", "", "Slack webhook URL")
	watchCmd.Flags().Float64Var(&watchOpts.CPULimit, "cpu", 80, "CPU threshold")
	watchCmd.Flags().Float64Var(&watchOpts.MemLimit, "mem", 500, "Memory threshold in megabytes") // when im hungry i take a megabyte out of my burger
	watchCmd.Flags().StringVar(&watchOpts.CmdCheck, "check", "", "Command health check")          // i'm DYING -gopher-it
	bindFlags("watch", watchCmd.Flags())
	rootCmd.AddCommand(watchCmd)
}
