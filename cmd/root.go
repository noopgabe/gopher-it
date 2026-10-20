package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	jsonOut bool
	yamlOut bool
	csvOut  bool
	quiet   bool
	verbose bool
	sudo    bool
	buffoon bool
	live    bool
)

var rootCmd = &cobra.Command{
	Use:   "gopher-it",
	Short: "Gopher-IT is a CLI tool for networking tasks, status checks, and also incredibly stupid things.",
	Long:  "Gopher-IT is an all-in-one CLI tool for basic networking, status checks, and advanced user commands. It is for everyone, from the humble beginner to Jeff in IT, who hasn't seen the light of day.",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Welcome to Gopher-IT! Please use a subcoommand (scan, trace, watch, secure, doctor, install, update, completion), or use --help to get a more detailed guide.")
		}
	},
}

func Execute() { // Execute him at once! This means nothing to the code whatever this is funny tho
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Configuration file (the default is at ~/.gopher-it/config.toml)")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "Output in JSON")
	rootCmd.PersistentFlags().BoolVar(&yamlOut, "yaml", false, "Output in YAML")
	rootCmd.PersistentFlags().BoolVar(&csvOut, "csv", false, "Output in CSV")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Becomes quiet")                                                                                // Hush!
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Becomes verbose")                                                                          // Speak!
	rootCmd.PersistentFlags().BoolVar(&sudo, "sudo", false, "Allow privilege escalation!")                                                                          // "You're calling the admin? Heh, I AM the admin!"
	rootCmd.PersistentFlags().BoolVar(&buffoon, "i-am-a-buffoon", false, "Enable dangerous features (you must pass this command when running a dangerous command)") // Let's be serious for a moment. You should never run this casually, as things could happen. Unserioused!
	rootCmd.PersistentFlags().BoolVar(&live, "live", false, "Enable live/watch mode)")                                                                              // yo bro im streaming gopher-it wanna watch on twitch
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return loadConfig()
	}
}

func loadConfig() error {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("Could not resolve home dir, %w", err)
		}
		viper.AddConfigPath(filepath.Join(home, ".gopher-it"))
		viper.SetConfigName("config")
		viper.SetConfigType("toml")
	}
	viper.SetEnvPrefix("GOPHERIT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		return fmt.Errorf("Could not bind global flags, %w", err)
	}
	// Now we have to overlay viper onto the bound vars. Bru
	jsonOut = viper.GetBool("json")
	yamlOut = viper.GetBool("yaml")
	csvOut = viper.GetBool("csv")
	quiet = viper.GetBool("quiet")
	verbose = viper.GetBool("verbose")
	sudo = viper.GetBool("sudo")
	buffoon = viper.GetBool("i-am-a-buffoon")
	live = viper.GetBool("live")
	return nil
}

func ConfigPath() string {
	if cfgFile != "" {
		return cfgFile // big brain moment
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "" // big brain moment electric boogaloo
	}
	return filepath.Join(home, ".gopher-it", "config.toml")
}

func IsSudo() bool    { return sudo }
func IsQuiet() bool   { return quiet }
func IsVerbose() bool { return verbose }

const buffoonWarning = `You have passed the --i-am-a-buffoonj flag, which allows you to run dangerous features not usually allowed. 
By running this, you acknowledge this is not a smart idea (unless you know what you are doing), and you will NOT recieve support for this unless this blew up your computer. 
Please be careful. If you do not know what you are doing, it is best to hit Ctrl+C NOW and run the command with sane defaults.`

var buffoonWarnOnce sync.Once

// During dangerous commands, this function REQUIRES the user to pass --i-am-a-buffoon.
// My reasoning here is that it does work, technically. However, they are flammable as hell, and sometimes are stupidly dangerous.
func requireBuffoon(action string) error {
	if !buffoon {
		return fmt.Errorf("You have attempted to run a dangerous command (%s) without passing the --i-am-a-buffoon flag. You can either pass it, or run the command normally. If you aren't sure, just run it normally.")
	}
	buffoonWarnOnce.Do(func() {
		fmt.Fprintln(os.Stderr, buffoonWarning)
	})
	return nil
}
