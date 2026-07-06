package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the SYSWARDEN Enterprise Dashboard (TUI)",
	Run: func(cmd *cobra.Command, args []string) {
		tuiCmd := exec.Command("/opt/syswarden/bin/syswarden-tui")
		tuiCmd.Stdin = os.Stdin
		tuiCmd.Stdout = os.Stdout
		tuiCmd.Stderr = os.Stderr
		if err := tuiCmd.Run(); err != nil {
			fmt.Printf("[ERROR] Failed to start TUI: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() { rootCmd.AddCommand(tuiCmd) }
