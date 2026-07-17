package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the SYSWARDEN Enterprise Dashboard (TUI)",
	Run: func(cmd *cobra.Command, args []string) {
		// Catch SIGINT/SIGTERM in the parent without exiting, so we survive if the child TUI is violently killed.
		// Using Notify instead of Ignore prevents the child from inheriting SIG_IGN.
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sigChan)

		tuiCmd := exec.Command("/opt/syswarden/bin/syswarden-tui") // #nosec
		tuiCmd.Stdin = os.Stdin
		tuiCmd.Stdout = os.Stdout
		tuiCmd.Stderr = os.Stderr

		err := tuiCmd.Run()

		// Forcefully disable all mouse tracking modes and ensure cursor is visible
		fmt.Print("\033[?1000l\033[?1002l\033[?1003l\033[?1006l\033[?25h")

		// Small delay to allow the terminal emulator to process the mouse release
		time.Sleep(50 * time.Millisecond)

		// Flush any lingering mouse artifacts (like the '*' character) from the stdin buffer
		_ = unix.IoctlSetInt(int(os.Stdin.Fd()), unix.TCFLSH, unix.TCIFLUSH)

		if err != nil {
			fmt.Printf("\n[ERROR] TUI exited abnormally: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() { rootCmd.AddCommand(tuiCmd) }
