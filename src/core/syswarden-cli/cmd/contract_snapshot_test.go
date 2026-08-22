package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const cliExitHelperEnvironment = "SYSWARDEN_CLI_EXIT_HELPER"

type commandContract struct {
	Path        string            `json:"path"`
	Use         string            `json:"use"`
	Short       string            `json:"short"`
	Long        string            `json:"long,omitempty"`
	Example     string            `json:"example,omitempty"`
	Flags       []flagContract    `json:"flags,omitempty"`
	ArgOutcomes map[string]string `json:"arg_outcomes"`
}

type flagContract struct {
	Name       string `json:"name"`
	Shorthand  string `json:"shorthand,omitempty"`
	Type       string `json:"type"`
	Default    string `json:"default"`
	NoOption   string `json:"no_option,omitempty"`
	Usage      string `json:"usage"`
	Persistent bool   `json:"persistent,omitempty"`
}

func TestCLICommandTreeSnapshot_SW_QA_001(t *testing.T) {
	wantPath := filepath.Join("..", "..", "..", "..", "testdata", "contracts", "cli-command-tree.json")
	got, err := json.MarshalIndent(snapshotCommandTree(rootCmd), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("SYSWARDEN_UPDATE_CONTRACT_GOLDENS") == "1" {
		if err := os.WriteFile(wantPath, got, 0600); err != nil {
			t.Fatalf("update CLI command fixture: %v", err)
		}
		return
	}

	want, err := os.ReadFile(wantPath) // #nosec G304 -- wantPath is a fixed repository fixture
	if err != nil {
		t.Fatalf("read CLI command fixture: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("CLI command contract changed; review and approve every difference before updating the fixture:\n%s", got)
	}
}

func snapshotCommandTree(root *cobra.Command) []commandContract {
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	var contracts []commandContract
	var walk func(*cobra.Command)
	walk = func(command *cobra.Command) {
		if command != root && command.Hidden {
			return
		}
		command.InitDefaultHelpFlag()
		contract := commandContract{
			Path:        command.CommandPath(),
			Use:         command.Use,
			Short:       command.Short,
			Long:        command.Long,
			Example:     command.Example,
			ArgOutcomes: make(map[string]string),
		}

		seenFlags := make(map[string]bool)
		appendFlags := func(flags *pflag.FlagSet, persistent bool) {
			flags.VisitAll(func(flag *pflag.Flag) {
				if seenFlags[flag.Name] {
					return
				}
				seenFlags[flag.Name] = true
				contract.Flags = append(contract.Flags, flagContract{
					Name:       flag.Name,
					Shorthand:  flag.Shorthand,
					Type:       flag.Value.Type(),
					Default:    flag.DefValue,
					NoOption:   flag.NoOptDefVal,
					Usage:      flag.Usage,
					Persistent: persistent,
				})
			})
		}
		appendFlags(command.LocalNonPersistentFlags(), false)
		appendFlags(command.PersistentFlags(), true)
		appendFlags(command.InheritedFlags(), true)
		sort.Slice(contract.Flags, func(i, j int) bool {
			return contract.Flags[i].Name < contract.Flags[j].Name
		})

		for count := 0; count <= 4; count++ {
			outcome := "ok"
			if command.Args != nil {
				args := make([]string, count)
				for index := range args {
					args[index] = fmt.Sprintf("arg-%d", index+1)
				}
				if err := command.Args(command, args); err != nil {
					outcome = err.Error()
				}
			}
			contract.ArgOutcomes[fmt.Sprintf("%d", count)] = outcome
		}

		contracts = append(contracts, contract)
		children := command.Commands()
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, child := range children {
			walk(child)
		}
	}
	walk(root)
	return contracts
}

func TestCLIExecutableHelpContract_SW_QA_001(t *testing.T) {
	contracts := snapshotCommandTree(rootCmd)
	for _, contract := range contracts {
		contract := contract
		t.Run(strings.ReplaceAll(contract.Path, " ", "_"), func(t *testing.T) {
			args := strings.Fields(strings.TrimPrefix(contract.Path, "syswarden"))
			args = append(args, "--help")
			exit, stdout, stderr := runCLIHelper(t, args)
			if exit != 0 {
				t.Fatalf("%s --help exit = %d, want 0\nstdout=%s\nstderr=%s", contract.Path, exit, stdout, stderr)
			}
			if contract.Long == "" && !strings.Contains(stdout, contract.Short) {
				t.Fatalf("%s --help does not expose Short %q:\n%s", contract.Path, contract.Short, stdout)
			}
			if contract.Long != "" && !strings.Contains(stdout, contract.Long) {
				t.Fatalf("%s --help does not expose Long %q:\n%s", contract.Path, contract.Long, stdout)
			}
			if contract.Example != "" && !strings.Contains(stdout, contract.Example) {
				t.Fatalf("%s --help does not expose Example %q:\n%s", contract.Path, contract.Example, stdout)
			}
			for _, flag := range contract.Flags {
				if !strings.Contains(stdout, "--"+flag.Name) {
					t.Fatalf("%s --help omits frozen flag --%s:\n%s", contract.Path, flag.Name, stdout)
				}
			}
		})
	}
}

func TestCLIProcessExitCodeContract_SW_QA_001(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantExit       int
		stdoutContains string
		stderrContains string
		stderrEmpty    bool
	}{
		{
			name:           "root command",
			wantExit:       0,
			stdoutContains: "Use 'syswarden manual'",
			stderrEmpty:    true,
		},
		{
			name:           "help",
			args:           []string{"--help"},
			wantExit:       0,
			stdoutContains: "Available Commands:",
			stderrEmpty:    true,
		},
		{
			name:           "unknown command",
			args:           []string{"does-not-exist"},
			wantExit:       1,
			stderrContains: "unknown command",
		},
		{
			name:           "argument validation",
			args:           []string{"check"},
			wantExit:       1,
			stderrContains: "accepts 1 arg(s), received 0",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			gotExit, stdout, stderr := runCLIHelper(t, test.args)
			if gotExit != test.wantExit {
				t.Fatalf("exit code = %d, want %d\nstdout=%s\nstderr=%s", gotExit, test.wantExit, stdout, stderr)
			}
			if !strings.Contains(stdout, test.stdoutContains) {
				t.Fatalf("stdout does not contain %q:\n%s", test.stdoutContains, stdout)
			}
			if !strings.Contains(stderr, test.stderrContains) {
				t.Fatalf("stderr does not contain %q:\n%s", test.stderrContains, stderr)
			}
			if test.stderrEmpty && stderr != "" {
				t.Fatalf("stderr is not empty:\n%s", stderr)
			}
		})
	}
}

func runCLIHelper(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestCLIExitHelperProcess$") // #nosec G204 G702 -- os.Args[0] is the fixed current test binary and the argument is static
	command.Env = append(os.Environ(), cliExitHelperEnvironment+"="+string(encoded))
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	exit := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exit = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run CLI helper: %v", err)
	}
	return exit, stdout.String(), stderr.String()
}

func TestCLIExitHelperProcess(t *testing.T) {
	encoded, enabled := os.LookupEnv(cliExitHelperEnvironment)
	if !enabled {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		os.Exit(97)
	}
	os.Args = append([]string{"syswarden"}, args...)
	Execute()
	os.Exit(0)
}
