package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/starfly-fabrics/starfly/pkg/soul"
)

// runDoc implements the `starfly doc` subcommand family:
//
//	starfly doc topology --manifest <file>
//	starfly doc runbook  --manifest <file>
//	starfly doc changelog --from <file> --to <file>
func runDoc(args []string) int {
	if len(args) == 0 {
		printDocUsage()
		return 1
	}

	subcommand := args[0]
	remaining := args[1:]

	switch subcommand {
	case "topology":
		return runDocTopology(remaining)
	case "runbook":
		return runDocRunbook(remaining)
	case "changelog":
		return runDocChangelog(remaining)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown doc subcommand %q\n", subcommand)
		printDocUsage()
		return 1
	}
}

func printDocUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  starfly doc topology  --manifest <file>          Generate fabric topology document
  starfly doc runbook   --manifest <file>          Generate operational runbook
  starfly doc changelog --from <file> --to <file>  Generate changelog from two manifests
`)
}

func runDocTopology(args []string) int {
	fs := flag.NewFlagSet("doc topology", flag.ExitOnError)
	var manifestPath string
	fs.StringVar(&manifestPath, "manifest", "", "path to soul manifest YAML file")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if manifestPath == "" {
		fmt.Fprintf(os.Stderr, "error: --manifest is required\n")
		return 1
	}

	m, err := loadManifestFile(manifestPath)
	if err != nil {
		slog.Error("loading manifest", "error", err)
		return 1
	}

	fmt.Print(soul.GenerateTopology(m))
	return 0
}

func runDocRunbook(args []string) int {
	fs := flag.NewFlagSet("doc runbook", flag.ExitOnError)
	var manifestPath string
	fs.StringVar(&manifestPath, "manifest", "", "path to soul manifest YAML file")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if manifestPath == "" {
		fmt.Fprintf(os.Stderr, "error: --manifest is required\n")
		return 1
	}

	m, err := loadManifestFile(manifestPath)
	if err != nil {
		slog.Error("loading manifest", "error", err)
		return 1
	}

	fmt.Print(soul.GenerateRunbook(m))
	return 0
}

func runDocChangelog(args []string) int {
	fs := flag.NewFlagSet("doc changelog", flag.ExitOnError)
	var fromPath, toPath string
	fs.StringVar(&fromPath, "from", "", "path to source (older) soul manifest")
	fs.StringVar(&toPath, "to", "", "path to target (newer) soul manifest")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if fromPath == "" || toPath == "" {
		fmt.Fprintf(os.Stderr, "error: --from and --to are required\n")
		return 1
	}

	from, err := loadManifestFile(fromPath)
	if err != nil {
		slog.Error("loading source manifest", "error", err)
		return 1
	}

	to, err := loadManifestFile(toPath)
	if err != nil {
		slog.Error("loading target manifest", "error", err)
		return 1
	}

	diff := soul.Diff(from, to)
	fmt.Print(soul.GenerateChangelog(diff))
	return 0
}
